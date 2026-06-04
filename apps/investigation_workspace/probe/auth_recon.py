"""Login-form recon probe — detect HTML login forms.

V1.2 — runs alongside passive_probe, sqli_recon, cmdi_recon during
bootstrap. Walks a small set of well-known login paths, fetches each
page, and parses the HTML for a <form> containing a <input type="password">
field. When at least one form is found, emits a single FindingEvent
with finding_type="login_form_detected" and the form's metadata in
the evidence dict so the brute-force probe can read it without
re-scanning.

PRESENCE DETECTION ONLY — no credentials are submitted here. The
attack probe (probe_brute_force_login) is responsible for credential
testing. This separation keeps the recon probe safe to run on every
bootstrap.

The form metadata carried in the FindingEvent.evidence dict is:
    {
      "detected_forms": [
        {
          "path":           "/login.php",
          "form_action":    "/login.php",  # absolute or relative
          "username_field": "username",
          "password_field": "password",
          "csrf_field":     "user_token",  # None if not found
        },
        ...
      ],
      "candidate_paths_probed": [...],
    }
"""
from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urljoin, urlparse

import httpx

from apps.investigation_workspace.probe.events import FindingEvent, StageEvent

# ── Shared success heuristic ─────────────────────────────────────────────────
# Any 302 whose Location still points at a login/error page means the
# credentials were rejected. A redirect elsewhere means the server accepted.
_LOGIN_REDIRECT_FAILURE_KEYWORDS: tuple[str, ...] = (
    "/login", "login.php", "/signin", "/auth",
    "?msg=invalid", "?error", "incorrect",
    "?login_failed", "?failed", "?wrong",
)


def is_form_login_success(resp: httpx.Response) -> bool:
    """True when a form POST looks like a successful login.

    Heuristic: 302/301 redirect whose Location does NOT contain any
    known login-failure keyword.  Used by brute_force_login and the
    api_exploit auth phase so both share identical detection logic.
    """
    if resp.status_code not in (301, 302):
        return False
    loc = resp.headers.get("location", "").lower()
    return not any(kw in loc for kw in _LOGIN_REDIRECT_FAILURE_KEYWORDS)

# Well-known login page paths. HTML form–based login pages, not JSON
# APIs (sqli_recon handles JSON APIs via POST+Content-Type detection).
LOGIN_FORM_PATHS: tuple[str, ...] = (
    "/login",
    "/login.php",
    "/admin",
    "/admin/login",
    "/signin",
    "/auth",
    "/user/login",
    "/wp-login.php",
)

_RECON_TIMEOUT_S = 6.0

# Patterns to parse form structure from HTML responses.
_FORM_RE       = re.compile(r"<form[^>]*>(.*?)</form>", re.S | re.I)
_ACTION_RE     = re.compile(r'\baction=[\'"]?([^\'">\s]+)', re.I)
_INPUT_RE      = re.compile(r"<input[^>]*>", re.I)
_TYPE_RE       = re.compile(r'\btype=[\'"]?([^\'">\s]+)', re.I)
_NAME_RE       = re.compile(r'\bname=[\'"]?([^\'">\s]+)', re.I)
_CSRF_NAMES    = ("user_token", "csrf_token", "_token", "__RequestVerificationToken",
                  "csrfmiddlewaretoken", "_csrf")


def _parse_login_form(html: str, page_url: str) -> dict | None:
    """Return form metadata dict if the HTML contains a login form, else None.

    A login form is defined as a <form> element containing both a
    username-type input and a password-type input.
    """
    for form_match in _FORM_RE.finditer(html):
        form_outer = html[form_match.start():form_match.end()]
        form_inner = form_match.group(1)

        action_m = _ACTION_RE.search(form_outer)
        raw_action = action_m.group(1) if action_m else ""
        form_action = urljoin(page_url, raw_action) if raw_action else page_url

        inputs: list[dict] = []
        for inp in _INPUT_RE.finditer(form_inner):
            tag = inp.group(0)
            type_m = _TYPE_RE.search(tag)
            name_m = _NAME_RE.search(tag)
            if not name_m:
                continue
            inputs.append({
                "type": (type_m.group(1).lower() if type_m else "text"),
                "name": name_m.group(1),
            })

        password_inputs  = [i["name"] for i in inputs if i["type"] == "password"]
        text_inputs      = [i["name"] for i in inputs
                            if i["type"] in ("text", "email", "") or "user" in i["name"].lower()
                            or "email" in i["name"].lower()]
        # Priority 1: exact match against known CSRF field names.
        csrf_inputs = [i["name"] for i in inputs if i["name"] in _CSRF_NAMES]
        # Priority 2 (fallback): any hidden input whose name contains "csrf"
        # or "token" — catches bare names like "csrf" (PortSwigger) that are
        # not in the static list.
        if not csrf_inputs:
            csrf_inputs = [
                i["name"] for i in inputs
                if i["type"] == "hidden"
                and ("csrf" in i["name"].lower() or "token" in i["name"].lower())
            ]

        if not password_inputs:
            continue  # Not a login form — no password field

        # Pick best username field: prefer one with "user"/"email" in the name
        _kw = ("user", "email", "login", "name")
        username_candidates = [n for n in text_inputs if any(kw in n.lower() for kw in _kw)]
        username_field = (username_candidates or text_inputs or ["username"])[0]

        # Collect submit button name/value pairs so the probe can include
        # them — some apps (DVWA) require the submit button value in the POST.
        _VAL_RE = re.compile(r'\bvalue=[\'"]?([^\'">\s]+)', re.I)
        submit_fields: dict[str, str] = {}
        for inp in _INPUT_RE.finditer(form_inner):
            tag = inp.group(0)
            type_m = _TYPE_RE.search(tag)
            if not type_m or type_m.group(1).lower() != "submit":
                continue
            name_m = _NAME_RE.search(tag)
            val_m  = _VAL_RE.search(tag)
            if name_m and val_m:
                submit_fields[name_m.group(1)] = val_m.group(1)

        return {
            "form_action":    form_action,
            "username_field": username_field,
            "password_field": password_inputs[0],
            "csrf_field":     csrf_inputs[0] if csrf_inputs else None,
            "submit_fields":  submit_fields,
        }

    return None


async def _probe_path(
    client: httpx.AsyncClient, base: str, path: str,
) -> dict | None:
    """Return form metadata dict for path, or None if no login form found."""
    url = base + path
    try:
        r = await client.get(url)
    except httpx.RequestError:
        return None

    if r.status_code == 404:
        return None

    # Follow a single redirect to a login page
    if r.status_code in (301, 302):
        loc = r.headers.get("location", "")
        if not loc:
            return None
        try:
            r2 = await client.get(urljoin(url, loc))
        except httpx.RequestError:
            return None
        r = r2

    if r.status_code != 200:
        return None

    ct = r.headers.get("content-type", "").lower()
    if "html" not in ct:
        return None

    form = _parse_login_form(r.text, url)
    if form is None:
        return None

    return {"path": path, **form}


async def run_auth_recon_probe(
    target: str,
    candidate_paths: tuple[str, ...] | None = None,
) -> AsyncIterator[StageEvent | FindingEvent]:
    """Bootstrap-stage probe: discover HTML login forms, emit one
    aggregated FindingEvent when any are found.

    candidate_paths overrides LOGIN_FORM_PATHS when provided,
    enabling re-invocation against a focused set of paths.

    Quiet on negative result — no FindingEvent emitted if the target
    exposes no recognised login form. Match sqli_recon's quiet pattern.
    """
    paths = candidate_paths if candidate_paths is not None else LOGIN_FORM_PATHS

    parsed = urlparse(target if "://" in target else f"http://{target}")
    base   = f"{parsed.scheme}://{parsed.netloc}"

    yield StageEvent(
        label    = "Scanning for login forms",
        actions  = tuple(f"GET {base}{p}" for p in paths),
        tools    = ("httpx async client", "HTML form parser"),
        confidence = "high",
    )

    found: list[dict] = []
    async with httpx.AsyncClient(
        timeout          = _RECON_TIMEOUT_S,
        follow_redirects = False,
        verify           = False,
    ) as client:
        for path in paths:
            result = await _probe_path(client, base, path)
            if result:
                found.append(result)

    yield StageEvent(
        label    = "Cataloguing login forms",
        actions  = (
            f"checked {len(paths)} candidate path(s)",
            f"{len(found)} login form(s) found" if found else "no login forms found",
        ),
        tools    = ("HTML form parser",),
        detected = tuple(
            f"form at {f['path']!r}: username={f['username_field']!r} "
            f"password={f['password_field']!r}"
            + (f" csrf={f['csrf_field']!r}" if f.get("csrf_field") else "")
            for f in found[:5]
        ) or ("no login forms to record",),
        confidence = "high",
    )

    if not found:
        return

    primary = found[0]
    paths_str = ", ".join(f["path"] for f in found)
    yield FindingEvent(
        after_stage_index = 1,
        finding_type      = "login_form_detected",
        title             = "Login form detected",
        severity          = "info",
        description       = (
            f"Found {len(found)} login form(s) at {paths_str}. "
            "Run brute-force login to test default credentials."
        ),
        endpoint          = primary["path"],
        evidence          = {
            "detected_forms":          found,
            "candidate_paths_probed":  list(paths),
        },
        phase             = "enumeration",
    )


# ── Shared auth helpers used by attack probes ─────────────────────────────────


async def discover_login_form(base_url: str) -> dict | None:
    """Scan LOGIN_FORM_PATHS and return the first HTML login-form metadata found.

    Returns a dict with keys: path, form_action, username_field, password_field,
    csrf_field, submit_fields — or None if no form is found at any candidate path.
    Callers use this to decide whether to POST as form-urlencoded or JSON.
    """
    async with httpx.AsyncClient(
        timeout          = _RECON_TIMEOUT_S,
        follow_redirects = False,
        verify           = False,
    ) as client:
        for path in LOGIN_FORM_PATHS:
            result = await _probe_path(client, base_url, path)
            if result:
                return result
    return None


async def attempt_default_creds_login(
    base_url:   str,
    creds:      tuple[tuple[str, str], ...],
    json_paths: tuple[str, ...] = (),
) -> dict | None:
    """Try each (username, password) pair against the target.

    Strategy:
      1. Scan for an HTML login form (form-urlencoded POST, 302-away success).
      2. Fall back to JSON POST against json_paths if no form is found.

    Returns None when all attempts fail.  On success returns:
        {
          "username":        str,
          "password":        str,
          "login_path":      str,   # path or URL that accepted the creds
          "session_cookies": dict,  # cookies to forward with authenticated requests
          "method":          "form" | "json",
        }

    No host gates.  Works against any target whose auth is either an HTML
    form or a JSON-accepting REST endpoint.
    """
    # ── 1. HTML form login ──────────────────────────────────────────────
    form = await discover_login_form(base_url)
    if form:
        form_action    = form["form_action"]
        username_field = form["username_field"]
        password_field = form["password_field"]
        csrf_field     = form.get("csrf_field")
        submit_fields: dict[str, str] = form.get("submit_fields") or {}

        async with httpx.AsyncClient(
            timeout          = _RECON_TIMEOUT_S,
            follow_redirects = False,
            verify           = False,
        ) as c:
            for username, password in creds:
                data: dict[str, str] = {
                    username_field: username,
                    password_field: password,
                    **submit_fields,
                }
                if csrf_field:
                    try:
                        page = await c.get(form_action)
                        # Generic: find input[name=csrf_field] value attribute.
                        _csrf_re = re.compile(
                            r'<input[^>]+name=[\'"]?' + re.escape(csrf_field)
                            + r'[\'"]?[^>]+value=[\'"]?([^\'">\s]+)',
                            re.I,
                        )
                        m = _csrf_re.search(page.text)
                        if m:
                            data[csrf_field] = m.group(1)
                    except httpx.RequestError:
                        pass
                try:
                    resp = await c.post(form_action, data=data)
                except httpx.RequestError:
                    continue
                if is_form_login_success(resp):
                    return {
                        "username":        username,
                        "password":        password,
                        "login_path":      form.get("path", form_action),
                        "session_cookies": dict(resp.cookies),
                        "method":          "form",
                    }

    # ── 2. JSON API login fallback ──────────────────────────────────────
    if json_paths:
        async with httpx.AsyncClient(
            timeout          = _RECON_TIMEOUT_S,
            follow_redirects = True,
            verify           = False,
        ) as c:
            for username, password in creds:
                for path in json_paths:
                    try:
                        r = await c.post(
                            base_url + path,
                            json    = {"username": username, "password": password},
                            headers = {"Content-Type": "application/json"},
                        )
                    except httpx.RequestError:
                        continue
                    has_cookie = "set-cookie" in r.headers
                    body_lower = r.text.lower()
                    has_token  = '"token"' in body_lower or '"session"' in body_lower
                    if r.status_code in (200, 302) and (has_cookie or has_token):
                        return {
                            "username":        username,
                            "password":        password,
                            "login_path":      path,
                            "session_cookies": dict(r.cookies),
                            "method":          "json",
                        }

    return None


_WORDLIST_PATH = (
    __import__("pathlib").Path(__file__).parent
    / "wordlists" / "default-passwords.csv"
)

# Built-in fallback when the vendored CSV is absent.
_FALLBACK_CREDS: tuple[tuple[str, str], ...] = (
    ("wiener",        "peter"),
    ("admin",         "admin"),
    ("admin",         "password"),
    ("administrator", "admin"),
    ("root",          "root"),
    ("test",          "test"),
)


def load_default_credentials() -> list[tuple[str, str]]:
    """Load (username, password) pairs from the vendored SecLists CSV.

    Falls back to a tiny built-in list when the CSV is absent. The
    _PRIORITY_CREDS prepend was removed in V2.2 Step 3 — priority ordering
    is now controlled via brute_force_login.yaml in the payload registry.
    """
    import csv

    pairs: list[tuple[str, str]] = []
    if _WORDLIST_PATH.exists():
        with open(_WORDLIST_PATH, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                user = (row.get("Username") or "").strip()
                pw   = (row.get("Password") or "").strip()
                if not user or not pw or user == "<BLANK>" or pw == "<BLANK>":
                    continue
                pairs.append((user, pw))

    return pairs if pairs else list(_FALLBACK_CREDS)
