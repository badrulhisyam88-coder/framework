"""Command-injection recon probe — discover candidate endpoints.

Phase 60 — runs alongside the passive and SQLi-recon probes during
bootstrap. Walks a small set of known command-injection page paths,
identifies which exist on the target, and emits ONE aggregated
`FindingEvent(finding_type="command_injection")` when at least one
responds.

PRESENCE DETECTION ONLY. No payloads are sent from here — the
exploitation probes (probe_cmdi_reflected / probe_cmdi_blind_time /
probe_cmdi_blind_boolean) are responsible for payload testing. This
separation keeps the recon probe safe to run on every bootstrap.

Authentication-aware: when an endpoint responds with a 302 to a
login page, the recon probe records "endpoint present, auth
required" in the finding evidence so the exploit probes know they
need to obtain auth state before attacking.

The list of probed paths is a public module constant
(COMMON_CMDI_PATHS) so the exploit probes import the same set.
"""
from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urlparse

import httpx

from apps.investigation_workspace.probe.events import FindingEvent, StageEvent

# Well-known command-injection page paths. Both this recon probe and
# the cmdi exploit probes consume the same tuple to stay in sync.
COMMON_CMDI_PATHS: tuple[str, ...] = (
    "/vulnerabilities/exec/",          # DVWA primary
    "/vulnerabilities/exec",           # DVWA no-slash variant
    "/commandi.php",                   # bWAPP command-injection module
    "/index.php?page=dns-lookup.php",  # Mutillidae DNS lookup
    "/ping.php",                       # generic PHP ping reflectors
    "/exec.php",                       # generic PHP exec endpoints
    "/admin/cmd",                      # admin panel command runner
    "/tools/ping",                     # diagnostic page convention
    "/diagnostic/ping",                # diagnostic page convention
)

_RECON_TIMEOUT_S    = 6.0
_FORM_INPUT_TAG_RE  = re.compile(r"<input[^>]*>", re.I)
_INPUT_ATTR_NAME_RE = re.compile(r'\bname=["\']([^"\']+)["\']', re.I)
_INPUT_ATTR_TYPE_RE = re.compile(r'\btype=["\']([^"\']+)["\']', re.I)
_FORM_ACTION_RE     = re.compile(r"<form[^>]*action=['\"]?([^'\"\s>]*)", re.I)
_LOGIN_HINTS    = ("login.php", "/login", "/signin", "/auth/login")


async def _probe_path(
    client: httpx.AsyncClient, base: str, path: str,
) -> dict | None:
    """Return a per-path observation dict, or None if the endpoint
    is absent. Observation shape:
        {
          "path": "/vulnerabilities/exec/",
          "status": 200,
          "auth_required": False,
          "form_inputs": [{"name": "ip", "type": "text"}, {"name": "Submit", "type": "submit"}],
          "form_action": "",                  # relative or absolute
        }
    """
    url = base + path
    try:
        # GET — we need the response body to parse the form. HEAD
        # wouldn't surface form parameter names.
        r = await client.get(url)
    except httpx.RequestError:
        return None

    # 302 to a login-shaped URL → endpoint exists, requires auth
    if r.status_code in (301, 302):
        loc = r.headers.get("location", "")
        if any(hint in loc.lower() for hint in _LOGIN_HINTS):
            return {
                "path":          path,
                "status":        r.status_code,
                "auth_required": True,
                "form_inputs":   [],  # list[{name, type}]
                "form_action":   "",
            }
        # Some other redirect — treat as absent (could be a vanity URL).
        return None

    if r.status_code == 404 or r.status_code >= 500:
        return None
    if r.status_code != 200:
        # 401/403 are intentionally excluded: a WAF blocking a path pattern
        # is not evidence the endpoint exists as a real cmdi surface. Only
        # login-redirect (302 above) and rendered pages (200 below) count.
        return None

    # 200 — require HTML + a <form> element to confirm the page actually
    # rendered an injection interface (not just a generic landing page).
    ct = r.headers.get("content-type", "").lower()
    if "html" not in ct:
        return None
    if "<form" not in r.text.lower():
        return None
    form_inputs = []
    for tag_m in _FORM_INPUT_TAG_RE.finditer(r.text):
        tag = tag_m.group(0)
        name_m = _INPUT_ATTR_NAME_RE.search(tag)
        type_m = _INPUT_ATTR_TYPE_RE.search(tag)
        if name_m:
            form_inputs.append({
                "name": name_m.group(1),
                "type": (type_m.group(1) if type_m else "text").lower(),
            })
    m_action = _FORM_ACTION_RE.search(r.text)
    form_action = m_action.group(1) if m_action else ""

    # If the page is the login page (200 but lacks a non-login form),
    # treat as auth_required. Heuristic: looks like a login page if
    # form inputs include 'username' AND 'password'.
    input_names = {inp["name"] for inp in form_inputs}
    if "username" in input_names and "password" in input_names:
        return {
            "path":          path,
            "status":        200,
            "auth_required": True,
            "form_inputs":   form_inputs,
            "form_action":   form_action,
        }

    return {
        "path":          path,
        "status":        200,
        "auth_required": False,
        "form_inputs":   form_inputs,
        "form_action":   form_action,
    }


async def run_cmdi_recon_probe(
    target: str,
    candidate_paths: tuple[str, ...] | None = None,
) -> AsyncIterator[StageEvent | FindingEvent]:
    """Bootstrap-stage probe: discover cmdi candidate endpoints,
    emit one aggregated FindingEvent when any are present.

    candidate_paths overrides COMMON_CMDI_PATHS when provided,
    enabling re-invocation against a focused set of paths.

    Quiet on negative result — no FindingEvent if no candidates
    respond.
    """
    paths = candidate_paths if candidate_paths is not None else COMMON_CMDI_PATHS

    parsed = urlparse(target if "://" in target else f"http://{target}")
    base = f"{parsed.scheme}://{parsed.netloc}"

    yield StageEvent(
        label    = "Probing for command-injection endpoints",
        actions  = tuple(f"GET {base}{p}" for p in paths),
        tools    = ("httpx async client",),
        confidence = "high",
    )

    observations: list[dict] = []
    async with httpx.AsyncClient(
        timeout         = _RECON_TIMEOUT_S,
        follow_redirects = False,
        verify           = False,
    ) as client:
        for path in paths:
            obs = await _probe_path(client, base, path)
            if obs is not None:
                observations.append(obs)

    found_paths   = [o["path"] for o in observations]
    public_paths  = [o["path"] for o in observations if not o["auth_required"]]
    auth_paths    = [o["path"] for o in observations if o["auth_required"]]
    # Form parameter names across all observations (e.g., DVWA exposes
    # "ip" on the exec form). The exploit probes use these as their
    # default injection points. Excludes submit/button inputs and CSRF tokens.
    all_inputs: list[str] = []
    for o in observations:
        for inp in o["form_inputs"]:
            name = inp["name"]
            if (
                inp.get("type", "text") not in ("submit", "button")
                and name not in ("user_token",)
                and name not in all_inputs
            ):
                all_inputs.append(name)

    yield StageEvent(
        label    = "Cataloguing command-injection candidates",
        actions  = (
            f"checked {len(paths)} candidate path(s)",
            f"{len(public_paths)} public",
            f"{len(auth_paths)} require auth",
        ),
        tools    = ("HTML form parser",),
        detected = tuple(f"present: {p}" for p in found_paths[:10])
                   or ("no command-injection endpoints found",),
        confidence = "high",
    )

    if not found_paths:
        return

    title = "Command injection candidate endpoint detected"
    auth_status = "requires_auth" if auth_paths and not public_paths else (
        "mixed (some public, some require auth)" if auth_paths else "public"
    )
    desc = (
        f"Found {len(found_paths)} endpoint(s) commonly associated with "
        f"command injection: {', '.join(found_paths)}. Authentication "
        f"status: {auth_status}."
    )
    yield FindingEvent(
        after_stage_index = 1,
        finding_type      = "command_injection",
        title             = title,
        severity          = "info",
        description       = desc,
        endpoint          = found_paths[0],
        phase             = "enumeration",
        evidence          = {
            # Persisted into NormalizedFinding.raw_data — read by the
            # exploit probes via FINDING_EVIDENCE_CTX.
            "detected_paths":         found_paths,
            "public_paths":           public_paths,
            "auth_required_paths":    auth_paths,
            "auth_required":          bool(auth_paths and not public_paths),
            "form_parameter_names":   all_inputs,
            "candidate_paths_probed": list(paths),
            "probe_method":           "GET + form parser",
            # Per-path detail for the exploit probes (form action,
            # available inputs per path).
            "observations":           observations,
        },
    )
