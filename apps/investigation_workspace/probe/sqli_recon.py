"""SQL-injection recon probe — login-endpoint discovery.

Phase 58 — runs alongside `run_passive_probe` during bootstrap. Walks
a small set of well-known login paths, identifies which ones the
target exposes, and emits a single `FindingEvent(finding_type="sqli")`
when at least one is found. This finding's binding in
`exploitation_paths/bindings.py` maps to `injection.sql`, which in
turn drives the `sqli_auth_bypass` ghost suggestion via the existing
catalog → ghost pipeline.

PRESENCE DETECTION ONLY. No SQL payloads are sent from here — the
attack probe (`probe_sqli_auth_bypass`) is responsible for payload
testing. This separation keeps the recon probe safe to run on every
bootstrap without firing exploits against unconsenting targets.

The list of probed paths is a public module constant
(`LOGIN_ENDPOINT_PATHS`) so the attack probe imports the same set
rather than duplicating it.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlparse

import httpx

from apps.investigation_workspace.probe.events import FindingEvent, StageEvent

# Well-known login-endpoint paths. Both this recon probe and the
# attack probe (probe_sqli_auth_bypass) consume the same tuple so they
# stay in sync. Extending the list here is the single change required
# to teach both probes about a new login URL convention.
LOGIN_ENDPOINT_PATHS: tuple[str, ...] = (
    "/rest/user/login",   # Juice Shop primary
    "/api/login",
    "/login",
    "/signin",
    "/auth",
    "/auth/login",
)

_RECON_TIMEOUT_S = 5.0


async def _check_path(
    client: httpx.AsyncClient, base: str, path: str
) -> dict | None:
    """Return {path, status_code, method} if path looks like a real login API endpoint, else None.

    Detection criterion: POST to the path with an empty JSON body. A
    real login endpoint typically returns:
      • 400/401/403/422  — validation/auth rejection (most APIs)
      • 200 with application/json  — surprisingly permissive API
    A static HTML page that happens to live at /login responds with:
      • 405 Method Not Allowed  — GET-only endpoint
      • 200 with text/html       — serving an HTML form, not an API
    Returns None for both static-page cases so we don't fire SQLi
    suggestions against /login on a marketing site. Connection
    errors and 404s also return None.

    Why POST and not OPTIONS: example.com (and many CDNs) return 200
    on OPTIONS for paths that have no special semantic. POST is a
    sharper signal — only endpoints designed to consume credentials
    distinguish themselves on it.
    """
    url = base + path
    try:
        r = await client.post(url, json={},
                              headers={"Content-Type": "application/json"})
    except httpx.RequestError:
        return None

    if r.status_code == 404 or r.status_code == 405:
        return None
    if r.status_code in (400, 401, 403, 415, 422):
        # Validation/auth rejection — confirms the endpoint processed
        # the request. 500/502 excluded: a server crash on empty input
        # is not evidence of a login API (parameterized-query endpoints
        # crash too; this was the main false-positive source on real sites).
        return {"path": path, "status_code": r.status_code, "method": "POST"}
    if r.status_code == 200:
        # Distinguish JSON API from HTML page.
        ct = r.headers.get("content-type", "").lower()
        if "json" in ct:
            return {"path": path, "status_code": r.status_code, "method": "POST"}
        return None
    # Anything else (e.g., 3xx redirect to login UI) — treat as
    # present; the attack probe will confirm or fail.
    if r.status_code < 500:
        return {"path": path, "status_code": r.status_code, "method": "POST"}
    return None


async def run_sqli_recon_probe(
    target: str,
    candidate_paths: tuple[str, ...] | None = None,
) -> AsyncIterator[StageEvent | FindingEvent]:
    """Bootstrap-stage probe: discover login endpoints, emit one
    aggregated FindingEvent when any are present.

    candidate_paths overrides LOGIN_ENDPOINT_PATHS when provided,
    enabling re-invocation against a focused set of paths.

    Quiet on negative result — no FindingEvent emitted if the target
    has no recognised login endpoints. Graph noise on every flat
    static target is not useful.
    """
    paths = candidate_paths if candidate_paths is not None else LOGIN_ENDPOINT_PATHS

    parsed = urlparse(target if "://" in target else f"http://{target}")
    base   = f"{parsed.scheme}://{parsed.netloc}"

    yield StageEvent(
        label    = "Probing for login endpoints",
        actions  = tuple(f"POST {base}{p}" for p in paths),
        tools    = ("httpx async client",),
        confidence = "high",
    )

    found: list[dict] = []
    async with httpx.AsyncClient(
        timeout         = _RECON_TIMEOUT_S,
        follow_redirects = True,
        verify           = False,
    ) as client:
        for path in paths:
            result = await _check_path(client, base, path)
            if result is not None:
                found.append(result)

    yield StageEvent(
        label    = "Cataloguing login endpoints",
        actions  = (
            f"checked {len(paths)} candidate path(s)",
            f"{len(found)} present" if found else "no login endpoints found",
        ),
        tools    = ("path matcher",),
        detected = tuple(f"present: {e['path']}" for e in found[:10])
                   or ("no login endpoints to record",),
        confidence = "high",
    )

    if not found:
        # Quiet negative — no FindingEvent.
        return

    auth_required = all(e["status_code"] in (401, 403) for e in found)

    title = "Login endpoint potentially injectable"
    paths_str = ", ".join(e["path"] for e in found)
    yield FindingEvent(
        # The two stages above are indices 0 and 1; the finding is
        # attributed to stage 1 (the cataloguing stage where the
        # conclusion was reached).
        after_stage_index = 1,
        finding_type      = "sqli",
        title             = title,
        severity          = "info",
        description       = (
            f"Found {len(found)} login endpoint(s) at {paths_str}. "
            f"These endpoints may be vulnerable to SQL injection "
            f"authentication bypass — run the suggested action to "
            f"test."
        ),
        endpoint          = found[0]["path"],
        evidence          = {
            # Persisted into NormalizedFinding.raw_data; available
            # to the attack probe + audit consumers.
            # Each entry: {path, status_code, method}
            "detected_login_endpoints": found,
            "candidate_paths_probed":   list(paths),
            "probe_method":             "POST",
            "auth_required":            auth_required,
        },
        phase             = "enumeration",
    )
