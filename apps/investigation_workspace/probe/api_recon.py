"""API surface recon probe — bootstrap phase.

Runs alongside the other recon probes during bootstrap. Probes the target
for API documentation endpoints, OpenAPI/Swagger surfaces, and JSON API
paths. Emits a single FindingEvent(finding_type="api_exposure") when at
least one signal is detected.

PRESENCE DETECTION ONLY — no credentials are sent, no API endpoints are
called with exploit payloads. The attack probe (probe_api_exploit) handles
the active exploitation phase.

The evidence dict emitted by the FindingEvent contains:
    {
      "signals":    [...],   # content-type / body-pattern hits on root
      "hit_paths":  [...],   # list of {path, status_code, content_type} dicts
    }
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from urllib.parse import urlparse

import httpx

from apps.investigation_workspace.probe.events import FindingEvent, StageEvent

# Candidate API documentation paths to probe concurrently.
_CANDIDATE_PATHS: tuple[str, ...] = (
    "/api",
    "/api/docs",
    "/openapi.json",
    "/swagger.json",
    "/v1",
)

# Root-response body markers that suggest an API target.
# Strings are matched against the lowercased body with bare substring search
# so both single- and double-quoted hrefs (href='/api', href="/api") are caught.
_BODY_SIGNALS: tuple[str, ...] = (
    "swagger",
    "openapi",
    "/api",        # bare path — catches href='/api', href="/api", /api/v1, etc.
    "swagger-ui",
    "/v1/",
    "/v2/",
)

_RECON_TIMEOUT_S = 5.0

# Signals used to detect bespoke HTML API doc pages (e.g. PortSwigger labs).
# Each is matched against the lowercased body. At least 2 must fire to count
# as a hit, avoiding false positives from generic HTML pages that happen to
# mention one HTTP verb or contain a table.
_HTML_DOC_SIGNALS: tuple[str, ...] = (
    "<th>verb</th>",
    "<th>method</th>",
    "id='endpoints'",
    'id="endpoints"',
    "/user/[",          # path template like /user/[username]
    "/users/[",
    "/account/[",
    ">delete<",         # HTTP verb in a table cell
    ">patch<",
    ">put<",
    "/api/",            # path fragment in body (different from /api bare)
)

_HTML_DOC_MIN_SIGNALS = 2


def _count_html_doc_signals(body_lower: str) -> int:
    """Return how many bespoke-API-doc signals are present in the body."""
    return sum(1 for s in _HTML_DOC_SIGNALS if s in body_lower)


async def _check_root(client: httpx.AsyncClient, base: str) -> list[str]:
    """GET the root; return a list of signal strings that matched."""
    signals: list[str] = []
    try:
        r = await client.get(base + "/")
    except httpx.RequestError:
        return signals

    ct = r.headers.get("content-type", "").lower()
    if "application/json" in ct:
        signals.append("root returns application/json — likely API target")

    body_lower = r.text.lower()
    for marker in _BODY_SIGNALS:
        if marker in body_lower:
            signals.append(f"root body contains {marker!r}")

    return signals


async def _check_candidate(
    client: httpx.AsyncClient, base: str, path: str,
) -> tuple[str, str, int, str]:
    """Return (strength, reason, status_code, content_type) for a candidate path.

    strength="strong": unambiguous API signal — 200+JSON, swagger-ui, or
                       bespoke HTML API doc page.
    strength="weak":   4xx with JSON content-type — plausible API boundary
                       but also matches CDN/proxy error responses. Only
                       promoted to a finding when the root also carries API
                       signals (see run_api_recon_probe).
    strength="":       no signal.
    """
    url = base + path
    try:
        r = await client.get(url)
    except httpx.RequestError:
        return "", "", 0, ""

    ct = r.headers.get("content-type", "").lower()
    content_type = ct.split(";")[0].strip()
    body_lower = r.text.lower()

    if r.status_code == 200:
        if "application/json" in ct:
            return "strong", "200 application/json", r.status_code, content_type
        if "swagger-ui" in body_lower:
            return "strong", "200 swagger-ui page", r.status_code, content_type
        n = _count_html_doc_signals(body_lower)
        if n >= _HTML_DOC_MIN_SIGNALS:
            return "strong", f"200 html api-doc ({n} signals)", r.status_code, content_type

    # 4xx + JSON: plausible API boundary, but CDN/proxy JSON 404s produce
    # the same pattern. Returned as "weak" — only counts toward a finding
    # when the root response also carries independent API signals.
    if r.status_code in (400, 401, 403, 404, 422) and "application/json" in ct:
        return "weak", f"{r.status_code} json boundary", r.status_code, content_type

    return "", "", 0, ""


async def run_api_recon_probe(
    target: str,
    candidate_paths: tuple[str, ...] | None = None,
) -> AsyncIterator[StageEvent | FindingEvent]:
    """Bootstrap-stage probe: find API surfaces, emit one FindingEvent when found.

    candidate_paths overrides _CANDIDATE_PATHS when provided,
    enabling re-invocation against a focused set of paths.

    Quiet on negative — no FindingEvent emitted when there are no API signals.
    """
    paths = candidate_paths if candidate_paths is not None else _CANDIDATE_PATHS

    parsed = urlparse(target if "://" in target else f"http://{target}")
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # ── Stage 0 — scan ──────────────────────────────────────────────────
    yield StageEvent(
        label    = "Scanning for API surfaces",
        actions  = (f"GET {base}/",) + tuple(f"GET {base}{p}" for p in paths),
        tools    = ("httpx async client", "content-type analyzer"),
        confidence = "high",
    )

    root_signals: list[str] = []
    hit_paths:    list[dict] = []

    async with httpx.AsyncClient(
        verify           = False,
        follow_redirects = True,
        timeout          = _RECON_TIMEOUT_S,
    ) as client:
        # Root check + candidate checks concurrently.
        root_task = asyncio.create_task(_check_root(client, base))
        candidate_tasks = {
            path: asyncio.create_task(_check_candidate(client, base, path))
            for path in paths
        }

        try:
            root_signals = await root_task
        except Exception:  # noqa: BLE001 — probe never raises
            root_signals = []

        weak_hits: list[tuple[str, int, str]] = []
        for path, task in candidate_tasks.items():
            try:
                strength, reason, sc, ct = await task
                if strength == "strong":
                    hit_paths.append({"path": path, "status_code": sc, "content_type": ct})
                    root_signals.append(f"{path}: {reason}")
                elif strength == "weak":
                    weak_hits.append((path, sc, ct))
            except Exception:  # noqa: BLE001 — probe never raises
                pass

        # Promote weak hits only when the root also carries API signals.
        # This prevents CDN/proxy JSON 404s from triggering api_exposure
        # on sites with no real API surface.
        if weak_hits and root_signals:
            for p, sc, ct in weak_hits:
                hit_paths.append({"path": p, "status_code": sc, "content_type": ct})
                root_signals.append(f"{p}: 4xx json boundary (corroborated by root signal)")

    all_signals = root_signals  # hit reasons already appended per-path above

    # ── Stage 1 — catalogue ──────────────────────────────────────────────
    yield StageEvent(
        label    = "Cataloguing API candidates",
        actions  = (
            f"checked {len(paths)} candidate path(s)",
            f"{len(all_signals)} signal(s) detected" if all_signals
            else "no API signals detected",
        ),
        tools    = ("path matcher", "content-type analyzer"),
        detected = tuple(all_signals[:10]) or ("no API signals to record",),
        confidence = "high",
    )

    if not all_signals:
        # Quiet negative — no FindingEvent.
        return

    first_endpoint = hit_paths[0]["path"] if hit_paths else "/"
    yield FindingEvent(
        after_stage_index = 1,
        finding_type      = "api_exposure",
        title             = "API surface candidate detected",
        severity          = "high",
        description       = (
            "The target exposes an API surface or documentation endpoint. "
            "Probe API endpoints for broken object-level authorization (IDOR) "
            "and other access-control gaps."
        ),
        endpoint = first_endpoint,
        evidence = {
            "signals":   all_signals,
            "hit_paths": hit_paths,
        },
        phase    = "enumeration",
    )
