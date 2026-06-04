"""Hidden API endpoint enumeration via wordlist + discovered-ID substitution.

Loads the vendored SecLists wordlist (api-endpoints.txt). Accepts an optional
high-priority candidate list (from probe C or an existing spec) and an optional
list of discovered resource IDs to substitute into {id} placeholders.

Per-path classification:
  2xx     → accessible, emit as finding
  401/403 → exists but requires auth — still a meaningful finding
  405     → exists, wrong method — fires OPTIONS to read Allow header
  5xx     → server error — noted but not a finding
  404 / other → absent, skip

Concurrency: asyncio.Semaphore(10) — at most 10 simultaneous requests.

Result: one ResultEvent per discovered endpoint cluster, plus a summary
ResultEvent listing all discovered paths with their status codes.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from urllib.parse import urlparse

import httpx

from apps.investigation_workspace.probe.events import ResultEvent, StageEvent

# ── Wordlist ──────────────────────────────────────────────────────────────────

_WORDLIST_CACHE: list[str] | None = None

_ENUM_TIMEOUT = 6.0
_CONCURRENCY = 10


def _load_wordlist() -> list[str]:
    global _WORDLIST_CACHE  # noqa: PLW0603
    if _WORDLIST_CACHE is not None:
        return _WORDLIST_CACHE
    from apps.conductor.wordlists import load_entries
    _WORDLIST_CACHE = load_entries("api_paths_default")
    return _WORDLIST_CACHE


# ── ID substitution ───────────────────────────────────────────────────────────

_DEFAULT_IDS = [str(n) for n in range(1, 6)]


def _fill_id(path: str, ids: list[str]) -> list[str]:
    """Expand {id} placeholder into concrete paths.

    If the path contains no {id}, returns [path] unchanged.
    Otherwise substitutes each caller-supplied ID and also the default
    numeric IDs 1-5 (deduplicated).
    """
    if "{id}" not in path:
        return [path]
    result: list[str] = []
    seen: set[str] = set()

    for id_val in ids:
        p = path.replace("{id}", id_val)
        if p not in seen:
            seen.add(p)
            result.append(p)

    for n in _DEFAULT_IDS:
        if n not in ids:
            p = path.replace("{id}", n)
            if p not in seen:
                seen.add(p)
                result.append(p)

    return result


# ── HTTP helpers ──────────────────────────────────────────────────────────────


async def _probe_path(
    client: httpx.AsyncClient,
    url: str,
) -> tuple[str, int]:
    """GET url; return (url, status_code). Returns (url, 0) on network error."""
    try:
        resp = await client.get(url)
        return (url, resp.status_code)
    except httpx.RequestError:
        return (url, 0)


async def _options_request(
    client: httpx.AsyncClient,
    url: str,
) -> str:
    """Send OPTIONS; return the Allow header value or empty string."""
    try:
        resp = await client.options(url)
        return resp.headers.get("allow", resp.headers.get("Allow", ""))
    except httpx.RequestError:
        return ""


# ── Main async generator ──────────────────────────────────────────────────────


async def run_endpoint_enum(
    target: str,
    session_cookies: dict,
    candidate_paths: list[str] | None = None,
    discovered_ids: list[str] | None = None,
) -> AsyncIterator[StageEvent | ResultEvent]:
    """Enumerate hidden API endpoints via wordlist and ID substitution.

    Args:
        target:          Base URL or host of the target.
        session_cookies: Authenticated session cookies (may be empty).
        candidate_paths: High-priority paths from authed recon or spec (optional).
        discovered_ids:  Resource IDs to substitute into {id} placeholders (optional).
    """
    parsed = urlparse(target if "://" in target else f"http://{target}")
    base = f"{parsed.scheme}://{parsed.netloc}"
    ids = list(discovered_ids or [])

    # ── Build probe list ──────────────────────────────────────────────────────
    wordlist = _load_wordlist()
    candidates = list(candidate_paths or [])
    candidate_set: set[str] = set(candidates)

    # Add wordlist entries not already in candidates
    for path in wordlist:
        if path not in candidate_set:
            candidates.append(path)
            candidate_set.add(path)

    # Expand {id} placeholders
    expanded: list[str] = []
    expanded_set: set[str] = set()
    for path in candidates:
        for filled in _fill_id(path, ids):
            if filled not in expanded_set:
                expanded_set.add(filled)
                expanded.append(filled)

    total = len(expanded)

    yield StageEvent(
        label="Enumerating API endpoints via wordlist",
        actions=(
            f"probing {total} path(s) (candidates + wordlist + ID expansion)",
            f"base URL: {base}",
        ),
        tools=("httpx async client", "api-endpoints.txt wordlist"),
        confidence="medium",
    )

    # ── Concurrent probing ────────────────────────────────────────────────────
    sem = asyncio.Semaphore(_CONCURRENCY)
    accessible: list[dict] = []
    auth_required: list[dict] = []
    wrong_method: list[dict] = []
    allow_headers: dict[str, str] = {}

    async with httpx.AsyncClient(
        timeout=_ENUM_TIMEOUT,
        follow_redirects=False,
        verify=False,
        cookies=session_cookies,
    ) as client:

        async def _bounded_probe(path: str) -> tuple[str, int]:
            async with sem:
                return await _probe_path(client, base + path)

        # Process in batches of 10
        for i in range(0, len(expanded), _CONCURRENCY):
            batch = expanded[i : i + _CONCURRENCY]
            results = await asyncio.gather(*[_bounded_probe(p) for p in batch])

            for url, status in results:
                path = url[len(base):]
                if status == 0:
                    continue
                if 200 <= status < 300:
                    accessible.append({"path": path, "status": status})
                elif status in (401, 403):
                    auth_required.append({"path": path, "status": status})
                elif status == 405:
                    wrong_method.append({"path": path, "status": status})
                    # Fire OPTIONS to read Allow header
                    async with sem:
                        allow = await _options_request(client, url)
                    if allow:
                        allow_headers[path] = allow

    discovered_count = len(accessible) + len(auth_required) + len(wrong_method)

    yield StageEvent(
        label="Endpoint enumeration complete",
        actions=(
            f"probed {total} path(s)",
            f"{len(accessible)} accessible (2xx)",
            f"{len(auth_required)} auth-required (401/403)",
            f"{len(wrong_method)} wrong-method (405)",
        ),
        tools=("httpx async client",),
        detected=tuple(
            f"{e['status']} {e['path']}"
            for e in (accessible + auth_required + wrong_method)[:12]
        ),
        confidence="high" if discovered_count > 0 else "low",
    )

    if discovered_count > 5:
        severity = "high"
    elif discovered_count > 0:
        severity = "medium"
    else:
        severity = "info"

    accessible_paths = [e["path"] for e in accessible]
    auth_paths = [e["path"] for e in auth_required]
    wrong_paths = [e["path"] for e in wrong_method]
    all_found_paths = accessible_paths + auth_paths + wrong_paths

    yield ResultEvent(
        label=f"Endpoint enumeration: {discovered_count} endpoint(s) found",
        kind="detected" if discovered_count > 0 else "note",
        evidence={
            "accessible": accessible,
            "auth_required": auth_required,
            "wrong_method": wrong_method,
            "allow_headers": allow_headers,
        },
        payload={
            "request": {
                "method": "GET",
                "url": base,
                "headers": {},
                "body": None,
            },
            "response": {
                "status": discovered_count,
                "headers": {},
                "body_excerpt": (
                    f"Probed {total} paths. "
                    f"Found {len(accessible)} accessible, "
                    f"{len(auth_required)} auth-gated, "
                    f"{len(wrong_method)} wrong-method."
                ),
            },
            "sent": {
                "payload_string": f"{total} GET requests (wordlist + candidates)",
                "encoding": "HTTP GET",
                "injection_point": "URL path",
            },
            "observed": {
                "indicators": [
                    f"{len(accessible)} endpoint(s) returned 2xx",
                    f"{len(auth_required)} endpoint(s) returned 401/403",
                    f"{len(wrong_method)} endpoint(s) returned 405",
                    f"{len(allow_headers)} Allow header(s) captured via OPTIONS",
                ],
            },
            "analysis": {
                "confirmed": discovered_count > 0,
                "severity": severity,
                "exploitability_notes": (
                    f"Discovered {discovered_count} API endpoint(s) without documentation. "
                    f"Accessible: {accessible_paths[:5]}. "
                    f"Auth-gated (confirm existence): {auth_paths[:5]}. "
                    "Feed accessible paths to HTTP method enumeration."
                    if discovered_count > 0
                    else "Wordlist enumeration found no active API endpoints."
                ),
                "references": [
                    {
                        "label": "OWASP API Security Top 10 — Broken Object Level Authorization",
                        "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                    },
                    {
                        "label": "SecLists — API wordlists",
                        "url": "https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content",
                    },
                ],
            },
            "next_actions": [
                {
                    "action_kind": "api_method_enum",
                    "label": "Enumerate HTTP methods on discovered endpoints",
                    "reason": (
                        f"{len(all_found_paths)} endpoint(s) found — probe each for "
                        "unexpected PATCH/DELETE/PUT method access"
                    ),
                }
            ] if all_found_paths else [],
        },
    )
