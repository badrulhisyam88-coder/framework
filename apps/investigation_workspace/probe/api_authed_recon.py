"""Authenticated page scraping — extract hidden API paths and resource IDs.

Fetches common authenticated pages (/, /catalog, /my-account, /products,
/shop, /dashboard, /admin) using caller-supplied session cookies.
Parses each HTML response with BeautifulSoup to extract:
  • href, src, action, data-url attributes containing /api/* or relative paths
  • fetch(), axios.*(), XMLHttpRequest URL strings inside <script> tags
  • any /api/* substring anywhere in page text
  • numeric IDs and UUIDs from URL patterns (/products/123, /user/abc-uuid)

Returns results via async generator (StageEvent + ResultEvent).
The ResultEvent evidence dict contains:
  discovered_paths: list[str]   — deduplicated /api/* paths found
  discovered_ids:   list[str]   — numeric/UUID resource IDs
  pages_scraped:    int

Used standalone as probe_api_authed_recon, and as Phase 1 of
probe_api_full_discovery which feeds C's output to A and B.
"""
from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urlparse

import httpx

from apps.investigation_workspace.probe.events import ResultEvent, StageEvent

try:
    from bs4 import BeautifulSoup

    _BS4 = True
except ImportError:
    _BS4 = False

# ── Constants ─────────────────────────────────────────────────────────────────

PAGES_TO_SCRAPE: tuple[str, ...] = (
    "/",
    "/catalog",
    "/catalog/",
    "/my-account",
    "/products",
    "/shop",
    "/dashboard",
    "/admin",
    "/product",
)

_SCRAPE_TIMEOUT = 8.0

# Regex: capture URL argument from fetch(), axios.*(), or XHR() calls.
# Matches single-quoted, double-quoted, or backtick-quoted URL strings.
_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.[a-z]+|XHR)\s*\(?\s*(['"`])([^'"` ]+)\1""",
    re.I,
)

_API_PATH_RAW_RE = re.compile(r"(/api[^\s'\"<>?#]*)", re.I)
_NUMERIC_ID_RE = re.compile(r"/(\d+)(?:[/?#]|$)")
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.I,
)

_ATTR_NAMES = ("href", "src", "action", "data-url", "data-endpoint")


# ── Internal helpers ──────────────────────────────────────────────────────────


def _extract_paths_from_html(html: str) -> list[str]:
    """Return deduplicated /api/* paths extracted from an HTML document."""
    found: list[str] = []
    seen: set[str] = set()

    def _add(p: str) -> None:
        p = p.strip().rstrip("/") or "/"
        if p.startswith("/api") and p not in seen:
            seen.add(p)
            found.append(p)

    if _BS4:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(True):
            for attr in _ATTR_NAMES:
                val = tag.get(attr, "")
                if val and "/api" in val:
                    _add(val)

        for script in soup.find_all("script"):
            text = script.get_text() or ""
            for m in _FETCH_RE.finditer(text):
                _add(m.group(2))

    # Raw-regex fallback (always run — catches paths in non-attribute positions)
    for m in _API_PATH_RAW_RE.finditer(html):
        _add(m.group(1))

    return found


def _extract_ids_from_html(html: str) -> tuple[list[str], list[str]]:
    """Return (numeric_ids, uuids) extracted from the HTML."""
    numeric: list[str] = []
    num_seen: set[str] = set()
    for m in _NUMERIC_ID_RE.finditer(html):
        v = m.group(1)
        if v != "0" and v not in num_seen:
            num_seen.add(v)
            numeric.append(v)
            if len(numeric) >= 50:
                break

    uuids: list[str] = []
    uuid_seen: set[str] = set()
    for m in _UUID_RE.finditer(html):
        v = m.group(0).lower()
        if v not in uuid_seen:
            uuid_seen.add(v)
            uuids.append(v)
            if len(uuids) >= 20:
                break

    return numeric, uuids


# ── Public async generator ────────────────────────────────────────────────────


async def run_authed_recon(
    target: str,
    session_cookies: dict,
) -> AsyncIterator[StageEvent | ResultEvent]:
    """Scrape authenticated pages and yield StageEvents + one ResultEvent.

    Args:
        target:          Full base URL or host of the target (scheme optional).
        session_cookies: Cookie dict to send with every request (may be empty).
    """
    if not _BS4:
        yield StageEvent(
            label=(
                "BeautifulSoup4 not installed — authenticated recon limited to "
                "raw-regex /api/* extraction (install beautifulsoup4 for full coverage)"
            ),
            tools=("raw regex",),
            confidence="low",
        )

    parsed = urlparse(target if "://" in target else f"http://{target}")
    base = f"{parsed.scheme}://{parsed.netloc}"

    yield StageEvent(
        label="Scraping authenticated pages for API paths and resource IDs",
        actions=tuple(f"GET {base}{p}" for p in PAGES_TO_SCRAPE),
        tools=("httpx async client", "BeautifulSoup4" if _BS4 else "raw regex"),
        confidence="medium",
    )

    all_paths: list[str] = []
    all_numeric: list[str] = []
    all_uuids: list[str] = []
    path_seen: set[str] = set()
    num_seen: set[str] = set()
    uuid_seen: set[str] = set()
    pages_scraped = 0

    async with httpx.AsyncClient(
        timeout=_SCRAPE_TIMEOUT,
        follow_redirects=True,
        verify=False,
        cookies=session_cookies,
    ) as client:
        for page in PAGES_TO_SCRAPE:
            url = base + page
            try:
                resp = await client.get(url)
            except httpx.RequestError:
                continue

            if resp.status_code < 200 or resp.status_code >= 300:
                continue

            ct = resp.headers.get("content-type", "").lower()
            if "html" not in ct:
                continue

            pages_scraped += 1
            html = resp.text

            for p in _extract_paths_from_html(html):
                if p not in path_seen:
                    path_seen.add(p)
                    all_paths.append(p)

            num_ids, uuids = _extract_ids_from_html(html)
            for v in num_ids:
                if v not in num_seen:
                    num_seen.add(v)
                    all_numeric.append(v)
            for v in uuids:
                if v not in uuid_seen:
                    uuid_seen.add(v)
                    all_uuids.append(v)

    discovered_ids = all_numeric[:50] + all_uuids[:20]

    yield StageEvent(
        label="Authenticated page scraping complete",
        actions=(
            f"scraped {pages_scraped} page(s)",
            f"discovered {len(all_paths)} unique /api/* path(s)",
            f"found {len(all_numeric)} numeric ID(s), {len(all_uuids)} UUID(s)",
        ),
        tools=("BeautifulSoup4" if _BS4 else "raw regex",),
        detected=tuple(all_paths[:10]),
        confidence="high" if all_paths else "low",
    )

    confirmed = bool(all_paths or discovered_ids)
    yield ResultEvent(
        label="Authenticated recon complete",
        kind="detected" if confirmed else "note",
        evidence={
            "discovered_paths": all_paths,
            "discovered_ids": discovered_ids,
            "pages_scraped": pages_scraped,
        },
        payload={
            "request": {
                "method": "GET",
                "url": base,
                "headers": {},
                "body": None,
            },
            "response": {
                "status": pages_scraped,
                "headers": {},
                "body_excerpt": (
                    f"Scraped {pages_scraped} pages; "
                    f"found {len(all_paths)} API paths, {len(discovered_ids)} IDs"
                ),
            },
            "sent": {
                "payload_string": f"session cookies: {list(session_cookies.keys())}",
                "encoding": "cookies",
                "injection_point": "Cookie header",
            },
            "observed": {
                "indicators": [
                    f"{len(all_paths)} /api/* path(s) extracted",
                    f"{len(all_numeric)} numeric resource ID(s) found",
                    f"{len(all_uuids)} UUID(s) found",
                ],
            },
            "analysis": {
                "confirmed": confirmed,
                "severity": "medium" if all_paths else "info",
                "exploitability_notes": (
                    f"Found {len(all_paths)} API path(s) and {len(discovered_ids)} "
                    "resource ID(s) by scraping authenticated pages. "
                    "Feed these into endpoint enumeration and method probing."
                    if confirmed
                    else "No API paths or resource IDs discovered from authenticated pages."
                ),
                "references": [
                    {
                        "label": "OWASP API Security — Broken Object Level Authorization",
                        "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                    }
                ],
            },
        },
    )


# ── Collector helper used by the orchestrator ─────────────────────────────────


async def extract_recon_data(target: str, session_cookies: dict) -> dict:
    """Run authed recon and return the ResultEvent evidence dict.

    Collects all events from run_authed_recon and returns the evidence dict
    from the final ResultEvent.  Used by probe_api_full_discovery to hand
    discovered paths and IDs to probe A (endpoint enum) and probe B (method
    enum) without duplicating the scraping logic.
    """
    evidence: dict = {"discovered_paths": [], "discovered_ids": [], "pages_scraped": 0}
    async for event in run_authed_recon(target, session_cookies):
        if isinstance(event, ResultEvent) and event.evidence:
            evidence = event.evidence
    return evidence
