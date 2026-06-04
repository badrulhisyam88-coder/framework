"""Headless browser network capture — intercept /api/* requests during navigation.

Uses Playwright (Chromium) to navigate common app paths with an authenticated
session context.  Intercepts every HTTP request made by the browser and filters
to /api/* paths, capturing per-request: URL, method, headers, request body,
response status, and response Content-Type.

Also follows internal same-origin links one level deep from each main page so
that navigation paths through catalog / product pages / checkout are covered.

Returns results via async generator (StageEvent per page + final ResultEvent).
The ResultEvent evidence dict contains:
  captured_requests: list[dict]  — per-request capture dicts
  pages_navigated:   int

Used standalone as probe_api_browser_recon.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlparse

from apps.investigation_workspace.probe.events import ResultEvent, StageEvent

try:
    from playwright.async_api import async_playwright  # type: ignore[import-untyped]

    _PW_AVAILABLE = True
except ImportError:
    _PW_AVAILABLE = False

# ── Constants ─────────────────────────────────────────────────────────────────

# Main pages to navigate in order.
NAV_PAGES: tuple[str, ...] = (
    "/",
    "/catalog",
    "/catalog/",
    "/products",
    "/shop",
    "/my-account",
    "/cart",
    "/wishlist",
)

# Max same-origin links to follow from each main page (bounds runtime).
_MAX_LINKS_PER_PAGE = 10

# Per-page navigation timeout in milliseconds.
_NAV_TIMEOUT_MS = 15_000

# Short wait after DOMContentLoaded to let XHR/fetch calls fire.
_XHR_SETTLE_MS = 2_000

# Chromium flags required for headless Docker operation (non-root user, no
# kernel sandbox, reduced /dev/shm usage).
_LAUNCH_ARGS: list[str] = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
]


# ── Async generator ───────────────────────────────────────────────────────────


async def run_browser_recon(
    target: str,
    session_cookies: dict,
) -> AsyncIterator[StageEvent | ResultEvent]:
    """Navigate common app pages with a headless browser and capture /api/* requests.

    Args:
        target:          Full base URL or host of the target (scheme optional).
        session_cookies: Cookie dict to inject into the browser context.
                         Caller obtains these via auth_recon helpers.
    """
    if not _PW_AVAILABLE:
        yield StageEvent(
            label=(
                "Playwright not installed — browser recon unavailable. "
                "Run: pip install playwright && playwright install chromium"
            ),
            tools=(),
            confidence="low",
        )
        yield ResultEvent(
            label="Browser recon skipped — Playwright not installed",
            kind="note",
            payload={
                "analysis": {
                    "confirmed": False,
                    "severity": "info",
                    "exploitability_notes": (
                        "Playwright is not installed in the runtime. "
                        "Add playwright to pyproject.toml and rebuild the Docker image."
                    ),
                    "references": [],
                },
                "observed": {"indicators": ["playwright import failed"]},
            },
        )
        return

    parsed = urlparse(target if "://" in target else f"http://{target}")
    base = f"{parsed.scheme}://{parsed.netloc}"
    hostname = parsed.hostname or "localhost"

    yield StageEvent(
        label="Starting headless Chromium browser session",
        actions=(
            f"target: {base}",
            f"session cookies: {list(session_cookies.keys()) or ['(none — unauthenticated)']}",
            f"pages to visit: {len(NAV_PAGES)} main + up to {_MAX_LINKS_PER_PAGE} links per page",
        ),
        tools=("playwright", "chromium headless"),
        confidence="high",
    )

    # Per-request capture dict; keyed by URL to deduplicate.
    captured: dict[str, dict] = {}
    # Mutable single-element list so sync closure can update it.
    current_source: list[str] = ["(pre-navigation)"]

    # ── Sync event handlers — called on every browser request/response ────
    def _on_request(request: object) -> None:  # type: ignore[type-arg]
        url: str = request.url  # type: ignore[attr-defined]
        if "/api/" not in url or url in captured:
            return
        captured[url] = {
            "url": url,
            "method": request.method,  # type: ignore[attr-defined]
            "headers": dict(request.headers),  # type: ignore[attr-defined]
            "body": request.post_data or "",  # type: ignore[attr-defined]
            "response_status": None,
            "response_content_type": None,
            "source_page": current_source[0],
        }

    def _on_response(response: object) -> None:  # type: ignore[type-arg]
        url: str = response.url  # type: ignore[attr-defined]
        if url not in captured:
            return
        captured[url]["response_status"] = response.status  # type: ignore[attr-defined]
        captured[url]["response_content_type"] = (
            response.headers.get("content-type", "")  # type: ignore[attr-defined]
        )

    # ── Playwright browser session ────────────────────────────────────────
    pages_navigated = 0
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=_LAUNCH_ARGS)
        ctx = await browser.new_context(ignore_https_errors=True)

        # Inject session cookies into the browser context.
        if session_cookies:
            cookie_list = [
                {"name": k, "value": v, "domain": hostname, "path": "/"}
                for k, v in session_cookies.items()
            ]
            await ctx.add_cookies(cookie_list)

        page = await ctx.new_page()
        page.on("request", _on_request)
        page.on("response", _on_response)

        visited_links: set[str] = set()

        for nav_path in NAV_PAGES:
            page_url = base + nav_path
            current_source[0] = nav_path

            yield StageEvent(
                label=f"Navigating {nav_path}",
                actions=(f"GET {page_url}",),
                tools=("chromium headless",),
                confidence="medium",
            )

            try:
                await page.goto(
                    page_url,
                    timeout=_NAV_TIMEOUT_MS,
                    wait_until="domcontentloaded",
                )
                await page.wait_for_timeout(_XHR_SETTLE_MS)
                pages_navigated += 1
            except Exception:
                continue

            # Follow internal links one level deep.
            try:
                raw_links: list[str] = await page.eval_on_selector_all(
                    "a[href]",
                    "els => els.map(e => e.href)",
                )
            except Exception:
                raw_links = []

            same_origin = [
                lnk for lnk in dict.fromkeys(raw_links)
                if lnk.startswith(base)
                and lnk != page_url
                and lnk not in visited_links
            ][:_MAX_LINKS_PER_PAGE]

            for link_url in same_origin:
                link_path = link_url[len(base):]
                if not link_path or link_path in NAV_PAGES:
                    continue
                visited_links.add(link_url)
                current_source[0] = f"{nav_path}→{link_path[:40]}"
                try:
                    await page.goto(
                        link_url,
                        timeout=_NAV_TIMEOUT_MS,
                        wait_until="domcontentloaded",
                    )
                    await page.wait_for_timeout(1_000)
                    pages_navigated += 1
                except Exception:
                    pass
                # Navigate back to main page for next link
                try:
                    await page.go_back(timeout=5_000)
                except Exception:
                    # If go_back fails, just re-navigate to the parent page
                    try:
                        await page.goto(
                            page_url,
                            timeout=_NAV_TIMEOUT_MS,
                            wait_until="domcontentloaded",
                        )
                    except Exception:
                        break
                current_source[0] = nav_path

        await browser.close()

    # ── Summary ───────────────────────────────────────────────────────────
    discovered = list(captured.values())

    yield StageEvent(
        label="Browser recon complete",
        actions=(
            f"navigated {pages_navigated} page(s)",
            f"discovered {len(discovered)} unique /api/* request(s)",
        ),
        tools=("chromium headless",),
        detected=tuple(
            f"{d['method']} {d['url']}" for d in discovered[:10]
        ),
        confidence="high" if discovered else "low",
    )

    confirmed = bool(discovered)
    yield ResultEvent(
        label=f"Browser recon: {len(discovered)} /api/* request(s) captured",
        kind="detected" if confirmed else "note",
        evidence={
            "captured_requests": discovered,
            "pages_navigated": pages_navigated,
        },
        payload={
            "request": {
                "method": "GET (headless browser)",
                "url": base,
                "headers": {},
                "body": None,
            },
            "response": {
                "status": pages_navigated,
                "headers": {},
                "body_excerpt": (
                    f"Browser navigated {pages_navigated} page(s); "
                    f"captured {len(discovered)} /api/* request(s)"
                ),
            },
            "sent": {
                "payload_string": (
                    f"session cookies: {list(session_cookies.keys())}"
                    if session_cookies else "(unauthenticated)"
                ),
                "encoding": "cookies",
                "injection_point": "Browser cookie jar",
            },
            "observed": {
                "indicators": [
                    f"{len(discovered)} unique /api/* URL(s) observed",
                    f"{pages_navigated} page(s) navigated",
                    f"sources: {', '.join(dict.fromkeys(d['source_page'] for d in discovered[:5]))}"
                    if discovered else "no API requests observed",
                ],
            },
            "analysis": {
                "confirmed": confirmed,
                "severity": "medium" if discovered else "info",
                "exploitability_notes": (
                    f"Browser navigation with authenticated session revealed "
                    f"{len(discovered)} /api/* request(s) across {pages_navigated} page(s). "
                    "Review the captured methods and endpoints; run method enumeration "
                    "or IDOR probes against the discovered paths."
                    if confirmed
                    else (
                        "No /api/* requests were observed during authenticated page navigation. "
                        "The target may use non-standard API paths or not expose a REST API."
                    )
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
