"""OWASP ZAP adapter — communicates with ZAP REST API.

Module-level run_spider() and run_passive_scan() are the primary API.
ZAPAdapter class is retained for backward compat with dormant consumers
(orchestration_service, api/routes).

Default URL is read from ZAP_API_URL env var (set to http://zap:8080 in
docker-compose). Falls back to http://localhost:8080 for bare-metal runs.

ZAP status model:
  reachable   — API responds HTTP 200, ready to scan.
  starting    — Connection timed out; ZAP process exists but API not ready yet (~60s startup).
  degraded    — Connected but returned a non-200 response.
  unavailable — Connection refused; container is not running or port is not open.

Adapter responsibility boundary: thin HTTP wrapper only. Scope/policy
(which scan types to run) belongs at the engine layer, not here.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_ZAP_DEFAULT_URL = os.environ.get("ZAP_API_URL", "http://localhost:8080")
_API_KEY = os.environ.get("ZAP_API_KEY", "")  # empty = key disabled

_POLL_INTERVAL = 5       # seconds between spider status polls
_CHECK_TIMEOUT = 2.0     # seconds for availability probes
_CHECK_RETRIES = 2       # attempts before reporting unavailable
_CHECK_RETRY_DELAY = 0.3 # seconds between retry attempts
_REQUEST_TIMEOUT = 20.0  # seconds for individual API calls
_SPIDER_TIMEOUT = 300    # max seconds to wait for spider to finish


# ── Shared API helper ─────────────────────────────────────────────────────────

async def _api_call(
    client: Any,
    base: str,
    api_key: str,
    path: str,
    params: dict | None = None,
) -> dict:
    """Make a ZAP API call. Returns parsed JSON dict or {} on error."""
    p = dict(params or {})
    if api_key:
        p["apikey"] = api_key
    url = f"{base}/JSON/{path}"
    try:
        resp = await client.get(url, params=p)
        if resp.status_code == 200:
            return resp.json()
        logger.warning("zap: API %s returned HTTP %d", path, resp.status_code)
        return {}
    except Exception as exc:
        logger.warning("zap: API %s error: %s", path, str(exc)[:120])
        return {}


# ── Module-level scan functions ───────────────────────────────────────────────

async def run_spider(
    target: str,
    timeout_seconds: int = 300,
    base_url: str | None = None,
    api_key: str = _API_KEY,
    start_url: str | None = None,
) -> dict:
    """Run ZAP spider against *target*. Returns discovered URLs.

    start_url overrides target as the spider starting point when provided
    (useful for re-invocation against a specific discovered page).

    Starts a fresh ZAP session before crawling (resets prior state).
    ZAP passive scanner runs automatically in the background as spider
    discovers pages — alerts from that traffic are available via
    run_passive_scan() after this call.

    Returns:
      urls   : list[str] — discovered URLs (empty on failure)
      status : str       — "success" | "failed" | "timeout"
      error  : str | None
    """
    _base = (base_url or _ZAP_DEFAULT_URL).rstrip("/")
    spider_target = start_url or target

    try:
        import httpx
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            await _api_call(
                client, _base, api_key, "core/action/newSession/", {"overwrite": "true"}
            )

            r = await _api_call(client, _base, api_key, "spider/action/scan/", {
                "url": spider_target,
                "maxChildren": "10",
                "recurse": "true",
            })
            scan_id = str(r.get("scan", ""))
            if not scan_id:
                return {"urls": [], "status": "failed", "error": "ZAP spider returned no scan ID"}

            elapsed = 0
            while elapsed < timeout_seconds:
                await asyncio.sleep(_POLL_INTERVAL)
                elapsed += _POLL_INTERVAL

                status = await _api_call(
                    client, _base, api_key, "spider/view/status/", {"scanId": scan_id}
                )
                pct = int(status.get("status", "0"))
                logger.info("zap: spider %d%% (elapsed %ds)", pct, elapsed)

                if pct >= 100:
                    break

            if elapsed >= timeout_seconds:
                return {
                    "urls": [], "status": "timeout",
                    "error": f"spider exceeded {timeout_seconds}s timeout",
                }

            urls_resp = await _api_call(
                client, _base, api_key, "spider/view/results/", {"scanId": scan_id}
            )
            urls = urls_resp.get("results", [])

            logger.info("zap: spider found %d URLs for %s", len(urls), spider_target)
            return {"urls": urls, "status": "success", "error": None}

    except TimeoutError:
        return {
            "urls": [], "status": "timeout",
            "error": f"spider exceeded {timeout_seconds}s timeout",
        }
    except Exception as exc:
        logger.warning("zap: spider failed for %s: %s", spider_target, exc)
        return {"urls": [], "status": "failed", "error": str(exc)[:500]}


async def run_passive_scan(
    target: str,
    timeout_seconds: int = 300,
    base_url: str | None = None,
    api_key: str = _API_KEY,
    scope_url: str | None = None,
) -> dict:
    """Retrieve ZAP passive scan alerts for *target*.

    scope_url overrides target as the baseurl filter for alerts when provided
    (useful for re-invocation scoped to a specific URL prefix).

    Passive scanning runs automatically in ZAP as traffic is observed
    (e.g., by the spider). This function queries alerts from the current
    session — call after run_spider() to get alerts from spider traffic.

    Returns:
      alerts : list[dict] — deduplicated ZAP alert dicts (empty on failure)
      status : str        — "success" | "failed"
      error  : str | None
    """
    _base = (base_url or _ZAP_DEFAULT_URL).rstrip("/")
    alert_filter = scope_url or target

    try:
        import httpx
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            r = await _api_call(client, _base, api_key, "alert/view/alerts/", {
                "baseurl": alert_filter,
                "start": "0",
                "count": "500",
            })
            alerts = r.get("alerts", [])

            seen: set[str] = set()
            unique: list[dict] = []
            for a in alerts:
                key = f"{a.get('name', '')}|{a.get('url', '')}|{a.get('param', '')}"
                if key not in seen:
                    seen.add(key)
                    unique.append(a)

            logger.info("zap: passive scan found %d alerts for %s", len(unique), alert_filter)
            return {"alerts": unique, "status": "success", "error": None}

    except Exception as exc:
        logger.warning("zap: passive scan failed for %s: %s", alert_filter, exc)
        return {"alerts": [], "status": "failed", "error": str(exc)[:500]}


# ── Backward-compat class ─────────────────────────────────────────────────────

class ZAPAdapter:
    """Backward-compatible adapter class.

    Delegates to the module-level functions. Kept because dormant
    scanner_orchestration consumers (orchestration_service, api/routes)
    reference ZAPAdapter by class name.
    """

    scanner_type = "zap"

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str = _API_KEY,
    ) -> None:
        self._base = (base_url or _ZAP_DEFAULT_URL).rstrip("/")
        self._api_key = api_key

    async def get_availability_status(self) -> dict[str, str]:
        """Probe ZAP and return a classified status dict."""
        import httpx

        last_status = "unavailable"
        last_detail = f"Container not reachable at {self._base}"

        for attempt in range(_CHECK_RETRIES):
            try:
                async with httpx.AsyncClient(timeout=_CHECK_TIMEOUT) as client:
                    resp = await client.get(f"{self._base}/JSON/core/view/version/")
                if resp.status_code == 200:
                    return {"status": "reachable", "detail": ""}
                last_status = "degraded"
                last_detail = f"API returned HTTP {resp.status_code}"
            except httpx.TimeoutException:
                return {
                    "status": "starting",
                    "detail": "ZAP initializing — API not ready yet (~60s startup)",
                }
            except httpx.ConnectError:
                last_status = "unavailable"
                last_detail = f"Container not reachable at {self._base}"
            except Exception as exc:
                last_status = "unavailable"
                last_detail = f"Connection failed: {str(exc)[:80]}"

            if attempt < _CHECK_RETRIES - 1:
                await asyncio.sleep(_CHECK_RETRY_DELAY)

        return {"status": last_status, "detail": last_detail}

    async def check_available(self) -> bool:
        result = await self.get_availability_status()
        return result["status"] == "reachable"

    async def get_version(self) -> str | None:
        """Return ZAP version string or None if unreachable."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=_CHECK_TIMEOUT) as client:
                resp = await client.get(f"{self._base}/JSON/core/view/version/")
                if resp.status_code == 200:
                    return resp.json().get("version")
        except Exception:
            pass
        return None

    async def run_scan(
        self,
        ctx: Any,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        """Legacy interface — runs spider + passive scan, returns alerts.

        Delegates to module-level run_spider() and run_passive_scan().
        """
        try:
            from apps.scanner_orchestration.target_resolution.models import TargetContext
            target = ctx.scanner_url if isinstance(ctx, TargetContext) else str(ctx)
        except Exception:
            target = str(ctx)

        if "#" in target:
            target = target.split("#")[0].rstrip("/")

        if not await self.check_available():
            return {
                "alerts": [], "target": target,
                "skipped": True,
                "reason": f"ZAP not reachable at {self._base}",
            }

        run_spider_flag = config.get("spider", True)
        spider_urls: list[str] = []

        if run_spider_flag:
            spider_result = await run_spider(
                target=target,
                base_url=self._base,
                api_key=self._api_key,
            )
            spider_urls = spider_result.get("urls", [])

        passive_result = await run_passive_scan(
            target=target,
            base_url=self._base,
            api_key=self._api_key,
        )
        alerts = passive_result.get("alerts", [])

        return {
            "alerts": alerts,
            "target": target,
            "spider_urls": len(spider_urls),
        }
