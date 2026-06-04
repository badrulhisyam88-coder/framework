"""DiagnosticsService — reconstructed after VESTIGE-1 deletion.

Checks reachability of the resolved target and optionally fingerprints it
(server header, page title). Always returns a TargetContext; sets
reachable=True/False based on HTTP probe result.
"""
from __future__ import annotations

import logging
import time

from apps.scanner_orchestration.target_resolution.models import TargetContext

logger = logging.getLogger("scanner_orchestration.diagnostics")

_PROBE_TIMEOUT = 10.0  # seconds


class DiagnosticsService:
    """Probes the target URL and enriches TargetContext with reachability data."""

    async def run(self, ctx: TargetContext) -> TargetContext:
        """Perform HTTP probe against ctx.scanner_url.

        Sets:
            reachable            — True if HTTP response received (any status)
            http_status          — response status code
            latency_ms           — round-trip time
            fingerprint          — Server header value if present
            fingerprint_confidence — "medium" when Server header present, else "none"
        """
        import httpx

        url = ctx.scanner_url
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(
                timeout=_PROBE_TIMEOUT,
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.get(url)

            latency = (time.monotonic() - t0) * 1000
            server = resp.headers.get("server", "") or resp.headers.get("x-powered-by", "")
            fingerprint = server.strip() if server.strip() else None

            logger.info(
                "diagnostics: %s reachable status=%d latency=%.0fms server=%r",
                url, resp.status_code, latency, fingerprint or "—",
            )

            return ctx.model_copy(update={
                "reachable": True,
                "http_status": resp.status_code,
                "latency_ms": round(latency, 1),
                "fingerprint": fingerprint,
                "fingerprint_confidence": "medium" if fingerprint else "none",
                "diagnostics": {"http": {"status": resp.status_code}},
            })

        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            logger.warning("diagnostics: %s unreachable: %s", url, exc)
            return ctx.model_copy(update={
                "reachable": False,
                "latency_ms": round(latency, 1),
                "diagnostics": {"http": {"error": str(exc)[:200]}},
            })
