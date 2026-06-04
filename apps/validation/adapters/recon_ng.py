"""Subdomain enumeration adapter.

Despite the filename — kept aligned with the originally proposed Recon-ng
integration — this adapter hits the same free data sources that Recon-ng's
unauthenticated subdomain modules use under the hood, but does so over plain
HTTP. That keeps the docker image lean (no recon-ng install, no marketplace
sync) and avoids the framework's mutable module catalog. Auth'd sources
(Shodan, Censys, BinaryEdge, HIBP, …) can be added later as additional
sources without changing this adapter's interface.

Sources used:
  * crt.sh — Certificate Transparency log search
              https://crt.sh/?q=%25.<domain>&output=json
  * hackertarget.com — DNS host search
              https://api.hackertarget.com/hostsearch/?q=<domain>
"""
from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass

import httpx

from sdk import Logger

CRT_SH_URL = "https://crt.sh/"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/"

_HTTP_TIMEOUT = httpx.Timeout(connect=5.0, read=20.0, write=5.0, pool=5.0)
_DNS_TIMEOUT_S = 3.0
_DNS_WORKERS = 16

_HOSTNAME_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-.")


def _looks_like_hostname(candidate: str, domain: str) -> bool:
    """True iff candidate is a real subdomain of `domain` (or `domain` itself).

    Filters out CT-log artifacts like CN= strings, descriptions, or
    free-text fields that happen to end in the target domain.
    """
    if not candidate or any(c not in _HOSTNAME_CHARS for c in candidate):
        return False
    if candidate == domain:
        return True
    if not candidate.endswith("." + domain):
        return False
    # No empty labels (".." or leading/trailing dot)
    if ".." in candidate or candidate.startswith(".") or candidate.endswith("."):
        return False
    return True


@dataclass
class ReconHit:
    hostname: str
    ip: str | None
    source: str


class ReconNgAdapter:
    """Enumerate subdomains for a target domain.

    Usage:
        adapter = ReconNgAdapter()
        hits = await adapter.enumerate("example.com")
    """

    async def enumerate(self, domain: str) -> list[ReconHit]:
        domain = (domain or "").strip().lower()
        if not domain:
            return []

        hits: dict[str, ReconHit] = {}
        async with httpx.AsyncClient(
            timeout=_HTTP_TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": "ai-assist-tool-recon/0.1"},
        ) as client:
            crt_results, ht_results = await asyncio.gather(
                self._query_crt_sh(client, domain),
                self._query_hackertarget(client, domain),
                return_exceptions=True,
            )

        for r in (crt_results, ht_results):
            if isinstance(r, Exception):
                Logger.error("recon.source.failed", extra={"error": str(r)})
                continue
            for hit in r:
                # Prefer the entry that has an IP if we already have a duplicate.
                existing = hits.get(hit.hostname)
                if existing is None or (existing.ip is None and hit.ip):
                    hits[hit.hostname] = hit

        await self._resolve_missing_ips(list(hits.values()))

        sorted_hits = sorted(hits.values(), key=lambda h: h.hostname)
        Logger.info(
            "recon.enumerate.complete",
            extra={
                "domain": domain,
                "hits": len(sorted_hits),
                "with_ip": sum(1 for h in sorted_hits if h.ip),
            },
        )
        return sorted_hits

    async def _query_crt_sh(
        self, client: httpx.AsyncClient, domain: str
    ) -> list[ReconHit]:
        params = {"q": f"%.{domain}", "output": "json"}
        try:
            resp = await client.get(CRT_SH_URL, params=params)
        except httpx.HTTPError as e:
            Logger.error("recon.crtsh.error", extra={"error": str(e)})
            return []
        if resp.status_code != 200:
            Logger.error(
                "recon.crtsh.bad_status",
                extra={"status": resp.status_code, "domain": domain},
            )
            return []
        try:
            payload = resp.json()
        except ValueError:
            return []

        seen: set[str] = set()
        out: list[ReconHit] = []
        for row in payload:
            name = (row.get("name_value") or "").strip()
            if not name:
                continue
            # CT entries may contain multiple newline-separated names plus
            # wildcards. Split and filter.
            for candidate in name.split("\n"):
                candidate = candidate.strip().lower().lstrip("*.")
                if not _looks_like_hostname(candidate, domain):
                    continue
                if candidate in seen:
                    continue
                seen.add(candidate)
                out.append(ReconHit(hostname=candidate, ip=None, source="crt.sh"))
        return out

    async def _query_hackertarget(
        self, client: httpx.AsyncClient, domain: str
    ) -> list[ReconHit]:
        try:
            resp = await client.get(HACKERTARGET_URL, params={"q": domain})
        except httpx.HTTPError as e:
            Logger.error("recon.hackertarget.error", extra={"error": str(e)})
            return []
        if resp.status_code != 200:
            Logger.error(
                "recon.hackertarget.bad_status",
                extra={"status": resp.status_code, "domain": domain},
            )
            return []
        body = (resp.text or "").strip()
        # hackertarget returns "error" / "API count exceeded" lines as plain text.
        if body.lower().startswith(("error", "api count", "invalid")):
            Logger.error(
                "recon.hackertarget.rejected",
                extra={"body": body[:120], "domain": domain},
            )
            return []

        out: list[ReconHit] = []
        for line in body.splitlines():
            parts = [p.strip() for p in line.split(",")]
            if not parts or not parts[0]:
                continue
            hostname = parts[0].lower().lstrip("*.")
            if not _looks_like_hostname(hostname, domain):
                continue
            ip = parts[1] if len(parts) > 1 and parts[1] else None
            out.append(ReconHit(hostname=hostname, ip=ip, source="hackertarget"))
        return out

    async def _resolve_missing_ips(self, hits: list[ReconHit]) -> None:
        missing = [h for h in hits if not h.ip]
        if not missing:
            return

        sem = asyncio.Semaphore(_DNS_WORKERS)
        loop = asyncio.get_running_loop()

        async def _resolve(hit: ReconHit) -> None:
            async with sem:
                try:
                    ip = await asyncio.wait_for(
                        loop.run_in_executor(None, socket.gethostbyname, hit.hostname),
                        timeout=_DNS_TIMEOUT_S,
                    )
                    hit.ip = ip
                except (asyncio.TimeoutError, OSError):
                    return

        await asyncio.gather(*[_resolve(h) for h in missing])
