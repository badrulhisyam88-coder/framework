"""Recon service.

Runs subdomain enumeration against an asset's target domain via the
ReconNgAdapter, then persists the unique (hostname, ip) hits to the
recon_results table. The result list is the handoff point for the
existing Nmap pipeline — callers can pull IPs and feed them to
ScannerService.
"""
from __future__ import annotations

from apps.validation.adapters.recon_ng import ReconNgAdapter
from apps.validation.database import get_db
from apps.validation.models import Asset, ReconResult
from apps.validation.repositories import AssetRepository, ReconResultRepository
from sdk import Logger


class ReconService:
    def __init__(self) -> None:
        self.adapter = ReconNgAdapter()

    async def run(self, asset_id: str) -> dict:
        async with get_db() as db:
            asset_repo = AssetRepository(db)
            asset = await asset_repo.get_by_id(asset_id)
        if asset is None:
            return {"error": "asset not found"}

        target = (asset.target or "").strip()
        if not target:
            return {"error": "asset has no target"}

        domain = self._target_domain(target)
        if not domain:
            Logger.info(
                "recon.skip.not_a_domain",
                extra={"asset_id": asset_id, "target": target},
            )
            return {
                "asset_id": asset_id,
                "domain": None,
                "hits": 0,
                "with_ip": 0,
                "skipped_reason": "Target is an IP/CIDR — recon needs a domain.",
            }

        Logger.info(
            "recon.start",
            extra={"asset_id": asset_id, "domain": domain},
        )

        hits = await self.adapter.enumerate(domain)

        async with get_db() as db:
            repo = ReconResultRepository(db)
            for hit in hits:
                await repo.upsert(ReconResult(
                    asset_id=asset_id,
                    hostname=hit.hostname,
                    ip=hit.ip,
                    source=hit.source,
                ))

        with_ip = sum(1 for h in hits if h.ip)
        Logger.info(
            "recon.complete",
            extra={
                "asset_id": asset_id,
                "domain": domain,
                "hits": len(hits),
                "with_ip": with_ip,
            },
        )
        return {
            "asset_id": asset_id,
            "domain": domain,
            "hits": len(hits),
            "with_ip": with_ip,
        }

    @staticmethod
    def _target_domain(target: str) -> str | None:
        """Return the domain portion of an asset target, or None if the
        target looks like an IP / CIDR / wildcard that can't be enumerated.
        """
        t = target.strip().lower()
        if not t or "/" in t or t.endswith(".x") or t.endswith(".*"):
            return None
        if all(c.isdigit() or c == "." for c in t):
            return None
        return t

    @staticmethod
    def collect_scan_targets(results: list[ReconResult]) -> list[str]:
        """Reduce a list of ReconResults to the unique IPs/hostnames that
        the Nmap pipeline should scan next. Prefers IPs when available.
        """
        out: list[str] = []
        seen: set[str] = set()
        for r in results:
            target = r.ip or r.hostname
            if target and target not in seen:
                seen.add(target)
                out.append(target)
        return out
