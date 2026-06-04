"""Reports router — PDF generation for assets, DC groups, and finding selections."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from apps.validation.database import get_db
from apps.validation.models import ReportConfig
from apps.validation.repositories import (
    AssetRepository,
    DCGroupRepository,
    FindingRepository,
    HostRepository,
)
from apps.validation.services.report_generator import ReportGenerator
from sdk import Logger

router = APIRouter()


_DEFAULT_SECTIONS = "executive,findings,resolved,metadata"
_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._-]")


class FindingsReportRequest(BaseModel):
    finding_ids: list[str]
    prepared_by: str | None = None
    title: str = "Findings Report"


def _sanitize_filename(name: str) -> str:
    cleaned = _FILENAME_SAFE.sub("_", name or "report")
    return cleaned.strip("_") or "report"


def _split_sections(raw: str) -> list[str]:
    return [s.strip() for s in (raw or "").split(",") if s.strip()]


def _pdf_response(pdf_bytes: bytes, filename: str) -> Response:
    safe = _sanitize_filename(filename)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{safe}"',
        },
    )


def _today_stamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d")


@router.post("/reports/generate/asset/{asset_id}")
async def generate_asset_report(
    asset_id: str,
    prepared_by: str | None = None,
    severity_filter: str = "all",
    sections: str = _DEFAULT_SECTIONS,
    title: str | None = None,
) -> Response:
    async with get_db() as db:
        asset_repo = AssetRepository(db)
        asset = await asset_repo.get_by_id(asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

    config = ReportConfig(
        title=(title or f"{asset.name} — Security Report").strip(),
        prepared_by=prepared_by,
        asset_ids=[asset.id],
        sections=_split_sections(sections),
        severity_filter=severity_filter,
    )

    try:
        pdf_bytes = await ReportGenerator().generate(config)
    except Exception as e:
        Logger.error(
            "report.asset.failed",
            extra={"asset_id": asset_id, "error": str(e)},
        )
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}") from e

    filename = f"{asset.name}_report_{_today_stamp()}.pdf"
    Logger.info(
        "report.asset.generated",
        extra={"asset_id": asset_id, "filename": filename, "size": len(pdf_bytes)},
    )
    return _pdf_response(pdf_bytes, filename)


@router.post("/reports/generate/dc-group/{dc_group_id}")
async def generate_dc_group_report(
    dc_group_id: str,
    prepared_by: str | None = None,
    severity_filter: str = "all",
    sections: str = _DEFAULT_SECTIONS,
    title: str | None = None,
) -> Response:
    async with get_db() as db:
        group_repo = DCGroupRepository(db)
        asset_repo = AssetRepository(db)
        group = await group_repo.get_by_id(dc_group_id)
        if not group:
            raise HTTPException(status_code=404, detail="DC group not found")
        assets = await asset_repo.list_by_group(dc_group_id)

    config = ReportConfig(
        title=(title or f"{group.name} — Security Report").strip(),
        prepared_by=prepared_by,
        asset_ids=[a.id for a in assets],
        sections=_split_sections(sections),
        severity_filter=severity_filter,
    )

    try:
        pdf_bytes = await ReportGenerator().generate(config)
    except Exception as e:
        Logger.error(
            "report.dc_group.failed",
            extra={"dc_group_id": dc_group_id, "error": str(e)},
        )
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}") from e

    filename = f"{group.name}_security_report_{_today_stamp()}.pdf"
    Logger.info(
        "report.dc_group.generated",
        extra={
            "dc_group_id": dc_group_id,
            "filename": filename,
            "asset_count": len(assets),
            "size": len(pdf_bytes),
        },
    )
    return _pdf_response(pdf_bytes, filename)


@router.post("/reports/generate/findings")
async def generate_findings_report(payload: FindingsReportRequest) -> Response:
    if not payload.finding_ids:
        raise HTTPException(status_code=400, detail="finding_ids is required")

    async with get_db() as db:
        finding_repo = FindingRepository(db)
        host_repo = HostRepository(db)
        asset_repo = AssetRepository(db)

        host_ips: set[str] = set()
        for fid in payload.finding_ids:
            finding = await finding_repo.get_by_id(fid)
            if not finding:
                continue
            host = await host_repo.get_by_id(finding.host_id)
            if host:
                host_ips.add(host.ip)

        # Resolve asset_ids by matching host.ip to asset.target (exact, CIDR, or hostname).
        all_assets = await asset_repo.list_all()
        asset_ids: list[str] = []
        for asset in all_assets:
            target = (asset.target or "").strip()
            if not target:
                continue
            matched = False
            try:
                exact = str(ipaddress.ip_address(target))
                if exact in host_ips:
                    matched = True
            except ValueError:
                pass
            if not matched and "/" in target:
                try:
                    net = ipaddress.ip_network(target, strict=False)
                    for ip in host_ips:
                        try:
                            if ipaddress.ip_address(ip) in net:
                                matched = True
                                break
                        except ValueError:
                            pass
                except ValueError:
                    pass
            if not matched and (target.endswith(".x") or target.endswith(".*")):
                try:
                    net = ipaddress.ip_network(target[:-1] + "0/24", strict=False)
                    for ip in host_ips:
                        try:
                            if ipaddress.ip_address(ip) in net:
                                matched = True
                                break
                        except ValueError:
                            pass
                except ValueError:
                    pass
            if matched:
                asset_ids.append(asset.id)

    config = ReportConfig(
        title=payload.title or "Findings Report",
        prepared_by=payload.prepared_by,
        asset_ids=asset_ids,
        sections=_split_sections(_DEFAULT_SECTIONS),
        severity_filter="all",
    )

    try:
        pdf_bytes = await ReportGenerator().generate(config)
    except Exception as e:
        Logger.error(
            "report.findings.failed",
            extra={"finding_count": len(payload.finding_ids), "error": str(e)},
        )
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}") from e

    filename = f"findings_report_{_today_stamp()}.pdf"
    Logger.info(
        "report.findings.generated",
        extra={
            "finding_count": len(payload.finding_ids),
            "asset_count": len(asset_ids),
            "filename": filename,
            "size": len(pdf_bytes),
        },
    )
    return _pdf_response(pdf_bytes, filename)
