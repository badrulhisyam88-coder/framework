"""Assets router — self-contained DC-group / asset management.

Layout: a DC group contains one or more assets; an asset has a target
(IP / CIDR / hostname) plus default scan parameters. This page lets an
operator manage groups, kick off scans, and inspect inline findings —
without navigating to Discovery, Queue, or Findings.
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from apps.validation.config import clamp_workers, get_default_workers
from apps.validation.database import get_db
from apps.validation.models import (
    Asset,
    DCGroup,
    FindingStatus,
    ScanRequest,
)
from apps.validation.repositories import (
    AssetRepository,
    CVERepository,
    DCGroupRepository,
    FindingRepository,
    HostRepository,
    ReconResultRepository,
    ServiceRepository,
)
from apps.validation.services.recon import ReconService
from apps.validation.services.scanner import ScannerService
from sdk import Logger

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_target(target: str) -> tuple[ipaddress._BaseNetwork | None, str | None, str | None]:
    """Return (cidr, exact_ip, hostname) for a free-form scan target string.

    Accepts:
      - exact IPv4/IPv6  → (None, "1.2.3.4", None)
      - CIDR             → (network, None, None)
      - wildcard "x.y.z.x" / "x.y.z.*" → treated as /24
      - hostname         → (None, None, "asycuda.org")
    """
    t = (target or "").strip()
    if not t:
        return None, None, None

    # CIDR
    if "/" in t:
        try:
            return ipaddress.ip_network(t, strict=False), None, None
        except ValueError:
            pass

    # Wildcard last octet
    if t.endswith(".x") or t.endswith(".*"):
        candidate = t[:-1] + "0/24"
        try:
            return ipaddress.ip_network(candidate, strict=False), None, None
        except ValueError:
            pass

    # Exact IP
    try:
        return None, str(ipaddress.ip_address(t)), None
    except ValueError:
        pass

    return None, None, t


async def _resolve_host_ids(target: str, db) -> list[str]:
    """Find host IDs in the discovery store that match an asset target."""
    cidr, ip, hostname = _parse_target(target)
    async with db.execute("SELECT id, ip, hostname FROM hosts") as cur:
        rows = await cur.fetchall()

    ids: list[str] = []
    for row in rows:
        if ip and row["ip"] == ip:
            ids.append(row["id"])
            continue
        if cidr is not None:
            try:
                if ipaddress.ip_address(row["ip"]) in cidr:
                    ids.append(row["id"])
                    continue
            except ValueError:
                pass
        if hostname and row["hostname"] and row["hostname"].lower() == hostname.lower():
            ids.append(row["id"])
    return ids


async def _recon_host_ids(asset_id: str, db) -> list[str]:
    """Host IDs whose IPs match any recon_result rows for this asset."""
    async with db.execute(
        "SELECT DISTINCT h.id "
        "FROM hosts h "
        "JOIN recon_results r ON r.ip = h.ip "
        "WHERE r.asset_id = ? AND r.ip IS NOT NULL",
        (asset_id,),
    ) as cur:
        rows = await cur.fetchall()
    return [r["id"] for r in rows]


async def _resolve_asset_host_ids(asset: Asset, db) -> list[str]:
    """Union of target-matched host IDs and recon-discovered host IDs."""
    target_ids = await _resolve_host_ids(asset.target, db)
    recon_ids = await _recon_host_ids(asset.id, db)
    seen: set[str] = set()
    out: list[str] = []
    for hid in target_ids + recon_ids:
        if hid not in seen:
            seen.add(hid)
            out.append(hid)
    return out


async def _open_findings_count_for_host_ids(host_ids: list[str], db) -> int:
    if not host_ids:
        return 0
    placeholders = ",".join("?" for _ in host_ids)
    async with db.execute(
        f"SELECT COUNT(*) FROM findings WHERE status='open' AND host_id IN ({placeholders})",
        tuple(host_ids),
    ) as cur:
        row = await cur.fetchone()
    return row[0] if row else 0


async def _build_asset_summary(asset: Asset, db) -> dict:
    """Computed display info for a single asset row (collapsed view)."""
    host_ids = await _resolve_asset_host_ids(asset, db)
    open_findings = await _open_findings_count_for_host_ids(host_ids, db)
    recon_count = await ReconResultRepository(db).count_by_asset(asset.id)
    return {
        "asset": asset,
        "host_ids": host_ids,
        "open_findings": open_findings,
        "recon_count": recon_count,
    }


async def _build_group_summary(group: DCGroup, db) -> dict:
    """Header counters for a DC group card."""
    asset_repo = AssetRepository(db)
    assets = await asset_repo.list_by_group(group.id)
    asset_summaries = [await _build_asset_summary(a, db) for a in assets]
    open_findings = sum(s["open_findings"] for s in asset_summaries)
    last_scanned = max(
        (a.last_scanned_at for a in assets if a.last_scanned_at),
        default=None,
    )
    return {
        "group": group,
        "assets": asset_summaries,
        "asset_count": len(assets),
        "open_findings": open_findings,
        "last_scanned": last_scanned,
    }


def _hx(request: Request) -> bool:
    return bool(request.headers.get("HX-Request"))


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------


@router.get("/assets", response_class=HTMLResponse)
async def assets_page(request: Request):
    async with get_db() as db:
        group_repo = DCGroupRepository(db)
        groups = await group_repo.list_all()
        summaries = [await _build_group_summary(g, db) for g in groups]
    return templates.TemplateResponse(
        "assets.html",
        {
            "request": request,
            "groups": summaries,
            "default_workers": get_default_workers(),
            "locations": ["KL", "Zambia", "Fiji", "Other"],
        },
    )


# ---------------------------------------------------------------------------
# DC Groups
# ---------------------------------------------------------------------------


@router.post("/assets/dc-groups", response_class=HTMLResponse)
async def create_dc_group(
    request: Request,
    name: str = Form(...),
    location: str | None = Form(None),
    notes: str | None = Form(None),
):
    name = (name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    async with get_db() as db:
        group_repo = DCGroupRepository(db)
        try:
            group = await group_repo.insert(DCGroup(
                name=name,
                location=(location or "").strip() or None,
                notes=(notes or "").strip() or None,
            ))
        except Exception as e:
            Logger.error("dc_group.create_failed", extra={"error": str(e), "name": name})
            raise HTTPException(
                status_code=400,
                detail=f"Could not create DC group: {e}",
            ) from e
        summary = await _build_group_summary(group, db)
    Logger.info("dc_group.created", extra={"id": group.id, "name": name})
    return templates.TemplateResponse(
        "partials/dc_group_card.html",
        {"request": request, "g": summary, "default_workers": get_default_workers()},
    )


@router.delete("/assets/dc-groups/{group_id}", response_class=HTMLResponse)
async def delete_dc_group(group_id: str, request: Request):
    async with get_db() as db:
        group_repo = DCGroupRepository(db)
        existing = await group_repo.get_by_id(group_id)
        if not existing:
            raise HTTPException(status_code=404, detail="DC group not found")
        await group_repo.delete(group_id)
    Logger.info("dc_group.deleted", extra={"id": group_id})
    return HTMLResponse(content="", status_code=200)


@router.get("/assets/dc-groups/{group_id}/scan-all-stream")
async def scan_all_stream(group_id: str, request: Request):
    """Server-Sent Events stream that scans every asset in the DC group
    sequentially and emits progress events. Events (all default 'message'
    type, discriminated by an `event` field in the JSON payload):

      {"event": "start",          "total": N}
      {"event": "asset-start",    "asset_id", "name", "current", "total"}
      {"event": "asset-complete", "asset_id", "name", "current", "total",
                                  "hosts", "services", "html"}
      {"event": "asset-error",    "asset_id", "name", "current", "total", "error"}
      {"event": "done",           "total": N}
    """
    async with get_db() as db:
        group_repo = DCGroupRepository(db)
        asset_repo = AssetRepository(db)
        group = await group_repo.get_by_id(group_id)
        if not group:
            raise HTTPException(status_code=404, detail="DC group not found")
        assets = await asset_repo.list_by_group(group_id)

    scanner = ScannerService()
    total = len(assets)

    async def event_generator():
        try:
            yield f"data: {json.dumps({'event': 'start', 'total': total})}\n\n"
            for i, asset in enumerate(assets):
                if await request.is_disconnected():
                    Logger.info(
                        "scan_all.client_disconnected",
                        extra={"group_id": group_id, "completed": i},
                    )
                    return
                idx = i + 1
                yield (
                    "data: "
                    + json.dumps({
                        "event": "asset-start",
                        "asset_id": asset.id,
                        "name": asset.name,
                        "current": idx,
                        "total": total,
                    })
                    + "\n\n"
                )

                try:
                    result = await scanner.run_scan(ScanRequest(
                        target=asset.target,
                        scan_type=asset.scan_type or "quick",
                        workers=clamp_workers(
                            asset.workers or get_default_workers()
                        ),
                    ))
                except Exception as e:
                    Logger.error(
                        "scan_all.asset_failed",
                        extra={
                            "asset_id": asset.id,
                            "target": asset.target,
                            "error": str(e),
                        },
                    )
                    yield (
                        "data: "
                        + json.dumps({
                            "event": "asset-error",
                            "asset_id": asset.id,
                            "name": asset.name,
                            "current": idx,
                            "total": total,
                            "error": str(e),
                        })
                        + "\n\n"
                    )
                    continue

                async with get_db() as db:
                    repo = AssetRepository(db)
                    await repo.update_last_scanned(
                        asset.id, datetime.utcnow(), result.scan_id
                    )
                    fresh = await repo.get_by_id(asset.id)
                    summary = await _build_asset_summary(fresh, db)

                row_html = templates.get_template(
                    "partials/asset_row.html"
                ).render(s=summary)

                yield (
                    "data: "
                    + json.dumps({
                        "event": "asset-complete",
                        "asset_id": asset.id,
                        "name": asset.name,
                        "current": idx,
                        "total": total,
                        "hosts": result.hosts_found,
                        "services": result.services_found,
                        "html": row_html,
                    })
                    + "\n\n"
                )

            yield f"data: {json.dumps({'event': 'done', 'total': total})}\n\n"
            Logger.info(
                "dc_group.scan_all.complete",
                extra={"group_id": group_id, "asset_count": total},
            )
        except Exception as e:
            Logger.error(
                "scan_all.stream_error",
                extra={"group_id": group_id, "error": str(e)},
            )
            yield (
                "data: "
                + json.dumps({"event": "error", "message": str(e)})
                + "\n\n"
            )

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


@router.post("/assets", response_class=HTMLResponse)
async def create_asset(
    request: Request,
    dc_group_id: str = Form(...),
    name: str = Form(...),
    target: str = Form(...),
    notes: str | None = Form(None),
    scan_type: str = Form("quick"),
    workers: int = Form(default=None),
):
    name = (name or "").strip()
    target = (target or "").strip()
    if not name or not target:
        raise HTTPException(status_code=400, detail="Name and target are required")
    effective_workers = clamp_workers(
        workers if workers is not None else get_default_workers()
    )

    async with get_db() as db:
        group_repo = DCGroupRepository(db)
        group = await group_repo.get_by_id(dc_group_id)
        if not group:
            raise HTTPException(status_code=404, detail="DC group not found")
        asset_repo = AssetRepository(db)
        asset = await asset_repo.insert(Asset(
            dc_group_id=dc_group_id,
            name=name,
            target=target,
            notes=(notes or "").strip() or None,
            scan_type=scan_type or "quick",
            workers=effective_workers,
        ))
        summary = await _build_asset_summary(asset, db)
    Logger.info(
        "asset.created",
        extra={"id": asset.id, "name": name, "target": target, "group": dc_group_id},
    )
    return templates.TemplateResponse(
        "partials/asset_row.html",
        {"request": request, "s": summary},
    )


@router.delete("/assets/{asset_id}", response_class=HTMLResponse)
async def delete_asset(asset_id: str, request: Request):
    async with get_db() as db:
        repo = AssetRepository(db)
        existing = await repo.get_by_id(asset_id)
        if not existing:
            raise HTTPException(status_code=404, detail="Asset not found")
        await repo.delete(asset_id)
    Logger.info("asset.deleted", extra={"id": asset_id})
    return HTMLResponse(content="", status_code=200)


@router.post("/assets/{asset_id}/scan", response_class=HTMLResponse)
async def scan_asset(asset_id: str, request: Request):
    async with get_db() as db:
        repo = AssetRepository(db)
        asset = await repo.get_by_id(asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

    scan_request = ScanRequest(
        target=asset.target,
        scan_type=asset.scan_type or "quick",
        workers=clamp_workers(asset.workers or get_default_workers()),
    )
    try:
        result = await ScannerService().run_scan(scan_request)
    except Exception as e:
        Logger.error(
            "asset.scan_failed",
            extra={"asset_id": asset_id, "target": asset.target, "error": str(e)},
        )
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}") from e

    async with get_db() as db:
        repo = AssetRepository(db)
        await repo.update_last_scanned(asset_id, datetime.utcnow(), result.scan_id)
        asset = await repo.get_by_id(asset_id)
        summary = await _build_asset_summary(asset, db)

    Logger.info(
        "asset.scanned",
        extra={
            "asset_id": asset_id,
            "scan_id": result.scan_id,
            "hosts_found": result.hosts_found,
            "services_found": result.services_found,
        },
    )

    return templates.TemplateResponse(
        "partials/asset_row.html",
        {"request": request, "s": summary},
    )


@router.post("/assets/{asset_id}/recon", response_class=HTMLResponse)
async def recon_asset(asset_id: str, request: Request):
    async with get_db() as db:
        repo = AssetRepository(db)
        asset = await repo.get_by_id(asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

    try:
        result = await ReconService().run(asset_id)
    except Exception as e:
        Logger.error(
            "asset.recon_failed",
            extra={"asset_id": asset_id, "target": asset.target, "error": str(e)},
        )
        raise HTTPException(status_code=500, detail=f"Recon failed: {e}") from e

    async with get_db() as db:
        summary = await _build_asset_summary(asset, db)

    Logger.info(
        "asset.recon",
        extra={
            "asset_id": asset_id,
            "domain": result.get("domain"),
            "hits": result.get("hits", 0),
            "with_ip": result.get("with_ip", 0),
            "skipped": result.get("skipped_reason"),
        },
    )

    return templates.TemplateResponse(
        "partials/asset_row.html",
        {"request": request, "s": summary},
    )


@router.get("/assets/{asset_id}/recon/scan-discovered-stream")
async def scan_discovered_stream(asset_id: str, request: Request):
    """SSE stream that runs an Nmap scan against every IP/hostname discovered
    by recon for this asset, sequentially. Events:

      {"event": "start",          "total": N}
      {"event": "target-start",   "target", "current", "total"}
      {"event": "target-complete","target", "current", "total", "hosts", "services"}
      {"event": "target-error",   "target", "current", "total", "error"}
      {"event": "done",           "total": N}
    """
    async with get_db() as db:
        asset_repo = AssetRepository(db)
        asset = await asset_repo.get_by_id(asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        recon_repo = ReconResultRepository(db)
        recon_results = await recon_repo.list_by_asset(asset_id)

    from apps.validation.services.recon import ReconService
    targets = ReconService.collect_scan_targets(recon_results)
    total = len(targets)
    scanner = ScannerService()

    async def event_generator():
        try:
            yield f"data: {json.dumps({'event': 'start', 'total': total})}\n\n"
            for i, target in enumerate(targets):
                if await request.is_disconnected():
                    Logger.info(
                        "scan_discovered.client_disconnected",
                        extra={"asset_id": asset_id, "completed": i},
                    )
                    return
                idx = i + 1
                yield (
                    "data: "
                    + json.dumps({
                        "event": "target-start",
                        "target": target,
                        "current": idx,
                        "total": total,
                    })
                    + "\n\n"
                )

                try:
                    result = await scanner.run_scan(ScanRequest(
                        target=target,
                        scan_type=asset.scan_type or "quick",
                        workers=clamp_workers(
                            asset.workers or get_default_workers()
                        ),
                    ))
                except Exception as e:
                    Logger.error(
                        "scan_discovered.target_failed",
                        extra={"asset_id": asset_id, "target": target, "error": str(e)},
                    )
                    yield (
                        "data: "
                        + json.dumps({
                            "event": "target-error",
                            "target": target,
                            "current": idx,
                            "total": total,
                            "error": str(e),
                        })
                        + "\n\n"
                    )
                    continue

                yield (
                    "data: "
                    + json.dumps({
                        "event": "target-complete",
                        "target": target,
                        "current": idx,
                        "total": total,
                        "hosts": result.hosts_found,
                        "services": result.services_found,
                    })
                    + "\n\n"
                )

            # Bump asset.last_scanned_at once the run finishes so the row UI
            # reflects "we did something here just now".
            if total:
                async with get_db() as db:
                    await AssetRepository(db).update_last_scanned(
                        asset_id, datetime.utcnow(), "recon-scan"
                    )

            yield f"data: {json.dumps({'event': 'done', 'total': total})}\n\n"
            Logger.info(
                "asset.scan_discovered.complete",
                extra={"asset_id": asset_id, "target_count": total},
            )
        except Exception as e:
            Logger.error(
                "scan_discovered.stream_error",
                extra={"asset_id": asset_id, "error": str(e)},
            )
            yield (
                "data: "
                + json.dumps({"event": "error", "message": str(e)})
                + "\n\n"
            )

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/assets/{asset_id}/details", response_class=HTMLResponse)
async def asset_details(asset_id: str, request: Request):
    async with get_db() as db:
        asset_repo = AssetRepository(db)
        asset = await asset_repo.get_by_id(asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

        host_repo = HostRepository(db)
        service_repo = ServiceRepository(db)
        finding_repo = FindingRepository(db)
        cve_repo = CVERepository(db)
        recon_repo = ReconResultRepository(db)

        recon_results = await recon_repo.list_by_asset(asset_id)

        host_ids = await _resolve_asset_host_ids(asset, db)
        hosts = []
        services_by_port: dict[tuple[str, int, str], dict] = {}
        for host_id in host_ids:
            host = await host_repo.get_by_id(host_id)
            if not host:
                continue
            hosts.append(host)
            services = await service_repo.list_by_host(host_id)
            for svc in services:
                key = (host.ip, svc.port, svc.protocol)
                services_by_port[key] = {
                    "host": host,
                    "service": svc,
                    "findings": [],
                }

        # Pull findings for these hosts and enrich for display
        findings: list = []
        if host_ids:
            all_findings = await finding_repo.list_all(limit=10_000)
            findings = [f for f in all_findings if f.host_id in host_ids]
            for f in findings:
                f.host = await host_repo.get_by_id(f.host_id)
                if f.service_id:
                    f.service = await service_repo.get_by_id(f.service_id)
                if f.cve_id:
                    f.cve = await cve_repo.get_by_id(f.cve_id)
                if f.service:
                    key = (f.host.ip, f.service.port, f.service.protocol)
                    if key in services_by_port:
                        services_by_port[key]["findings"].append(f)

    # Sort: ports ascending, findings grouped by host then by severity
    ports_sorted = sorted(services_by_port.values(), key=lambda s: (
        s["host"].ip, s["service"].port
    ))
    findings_sorted = sorted(
        findings,
        key=lambda f: (
            0 if f.status == "open" else 1,
            -(f.cvss_score or 0.0),
            f.finding_type,
        ),
    )

    return templates.TemplateResponse(
        "partials/asset_details.html",
        {
            "request": request,
            "asset": asset,
            "hosts": hosts,
            "ports": ports_sorted,
            "findings": findings_sorted,
            "status_choices": [s.value for s in FindingStatus],
            "recon_results": recon_results,
        },
    )


@router.patch(
    "/assets/findings/{finding_id}/status", response_class=HTMLResponse
)
async def update_finding_status_inline(
    finding_id: str,
    request: Request,
    status: str = Form(...),
):
    """Patch a finding's status from the Assets page without navigating."""
    try:
        new_status = FindingStatus(status)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status}") from e
    async with get_db() as db:
        repo = FindingRepository(db)
        finding = await repo.get_by_id(finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        await repo.update_status(finding_id, new_status)
    Logger.info(
        "finding.status_updated_inline",
        extra={"finding_id": finding_id, "status": str(new_status), "source": "assets"},
    )
    return HTMLResponse(content="", status_code=200)
