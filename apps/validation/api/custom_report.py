"""Custom Report router — page, SSE scan stream, PDF export."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

from apps.validation.services.custom_report_scanner import (
    DEFAULT_PORTS,
    run_scan_stream,
)
from apps.validation.services.cve_registry import get_rule, known_cves
from sdk import Logger

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")

_TEMPLATE_DIR = "frontend/templates"
_PDF_TEMPLATE = "custom_report_pdf.html"
_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._-]")
_RESULT_RANK = {"vulnerable": 0, "unknown_version": 1, "safe": 2, "not_applicable": 3}


@router.get("/custom-report", response_class=HTMLResponse)
async def custom_report_page(request: Request):
    return templates.TemplateResponse(
        "custom_report.html",
        {
            "request": request,
            "active": "custom_report",
            "known_cves": known_cves(),
            "default_ports": ",".join(str(p) for p in DEFAULT_PORTS),
        },
    )


@router.get("/custom-report/scan-stream")
async def custom_report_scan_stream(
    request: Request,
    cve_id: str,
    ip_range: str,
    ports: str = "",
    workers: int = 16,
):
    async def event_generator():
        try:
            async for event in run_scan_stream(cve_id, ip_range, ports, workers):
                if await request.is_disconnected():
                    Logger.info(
                        "custom_report.client_disconnected",
                        extra={"cve_id": cve_id},
                    )
                    break
                etype = event.get("type", "message")
                payload = json.dumps({k: v for k, v in event.items() if k != "type"})
                yield f"event: {etype}\ndata: {payload}\n\n"
        except Exception as e:
            Logger.error("custom_report.stream_error", extra={"error": str(e)})
            yield f"event: error\ndata: {json.dumps({'message': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


def _sanitize_filename(name: str) -> str:
    cleaned = _FILENAME_SAFE.sub("_", name or "report")
    return cleaned.strip("_") or "report"


@router.post("/custom-report/pdf")
async def custom_report_pdf(payload: dict[str, Any]) -> Response:
    """
    Render the accumulated scan results as a PDF using the same WeasyPrint
    pipeline as the rest of the validation reports. Stateless — the browser
    posts back the rows it collected from the SSE stream.
    """
    cve_id = str(payload.get("cve_id") or "").strip()
    ip_range = str(payload.get("ip_range") or "").strip()
    ports = str(payload.get("ports") or "").strip()
    prepared_by = (payload.get("prepared_by") or "").strip() or None
    results = payload.get("results") or []
    summary = payload.get("summary") or {}

    rule = get_rule(cve_id)
    if rule is None:
        raise HTTPException(status_code=400, detail=f"Unknown CVE '{cve_id}'")

    sorted_results = sorted(
        results,
        key=lambda r: (
            _RESULT_RANK.get(r.get("status", ""), 9),
            r.get("ip", ""),
        ),
    )

    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(_PDF_TEMPLATE)

    html_str = template.render(
        title=f"{rule.cve_id} — Vulnerability Scan",
        prepared_by=prepared_by,
        generated_at=datetime.utcnow(),
        cve=rule,
        rule_introduced=".".join(str(x) for x in rule.introduced),
        rule_fixed=".".join(str(x) for x in rule.fixed),
        ip_range=ip_range or "(unspecified)",
        ports=ports or "(default)",
        results=sorted_results,
        vulnerable=[r for r in sorted_results if r.get("status") == "vulnerable"],
        summary=summary,
    )

    try:
        pdf_bytes = HTML(string=html_str, base_url=_TEMPLATE_DIR).write_pdf()
    except Exception as e:
        Logger.error("custom_report.pdf_failed", extra={"error": str(e)})
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}") from e

    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M")
    filename = _sanitize_filename(f"{rule.cve_id}_scan_{stamp}.pdf")

    Logger.info(
        "custom_report.pdf_generated",
        extra={
            "cve_id": rule.cve_id,
            "result_count": len(sorted_results),
            "size_bytes": len(pdf_bytes),
        },
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
