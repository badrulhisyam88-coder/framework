"""Aggregation card builders for the workspace phase panes.

Pure functions — no fastapi/aiosqlite/pydantic imports.
Consumed by routes.py; tested directly in tests/api/.
"""
from __future__ import annotations


def _humanize_finding_type(finding_type: str) -> str:
    """Convert snake_case finding_type to Title Case display."""
    return finding_type.replace("_", " ").title()


def _dominant_validation(findings: list[dict]) -> tuple[str, str | None, list[str]]:
    """Compute dominant validation_status from a group of findings.

    Priority: dropped (all) > validated (any) > incomplete (any) > pending.
    """
    statuses = [f.get("validation_status", "pending") for f in findings]
    if all(s == "dropped" for s in statuses):
        reason = findings[0].get("validation_reason") if findings else None
        return "dropped", reason, []
    all_gaps: list[str] = []
    for f in findings:
        all_gaps.extend(f.get("enumeration_gaps") or [])
    if any(s == "validated" for s in statuses):
        reason = next(
            (f.get("validation_reason") for f in findings if f.get("validation_status") == "validated"),
            None,
        )
        return "validated", reason, []
    if any(s == "incomplete" for s in statuses):
        reason = next(
            (f.get("validation_reason") for f in findings if f.get("validation_status") == "incomplete"),
            None,
        )
        return "incomplete", reason, list(dict.fromkeys(all_gaps))
    return "pending", None, []


def _build_aggregations(
    phase_name: str,
    finding_ids: list[str],
    findings_by_id: dict[str, dict],
) -> list[dict]:
    """Build aggregation summary cards for Recon and Enumeration phase panes.

    Findings handled by a whitelist card are tracked in _seen_fids so they are
    not double-counted in the catch-all group at the end of the function.
    """
    cards: list[dict] = []
    _seen_fids: set[str] = set()

    phase_findings = [findings_by_id[fid] for fid in finding_ids if fid in findings_by_id]

    if phase_name == "recon":
        # ── Security headers group ────────────────────────────────────────
        header_ftypes = {
            "missing_csp_header",
            "missing_hsts_header",
            "missing_x_frame_options",
            "missing_x_content_type_options",
            "missing_referrer_policy",
        }
        header_findings = [f for f in phase_findings if f["finding_type"] in header_ftypes]
        if header_findings:
            n = len(header_findings)
            sub_labels = "; ".join(
                ft.replace("missing_", "").replace("_header", "").upper()
                for ft in sorted({f["finding_type"] for f in header_findings})
            )
            v_status, v_reason, v_gaps = _dominant_validation(header_findings)
            cards.append({
                "kind":              "security_headers",
                "title":             f"Security headers — {n} of 5 baseline headers absent",
                "sub_text":          sub_labels,
                "count":             n,
                "items": [
                    {
                        "title":       f["title"],
                        "severity":    f["severity"],
                        "description": f["description"] or "",
                    }
                    for f in header_findings
                ],
                "finding_id":        header_findings[0]["finding_id"],
                "validation_status": v_status,
                "validation_reason": v_reason,
                "enumeration_gaps":  v_gaps,
            })
            _seen_fids.update(f["finding_id"] for f in header_findings)

        # ── HTTP service card ─────────────────────────────────────────────
        http_service = next(
            (f for f in phase_findings if f["finding_type"] == "http_service_detected"),
            None,
        )
        if http_service:
            svc_rd = http_service["raw_data"]
            raw_data = svc_rd if isinstance(svc_rd, dict) else {}
            status_code = raw_data.get("status_code", "?")
            server = raw_data.get("server", "unknown")
            content_type = raw_data.get("content_type", "")
            skip_keys = {"_phase", "all_headers", "probe_method"}
            items = [
                {"key": k, "value": str(v)}
                for k, v in raw_data.items()
                if k not in skip_keys
            ]
            v_status, v_reason, v_gaps = _dominant_validation([http_service])
            cards.append({
                "kind":              "http_service",
                "title":             f"HTTP service — HTTP {status_code} · {server}",
                "sub_text":          content_type,
                "items":             items,
                "finding_id":        http_service["finding_id"],
                "validation_status": v_status,
                "validation_reason": v_reason,
                "enumeration_gaps":  v_gaps,
            })
            _seen_fids.add(http_service["finding_id"])

    elif phase_name == "enumeration":
        # ── API surface card ──────────────────────────────────────────────
        api_exposure = next(
            (f for f in phase_findings if f["finding_type"] == "api_exposure"),
            None,
        )
        if api_exposure:
            api_rd = api_exposure["raw_data"]
            raw_data = api_rd if isinstance(api_rd, dict) else {}
            signals: list = raw_data.get("signals", [])
            hit_paths: list = raw_data.get("hit_paths", [])
            v_status, v_reason, v_gaps = _dominant_validation([api_exposure])
            cards.append({
                "kind":              "api_surface",
                "title":             f"API surface — {len(signals)} signals across {len(hit_paths)} paths",
                "sub_text":          ", ".join(
                    p["path"] if isinstance(p, dict) else str(p)
                    for p in hit_paths[:3]
                ),
                "items":             [{"signal": str(s)} for s in signals[:10]],
                "finding_id":        api_exposure["finding_id"],
                "validation_status": v_status,
                "validation_reason": v_reason,
                "enumeration_gaps":  v_gaps,
            })
            _seen_fids.add(api_exposure["finding_id"])

        # ── Login form card ───────────────────────────────────────────────
        login_form = next(
            (f for f in phase_findings if f["finding_type"] == "login_form_detected"),
            None,
        )
        if login_form:
            v_status, v_reason, v_gaps = _dominant_validation([login_form])
            cards.append({
                "kind":              "login_form",
                "title":             login_form["title"] or "Login form detected",
                "sub_text":          login_form["endpoint"] or "",
                "items":             [],
                "finding_id":        login_form["finding_id"],
                "validation_status": v_status,
                "validation_reason": v_reason,
                "enumeration_gaps":  v_gaps,
            })
            _seen_fids.add(login_form["finding_id"])

        # ── SQLi recon card ───────────────────────────────────────────────
        sqli_findings = [f for f in phase_findings if "sqli" in f["finding_type"].lower()]
        if sqli_findings:
            v_status, v_reason, v_gaps = _dominant_validation(sqli_findings)
            cards.append({
                "kind":              "sqli_recon",
                "title":             sqli_findings[0]["title"] or "SQL injection surface detected",
                "sub_text":          sqli_findings[0]["endpoint"] or "",
                "items": [
                    {
                        "title":       f["title"],
                        "severity":    f["severity"],
                        "description": f["description"] or "",
                    }
                    for f in sqli_findings
                ],
                "finding_id":        sqli_findings[0]["finding_id"],
                "validation_status": v_status,
                "validation_reason": v_reason,
                "enumeration_gaps":  v_gaps,
            })
            _seen_fids.update(f["finding_id"] for f in sqli_findings)

        # ── Command injection recon card ──────────────────────────────────
        cmdi_findings = [
            f for f in phase_findings
            if "command_injection" in f["finding_type"].lower()
            or "cmdi" in f["finding_type"].lower()
        ]
        if cmdi_findings:
            v_status, v_reason, v_gaps = _dominant_validation(cmdi_findings)
            cards.append({
                "kind":              "cmdi_recon",
                "title":             cmdi_findings[0]["title"] or "Command injection surface detected",
                "sub_text":          cmdi_findings[0]["endpoint"] or "",
                "items": [
                    {
                        "title":       f["title"],
                        "severity":    f["severity"],
                        "description": f["description"] or "",
                    }
                    for f in cmdi_findings
                ],
                "finding_id":        cmdi_findings[0]["finding_id"],
                "validation_status": v_status,
                "validation_reason": v_reason,
                "enumeration_gaps":  v_gaps,
            })
            _seen_fids.update(f["finding_id"] for f in cmdi_findings)

    # ── Catch-all: one card per unhandled finding_type, alphabetically sorted ─
    unseen = [f for f in phase_findings if f["finding_id"] not in _seen_fids]
    by_type: dict[str, list[dict]] = {}
    for f in unseen:
        by_type.setdefault(f["finding_type"], []).append(f)
    for ftype in sorted(by_type):
        group = by_type[ftype]
        n = len(group)
        v_status, v_reason, v_gaps = _dominant_validation(group)
        cards.append({
            "kind":              "catch_all",
            "title":             _humanize_finding_type(ftype),
            "sub_text":          f"{n} occurrence{'s' if n != 1 else ''}",
            "count":             n,
            "items": [
                {
                    "title":       f.get("title") or _humanize_finding_type(ftype),
                    "path":        f.get("endpoint") or "",
                    "severity":    f.get("severity", "info"),
                    "description": f.get("description") or "",
                }
                for f in group
            ],
            "finding_id":        group[0]["finding_id"],
            "validation_status": v_status,
            "validation_reason": v_reason,
            "enumeration_gaps":  v_gaps,
        })

    return cards
