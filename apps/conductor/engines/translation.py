"""Shared FindingEvent → conductor finding dict translator.

All engine wrappers that consume FindingEvent-emitting probes use this
instead of per-engine _translate() copies.
"""
from __future__ import annotations


def translate_finding_event(fe, engine_id: str, target: str) -> dict:
    """Translate a FindingEvent into the conductor's unified finding dict.

    Deferred import of generate_finding_id so this module is safe to import
    without triggering the full probe dependency chain at startup.
    """
    from apps.investigation_workspace.probe.finding_id import generate_finding_id

    finding_id = fe.id or generate_finding_id(
        probe_id=engine_id,
        target=target,
        path=fe.endpoint or "/",
        finding_type=fe.finding_type,
    )
    return {
        "id": finding_id,
        "probe_id": engine_id,
        "phase": fe.phase,
        "category": fe.finding_type,
        "title": fe.title,
        "path": fe.endpoint,
        "severity": fe.severity,
        "confidence": fe.confidence or "high",
        "description": fe.description,
        "evidence": fe.evidence or {},
        "next_actions": fe.next_actions or [],
    }
