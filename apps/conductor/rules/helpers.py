"""Shared helpers for rule evaluation."""
from __future__ import annotations


def finding_type(finding: dict) -> str:
    """Return the finding type — handles both 'category' (conductor) and 'finding_type' (DB)."""
    return finding.get("finding_type") or finding.get("category") or ""


def detect_server(all_findings: list[dict]) -> str:
    """Return server identifier from cross-finding evidence, or '' if unknown.

    Checks http_service_detected findings (passive_probe) for evidence["server"],
    then service_detected findings (nmap) for evidence["service_version"].
    Returns the first non-empty value found, lowercased.
    """
    for f in all_findings:
        ftype = finding_type(f)
        ev = f.get("evidence", {})
        if ftype == "http_service_detected":
            val = ev.get("server", "")
            if val:
                return val.lower()
        if ftype == "service_detected":
            val = ev.get("service_version", "")
            if val:
                return val.lower()
    return ""


def has_finding_type(all_findings: list[dict], ftype: str) -> bool:
    """Return True if any finding in all_findings has the given finding type."""
    return any(finding_type(f) == ftype for f in all_findings)


def extract_paths_from_zap_findings(
    all_findings: list[dict],
    filter_fn=None,
) -> list[str]:
    """Return URL paths from zap_endpoint_discovered findings.

    filter_fn — optional callable(url: str) -> bool to select a subset.
    """
    urls = [
        f.get("evidence", {}).get("url", "")
        for f in all_findings
        if finding_type(f) == "zap_endpoint_discovered"
    ]
    if filter_fn is not None:
        urls = [u for u in urls if filter_fn(u)]
    return [u for u in urls if u]
