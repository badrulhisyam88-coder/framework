"""Regression tests — aggregation catch-all card and whitelist stability.

Tests 1-6 validate that _build_aggregations:
  - leaves existing whitelist cards unchanged (regression guard)
  - emits a catch-all card for any unhandled finding_type
  - groups multiple unhandled types into separate cards
  - never double-counts a finding already in a whitelist card
  - produces deterministic alphabetical ordering
"""
from __future__ import annotations

from apps.investigation_workspace.aggregations import (
    _build_aggregations,
    _humanize_finding_type,
)

# ── Fixture helpers ───────────────────────────────────────────────────────────


def _finding(fid: str, ftype: str, **kw) -> dict:
    return {
        "finding_id":   fid,
        "finding_type": ftype,
        "title":        kw.get("title", f"title-{fid}"),
        "severity":     kw.get("severity", "info"),
        "description":  kw.get("description", ""),
        "endpoint":     kw.get("endpoint", ""),
        "raw_data":     kw.get("raw_data", {}),
    }


# ── Test 1: existing whitelist behavior is unchanged ─────────────────────────


def test_existing_whitelist_unchanged():
    """Whitelist-handled findings produce their bespoke cards; no catch-all for them."""
    api = _finding("f1", "api_exposure", raw_data={
        "signals": ["s1"],
        "hit_paths": [{"path": "/api", "status_code": 200, "content_type": "application/json"}],
    })
    login = _finding("f2", "login_form_detected", title="Login form", endpoint="/login")
    sqli = _finding("f3", "sqli_blind", title="Blind SQLi", endpoint="/search")

    findings_by_id = {f["finding_id"]: f for f in [api, login, sqli]}
    finding_ids = [f["finding_id"] for f in [api, login, sqli]]

    cards = _build_aggregations("enumeration", finding_ids, findings_by_id)

    kinds = [c["kind"] for c in cards]
    assert "api_surface" in kinds
    assert "login_form" in kinds
    assert "sqli_recon" in kinds
    # No catch-all for these findings
    assert all(c["kind"] != "catch_all" for c in cards), (
        "Whitelist findings must not appear in catch-all"
    )


# ── Test 2: catch-all renders unhandled finding_type ─────────────────────────


def test_catch_all_renders_unhandled_type():
    """service_detected (no whitelist) → one catch-all card with correct content."""
    f1 = _finding("f1", "service_detected", title="SSH on port 22", endpoint="host:22")
    f2 = _finding("f2", "service_detected", title="HTTP on port 80", endpoint="host:80")

    findings_by_id = {f["finding_id"]: f for f in [f1, f2]}
    finding_ids = [f["finding_id"] for f in [f1, f2]]

    cards = _build_aggregations("enumeration", finding_ids, findings_by_id)

    assert len(cards) == 1
    card = cards[0]
    assert card["kind"] == "catch_all"
    assert card["title"] == "Service Detected"
    assert card["count"] == 2
    assert len(card["items"]) == 2


# ── Test 3: catch-all groups by finding_type ─────────────────────────────────


def test_catch_all_groups_by_finding_type():
    """Mixed unhandled types → one catch-all card per type, alphabetically sorted."""
    svc1 = _finding("s1", "service_detected")
    svc2 = _finding("s2", "service_detected")
    svc3 = _finding("s3", "service_detected")
    vuln = _finding("v1", "vulnerability_confirmed")
    vuln2 = _finding("v2", "vulnerability_confirmed")

    findings_by_id = {f["finding_id"]: f for f in [svc1, svc2, svc3, vuln, vuln2]}
    finding_ids = [f["finding_id"] for f in [svc1, svc2, svc3, vuln, vuln2]]

    cards = _build_aggregations("enumeration", finding_ids, findings_by_id)

    assert len(cards) == 2
    # Alphabetical: service_detected < vulnerability_confirmed
    assert cards[0]["title"] == "Service Detected"
    assert cards[0]["count"] == 3
    assert cards[1]["title"] == "Vulnerability Confirmed"
    assert cards[1]["count"] == 2


# ── Test 4: no double-counting between whitelist and catch-all ────────────────


def test_catch_all_does_not_double_count():
    """Findings in whitelist cards must not also appear in catch-all."""
    api = _finding("f1", "api_exposure", raw_data={"signals": [], "hit_paths": []})
    svc = _finding("f2", "service_detected")

    findings_by_id = {f["finding_id"]: f for f in [api, svc]}
    finding_ids = [f["finding_id"] for f in [api, svc]]

    cards = _build_aggregations("enumeration", finding_ids, findings_by_id)

    whitelist_cards = [c for c in cards if c["kind"] != "catch_all"]
    catch_all_cards = [c for c in cards if c["kind"] == "catch_all"]

    assert len(whitelist_cards) == 1
    assert whitelist_cards[0]["kind"] == "api_surface"

    assert len(catch_all_cards) == 1
    assert catch_all_cards[0]["title"] == "Service Detected"

    # No finding_id appears in both
    whitelist_fids = {c["finding_id"] for c in whitelist_cards}
    catchall_fids = {c["finding_id"] for c in catch_all_cards}
    assert whitelist_fids.isdisjoint(catchall_fids)


# ── Test 5: _humanize_finding_type helper ────────────────────────────────────


def test_humanize_finding_type_helper():
    assert _humanize_finding_type("service_detected") == "Service Detected"
    assert _humanize_finding_type("vulnerability_confirmed") == "Vulnerability Confirmed"
    assert _humanize_finding_type("vulnerability_assessed") == "Vulnerability Assessed"
    assert _humanize_finding_type("http_service_detected") == "Http Service Detected"
    assert _humanize_finding_type("single") == "Single"


# ── Test 6: deterministic ordering across repeated calls ─────────────────────


def test_catch_all_card_ordering_deterministic():
    """Same input produces same alphabetical card order on every call."""
    findings = [
        _finding("z1", "zzz_type"),
        _finding("a1", "aaa_type"),
        _finding("m1", "mmm_type"),
    ]
    findings_by_id = {f["finding_id"]: f for f in findings}
    finding_ids = [f["finding_id"] for f in findings]

    cards_a = _build_aggregations("enumeration", finding_ids, findings_by_id)
    cards_b = _build_aggregations("enumeration", finding_ids, findings_by_id)

    titles_a = [c["title"] for c in cards_a]
    titles_b = [c["title"] for c in cards_b]
    assert titles_a == titles_b
    assert titles_a == ["Aaa Type", "Mmm Type", "Zzz Type"]
