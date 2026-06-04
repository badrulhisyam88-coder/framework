"""Seam tests: ID round-trip across layer boundaries.

Pattern: TWO-PARALLEL-ID-SYSTEMS (PR L bug)
  Bug example: Since PR B, findings had two IDs simultaneously.
    - Conductor's FindingsOrchestrator generates deterministic IDs via
      generate_finding_id() → format: fnd_xxxxxxxxxxxx (16 chars)
    - _persist in routes.py created NormalizedFinding without passing
      finding_id=evt.id, so the model defaulted to str(uuid4()) — a
      random UUID4 with no relation to fnd_xxx.
  Both layers worked in isolation. The bug only surfaced when
  FilterOrchestrator UPDATE WHERE finding_id='fnd_xxx' found 0 rows.

  Test assertion: every layer that produces an entity ID must survive
  to the layer that consumes it for cross-layer operations (writes).
"""
from __future__ import annotations


def _read_routes_source() -> str:
    with open("apps/investigation_workspace/api/routes.py") as f:
        return f.read()


def _find_normalized_finding_constructor(src: str) -> str:
    """Return the text of the NormalizedFinding(...) constructor block."""
    idx = src.find("NormalizedFinding(")
    assert idx != -1, "NormalizedFinding constructor not found in routes.py"
    return src[idx : idx + 600]


def test_storage_bridge_preserves_finding_id_across_layers():
    """_persist must pass evt.id as finding_id to NormalizedFinding.

    Without this line, NormalizedFinding defaults to uuid4(), creating a
    different ID from the Conductor's fnd_xxx finding["id"]. FilterOrchestrator
    UPDATEs use the Conductor's ID and always match 0 rows — silent failure.

    This test FAILS in pre-fix code. It PASSES after the PR L one-line fix.
    """
    src = _read_routes_source()
    block = _find_normalized_finding_constructor(src)
    assert "finding_id" in block, (
        "_persist does not pass finding_id to NormalizedFinding. "
        "NormalizedFinding defaults to uuid4() — diverging from the "
        "Conductor's fnd_xxx ID. FilterOrchestrator UPDATEs match 0 rows."
    )
    assert "evt.id" in block, (
        "_persist passes finding_id but not sourced from evt.id. "
        "Must use evt.id so the Conductor's fnd_xxx ID survives to the DB."
    )


def test_finding_id_format_is_fnd_prefixed():
    """generate_finding_id produces fnd_ prefixed IDs — confirming the format
    FilterOrchestrator uses for UPDATE WHERE finding_id=? statements."""
    from apps.investigation_workspace.probe.finding_id import generate_finding_id

    fid = generate_finding_id("passive_probe", "http://target", "/", "http_service_detected")
    assert fid.startswith("fnd_"), (
        f"generate_finding_id returned {fid!r} — expected fnd_ prefix. "
        "If the format changes, ensure _persist's finding_id= assignment stays consistent."
    )
    assert len(fid) == 16, (
        f"Expected 16-char ID (fnd_ + 12 hex chars), got {len(fid)} chars."
    )


def test_finding_id_is_deterministic():
    """generate_finding_id must be deterministic — same inputs produce same ID.
    This is what makes the round-trip test meaningful: both Conductor and
    FilterOrchestrator will use the same ID for the same logical finding."""
    from apps.investigation_workspace.probe.finding_id import generate_finding_id

    a = generate_finding_id("sqli_recon", "http://t", "/login", "sqli")
    b = generate_finding_id("sqli_recon", "http://t", "/login", "sqli")
    assert a == b, (
        "generate_finding_id is not deterministic — can't guarantee round-trip ID stability"
    )
