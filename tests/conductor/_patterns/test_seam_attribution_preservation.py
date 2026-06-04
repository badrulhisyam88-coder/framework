"""Seam tests: metadata (attribution) survival across layer transitions.

Pattern: ATTRIBUTION LOSS AT SEAM (PR D-fix-2 bug)
  Bug example: StorageBridge hardcoded source_scanner="passive_probe" from when
    only one consumer existed. When nmap, nuclei, zap were added as engines, all
    their findings were attributed to "passive_probe". Source-based queries were
    silently wrong.

  Test assertion: when an entity carries attribution metadata (source_scanner,
  probe_id, engine_id), that metadata must survive all layer transitions intact.
"""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_source_scanner_survives_storage_bridge():
    """StorageBridge must propagate probe_id from the finding dict to
    FindingEvent.source_scanner — not hardcode a constant.

    The fix in PR D-fix-2 wired this correctly. This test guards regression.
    """
    from apps.conductor.findings.storage_bridge import StorageBridge

    captured = {}

    async def _mock_persist(fe) -> str:
        captured["source_scanner"] = fe.source_scanner
        return "fnd_test"

    bridge = StorageBridge(persist_fn=_mock_persist)
    finding = {
        "id": "fnd_test_001",
        "category": "service_detected",
        "title": "Test",
        "severity": "info",
        "description": "",
        "phase": "recon",
        "evidence": {},
        "probe_id": "nmap",          # attribution to preserve
    }

    await bridge.persist(finding, "inv-test")
    assert captured["source_scanner"] == "nmap", (
        f"source_scanner was {captured['source_scanner']!r}, expected 'nmap'. "
        "StorageBridge must pass probe_id as source_scanner, not hardcode 'passive_probe'."
    )


def test_probe_id_preserved_in_translated_finding():
    """translate_finding_event must carry probe_id (engine identity) from
    FindingEvent to the finding dict under key 'probe_id'."""
    from apps.conductor.engines.translation import translate_finding_event
    from apps.investigation_workspace.probe.events import FindingEvent

    fe = FindingEvent(
        after_stage_index=0,
        finding_type="api_exposure",
        title="API Exposure",
        severity="medium",
        description="",
        evidence={"hit_paths": []},
        phase="enumeration",
        id="fnd_api_001",
        source_scanner="api_recon",
    )

    result = translate_finding_event(fe, engine_id="api_recon", target="http://t")
    assert result.get("probe_id") == "api_recon", (
        f"probe_id was {result.get('probe_id')!r} in translated finding, expected 'api_recon'. "
        "FilterOrchestrator and DB attribution depend on this field surviving translation."
    )
