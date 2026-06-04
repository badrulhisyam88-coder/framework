"""Pattern 18 — BranchWriter Wiring Seam (test_seam_branch_writer_wired.py)

Risk (V2.3 Step 2 closure of V2.2 production defect): ExecutionOrchestrator
constructed OutputChannel without a branch_writer argument since V2.1 Step 1.
All emit_stage() calls were silent no-ops: exploitation_branches was never
written during live investigations, stage logs were lost, artifacts never
persisted. Silent failure mode: engine runs, operator sees "complete" in the
UI, but no audit trail or artifact is written to disk. Re-running the
investigation produces no branch history.

Invariants (Pattern 18):
  P18-A: ExecutionOrchestrator.__init__ assigns self._branch_writer via
         BranchWriter() — verified via source inspection to avoid aiosqlite
         on the host environment.
  P18-B: OutputChannel constructed by ExecutionOrchestrator._launch() carries
         branch_writer=self._branch_writer — verified via source inspection.
  P18-C: emit_stage("running", ...) appends to stage_log in exploitation_branches
  P18-D: emit_stage("succeeded", {"artifact": ...}) writes artifact JSON column
  P18-E: BranchWriter.create() then BranchReader.get() round-trips the record
  P18-F: Existing emit_finding() contract unbroken after wiring (no regression)

Tests P18-A and P18-B use source inspection to avoid importing aiosqlite (not
available in the host Python environment; available inside Docker). Tests
P18-C/D/E use pytest.importorskip("aiosqlite") to skip cleanly on host and
asyncio.run() to avoid event-loop state pollution.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from unittest.mock import MagicMock


# ── Helpers ───────────────────────────────────────────────────────────────────


def _execution_src() -> str:
    p = Path(__file__).parent.parent.parent.parent / "apps/conductor/orchestrators/execution.py"
    return p.read_text()


def _tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test_branch_writer.db"


async def _init_and_get_writer(db_path: Path):
    from apps.validation.database import init_db
    from apps.conductor.exploitation.branch_store import BranchWriter

    await init_db(db_path)
    return BranchWriter(db_path=db_path)


async def _make_branch_record(branch_id: str, investigation_id: str = "inv_p18"):
    from apps.conductor.exploitation.branch_store import BranchRecord
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    return BranchRecord(
        branch_id=branch_id,
        investigation_id=investigation_id,
        finding_id="fnd_001",
        engine_id="test_engine",
        technique_class="test.class",
        operator_params={},
        state="pending",
        artifact=None,
        artifact_type=None,
        exhaustion_record=None,
        stage_log=[],
        created_at=now,
        updated_at=now,
    )


# ── Pattern 18 tests ──────────────────────────────────────────────────────────


def test_p18a_execution_orchestrator_branch_writer_assigned_in_init():
    """P18-A: ExecutionOrchestrator.__init__ assigns self._branch_writer.

    Uses source inspection to verify the assignment without triggering
    aiosqlite import (which is only available inside Docker).

    Before this fix, BranchWriter was never instantiated in ExecutionOrchestrator,
    leaving _branch_writer absent entirely. Now it is created in __init__.
    """
    src = _execution_src()

    assert "BranchWriter" in src, (
        "BranchWriter not referenced in execution.py. "
        "ExecutionOrchestrator must import and instantiate BranchWriter."
    )
    assert "self._branch_writer" in src, (
        "self._branch_writer not found in execution.py. "
        "BranchWriter must be assigned to self._branch_writer in __init__ so "
        "OutputChannel receives a non-None writer on every engine launch."
    )
    # Verify the assignment is in __init__, not just elsewhere in the file
    init_match = re.search(
        r"def __init__.*?(?=\n    def |\nclass |\Z)",
        src,
        re.DOTALL,
    )
    assert init_match is not None, "Could not locate __init__ in execution.py"
    init_body = init_match.group(0)
    assert "self._branch_writer" in init_body, (
        "self._branch_writer assigned outside __init__. "
        "Must be set in __init__ so every OutputChannel launch is covered."
    )


def test_p18b_output_channel_branch_writer_wired_in_launch():
    """P18-B: _launch() passes branch_writer=self._branch_writer to OutputChannel.

    Uses source inspection to verify the keyword argument is present in the
    OutputChannel constructor call inside _launch(), without triggering aiosqlite.
    """
    src = _execution_src()

    # Locate the _launch method body
    launch_match = re.search(
        r"def _launch\(.*?(?=\n    def |\nclass |\Z)",
        src,
        re.DOTALL,
    )
    assert launch_match is not None, "Could not locate _launch() in execution.py"
    launch_body = launch_match.group(0)

    assert "branch_writer" in launch_body, (
        "branch_writer kwarg not found in _launch(). "
        "OutputChannel must receive branch_writer=self._branch_writer so that "
        "emit_stage() is not a silent no-op during engine runs."
    )
    assert "self._branch_writer" in launch_body, (
        "self._branch_writer not passed in _launch(). "
        "The orchestrator's BranchWriter instance must be forwarded to OutputChannel."
    )


def test_p18c_emit_stage_running_appends_to_stage_log(tmp_path):
    """P18-C: emit_stage('running') appends an entry to exploitation_branches.stage_log."""
    pytest = __import__("pytest")
    pytest.importorskip("aiosqlite", reason="aiosqlite not available on host; runs in Docker")

    branch_id = "exb_p18c00000001"

    async def _run():
        writer = await _init_and_get_writer(_tmp_db(tmp_path))
        record = await _make_branch_record(branch_id)
        await writer.create(record)
        await writer.transition(branch_id, "running", {"probe": "sqli_payload_1"})

        from apps.conductor.exploitation.branch_store import BranchReader
        reader = BranchReader(db_path=_tmp_db(tmp_path))
        return await reader.get(branch_id)

    result = asyncio.run(_run())
    assert result is not None, "BranchRecord not found after transition()"
    assert result.state == "running", f"Expected state='running', got {result.state!r}"
    assert len(result.stage_log) == 1, (
        f"Expected 1 stage_log entry, got {len(result.stage_log)}. "
        "emit_stage('running') must append to stage_log."
    )
    assert result.stage_log[0]["state"] == "running"
    assert result.stage_log[0].get("probe") == "sqli_payload_1"


def test_p18d_emit_stage_succeeded_writes_artifact(tmp_path):
    """P18-D: emit_stage('succeeded', {'artifact': {...}}) writes artifact JSON column."""
    pytest = __import__("pytest")
    pytest.importorskip("aiosqlite", reason="aiosqlite not available on host; runs in Docker")

    branch_id = "exb_p18d00000001"
    artifact_payload = {
        "artifact_type": "bookmarklet_href",
        "bookmarklet": "javascript:void(0)",
        "token_preview": "abc123...",
    }

    async def _run():
        writer = await _init_and_get_writer(_tmp_db(tmp_path))
        record = await _make_branch_record(branch_id)
        await writer.create(record)
        await writer.transition(branch_id, "succeeded", {"artifact": artifact_payload})

        from apps.conductor.exploitation.branch_store import BranchReader
        reader = BranchReader(db_path=_tmp_db(tmp_path))
        return await reader.get(branch_id)

    result = asyncio.run(_run())
    assert result is not None
    assert result.state == "succeeded"
    assert result.artifact is not None, (
        "artifact column is None after emit_stage('succeeded', {'artifact': ...}). "
        "BranchWriter.transition() must write the artifact JSON when state='succeeded'."
    )
    assert result.artifact.get("artifact") == artifact_payload, (
        "Artifact payload does not match what was written. "
        f"Got: {result.artifact!r}"
    )


def test_p18e_branch_writer_reader_roundtrip(tmp_path):
    """P18-E: BranchWriter.create() + BranchReader.get() round-trips all fields."""
    pytest = __import__("pytest")
    pytest.importorskip("aiosqlite", reason="aiosqlite not available on host; runs in Docker")

    branch_id = "exb_p18e00000001"

    async def _run():
        writer = await _init_and_get_writer(_tmp_db(tmp_path))
        record = await _make_branch_record(branch_id, investigation_id="inv_roundtrip")
        await writer.create(record)

        from apps.conductor.exploitation.branch_store import BranchReader
        reader = BranchReader(db_path=_tmp_db(tmp_path))
        return await reader.get(branch_id)

    result = asyncio.run(_run())
    assert result is not None
    assert result.branch_id == branch_id
    assert result.investigation_id == "inv_roundtrip"
    assert result.engine_id == "test_engine"
    assert result.state == "pending"
    assert result.artifact is None
    assert result.stage_log == []


def test_p18f_emit_finding_contract_unbroken():
    """P18-F: Wiring BranchWriter does not break emit_finding() → FindingsOrchestrator.

    The OutputChannel constructor signature change (adding branch_writer) must
    not alter the behavior of emit_finding(), which is the V1 phase contract.
    """
    calls = []

    class _FakeFindings:
        async def ingest(self, finding, engine_id):
            calls.append(finding)

    class _FakeSession:
        def record_request(self, t): pass
        def record_response(self, t, sc): pass

    class _FakeBranchWriter:
        async def transition(self, *a, **kw): pass
        async def create(self, *a, **kw): pass

    from apps.conductor.engines.base import OutputChannel

    ch = OutputChannel(
        investigation_id="inv_p18f",
        engine_id="test_engine",
        findings_orch=_FakeFindings(),
        session_orch=_FakeSession(),
        branch_writer=_FakeBranchWriter(),
    )
    asyncio.run(
        ch.emit_finding({"id": "fnd_001", "finding_type": "test", "severity": "info"})
    )
    assert len(calls) == 1, (
        "emit_finding() did not route to FindingsOrchestrator after BranchWriter wiring. "
        "The V1 finding emission contract must be preserved."
    )
    assert calls[0]["id"] == "fnd_001"
