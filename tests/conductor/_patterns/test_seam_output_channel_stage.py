"""Seam tests: OutputChannel.emit_stage() extension preserves emit_finding() contract.

Pattern: OUTPUT-CHANNEL-STAGE-SEAM (V2.1 addition)
  Risk: Adding emit_stage() to OutputChannel could silently break the existing
    emit_finding() → FindingsOrchestrator contract if the constructor signature
    changes in a way that drops findings_orch or session_orch.

  Test assertions:
    1. OutputChannel still exposes emit_finding() (Seam 8 contract).
    2. emit_stage() exists and is callable.
    3. emit_stage() is a no-op when branch_writer=None (default).
    4. emit_stage() routes to branch_writer.transition() when wired.
"""
from __future__ import annotations

import asyncio


def test_emit_finding_still_exists():
    """emit_finding must exist on OutputChannel — Seam 8 contract.

    Adding emit_stage must not remove or rename emit_finding.
    """
    from apps.conductor.engines.base import OutputChannel
    assert hasattr(OutputChannel, "emit_finding"), (
        "OutputChannel.emit_finding missing. Seam 8 contract broken — "
        "engines would fail to push findings to FindingsOrchestrator."
    )


def test_emit_stage_exists():
    """emit_stage must exist on OutputChannel for V2 exploitation engines."""
    from apps.conductor.engines.base import OutputChannel
    assert hasattr(OutputChannel, "emit_stage"), (
        "OutputChannel.emit_stage missing. V2 exploitation engines cannot "
        "update branch state without this method."
    )


def test_emit_stage_noop_when_no_branch_writer():
    """emit_stage must be a no-op when branch_writer=None (default).

    All V1 phase engines construct OutputChannel without branch_writer.
    A crash or exception from emit_stage() would break V1 phase operation.
    """

    class _FakeFindingsOrch:
        async def ingest(self, finding, engine_id): pass

    class _FakeSessionOrch:
        def record_request(self, target): pass
        def record_response(self, target, status_code): pass

    from apps.conductor.engines.base import OutputChannel

    ch = OutputChannel(
        investigation_id="inv_test",
        engine_id="test_engine",
        findings_orch=_FakeFindingsOrch(),
        session_orch=_FakeSessionOrch(),
        branch_writer=None,
    )
    # Must not raise
    asyncio.run(ch.emit_stage("exb_abc123456789", "running"))


def test_emit_stage_routes_to_branch_writer():
    """emit_stage must call branch_writer.transition() when one is wired."""

    class _FakeFindingsOrch:
        async def ingest(self, finding, engine_id): pass

    class _FakeSessionOrch:
        def record_request(self, target): pass
        def record_response(self, target, status_code): pass

    class _FakeBranchWriter:
        def __init__(self):
            self.calls = []
        async def transition(self, branch_id, state, payload=None):
            self.calls.append((branch_id, state, payload))

    from apps.conductor.engines.base import OutputChannel

    writer = _FakeBranchWriter()
    ch = OutputChannel(
        investigation_id="inv_test",
        engine_id="test_engine",
        findings_orch=_FakeFindingsOrch(),
        session_orch=_FakeSessionOrch(),
        branch_writer=writer,
    )
    asyncio.run(ch.emit_stage("exb_abc123456789", "running", {"probe": "sqli"}))
    assert len(writer.calls) == 1
    assert writer.calls[0] == ("exb_abc123456789", "running", {"probe": "sqli"})


def test_output_channel_constructor_still_accepts_four_positional_args():
    """OutputChannel constructor must still work with 4 positional args (no branch_writer).

    All existing engine tests and ExecutionOrchestrator instantiate with 4 args.
    If branch_writer becomes required, all call sites break silently.
    """
    import inspect
    from apps.conductor.engines.base import OutputChannel

    sig = inspect.signature(OutputChannel.__init__)
    params = list(sig.parameters.values())
    # self + 4 required + branch_writer (optional) = 6 total
    required = [p for p in params if p.name != "self" and p.default is inspect.Parameter.empty]
    assert len(required) == 4, (
        f"OutputChannel.__init__ has {len(required)} required params (excluding self), "
        "expected 4 (investigation_id, engine_id, findings_orch, session_orch). "
        "branch_writer must remain optional to avoid breaking V1 call sites."
    )
