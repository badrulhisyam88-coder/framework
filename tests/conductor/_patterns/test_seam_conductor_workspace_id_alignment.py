"""Pattern 22 — Conductor _active keyed by workspace investigation_id.

Invariant: when runtime.py calls conductor.start_investigation() on behalf of
a workspace investigation, the returned investigation_id (and the key in
conductor._active) must equal run.investigation_id (the workspace UUID).

Root cause of ghost-execute 409:
  conductor.start_investigation() generated its own UUID (str(uuid4())) and
  keyed _active by that UUID. runtime.py never passed run.investigation_id.
  execute_suggestion called get_context(workspace_uuid) → _active.get(workspace_uuid)
  = None — unconditionally, every call, no server restart required.

Fix: conductor.start_investigation() accepts optional investigation_id parameter;
     runtime.py passes run.investigation_id.

Three tests:
  P22-A (source): conductor.start_investigation signature accepts investigation_id param
  P22-B (behaviour): when investigation_id is provided, _active is keyed by that value
  P22-C (integration): execute route called with workspace_id finds context → dispatch_engine fires
"""
from __future__ import annotations

import asyncio
import inspect

import pytest


# ── P22-A — Signature accepts investigation_id parameter ─────────────────────


def test_p22a_start_investigation_accepts_investigation_id_param():
    """conductor.start_investigation must accept an optional investigation_id
    keyword argument.

    Without this parameter, runtime.py cannot pass the workspace UUID and the
    conductor always keys _active by its own generated UUID — making
    get_context(workspace_uuid) always return None.
    """
    from apps.conductor.conductor import Conductor

    sig = inspect.signature(Conductor.start_investigation)
    assert "investigation_id" in sig.parameters, (
        "Conductor.start_investigation must accept an 'investigation_id' parameter. "
        "Without it, runtime.py cannot align the conductor _active key with the "
        "workspace investigation_id, causing get_context() to always return None."
    )
    param = sig.parameters["investigation_id"]
    assert param.default is None, (
        f"investigation_id default must be None (optional). "
        f"Got: {param.default!r}. Existing callers that pass no investigation_id "
        "must be unaffected (conductor generates its own UUID as fallback)."
    )


# ── P22-B — Behaviour: _active keyed by provided investigation_id ─────────────


def test_p22b_active_keyed_by_provided_investigation_id():
    """When investigation_id is passed to start_investigation, _active is keyed
    by that value so get_context(workspace_uuid) returns the live context.

    This is the precise invariant that get_context() relies on. If _active is
    keyed by any other value (conductor-generated UUID, None, etc.), every call
    to execute_suggestion for a V2 engine returns 409.
    """
    pytest.importorskip(
        "aiosqlite", reason="aiosqlite not available on host; runs in Docker"
    )
    import tempfile
    from pathlib import Path

    from apps.conductor.conductor import Conductor
    from apps.conductor.events.bus import EventBus

    workspace_uuid = "inv_workspace_test_00001"

    async def _run():
        with tempfile.TemporaryDirectory() as tmp:
            bus = EventBus()
            conductor = Conductor(bus=bus, db_path=Path(tmp) / "test.db")
            returned_id = await conductor.start_investigation(
                "mock://target",
                {"max_chain_depth": 0},
                investigation_id=workspace_uuid,
            )

        assert returned_id == workspace_uuid, (
            f"start_investigation returned {returned_id!r} instead of the "
            f"provided investigation_id {workspace_uuid!r}. "
            "The caller uses the return value to filter bus events; "
            "it must equal the provided ID."
        )
        ctx = conductor.get_context(workspace_uuid)
        assert ctx is not None, (
            f"get_context('{workspace_uuid}') returned None. "
            "_active must be keyed by the provided investigation_id, not a "
            "conductor-generated UUID. This is the root cause of ghost-execute 409."
        )
        assert ctx.investigation_id == workspace_uuid, (
            f"Context investigation_id {ctx.investigation_id!r} != {workspace_uuid!r}."
        )

    asyncio.run(_run())


# ── P22-C — Integration: execute route finds context via workspace_id ─────────


def test_p22c_execute_route_finds_context_via_workspace_id():
    """When _active is keyed by workspace_uuid, the execute route finds the
    conductor context and calls dispatch_engine instead of returning 409.

    This is the end-to-end invariant: the ID fix in start_investigation() and
    runtime.py must propagate to a real 200 response when the operator clicks
    Execute in the exploitation tab.
    """
    pytest.importorskip("fastapi", reason="fastapi not available on host; runs in Docker")
    import httpx
    from fastapi import FastAPI
    from unittest.mock import AsyncMock, MagicMock, patch

    from apps.investigation_workspace.api.routes import router

    workspace_uuid = "inv_p22c_workspace_test"
    finding_id = "fnd_p22c_001"

    # Conductor has the workspace UUID in _active (the post-fix invariant).
    mock_exec_orch = AsyncMock()
    mock_ctx = MagicMock()
    mock_ctx.exec_orch = mock_exec_orch
    mock_conductor = MagicMock()
    mock_conductor.get_context.return_value = mock_ctx

    # Finding whose investigation_id == workspace_uuid (route checks equality).
    mock_finding = MagicMock()
    mock_finding.id = finding_id
    mock_finding.investigation_id = workspace_uuid

    mock_inv = MagicMock()
    mock_inv.targets = ["http://target.local"]

    app = FastAPI()
    app.include_router(router)

    mock_db_cm = AsyncMock()
    mock_db_cm.__aenter__ = AsyncMock(return_value=AsyncMock())
    mock_db_cm.__aexit__ = AsyncMock(return_value=False)

    with (
        patch(
            "apps.investigation_workspace.api.routes.get_shared_conductor",
            return_value=mock_conductor,
        ),
        patch(
            "apps.investigation_workspace.api.routes.NormalizedFindingRepository"
        ) as mock_repo_cls,
        patch(
            "apps.investigation_workspace.api.routes.InvestigationService"
        ) as mock_svc_cls,
        patch(
            "apps.investigation_workspace.api.routes.get_db",
            return_value=mock_db_cm,
        ),
    ):
        mock_repo = AsyncMock()
        mock_repo.get_by_id.return_value = mock_finding
        mock_repo_cls.return_value = mock_repo

        mock_svc = AsyncMock()
        mock_svc.get_by_id.return_value = mock_inv
        mock_svc_cls.return_value = mock_svc

        async def _run():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                return await client.post(
                    f"/workspace/investigations/{workspace_uuid}"
                    f"/finding/{finding_id}/suggest/xss_reflect/execute",
                    content=b"",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

        resp = asyncio.run(_run())

    # P22-C invariant: the route must have called get_context with the workspace UUID.
    mock_conductor.get_context.assert_called_once_with(workspace_uuid), (
        f"get_context called with wrong ID. "
        f"Before the fix, conductor keyed _active by its own UUID so this "
        f"would have returned None — causing a 409 on every operator execute."
    )

    assert resp.status_code == 200, (
        f"Expected 200 when conductor context is keyed by workspace_uuid, "
        f"got {resp.status_code}. This is the ghost-execute 409 defect. "
        f"Body: {resp.text[:300]}"
    )

    mock_exec_orch.dispatch_engine.assert_called_once(), (
        "dispatch_engine must be called exactly once when context is found."
    )
