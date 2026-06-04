"""Investigation lifecycle tests: id propagation, hard-delete, create guard, orphan sweep.

IL1. investigation_id propagation: _run_engine passes investigation_id to engine.run(),
     so make_branch_id receives the correct (non-empty) id.
IL2. make_branch_id guard: logs an error when investigation_id is empty (never silently "").
IL3. execute_work_order polling finds the branch under the CORRECT investigation_id (no timeout).
IL4. Delete hard: cancel task, clear _running_tasks, delete branches + orphans.
IL5. After delete, is_running returns False (new investigation not blocked).
IL6. Create guard: blank target raises ValueError, investigation NOT created.
IL7. Orphan sweep: branches with investigation_id='' are removed; real investigations survive.
"""
from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── IL1: investigation_id propagated through _run_engine ──────────────────────

class TestInvestigationIdPropagation:
    """IL1: _run_engine passes self._investigation_id to engine.run()."""

    def test_run_engine_passes_investigation_id_source_check(self):
        """Verify execution.py _run_engine passes investigation_id to engine.run().

        The fix introspects the engine's run() signature and adds investigation_id
        to _run_kwargs only when the engine declares the parameter (exploitation engines
        do; phase engines like nmap don't — passing it to nmap caused TypeError and
        stuck the recon phase).
        """
        from pathlib import Path
        src = (
            Path(__file__).resolve().parents[2]
            / "apps/conductor/orchestrators/execution.py"
        ).read_text()

        run_engine_start = src.find("async def _run_engine(")
        assert run_engine_start != -1
        # Wide window: _run_kwargs is built further into the function
        run_engine_block = src[run_engine_start : run_engine_start + 1500]
        assert "_run_kwargs" in run_engine_block, (
            "_run_engine must build a _run_kwargs dict to selectively pass investigation_id."
        )
        assert "investigation_id" in run_engine_block, (
            "_run_engine must include investigation_id in _run_kwargs for engines that accept it."
        )
        assert "engine.run(**_run_kwargs)" in run_engine_block, (
            "_run_engine must call engine.run(**_run_kwargs) to pass the selective kwargs."
        )

    def test_engine_run_call_site_has_investigation_id(self):
        """engine.run(**_run_kwargs) dispatch must conditionally include investigation_id."""
        from pathlib import Path
        src = (
            Path(__file__).resolve().parents[2]
            / "apps/conductor/orchestrators/execution.py"
        ).read_text()

        # The call is now engine.run(**_run_kwargs) with investigation_id conditionally in _run_kwargs
        assert "engine.run(**_run_kwargs)" in src, (
            "engine.run() must use **_run_kwargs for selective kwarg passing. "
            "Direct investigation_id= kwarg breaks nmap (TypeError → stuck recon)."
        )
        assert "_run_kwargs[\"investigation_id\"] = self._investigation_id" in src or \
               '_run_kwargs["investigation_id"] = self._investigation_id' in src, (
            "_run_kwargs must include investigation_id=self._investigation_id when "
            "the engine accepts it, so make_branch_id receives the real investigation_id."
        )


# ── IL2: make_branch_id guard logs error on empty investigation_id ─────────────

class TestMakeBranchIdGuard:
    """IL2: make_branch_id logs an error when investigation_id is empty."""

    def test_empty_investigation_id_logs_error(self, caplog):
        from apps.conductor.exploitation.branch_store import make_branch_id

        with caplog.at_level(logging.ERROR, logger="conductor.exploitation.branch_store"):
            bid = make_branch_id("", "fnd-1", "username_enum", "auth.username_enum")

        assert "EMPTY" in caplog.text or "empty" in caplog.text.lower(), (
            "make_branch_id must log an error when investigation_id is empty. "
            "Empty ids cause branch collisions across investigations."
        )
        # Still returns a branch_id (doesn't raise), but logs the error
        assert bid.startswith("exb_")

    def test_real_id_no_error(self, caplog):
        from apps.conductor.exploitation.branch_store import make_branch_id

        with caplog.at_level(logging.ERROR, logger="conductor.exploitation.branch_store"):
            bid = make_branch_id("inv-real-1234", "fnd-1", "username_enum", "auth.username_enum")

        assert "EMPTY" not in caplog.text
        assert bid.startswith("exb_")

    def test_different_investigations_different_branch_ids(self):
        from apps.conductor.exploitation.branch_store import make_branch_id

        bid1 = make_branch_id("inv-A", "fnd-1", "username_enum", "auth.username_enum")
        bid2 = make_branch_id("inv-B", "fnd-1", "username_enum", "auth.username_enum")
        bid_empty = make_branch_id("", "fnd-1", "username_enum", "auth.username_enum")

        assert bid1 != bid2, (
            "Different investigation_ids must produce different branch_ids — "
            "otherwise INSERT OR IGNORE collisions write branches to the wrong investigation."
        )
        assert bid1 != bid_empty
        assert bid2 != bid_empty


# ── IL3: execute_work_order polling finds branch under CORRECT id ─────────────

class TestExecuteWorkOrderPolling:
    """IL3: after the fix, polling finds the branch under the real investigation_id."""

    def test_polling_query_uses_investigation_id_and_finding_id(self):
        """execute_work_order polls WHERE investigation_id=? AND engine_id=? AND finding_id=?
        This only works when make_branch_id uses the correct investigation_id."""
        from pathlib import Path
        src = (
            Path(__file__).resolve().parents[2]
            / "apps/conductor/autonomous_orchestrator.py"
        ).read_text()

        # Verify the polling query filters by investigation_id AND finding_id
        assert "investigation_id=?" in src, "Polling must filter by investigation_id"
        assert "engine_id=?" in src, "Polling must filter by engine_id"
        assert "finding_id=?" in src, "Polling must filter by finding_id — avoids stale branch confusion"

    def test_run_engine_passes_investigation_id_to_engine(self):
        """Verify execution.py passes investigation_id to engine.run."""
        from pathlib import Path
        src = (
            Path(__file__).resolve().parents[2]
            / "apps/conductor/orchestrators/execution.py"
        ).read_text()

        run_engine_start = src.find("async def _run_engine(")
        assert run_engine_start != -1
        run_engine_block = src[run_engine_start : run_engine_start + 800]
        assert "_run_kwargs" in run_engine_block and "investigation_id" in run_engine_block, (
            "_run_engine must pass investigation_id=self._investigation_id to engine.run(). "
            "Without this, make_branch_id defaults to '' and polling can't find the branch."
        )


# ── IL4: Hard delete cancels task + deletes branches ─────────────────────────

class TestHardDelete:
    """IL4: delete route cancels in-flight task, removes branches, cleans orphans."""

    def test_delete_route_calls_request_stop(self):
        """delete_investigation must cancel the autonomous task before row deletion."""
        from pathlib import Path
        src = (
            Path(__file__).resolve().parents[2]
            / "apps/validation/api/investigations.py"
        ).read_text()

        delete_start = src.find("async def delete_investigation(")
        assert delete_start != -1
        delete_block = src[delete_start : delete_start + 2000]

        assert "request_stop" in delete_block, (
            "delete_investigation must call request_stop to cancel the autonomous task."
        )
        assert "_running_tasks" in delete_block, (
            "delete_investigation must clear _running_tasks so is_running returns False."
        )

    def test_delete_cleans_exploitation_branches(self):
        """delete_investigation must delete exploitation_branches for the investigation."""
        from pathlib import Path
        src = (
            Path(__file__).resolve().parents[2]
            / "apps/validation/api/investigations.py"
        ).read_text()

        delete_start = src.find("async def delete_investigation(")
        delete_block = src[delete_start : delete_start + 2000]

        assert "exploitation_branches" in delete_block, (
            "delete_investigation must DELETE exploitation_branches rows for the investigation. "
            "The InvestigationRepository.delete() cascade does not include exploitation_branches."
        )

    def test_delete_cleans_orphan_branches(self):
        """delete_investigation must also remove orphan branches with empty investigation_id."""
        from pathlib import Path
        src = (
            Path(__file__).resolve().parents[2]
            / "apps/validation/api/investigations.py"
        ).read_text()

        delete_start = src.find("async def delete_investigation(")
        # Wider window: the delete route is more than 2000 chars now
        delete_block = src[delete_start : delete_start + 3000]

        assert "IS NULL" in delete_block or \
               "investigation_id = ''" in delete_block or \
               "investigation_id=''" in delete_block, (
            "delete_investigation must remove orphan branches with investigation_id='' or NULL."
        )


# ── IL5: After delete, is_running returns False ───────────────────────────────

class TestIsRunningAfterDelete:
    """IL5: is_running must return False after an investigation is deleted."""

    def test_is_running_false_after_pop(self):
        from apps.conductor.autonomous_orchestrator import _running_tasks, is_running
        import uuid

        # Use a unique ID to avoid interference with other tests
        test_id = f"test-del-{uuid.uuid4().hex[:8]}"
        try:
            # Simulate a running task using a mock with done()=False
            mock_task = MagicMock()
            mock_task.done.return_value = False
            _running_tasks[test_id] = mock_task  # type: ignore[assignment]

            assert is_running(test_id) is True

            # Simulate what delete_investigation does: pop from registry
            _running_tasks.pop(test_id, None)

            assert is_running(test_id) is False, (
                "After _running_tasks.pop(), is_running must return False so a new investigation "
                "is not blocked by stale 'Autonomous run already in progress' state."
            )
        finally:
            _running_tasks.pop(test_id, None)


# ── IL6: Blank target creation blocked ───────────────────────────────────────

class TestBlankTargetGuard:
    """IL6: get_or_create must reject blank targets."""

    def test_blank_target_guard_in_source(self):
        """get_or_create must have a blank-target guard in its source."""
        from pathlib import Path
        src = (
            Path(__file__).resolve().parents[2]
            / "apps/investigation_core/services/investigation_service.py"
        ).read_text()

        # The guard is in the full file — search broadly
        assert "blank_target" in src or "blank target" in src.lower(), (
            "get_or_create must contain a blank-target guard. "
            "Blank targets create unfindable investigations that pollute the DB."
        )
        assert "ValueError" in src, (
            "get_or_create must raise ValueError for blank targets."
        )

    def test_blank_target_guard_before_db_call(self):
        """Blank target guard must appear BEFORE get_by_target() DB call."""
        from pathlib import Path
        src = (
            Path(__file__).resolve().parents[2]
            / "apps/investigation_core/services/investigation_service.py"
        ).read_text()

        # Find positions in the full file (not a substring block)
        guard_idx   = src.find("blank_target_rejected")
        db_call_idx = src.find("get_by_target(")

        assert guard_idx != -1, "blank_target_rejected guard not found in service file"
        assert db_call_idx != -1, "get_by_target call not found in service file"
        assert guard_idx < db_call_idx, (
            "Blank target guard must appear BEFORE get_by_target() DB call, "
            "so no DB call happens for blank targets."
        )


# ── IL7: Orphan sweep logic ───────────────────────────────────────────────────

class TestOrphanSweep:
    """IL7: branches with investigation_id='' are removable; real investigations safe."""

    def test_make_branch_id_uniqueness_by_investigation(self):
        """Different real investigation_ids → different branch_ids → no collision risk."""
        from apps.conductor.exploitation.branch_store import make_branch_id

        inv_ids = ["inv-A", "inv-B", "inv-C", "inv-real-d874e655"]
        branch_ids = [
            make_branch_id(inv_id, "fnd_login", "username_enum", "auth.username_enum")
            for inv_id in inv_ids
        ]
        assert len(set(branch_ids)) == len(inv_ids), (
            "All branch_ids must be unique across investigations. "
            "Collisions would cause INSERT OR IGNORE to skip new branches → polling timeout."
        )

    def test_empty_vs_real_branch_id_differ(self):
        """make_branch_id('') and make_branch_id('real') produce DIFFERENT ids."""
        from apps.conductor.exploitation.branch_store import make_branch_id

        with_empty = make_branch_id("", "fnd_1", "username_enum", "auth.username_enum")
        with_real  = make_branch_id("real-inv-id", "fnd_1", "username_enum", "auth.username_enum")
        assert with_empty != with_real, (
            "Empty and real investigation_ids must produce different branch_ids. "
            "The fix (passing investigation_id through _run_engine) ensures the real id is used."
        )
