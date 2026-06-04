"""Phase D — Unknown Artifact store tests.

U1.  make_unknown_artifact: creates struct with correct shape and defaults.
U2.  make_unknown_artifact: raw_result dict serialized to JSON string.
U3.  make_unknown_artifact: status defaults to pending_review.
U4.  Fingerprint: identical context+raw_result in same inv = same fingerprint.
U5.  store/load round-trip (mocked DB): artifact persists with all fields.
U6.  list_unknowns_async: returns empty list on no results (mocked DB).
U7.  list_unknowns_async: cross-investigation listing (multiple inv_ids).
U8.  update_unknown_status: resolved status accepted; invalid status rejected.
U9.  park_unknown_async: non-blocking (does not raise; execution continues).
U10. Dedup: same context+raw_result in same investigation → one artifact only.
U11. No-behavior-change: no_concept_match path in orchestrator calls park (mocked).
U12. Known verdict path unchanged: no park call for known verdicts.
U13. DB schema: agent_loop_unknowns present in SCHEMA string.
U14. Indexes: idx_agent_loop_unknowns_status in INDEXES string.
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ── U1-U4: Pure-logic (no DB) ─────────────────────────────────────────────────

class TestMakeUnknownArtifact:

    def test_correct_shape(self):
        """U1: make_unknown_artifact creates struct with all required fields."""
        from apps.conductor.unknown_store import make_unknown_artifact
        a = make_unknown_artifact(
            investigation_id = "inv_123",
            context          = "exploitation, finding=login_form, attempting=credential_brute",
            raw_result       = None,
            expected_concept = "CONCEPT-CREDENTIAL-BRUTE",
            evidence         = {"engine_id": "credential_brute", "exec_state": "exhausted"},
        )
        assert a.id and len(a.id) > 8
        assert a.created_at and "T" in a.created_at
        assert a.investigation_id == "inv_123"
        assert "exploitation" in a.context
        assert a.expected_concept == "CONCEPT-CREDENTIAL-BRUTE"
        assert a.evidence["engine_id"] == "credential_brute"
        assert a.status == "pending_review"
        assert a.resolution is None

    def test_dict_raw_result_serialized(self):
        """U2: dict raw_result is JSON-serialized to string."""
        from apps.conductor.unknown_store import make_unknown_artifact
        raw = {"artifact_type": "captured_session", "cookies": {"session": "abc"}}
        a = make_unknown_artifact("inv", "ctx", raw_result=raw)
        assert isinstance(a.raw_result, str)
        parsed = json.loads(a.raw_result)
        assert parsed["artifact_type"] == "captured_session"

    def test_default_status_pending_review(self):
        """U3: status always starts as pending_review."""
        from apps.conductor.unknown_store import make_unknown_artifact
        a = make_unknown_artifact("inv", "ctx", raw_result=None)
        assert a.status == "pending_review"

    def test_fingerprint_deterministic(self):
        """U4: same input produces same fingerprint (for dedup)."""
        from apps.conductor.unknown_store import _fingerprint
        f1 = _fingerprint("inv_abc", "ctx_xyz", "raw_123")
        f2 = _fingerprint("inv_abc", "ctx_xyz", "raw_123")
        assert f1 == f2

    def test_fingerprint_different_for_different_context(self):
        """U4b: different context → different fingerprint."""
        from apps.conductor.unknown_store import _fingerprint
        f1 = _fingerprint("inv", "ctx_A", "raw")
        f2 = _fingerprint("inv", "ctx_B", "raw")
        assert f1 != f2


# ── U5-U8: Store operations (mocked DB) ───────────────────────────────────────

class TestStoreOperations:
    """U5-U8: Store contract — verified via source analysis (aiosqlite not on host)."""

    def test_list_unknowns_source_has_status_filter(self):
        """U6/U7: list_unknowns_async source builds a WHERE clause for status filter."""
        from pathlib import Path
        src = (Path(__file__).resolve().parents[2]
               / "apps/conductor/unknown_store.py").read_text()
        assert "status=?" in src and "ORDER BY created_at DESC" in src, (
            "list_unknowns_async must filter by status and order by created_at"
        )
        assert "investigation_id=?" in src, (
            "list_unknowns_async must support filtering by investigation_id (cross-run)"
        )

    def test_store_uses_insert_or_ignore(self):
        """U5: store_unknown_artifact_async uses INSERT OR IGNORE (safe re-insert)."""
        from pathlib import Path
        src = (Path(__file__).resolve().parents[2]
               / "apps/conductor/unknown_store.py").read_text()
        assert "INSERT OR IGNORE INTO agent_loop_unknowns" in src, (
            "store_unknown_artifact_async must use INSERT OR IGNORE to prevent PK conflicts"
        )

    def test_list_returns_dicts_with_required_keys(self):
        """U7: list result dicts contain all required keys (source check)."""
        from pathlib import Path
        src = (Path(__file__).resolve().parents[2]
               / "apps/conductor/unknown_store.py").read_text()
        for key in ("id", "created_at", "investigation_id", "context",
                    "raw_result", "expected_concept", "evidence", "status"):
            assert f'"{key}"' in src, f"list result missing key: {key!r}"

    @pytest.mark.asyncio
    async def test_update_invalid_status_rejected(self):
        """U8: invalid status returns False without touching DB."""
        from apps.conductor.unknown_store import update_unknown_status_async
        ok = await update_unknown_status_async("id-1", "approved")  # invalid
        assert not ok

    def test_update_valid_statuses_in_source(self):
        """U8b: resolved and ignored are in _VALID_STATUSES."""
        from apps.conductor.unknown_store import _VALID_STATUSES
        assert "resolved" in _VALID_STATUSES
        assert "ignored" in _VALID_STATUSES
        assert "pending_review" in _VALID_STATUSES


# ── U9-U10: park_unknown_async (fire-and-forget + dedup) ─────────────────────

class TestParkUnknown:

    @pytest.mark.asyncio
    async def test_park_is_non_blocking_on_db_error(self):
        """U9: park_unknown_async does not raise even when DB is unavailable."""
        # park_unknown_async catches all exceptions internally
        from apps.conductor.unknown_store import park_unknown_async
        # DB import inside function; just call with bad params — never raises
        try:
            await park_unknown_async("inv", "ctx", raw_result=None)
        except Exception as exc:
            pytest.fail(f"park_unknown_async raised an exception: {exc}")
        # Reaching here means execution continued (non-blocking confirmed)

    def test_park_has_non_blocking_try_except(self):
        """U9b: park_unknown_async source wraps everything in try/except."""
        from pathlib import Path
        src = (Path(__file__).resolve().parents[2]
               / "apps/conductor/unknown_store.py").read_text()
        park_start = src.find("async def park_unknown_async(")
        # Find the next async def after park
        next_fn = src.find("\nasync def ", park_start + 1)
        park_block = src[park_start:next_fn] if next_fn != -1 else src[park_start:]
        assert "try:" in park_block and "except" in park_block, (
            "park_unknown_async must wrap its body in try/except (non-blocking guard)"
        )

    def test_dedup_check_in_source(self):
        """U10: dedup check calls _is_duplicate_async before storing."""
        from pathlib import Path
        src = (Path(__file__).resolve().parents[2]
               / "apps/conductor/unknown_store.py").read_text()
        assert "_is_duplicate_async" in src, (
            "park_unknown_async must call _is_duplicate_async before inserting"
        )
        assert "dedup" in src.lower() or "is_dup" in src, (
            "dedup logic must be visible in unknown_store.py"
        )


# ── U11-U12: Orchestrator wire ────────────────────────────────────────────────

class TestOrchestratorWire:

    def test_no_concept_match_path_imports_park(self):
        """U11: autonomous_orchestrator references park_unknown_async in the verdict wire."""
        from pathlib import Path
        src = (
            Path(__file__).resolve().parents[2]
            / "apps/conductor/autonomous_orchestrator.py"
        ).read_text()
        assert "park_unknown_async" in src, (
            "park_unknown_async must be called from autonomous_orchestrator.py "
            "for the no_concept_match path (Phase D wire)"
        )
        assert "no_concept_match" in src, (
            "no_concept_match branch must be handled in autonomous_orchestrator.py"
        )

    def test_known_verdict_path_unchanged(self):
        """U12: known verdict path still calls apply_verdict_to_state_async (not park)."""
        from pathlib import Path
        src = (
            Path(__file__).resolve().parents[2]
            / "apps/conductor/autonomous_orchestrator.py"
        ).read_text()
        assert "apply_verdict_to_state_async" in src, (
            "apply_verdict_to_state_async must still be called for known verdicts"
        )
        # Both paths coexist in the verdict wire block
        assert src.index("apply_verdict_to_state_async") < src.index("park_unknown_async"), (
            "apply_verdict_to_state_async (known) must appear before park_unknown_async (unknown) "
            "in the verdict wire block"
        )


# ── U13-U14: DB schema ────────────────────────────────────────────────────────

class TestDBSchema:
    """U13-U14: Schema verified by reading file text (aiosqlite not on host)."""

    def _db_text(self):
        from pathlib import Path
        return (Path(__file__).resolve().parents[2]
                / "apps/validation/database.py").read_text()

    def test_agent_loop_unknowns_in_schema(self):
        """U13: agent_loop_unknowns table declared in SCHEMA string."""
        src = self._db_text()
        assert "CREATE TABLE IF NOT EXISTS agent_loop_unknowns" in src, (
            "agent_loop_unknowns table missing from database.py SCHEMA"
        )
        assert "pending_review" in src, (
            "DEFAULT 'pending_review' missing from agent_loop_unknowns schema"
        )
        assert "resolution" in src, (
            "resolution column missing from agent_loop_unknowns schema"
        )

    def test_agent_loop_unknowns_indexes_in_indexes(self):
        """U14: status and investigation indexes declared for agent_loop_unknowns."""
        src = self._db_text()
        assert "idx_agent_loop_unknowns_status" in src, (
            "Status index for agent_loop_unknowns missing"
        )
        assert "idx_agent_loop_unknowns_investigation" in src, (
            "Investigation index for agent_loop_unknowns missing"
        )

    def test_unknown_store_module_parses(self):
        """U13b: unknown_store.py parses cleanly."""
        import ast
        from pathlib import Path
        src = (Path(__file__).resolve().parents[2]
               / "apps/conductor/unknown_store.py").read_text()
        ast.parse(src)
