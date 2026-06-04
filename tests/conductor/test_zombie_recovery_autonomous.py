"""Phase 6 — Synthetic recovery tests for autonomous_status and orchestration.db.

A1.  recover_zombie_autonomous_status exists and is a coroutine.
A2.  Source queries exploitation_branches WHERE branch_id LIKE 'state_%'.
A3.  Source sets autonomous_status to a terminal value (not 'running').
A4.  Source preserves other JSON fields (parse/mutate/re-serialize, not overwrite).
A5.  app.py lifespan wires all four recovery calls.
A6.  (aiosqlite) Stuck autonomous_status='running' → recovered; other JSON preserved.
A7.  (aiosqlite) Idempotency: second call recovers 0 rows.

O1.  recover_zombie_orchestration_status exists and is a coroutine.
O2.  Source queries investigations WHERE state IN running variants.
O3.  Source queries phase_state WHERE status='running'.
O4.  (sqlite3) investigations stuck RECON_RUNNING → FAILED.
O5.  (sqlite3) phase_state stuck 'running' → 'failed'.
O6.  (sqlite3) Absent orchestration.db → returns (0, 0) cleanly without error.
O7.  (sqlite3) Idempotency: second call recovers 0 rows.
"""
from __future__ import annotations

import importlib
import inspect
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# A1–A5: Source analysis + wiring checks (no aiosqlite needed)
# ─────────────────────────────────────────────────────────────────────────────

def test_recover_zombie_autonomous_status_is_coroutine():
    """A1: function exists and is a coroutine."""
    from apps.conductor.exploitation.zombie_recovery import recover_zombie_autonomous_status
    assert inspect.iscoroutinefunction(recover_zombie_autonomous_status)


def test_autonomous_recovery_queries_state_rows():
    """A2: source queries exploitation_branches WHERE branch_id LIKE 'state_%'."""
    from apps.conductor.exploitation import zombie_recovery as _m
    src = inspect.getsource(_m._recover_autonomous)
    assert "exploitation_branches" in src
    assert "state_%" in src or "LIKE" in src


def test_autonomous_recovery_uses_terminal_status():
    """A3: source sets autonomous_status to a terminal value (not 'running')."""
    from apps.conductor.exploitation import zombie_recovery as _m
    src = inspect.getsource(_m)
    # The recovered status constant must not be 'running'
    assert "_AUTO_RECOVERED_STATUS" in src
    assert _m._AUTO_RECOVERED_STATUS != "running", (
        "recovered status must be a terminal value, not 'running'"
    )


def test_autonomous_recovery_preserves_other_fields():
    """A4: source mutates only autonomous_status (parse/mutate/re-serialize pattern)."""
    from apps.conductor.exploitation import zombie_recovery as _m
    src = inspect.getsource(_m._recover_autonomous)
    # Must parse JSON, mutate, and re-serialize — not blindly overwrite the whole column
    assert "json.loads" in src or "json.dumps" in src
    assert "autonomous_status" in src
    # Must not replace the entire artifact with just the status field
    assert "json.dumps(data)" in src


def test_all_four_recovery_calls_in_lifespan():
    """A5: app.py lifespan wires all four recovery functions."""
    src = (Path(__file__).resolve().parents[2] / "core" / "api" / "app.py").read_text()
    assert "recover_zombie_branches" in src
    assert "recover_zombie_scans" in src
    assert "recover_zombie_autonomous_status" in src
    assert "recover_zombie_orchestration_status" in src


# ─────────────────────────────────────────────────────────────────────────────
# A6–A7: Integration tests for autonomous recovery (aiosqlite required)
# ─────────────────────────────────────────────────────────────────────────────

_HAS_AIOSQLITE = importlib.util.find_spec("aiosqlite") is not None

_BRANCHES_TABLE = """
    CREATE TABLE IF NOT EXISTS exploitation_branches (
        branch_id        TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        finding_id       TEXT,
        engine_id        TEXT,
        technique_class  TEXT,
        operator_params  TEXT DEFAULT '{}',
        state            TEXT NOT NULL DEFAULT 'pending',
        artifact         TEXT,
        artifact_type    TEXT,
        exhaustion_record TEXT,
        stage_log        TEXT DEFAULT '[]',
        created_at       TEXT NOT NULL,
        updated_at       TEXT NOT NULL
    )
"""

_SAMPLE_ARTIFACT = {
    "investigation_id":    "inv-auto-001",
    "target":              "http://target",
    "objective":           "get credentials",
    "credentials":         {"username": "wiener", "password": "peter"},
    "session":             None,
    "endpoints":           ["/api/login"],
    "tokens":              {},
    "attempt_tree":        [],
    "parsed_objective":    None,
    "ranked_lists":        {},
    "pending_work_orders": {},
    "captured_session":    None,
    "autonomous_stop_requested": False,
    "autonomous_status":   "running",   # ← stuck value to recover
    "autonomous_run_log":  [{"attempt": 1, "primitive_id": "cred_brute"}],
    "agent_state":         {"facts": ["login_form_detected"]},
}


@pytest.mark.skipif(not _HAS_AIOSQLITE, reason="aiosqlite not installed on host")
@pytest.mark.asyncio
async def test_stuck_autonomous_status_recovered(tmp_path, monkeypatch):
    """A6: stuck autonomous_status='running' → recovered; all other JSON fields preserved."""
    import aiosqlite
    import json
    from datetime import datetime, timezone

    db_path = tmp_path / "test.db"
    now_iso = datetime.now(timezone.utc).isoformat()

    async with aiosqlite.connect(str(db_path)) as db:
        db.row_factory = aiosqlite.Row
        await db.execute(_BRANCHES_TABLE)
        await db.execute(
            "INSERT INTO exploitation_branches "
            "(branch_id, investigation_id, finding_id, engine_id, technique_class, "
            "state, artifact, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "state_inv-auto-001",
                "inv-auto-001",
                "inv-auto-001",
                "investigation_state",
                "investigation.state",
                "succeeded",
                json.dumps(_SAMPLE_ARTIFACT),
                now_iso,
                now_iso,
            ),
        )
        await db.commit()

    @asynccontextmanager
    async def _fake_get_db(_db_path=None):
        async with aiosqlite.connect(str(db_path)) as conn:
            conn.row_factory = aiosqlite.Row
            yield conn

    monkeypatch.setattr("apps.validation.database.get_db", _fake_get_db)

    from apps.conductor.exploitation.zombie_recovery import _recover_autonomous
    recovered = await _recover_autonomous()
    assert recovered == 1, f"expected 1, got {recovered}"

    # Verify the JSON blob
    async with aiosqlite.connect(str(db_path)) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT artifact FROM exploitation_branches WHERE branch_id=?",
            ("state_inv-auto-001",),
        )
        row = await cur.fetchone()

    data = json.loads(row["artifact"])

    # autonomous_status must be the terminal recovered value, NOT 'running'
    assert data["autonomous_status"] != "running", (
        "autonomous_status must not be 'running' after recovery"
    )
    assert data["autonomous_status"] == "operator_stopped", (
        f"expected 'operator_stopped', got {data['autonomous_status']!r}"
    )

    # recovery_reason marker added
    assert data.get("recovery_reason") == "container_restart", (
        "recovery_reason must be 'container_restart'"
    )

    # ALL other fields must be preserved exactly
    for key in ("target", "objective", "credentials", "endpoints",
                "autonomous_run_log", "agent_state"):
        assert data.get(key) == _SAMPLE_ARTIFACT[key], (
            f"field {key!r} must be preserved unchanged after recovery"
        )


@pytest.mark.skipif(not _HAS_AIOSQLITE, reason="aiosqlite not installed on host")
@pytest.mark.asyncio
async def test_autonomous_recovery_idempotent(tmp_path, monkeypatch):
    """A7: running recovery twice → second call recovers 0 rows."""
    import aiosqlite
    import json
    from datetime import datetime, timezone

    db_path = tmp_path / "test.db"
    now_iso = datetime.now(timezone.utc).isoformat()
    artifact = {**_SAMPLE_ARTIFACT, "investigation_id": "inv-auto-002",
                "autonomous_status": "running"}

    async with aiosqlite.connect(str(db_path)) as db:
        db.row_factory = aiosqlite.Row
        await db.execute(_BRANCHES_TABLE)
        await db.execute(
            "INSERT INTO exploitation_branches "
            "(branch_id, investigation_id, finding_id, engine_id, technique_class, "
            "state, artifact, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            ("state_inv-auto-002", "inv-auto-002", "inv-auto-002",
             "investigation_state", "investigation.state", "succeeded",
             json.dumps(artifact), now_iso, now_iso),
        )
        await db.commit()

    @asynccontextmanager
    async def _fake_get_db(_db_path=None):
        async with aiosqlite.connect(str(db_path)) as conn:
            conn.row_factory = aiosqlite.Row
            yield conn

    monkeypatch.setattr("apps.validation.database.get_db", _fake_get_db)

    from apps.conductor.exploitation.zombie_recovery import _recover_autonomous
    first  = await _recover_autonomous()
    second = await _recover_autonomous()
    assert first == 1,  f"first run: expected 1, got {first}"
    assert second == 0, f"second run: expected 0 (idempotent), got {second}"


# ─────────────────────────────────────────────────────────────────────────────
# O1–O3: Source analysis for orchestration recovery (always runs)
# ─────────────────────────────────────────────────────────────────────────────

def test_recover_zombie_orchestration_status_is_coroutine():
    """O1: function exists and is a coroutine."""
    from apps.conductor.exploitation.zombie_recovery import recover_zombie_orchestration_status
    assert inspect.iscoroutinefunction(recover_zombie_orchestration_status)


def test_orchestration_recovery_queries_investigations():
    """O2: source queries investigations WHERE state IN running variants."""
    from apps.conductor.exploitation import zombie_recovery as _m
    src = inspect.getsource(_m._do_recover_orchestration)
    assert "investigations" in src
    assert "RECON_RUNNING" in src or "_ORCH_INV_RUNNING_STATES" in src


def test_orchestration_recovery_queries_phase_state():
    """O3: source queries phase_state WHERE status='running'."""
    from apps.conductor.exploitation import zombie_recovery as _m
    src = inspect.getsource(_m._do_recover_orchestration)
    assert "phase_state" in src
    assert "'running'" in src


# ─────────────────────────────────────────────────────────────────────────────
# O4–O7: Integration tests for orchestration recovery (sync sqlite3, no skipif)
# ─────────────────────────────────────────────────────────────────────────────

_ORCH_SCHEMA = """
    CREATE TABLE IF NOT EXISTS investigations (
        id TEXT PRIMARY KEY, target TEXT NOT NULL,
        config_json TEXT NOT NULL DEFAULT '{}',
        state TEXT NOT NULL DEFAULT 'CREATED',
        created_at REAL NOT NULL, updated_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS phase_state (
        investigation_id TEXT NOT NULL, phase TEXT NOT NULL,
        status TEXT NOT NULL, started_at REAL NOT NULL, completed_at REAL,
        PRIMARY KEY (investigation_id, phase)
    );
"""


def _make_test_orch_db(db_path: Path) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.executescript(_ORCH_SCHEMA)
    import time
    now = time.time()
    conn.execute(
        "INSERT INTO investigations (id, target, state, created_at, updated_at) VALUES (?,?,?,?,?)",
        ("inv-orch-001", "http://target", "RECON_RUNNING", now, now),
    )
    conn.execute(
        "INSERT INTO investigations (id, target, state, created_at, updated_at) VALUES (?,?,?,?,?)",
        ("inv-orch-002", "http://target2", "ENUM_RUNNING", now, now),
    )
    conn.execute(
        "INSERT INTO phase_state (investigation_id, phase, status, started_at) VALUES (?,?,?,?)",
        ("inv-orch-001", "recon", "running", now),
    )
    conn.execute(
        "INSERT INTO phase_state (investigation_id, phase, status, started_at) VALUES (?,?,?,?)",
        ("inv-orch-002", "enumeration", "running", now),
    )
    conn.commit()
    conn.close()


def test_orchestration_investigations_recovered(tmp_path):
    """O4: stuck RECON_RUNNING / ENUM_RUNNING → FAILED in investigations."""
    db_path = tmp_path / "orchestration.db"
    _make_test_orch_db(db_path)

    from apps.conductor.exploitation.zombie_recovery import _do_recover_orchestration
    inv_rec, phase_rec = _do_recover_orchestration(db_path=str(db_path))

    assert inv_rec == 2, f"expected 2 investigation recoveries, got {inv_rec}"
    assert phase_rec == 2, f"expected 2 phase_state recoveries, got {phase_rec}"

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT state FROM investigations").fetchall()
    conn.close()
    for row in rows:
        assert row["state"] == "FAILED", f"expected FAILED, got {row['state']!r}"


def test_orchestration_phase_state_recovered(tmp_path):
    """O5: stuck phase_state status='running' → 'failed'."""
    db_path = tmp_path / "orchestration.db"
    _make_test_orch_db(db_path)

    from apps.conductor.exploitation.zombie_recovery import _do_recover_orchestration
    _do_recover_orchestration(db_path=str(db_path))

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT status FROM phase_state").fetchall()
    conn.close()
    for row in rows:
        assert row["status"] == "failed", f"expected 'failed', got {row['status']!r}"


def test_orchestration_absent_db_returns_zero(tmp_path):
    """O6: non-existent orchestration.db → returns (0, 0) without error."""
    absent = tmp_path / "no_such_orchestration.db"
    assert not absent.exists()

    from apps.conductor.exploitation.zombie_recovery import _do_recover_orchestration
    result = _do_recover_orchestration(db_path=str(absent))
    assert result == (0, 0), f"expected (0, 0), got {result}"


def test_orchestration_recovery_idempotent(tmp_path):
    """O7: second call recovers 0 rows (idempotent)."""
    db_path = tmp_path / "orchestration.db"
    _make_test_orch_db(db_path)

    from apps.conductor.exploitation.zombie_recovery import _do_recover_orchestration
    first  = _do_recover_orchestration(db_path=str(db_path))
    second = _do_recover_orchestration(db_path=str(db_path))

    assert first[0] > 0 or first[1] > 0, "first run should recover something"
    assert second == (0, 0), (
        f"second run must return (0, 0) — idempotency violated, got {second}"
    )
