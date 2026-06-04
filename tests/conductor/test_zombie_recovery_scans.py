"""V3 — Synthetic recovery test for zombie scan_executions on container restart.

Tests:
  S1. recover_zombie_scans function exists and is a coroutine.
  S2. Source contains the correct query targeting scan_executions WHERE status='running'.
  S3. Source sets error_message='container_restart' on recovery.
  S4. recover_zombie_scans is wired in app.py lifespan alongside recover_zombie_branches.
  S5. (aiosqlite) Stuck 'running' row → recovered to 'failed' + error_message='container_restart'.
  S6. (aiosqlite) Running recovery twice → idempotent (second run: 0 rows changed).
"""
from __future__ import annotations

import importlib
import inspect
from contextlib import asynccontextmanager

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# S1 — Function existence + coroutine check
# ─────────────────────────────────────────────────────────────────────────────

def test_recover_zombie_scans_is_coroutine():
    """S1: recover_zombie_scans is importable and is a coroutine function."""
    from apps.conductor.exploitation.zombie_recovery import recover_zombie_scans
    assert inspect.iscoroutinefunction(recover_zombie_scans)


# ─────────────────────────────────────────────────────────────────────────────
# S2+S3 — Source analysis (always runs, no aiosqlite needed)
# ─────────────────────────────────────────────────────────────────────────────

def test_recovery_queries_scan_executions_running():
    """S2: _recover_scans queries scan_executions WHERE status = 'running'."""
    from apps.conductor.exploitation import zombie_recovery as _m
    src = inspect.getsource(_m._recover_scans)
    assert "scan_executions" in src
    # Must target 'running' scans
    assert "status" in src and "'running'" in src


def test_recovery_sets_container_restart_reason():
    """S3: zombie_recovery module uses 'container_restart' as the error reason."""
    from apps.conductor.exploitation import zombie_recovery as _m
    # _SCAN_NOTE is module-level; check the module source rather than function source
    src = inspect.getsource(_m)
    assert "container_restart" in src
    assert "error_message" in src


# ─────────────────────────────────────────────────────────────────────────────
# S4 — Startup wiring check
# ─────────────────────────────────────────────────────────────────────────────

def test_both_recovery_calls_in_lifespan():
    """S4: app.py lifespan calls both recover_zombie_branches and recover_zombie_scans."""
    from pathlib import Path
    # Read as text to avoid importing fastapi (not installed on host)
    src = (Path(__file__).resolve().parents[2] / "core" / "api" / "app.py").read_text()
    assert "recover_zombie_branches" in src
    assert "recover_zombie_scans" in src


# ─────────────────────────────────────────────────────────────────────────────
# S5+S6 — Integration tests (require aiosqlite)
# ─────────────────────────────────────────────────────────────────────────────

_HAS_AIOSQLITE = importlib.util.find_spec("aiosqlite") is not None

_CREATE_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS scan_executions (
        scan_id          TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        scanner_type     TEXT NOT NULL,
        target           TEXT NOT NULL,
        profile          TEXT NOT NULL DEFAULT 'quick_web_scan',
        status           TEXT NOT NULL DEFAULT 'queued',
        created_at       TEXT NOT NULL,
        started_at       TEXT,
        completed_at     TEXT,
        findings_count   INTEGER NOT NULL DEFAULT 0,
        evidence_refs    TEXT NOT NULL DEFAULT '[]',
        raw_result_ref   TEXT,
        config           TEXT NOT NULL DEFAULT '{}',
        error_message    TEXT,
        group_id         TEXT
    )
"""


@pytest.mark.skipif(not _HAS_AIOSQLITE, reason="aiosqlite not installed on host")
@pytest.mark.asyncio
async def test_stuck_scan_recovered_to_failed(tmp_path, monkeypatch):
    """S5: a stuck 'running' passive_probe scan is marked failed with reason 'container_restart'."""
    import aiosqlite
    from datetime import datetime, timezone

    db_path = tmp_path / "test.db"
    now_iso = datetime.now(timezone.utc).isoformat()

    async with aiosqlite.connect(str(db_path)) as db:
        db.row_factory = aiosqlite.Row
        await db.execute(_CREATE_TABLE_SQL)
        await db.execute(
            "INSERT INTO scan_executions "
            "(scan_id, investigation_id, scanner_type, target, status, created_at) "
            "VALUES (?,?,?,?,?,?)",
            ("scan-stuck-001", "inv-001", "passive_probe", "http://target",
             "running", now_iso),
        )
        await db.commit()

    @asynccontextmanager
    async def _fake_get_db(_db_path=None):
        async with aiosqlite.connect(str(db_path)) as conn:
            conn.row_factory = aiosqlite.Row
            yield conn

    monkeypatch.setattr("apps.validation.database.get_db", _fake_get_db)

    from apps.conductor.exploitation.zombie_recovery import _recover_scans

    recovered = await _recover_scans()
    assert recovered == 1, f"expected 1 recovery, got {recovered}"

    # Verify DB state
    async with aiosqlite.connect(str(db_path)) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT status, error_message, completed_at "
            "FROM scan_executions WHERE scan_id=?",
            ("scan-stuck-001",),
        )
        row = await cur.fetchone()

    assert row["status"] == "failed"
    assert row["error_message"] == "container_restart"
    assert row["completed_at"] is not None, "completed_at should be set after recovery"


@pytest.mark.skipif(not _HAS_AIOSQLITE, reason="aiosqlite not installed on host")
@pytest.mark.asyncio
async def test_scan_recovery_is_idempotent(tmp_path, monkeypatch):
    """S6: running recovery twice leaves the same final state; second run recovers 0 rows."""
    import aiosqlite
    from datetime import datetime, timezone

    db_path = tmp_path / "test.db"
    now_iso = datetime.now(timezone.utc).isoformat()

    async with aiosqlite.connect(str(db_path)) as db:
        db.row_factory = aiosqlite.Row
        await db.execute(_CREATE_TABLE_SQL)
        await db.execute(
            "INSERT INTO scan_executions "
            "(scan_id, investigation_id, scanner_type, target, status, created_at) "
            "VALUES (?,?,?,?,?,?)",
            ("scan-idem-001", "inv-002", "passive_probe", "http://target2",
             "running", now_iso),
        )
        await db.commit()

    @asynccontextmanager
    async def _fake_get_db(_db_path=None):
        async with aiosqlite.connect(str(db_path)) as conn:
            conn.row_factory = aiosqlite.Row
            yield conn

    monkeypatch.setattr("apps.validation.database.get_db", _fake_get_db)

    from apps.conductor.exploitation.zombie_recovery import _recover_scans

    first_run  = await _recover_scans()
    second_run = await _recover_scans()

    assert first_run  == 1, f"first run: expected 1, got {first_run}"
    assert second_run == 0, (
        f"idempotency violated: second run returned {second_run} "
        "(should be 0 — first run moved all 'running' rows out of that state)"
    )
