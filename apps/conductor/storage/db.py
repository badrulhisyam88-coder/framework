"""SQLite setup for data/orchestration.db.

Schema is deliberately minimal and ALTER-friendly — no migration framework.
All tables use IF NOT EXISTS so init_db() is safe to call on every startup.

Tables created here:
  investigations   — lifecycle state per investigation (Conductor-owned)
  phase_state      — per-investigation phase progression (PhaseOrchestrator-owned)
  engine_runs      — engine dispatch records for restart reconciliation (ExecOrch-owned)
  chain_events     — chain dispatch history per branch (ChainOrchestrator-owned)
"""
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger("conductor.storage.db")

_DEFAULT_DB_PATH = Path("data/orchestration.db")


def get_connection(db_path: Path = _DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Return a sqlite3 connection with WAL mode and row_factory set."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: Path = _DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Create schema if it doesn't exist; return open connection."""
    conn = get_connection(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS investigations (
            id          TEXT PRIMARY KEY,
            target      TEXT NOT NULL,
            config_json TEXT NOT NULL DEFAULT '{}',
            state       TEXT NOT NULL DEFAULT 'CREATED',
            created_at  REAL NOT NULL,
            updated_at  REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS phase_state (
            investigation_id TEXT NOT NULL,
            phase            TEXT NOT NULL,
            status           TEXT NOT NULL,  -- running | completed | failed
            started_at       REAL NOT NULL,
            completed_at     REAL,
            PRIMARY KEY (investigation_id, phase)
        );

        CREATE TABLE IF NOT EXISTS engine_runs (
            run_id           TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            engine_id        TEXT NOT NULL,
            target           TEXT NOT NULL,
            status           TEXT NOT NULL DEFAULT 'running',
            started_at       REAL NOT NULL,
            ended_at         REAL
        );

        CREATE TABLE IF NOT EXISTS chain_events (
            id               TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            finding_id       TEXT NOT NULL,
            action_engine_id TEXT NOT NULL,
            trigger          TEXT NOT NULL,
            depth            INTEGER NOT NULL,
            fired_at         REAL NOT NULL,
            result           TEXT
        );
    """)
    conn.commit()
    logger.info("orchestration.db initialised at %s", db_path)
    return conn
