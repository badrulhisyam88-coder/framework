"""
Database initialization and schema management.

All tables created here. Run once on startup via lifespan.
Never modify schema without migration plan.
"""

import aiosqlite
from pathlib import Path

from sdk import Logger

DB_PATH = Path("/app/data/validation.db")

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- Discovered hosts
CREATE TABLE IF NOT EXISTS hosts (
    id           TEXT PRIMARY KEY,
    ip           TEXT NOT NULL UNIQUE,
    hostname     TEXT,
    os_guess     TEXT,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active'  -- active / stale / removed
);

-- Discovered services on hosts
CREATE TABLE IF NOT EXISTS services (
    id           TEXT PRIMARY KEY,
    host_id      TEXT NOT NULL REFERENCES hosts(id),
    port         INTEGER NOT NULL,
    protocol     TEXT NOT NULL DEFAULT 'tcp',
    service_name TEXT,
    product      TEXT,
    version      TEXT,
    banner       TEXT,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    UNIQUE(host_id, port, protocol)
);

-- CVE reference data (populated by NVD sync)
CREATE TABLE IF NOT EXISTS cves (
    cve_id            TEXT PRIMARY KEY,
    description       TEXT NOT NULL,
    cvss_score        REAL,
    cvss_vector       TEXT,
    cvss_version      TEXT,
    affected_products TEXT NOT NULL,  -- JSON array: [{vendor, product, version_ranges}]
    published_date    TEXT NOT NULL,
    last_modified     TEXT NOT NULL,
    source_url        TEXT
);

-- Validation queue (approval-gated)
CREATE TABLE IF NOT EXISTS queue_items (
    id               TEXT PRIMARY KEY,
    host_id          TEXT NOT NULL REFERENCES hosts(id),
    service_id       TEXT NOT NULL REFERENCES services(id),
    cve_id           TEXT REFERENCES cves(cve_id),  -- nullable: not all checks are CVE-based
    validation_type  TEXT NOT NULL,  -- ssh_cred / web_header / tls_config / sqli / telnet_cleartext / smb_enum
    plugin_name      TEXT NOT NULL,
    profile_name     TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',  -- pending / approved / rejected / running / completed / failed
    created_at       TEXT NOT NULL,
    approved_at      TEXT,
    executed_at      TEXT,
    completed_at     TEXT,
    notes            TEXT  -- user notes on approval/rejection
);

-- Validated findings with evidence
CREATE TABLE IF NOT EXISTS findings (
    id                    TEXT PRIMARY KEY,
    queue_item_id         TEXT REFERENCES queue_items(id),
    host_id               TEXT NOT NULL REFERENCES hosts(id),
    service_id            TEXT REFERENCES services(id),
    cve_id                TEXT REFERENCES cves(cve_id),
    timestamp             TEXT NOT NULL,
    finding_type          TEXT NOT NULL,
    cvss_score            REAL,
    severity              TEXT NOT NULL,  -- info / low / medium / high / critical
    validation_status     TEXT NOT NULL,  -- cve_matched / validated_exploitable / validated_not_exploitable
    evidence              TEXT NOT NULL,  -- JSON: {sent, received, context, duration_ms}
    environment_context   TEXT,          -- why exploitable/not in this environment
    status                TEXT NOT NULL DEFAULT 'open'  -- open / acknowledged / resolved
);

-- Change detection log
CREATE TABLE IF NOT EXISTS changes (
    id            TEXT PRIMARY KEY,
    host_id       TEXT REFERENCES hosts(id),
    service_id    TEXT REFERENCES services(id),
    change_type   TEXT NOT NULL,  -- new_host / new_service / new_port / service_changed / host_gone
    detail        TEXT NOT NULL,  -- JSON describing the change
    detected_at   TEXT NOT NULL,
    acknowledged  INTEGER NOT NULL DEFAULT 0
);

-- Audit history (human-readable summaries only)
CREATE TABLE IF NOT EXISTS history (
    id          TEXT PRIMARY KEY,
    action      TEXT NOT NULL,  -- scan / approve / reject / finding / sync
    summary     TEXT NOT NULL,
    detail      TEXT,           -- JSON, optional
    timestamp   TEXT NOT NULL
);

-- NVD sync metadata
CREATE TABLE IF NOT EXISTS sync_meta (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
"""

INDEXES = """
CREATE INDEX IF NOT EXISTS idx_services_host_id ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_queue_status ON queue_items(status);
CREATE INDEX IF NOT EXISTS idx_queue_host ON queue_items(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_validation_status ON findings(validation_status);
CREATE INDEX IF NOT EXISTS idx_changes_acknowledged ON changes(acknowledged);
CREATE INDEX IF NOT EXISTS idx_cves_score ON cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history(timestamp);
"""


async def init_db(db_path: Path = DB_PATH) -> None:
    """Initialize database schema. Safe to call on every startup."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.executescript(INDEXES)
        await db.commit()
    Logger.info("database.initialized", extra={"path": str(db_path)})


async def get_db(db_path: Path = DB_PATH) -> aiosqlite.Connection:
    """
    Get a database connection. Callers must close it.

    Usage:
        async with await get_db() as db:
            ...
    """
    db = await aiosqlite.connect(db_path)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA foreign_keys=ON")
    await db.execute("PRAGMA journal_mode=WAL")
    return db
