"""
Database initialization and schema management.
"""

from pathlib import Path

import aiosqlite

from sdk import Logger

DB_PATH = Path("/app/data/validation.db")

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY, ip TEXT NOT NULL UNIQUE, hostname TEXT,
    os_guess TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY, host_id TEXT NOT NULL REFERENCES hosts(id),
    port INTEGER NOT NULL, protocol TEXT NOT NULL DEFAULT 'tcp',
    service_name TEXT, product TEXT, version TEXT, banner TEXT,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    UNIQUE(host_id, port, protocol)
);
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY, description TEXT NOT NULL,
    cvss_score REAL, cvss_vector TEXT, cvss_version TEXT,
    affected_products TEXT NOT NULL, published_date TEXT NOT NULL,
    last_modified TEXT NOT NULL, source_url TEXT
);
CREATE TABLE IF NOT EXISTS queue_items (
    id TEXT PRIMARY KEY, host_id TEXT NOT NULL REFERENCES hosts(id),
    service_id TEXT NOT NULL REFERENCES services(id),
    cve_id TEXT REFERENCES cves(cve_id), validation_type TEXT NOT NULL,
    plugin_name TEXT NOT NULL, profile_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL,
    approved_at TEXT, executed_at TEXT, completed_at TEXT, notes TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, queue_item_id TEXT REFERENCES queue_items(id),
    host_id TEXT NOT NULL REFERENCES hosts(id),
    service_id TEXT REFERENCES services(id),
    cve_id TEXT REFERENCES cves(cve_id), timestamp TEXT NOT NULL,
    finding_type TEXT NOT NULL, cvss_score REAL, severity TEXT NOT NULL,
    validation_status TEXT NOT NULL, evidence TEXT NOT NULL,
    environment_context TEXT, status TEXT NOT NULL DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS changes (
    id TEXT PRIMARY KEY, host_id TEXT REFERENCES hosts(id),
    service_id TEXT REFERENCES services(id), change_type TEXT NOT NULL,
    detail TEXT NOT NULL, detected_at TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS history (
    id TEXT PRIMARY KEY, action TEXT NOT NULL, summary TEXT NOT NULL,
    detail TEXT, timestamp TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sync_meta (
    key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS known_issues (
    id TEXT PRIMARY KEY,
    finding_type TEXT NOT NULL,
    match_field TEXT NOT NULL,
    match_value TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT 'user',
    hit_count INTEGER NOT NULL DEFAULT 0,
    last_hit TEXT
);
CREATE TABLE IF NOT EXISTS dc_groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    location    TEXT,
    notes       TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
    id              TEXT PRIMARY KEY,
    dc_group_id     TEXT REFERENCES dc_groups(id),
    name            TEXT NOT NULL,
    target          TEXT NOT NULL,
    notes           TEXT,
    scan_type       TEXT DEFAULT 'quick',
    workers         INTEGER DEFAULT 4,
    last_scanned_at TEXT,
    last_scan_id    TEXT,
    created_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
    id              TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    prepared_by     TEXT,
    period_start    TEXT,
    period_end      TEXT,
    asset_ids       TEXT NOT NULL,
    sections        TEXT NOT NULL,
    severity_filter TEXT NOT NULL DEFAULT 'all',
    generated_at    TEXT NOT NULL,
    file_path       TEXT
);
CREATE TABLE IF NOT EXISTS cve_watchlist (
    id          TEXT PRIMARY KEY,
    cve_id      TEXT NOT NULL UNIQUE,
    description TEXT,
    cvss_score  REAL,
    severity    TEXT,
    added_at    TEXT NOT NULL,
    last_hit    TEXT,
    hit_count   INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS recon_results (
    id            TEXT PRIMARY KEY,
    asset_id      TEXT NOT NULL REFERENCES assets(id),
    hostname      TEXT NOT NULL,
    ip            TEXT,
    source        TEXT,
    discovered_at TEXT NOT NULL,
    UNIQUE(asset_id, hostname)
);
CREATE TABLE IF NOT EXISTS msf_runs (
    id            TEXT PRIMARY KEY,
    module_path   TEXT NOT NULL,
    module_type   TEXT NOT NULL,
    options_json  TEXT NOT NULL,
    target        TEXT,
    mode          TEXT NOT NULL DEFAULT 'run',
    status        TEXT NOT NULL DEFAULT 'pending',
    output        TEXT,
    started_at    TEXT NOT NULL,
    completed_at  TEXT
);

CREATE TABLE IF NOT EXISTS investigations (
    investigation_id        TEXT PRIMARY KEY,
    title                   TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'active',
    workflow_stage          TEXT NOT NULL DEFAULT 'discovery',
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    targets                 TEXT NOT NULL DEFAULT '[]',
    findings                TEXT NOT NULL DEFAULT '[]',
    evidence_refs           TEXT NOT NULL DEFAULT '[]',
    active_learning_paths   TEXT NOT NULL DEFAULT '[]',
    completed_learning_paths TEXT NOT NULL DEFAULT '[]',
    notes                   TEXT
);
CREATE TABLE IF NOT EXISTS timeline_events (
    event_id            TEXT PRIMARY KEY,
    investigation_id    TEXT NOT NULL REFERENCES investigations(investigation_id),
    event_type          TEXT NOT NULL,
    timestamp           TEXT NOT NULL,
    actor               TEXT NOT NULL DEFAULT 'system',
    summary             TEXT NOT NULL,
    detail              TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS learning_path_progress (
    id                  TEXT PRIMARY KEY,
    investigation_id    TEXT NOT NULL REFERENCES investigations(investigation_id),
    path_id             TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'active',
    started_at          TEXT NOT NULL,
    completed_at        TEXT,
    current_step_index  INTEGER NOT NULL DEFAULT 0,
    completed_steps     TEXT NOT NULL DEFAULT '[]',
    UNIQUE(investigation_id, path_id)
);
CREATE TABLE IF NOT EXISTS evidence_artifacts (
    evidence_id         TEXT PRIMARY KEY,
    investigation_id    TEXT NOT NULL REFERENCES investigations(investigation_id),
    finding_id          TEXT,
    learning_path_id    TEXT,
    guided_action_id    TEXT,
    artifact_type       TEXT NOT NULL,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    content             TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL,
    created_by          TEXT NOT NULL DEFAULT 'user',
    metadata            TEXT NOT NULL DEFAULT '{}',
    tags                TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS guided_action_approvals (
    approval_id         TEXT PRIMARY KEY,
    investigation_id    TEXT NOT NULL REFERENCES investigations(investigation_id),
    action_id           TEXT NOT NULL,
    finding_id          TEXT,
    status              TEXT NOT NULL DEFAULT 'pending',
    requested_at        TEXT NOT NULL,
    reviewed_at         TEXT,
    completed_at        TEXT,
    notes               TEXT,
    evidence_refs       TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS skill_mastery (
    mastery_id              TEXT PRIMARY KEY,
    skill_id                TEXT NOT NULL,
    investigation_id        TEXT NOT NULL REFERENCES investigations(investigation_id),
    status                  TEXT NOT NULL DEFAULT 'locked',
    evidence_refs           TEXT NOT NULL DEFAULT '[]',
    completed_learning_paths TEXT NOT NULL DEFAULT '[]',
    completed_actions       TEXT NOT NULL DEFAULT '[]',
    confidence_score        REAL NOT NULL DEFAULT 0.0,
    created_at              TEXT NOT NULL,
    started_at              TEXT,
    validated_at            TEXT,
    UNIQUE(skill_id, investigation_id)
);
CREATE TABLE IF NOT EXISTS export_records (
    export_id               TEXT PRIMARY KEY,
    investigation_id        TEXT NOT NULL REFERENCES investigations(investigation_id),
    export_type             TEXT NOT NULL DEFAULT 'investigation_summary',
    file_path               TEXT,
    vault_path              TEXT,
    status                  TEXT NOT NULL DEFAULT 'generated',
    generated_at            TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS posture_snapshots (
    snapshot_id                 TEXT PRIMARY KEY,
    investigation_id            TEXT NOT NULL REFERENCES investigations(investigation_id),
    campaign_id                 TEXT,
    label                       TEXT NOT NULL DEFAULT 'baseline',
    snapshot_kind               TEXT NOT NULL DEFAULT 'baseline',
    captured_at                 TEXT NOT NULL,
    findings_count              INTEGER NOT NULL DEFAULT 0,
    findings_by_severity        TEXT NOT NULL DEFAULT '{}',
    findings_by_type            TEXT NOT NULL DEFAULT '{}',
    active_themes               TEXT NOT NULL DEFAULT '[]',
    evidence_quality_score      INTEGER NOT NULL DEFAULT 0,
    remediation_documented      TEXT NOT NULL DEFAULT '[]',
    captured_by                 TEXT NOT NULL DEFAULT 'user',
    notes                       TEXT
);
CREATE TABLE IF NOT EXISTS investigation_campaigns (
    campaign_id      TEXT PRIMARY KEY,
    title            TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'planning',
    objectives       TEXT NOT NULL DEFAULT '[]',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    created_by       TEXT NOT NULL DEFAULT 'user'
);
CREATE TABLE IF NOT EXISTS campaign_memberships (
    membership_id           TEXT PRIMARY KEY,
    campaign_id             TEXT NOT NULL REFERENCES investigation_campaigns(campaign_id),
    investigation_id        TEXT NOT NULL REFERENCES investigations(investigation_id),
    stage                   TEXT NOT NULL DEFAULT 'recon',
    sequence_order          INTEGER NOT NULL DEFAULT 0,
    parent_investigation_id TEXT,
    joined_at               TEXT NOT NULL,
    notes                   TEXT,
    UNIQUE(campaign_id, investigation_id)
);
-- Phase 59a cleanup — investigation_milestones table removed. DROP is
-- permanent; IF EXISTS makes it safe on fresh/already-dropped databases.
-- See _post_create_drops() below.
CREATE TABLE IF NOT EXISTS scan_executions (
    scan_id             TEXT PRIMARY KEY,
    investigation_id    TEXT NOT NULL REFERENCES investigations(investigation_id),
    scanner_type        TEXT NOT NULL,
    target              TEXT NOT NULL,
    profile             TEXT NOT NULL DEFAULT 'quick_web_scan',
    status              TEXT NOT NULL DEFAULT 'queued',
    created_at          TEXT NOT NULL,
    started_at          TEXT,
    completed_at        TEXT,
    findings_count      INTEGER NOT NULL DEFAULT 0,
    evidence_refs       TEXT NOT NULL DEFAULT '[]',
    raw_result_ref      TEXT,
    config              TEXT NOT NULL DEFAULT '{}',
    error_message       TEXT,
    group_id            TEXT
);
CREATE TABLE IF NOT EXISTS normalized_findings (
    finding_id          TEXT PRIMARY KEY,
    scan_id             TEXT NOT NULL REFERENCES scan_executions(scan_id),
    investigation_id    TEXT NOT NULL REFERENCES investigations(investigation_id),
    source_scanner      TEXT NOT NULL,
    finding_type        TEXT NOT NULL,
    severity            TEXT NOT NULL,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    target              TEXT NOT NULL,
    port                INTEGER,
    endpoint            TEXT,
    evidence_refs       TEXT NOT NULL DEFAULT '[]',
    related_cves        TEXT NOT NULL DEFAULT '[]',
    related_cwes        TEXT NOT NULL DEFAULT '[]',
    tags                TEXT NOT NULL DEFAULT '[]',
    raw_data            TEXT NOT NULL DEFAULT '{}',
    created_at          TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exploitation_branches (
    branch_id        TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    finding_id       TEXT NOT NULL,
    engine_id        TEXT NOT NULL,
    technique_class  TEXT NOT NULL,
    operator_params  TEXT NOT NULL DEFAULT '{}',
    state            TEXT NOT NULL DEFAULT 'pending',
    artifact         TEXT,
    artifact_type    TEXT,
    exhaustion_record TEXT,
    stage_log        TEXT NOT NULL DEFAULT '[]',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_loop_unknowns (
    id               TEXT PRIMARY KEY,
    created_at       TEXT NOT NULL,
    investigation_id TEXT NOT NULL,
    context          TEXT NOT NULL DEFAULT '',
    raw_result       TEXT NOT NULL DEFAULT '',
    expected_concept TEXT,
    evidence         TEXT NOT NULL DEFAULT '{}',
    status           TEXT NOT NULL DEFAULT 'pending_review',
    resolution       TEXT
);
CREATE TABLE IF NOT EXISTS investigation_chat_history (
    id               TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    role             TEXT NOT NULL,
    content          TEXT NOT NULL,
    created_at       TEXT NOT NULL
);
"""

INDEXES = """
CREATE INDEX IF NOT EXISTS idx_services_host_id ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_queue_status ON queue_items(status);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_changes_acknowledged ON changes(acknowledged);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history(timestamp);
CREATE INDEX IF NOT EXISTS idx_known_issues_finding_type ON known_issues(finding_type);
CREATE INDEX IF NOT EXISTS idx_assets_dc_group_id ON assets(dc_group_id);
CREATE INDEX IF NOT EXISTS idx_recon_results_asset_id ON recon_results(asset_id);
CREATE INDEX IF NOT EXISTS idx_timeline_investigation_id
    ON timeline_events(investigation_id);
CREATE INDEX IF NOT EXISTS idx_learning_progress_investigation_id
    ON learning_path_progress(investigation_id);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);
CREATE INDEX IF NOT EXISTS idx_evidence_investigation_id
    ON evidence_artifacts(investigation_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding_id ON evidence_artifacts(finding_id);
CREATE INDEX IF NOT EXISTS idx_approvals_investigation_id
    ON guided_action_approvals(investigation_id);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON guided_action_approvals(status);
CREATE INDEX IF NOT EXISTS idx_skill_mastery_investigation
    ON skill_mastery(investigation_id);
CREATE INDEX IF NOT EXISTS idx_skill_mastery_status ON skill_mastery(status);
CREATE INDEX IF NOT EXISTS idx_export_records_investigation
    ON export_records(investigation_id);
CREATE INDEX IF NOT EXISTS idx_scan_executions_investigation
    ON scan_executions(investigation_id);
CREATE INDEX IF NOT EXISTS idx_scan_executions_status ON scan_executions(status);
CREATE INDEX IF NOT EXISTS idx_normalized_findings_scan
    ON normalized_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_normalized_findings_investigation
    ON normalized_findings(investigation_id);
CREATE INDEX IF NOT EXISTS idx_normalized_findings_type
    ON normalized_findings(finding_type);
-- Phase 59a cleanup — milestone indices removed alongside their table.
CREATE INDEX IF NOT EXISTS idx_campaign_memberships_campaign
    ON campaign_memberships(campaign_id);
CREATE INDEX IF NOT EXISTS idx_campaign_memberships_investigation
    ON campaign_memberships(investigation_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_status
    ON investigation_campaigns(status);
CREATE INDEX IF NOT EXISTS idx_posture_snapshots_investigation
    ON posture_snapshots(investigation_id);
CREATE INDEX IF NOT EXISTS idx_posture_snapshots_campaign
    ON posture_snapshots(campaign_id);
CREATE INDEX IF NOT EXISTS idx_exploitation_branches_investigation
    ON exploitation_branches(investigation_id);
CREATE INDEX IF NOT EXISTS idx_agent_loop_unknowns_status
    ON agent_loop_unknowns(status);
CREATE INDEX IF NOT EXISTS idx_agent_loop_unknowns_investigation
    ON agent_loop_unknowns(investigation_id);
CREATE INDEX IF NOT EXISTS idx_chat_history_investigation
    ON investigation_chat_history(investigation_id);
CREATE INDEX IF NOT EXISTS idx_exploitation_branches_finding
    ON exploitation_branches(finding_id);
CREATE INDEX IF NOT EXISTS idx_exploitation_branches_state
    ON exploitation_branches(state);
"""


async def _post_create_drops(db: aiosqlite.Connection) -> None:
    """Permanent DROP statements for tables removed in cleanup phases.

    IF EXISTS makes each drop a safe no-op on fresh DBs and on DBs
    that already lost the table to a previous boot. Add new entries
    when future cleanup phases remove tables.
    """
    # Phase 59a cleanup — investigation_milestones table removed.
    # DROP is permanent; IF EXISTS makes it safe on fresh/already-
    # dropped databases.
    await db.execute("DROP TABLE IF EXISTS investigation_milestones")
    await db.commit()


async def init_db(db_path: Path = DB_PATH) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.executescript(INDEXES)
        await _post_create_drops(db)

        # Additive migration: group_id for scan group orchestration.
        # Safe to re-run — checks column existence before ALTER.
        async with db.execute("PRAGMA table_info(scan_executions)") as cur:
            cols = {row[1] for row in await cur.fetchall()}
        if "group_id" not in cols:
            await db.execute(
                "ALTER TABLE scan_executions ADD COLUMN group_id TEXT"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_executions_group"
                " ON scan_executions(group_id)"
            )

        # Additive migration: V1.7 validation status fields on normalized_findings.
        async with db.execute("PRAGMA table_info(normalized_findings)") as cur:
            nf_cols = {row[1] for row in await cur.fetchall()}
        _nf_migrations = [
            ("validation_status",        "TEXT NOT NULL DEFAULT 'pending'"),
            ("validation_reason",        "TEXT"),
            ("enumeration_gaps",         "TEXT"),
            ("validated_at",             "TEXT"),
            ("superseded_by",            "TEXT"),
            ("enumeration_block_reason", "TEXT"),
        ]
        for col_name, col_def in _nf_migrations:
            if col_name not in nf_cols:
                await db.execute(
                    f"ALTER TABLE normalized_findings ADD COLUMN {col_name} {col_def}"
                )

        await db.commit()
    Logger.info("database.initialized", extra={"path": str(db_path)})


class _DBConnection:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn = None

    async def __aenter__(self):
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._conn:
            await self._conn.close()
            self._conn = None


def get_db(db_path: Path = DB_PATH) -> _DBConnection:
    """Usage: async with get_db() as db: ..."""
    return _DBConnection(db_path)
