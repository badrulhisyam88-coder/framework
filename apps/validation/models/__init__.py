"""
Pydantic models for the validation module.

These are the data contracts between layers.
Repositories return these. APIs return these. Plugins produce these.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class HostStatus(StrEnum):
    ACTIVE = "active"
    STALE = "stale"
    REMOVED = "removed"


class ServiceProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class QueueStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ValidationStatus(StrEnum):
    CVE_MATCHED = "cve_matched"              # Version match only, not yet tested
    VALIDATED_EXPLOITABLE = "validated_exploitable"       # Tested, confirmed
    VALIDATED_NOT_EXPLOITABLE = "validated_not_exploitable"  # Tested, not exploitable here


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class KnownIssueMatchField(StrEnum):
    """How a known_issue rule matches against a finding."""
    FINDING_TYPE = "finding_type"
    FINDING_TYPE_PORT = "finding_type+port"
    FINDING_TYPE_EVIDENCE_CONTAINS = "finding_type+evidence_contains"
    CVE_ID = "cve_id"
    FINDING_TYPE_VALIDATION_STATUS = "finding_type+validation_status"


class ChangeType(StrEnum):
    NEW_HOST = "new_host"
    NEW_SERVICE = "new_service"
    NEW_PORT = "new_port"
    SERVICE_CHANGED = "service_changed"
    HOST_GONE = "host_gone"


class HistoryAction(StrEnum):
    SCAN = "scan"
    APPROVE = "approve"
    REJECT = "reject"
    FINDING = "finding"
    SYNC = "sync"
    ARCHIVE = "archive"


class ArchiveReason(StrEnum):
    COMPLETED_EXPLOITABLE = "completed_exploitable"            # keep 90 days
    COMPLETED_NOT_EXPLOITABLE = "completed_not_exploitable"    # keep 30 days
    REJECTED_PERMANENT = "rejected_permanent"                  # keep 30 days
    REJECTED_REPEAT = "rejected_repeat"                        # rejected 3+ times, purge now
    TEST_TARGET = "test_target"                                # localhost / 127.0.0.1, purge on demand


class ValidationType(StrEnum):
    SSH_CRED = "ssh_cred"
    WEB_HEADER = "web_header"
    WEB_WORDPRESS = "web_wordpress"
    WEB_DRUPAL = "web_drupal"
    WEB_APACHE = "web_apache"
    WEB_NGINX = "web_nginx"
    TLS_CONFIG = "tls_config"
    SQLI = "sqli"
    TELNET_CLEARTEXT = "telnet_cleartext"
    SMB_ENUM = "smb_enum"
    CVE_POC = "cve_poc"


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


class Host(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    ip: str
    hostname: str | None = None
    os_guess: str | None = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    status: HostStatus = HostStatus.ACTIVE

    # Populated on read for display
    asset_name: str | None = None


class Service(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    host_id: str
    port: int
    protocol: ServiceProtocol = ServiceProtocol.TCP
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class CVE(BaseModel):
    cve_id: str
    description: str
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    affected_products: list[dict[str, Any]] = Field(default_factory=list)
    published_date: datetime
    last_modified: datetime
    source_url: str | None = None


class Evidence(BaseModel):
    """What was sent, what came back. This is what makes findings defensible."""
    sent: str | None = None           # exact payload or command
    received: str | None = None       # exact response
    context: dict[str, Any] = Field(default_factory=dict)  # headers, banners, env info
    duration_ms: int | None = None
    raw_output: str | None = None     # full tool output if applicable


class QueueItem(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    host_id: str
    service_id: str
    cve_id: str | None = None
    validation_type: ValidationType
    plugin_name: str
    profile_name: str
    status: QueueStatus = QueueStatus.PENDING
    created_at: datetime = Field(default_factory=datetime.utcnow)
    approved_at: datetime | None = None
    executed_at: datetime | None = None
    completed_at: datetime | None = None
    notes: str | None = None

    # Populated on read for display
    host: Host | None = None
    service: Service | None = None
    cve: CVE | None = None
    asset_name: str | None = None


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    queue_item_id: str | None = None
    host_id: str
    service_id: str | None = None
    cve_id: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    finding_type: str
    cvss_score: float | None = None
    severity: FindingSeverity
    validation_status: ValidationStatus
    evidence: Evidence
    environment_context: str | None = None
    status: FindingStatus = FindingStatus.OPEN

    # Populated on read for display
    host: Host | None = None
    service: Service | None = None
    cve: CVE | None = None
    asset_name: str | None = None


class Change(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    host_id: str | None = None
    service_id: str | None = None
    change_type: ChangeType
    detail: dict[str, Any]
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    acknowledged: bool = False


class HistoryEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    action: HistoryAction
    summary: str
    detail: dict[str, Any] | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class KnownIssue(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    finding_type: str
    match_field: KnownIssueMatchField
    match_value: str
    reason: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str = "user"
    hit_count: int = 0
    last_hit: datetime | None = None


class DCGroup(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    location: str | None = None
    notes: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Asset(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    dc_group_id: str | None = None
    name: str
    target: str
    notes: str | None = None
    scan_type: str = "quick"
    workers: int = 4
    last_scanned_at: datetime | None = None
    last_scan_id: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ReportConfig(BaseModel):
    title: str
    prepared_by: str | None = None
    period_start: str | None = None
    period_end: str | None = None
    asset_ids: list[str] = Field(default_factory=list)
    sections: list[str] = Field(default_factory=list)
    severity_filter: str = "all"


class WatchlistEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    cve_id: str
    description: str | None = None
    cvss_score: float | None = None
    severity: str | None = None
    added_at: datetime = Field(default_factory=datetime.utcnow)
    last_hit: datetime | None = None
    hit_count: int = 0


class ReconResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    asset_id: str
    hostname: str
    ip: str | None = None
    source: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class MsfRunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class MsfRunMode(StrEnum):
    RUN = "run"
    CHECK = "check"


class MsfRun(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    module_path: str
    module_type: str  # auxiliary / exploit / post / encoder / nop / payload
    options: dict[str, Any] = Field(default_factory=dict)
    target: str | None = None
    mode: MsfRunMode = MsfRunMode.RUN
    status: MsfRunStatus = MsfRunStatus.PENDING
    output: str | None = None
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None


# ---------------------------------------------------------------------------
# Request/Response schemas (API layer)
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target: str                          # IP, CIDR, or hostname
    scan_type: str = "quick"            # quick / full / custom
    custom_args: str | None = None      # only if scan_type=custom
    workers: int = Field(default=4, ge=1, le=32)  # parallel-worker count


class ScanResult(BaseModel):
    scan_id: str
    target: str
    hosts_found: int
    services_found: int
    new_hosts: int
    new_services: int
    queue_items_created: int
    duration_ms: int


class ApprovalRequest(BaseModel):
    notes: str | None = None


class RejectionRequest(BaseModel):
    notes: str | None = None


class MarkKnownIssueRequest(BaseModel):
    """Body for POST /findings/{id}/mark-known-issue."""
    reason: str = Field(min_length=10)
    match_on: KnownIssueMatchField


class NVDSyncResult(BaseModel):
    cves_added: int
    cves_updated: int
    duration_ms: int
    last_sync: datetime


def cvss_to_severity(score: float | None) -> FindingSeverity:
    """Convert CVSS score to severity label."""
    if score is None:
        return FindingSeverity.INFO
    if score >= 9.0:
        return FindingSeverity.CRITICAL
    if score >= 7.0:
        return FindingSeverity.HIGH
    if score >= 4.0:
        return FindingSeverity.MEDIUM
    if score >= 0.1:
        return FindingSeverity.LOW
    return FindingSeverity.INFO
