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


class ValidationType(StrEnum):
    SSH_CRED = "ssh_cred"
    WEB_HEADER = "web_header"
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


# ---------------------------------------------------------------------------
# Request/Response schemas (API layer)
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target: str                          # IP, CIDR, or hostname
    scan_type: str = "quick"            # quick / full / custom
    custom_args: str | None = None      # only if scan_type=custom


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


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


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
