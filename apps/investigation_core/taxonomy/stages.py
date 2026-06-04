"""Centralised taxonomy for investigation workflow stages and timeline event types."""

from enum import StrEnum


class WorkflowStage(StrEnum):
    DISCOVERY = "discovery"
    DETECTION = "detection"
    VALIDATION = "validation"
    LEARNING = "learning"
    KNOWLEDGE_EXPORT = "knowledge_export"
    RESOLVED = "resolved"


class EventType(StrEnum):
    INVESTIGATION_CREATED = "investigation_created"
    SCAN_STARTED = "scan_started"
    FINDING_DETECTED = "finding_detected"
    FINDING_VALIDATED = "finding_validated"
    LEARNING_PATH_STARTED = "learning_path_started"
    LEARNING_STEP_COMPLETED = "learning_step_completed"
    EVIDENCE_ATTACHED = "evidence_attached"
    KNOWLEDGE_EXPORTED = "knowledge_exported"
    STAGE_ADVANCED = "stage_advanced"
    STATUS_CHANGED = "status_changed"
    EVIDENCE_CAPTURED = "evidence_captured"
    GUIDED_ACTION_RECOMMENDED = "guided_action_recommended"
    GUIDED_ACTION_APPROVED = "guided_action_approved"
    GUIDED_ACTION_COMPLETED = "guided_action_completed"
    SKILL_UNLOCKED = "skill_unlocked"
    SKILL_MASTERED = "skill_mastered"
    EXPORT_GENERATED = "export_generated"
    SCAN_QUEUED = "scan_queued"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    FINDINGS_NORMALIZED = "findings_normalized"
    TARGET_RESOLVED = "target_resolved"
    TARGET_REACHABLE = "target_reachable"
    TARGET_UNREACHABLE = "target_unreachable"
    TARGET_FINGERPRINTED = "target_fingerprinted"
    # Phase 13 — investigation continuity
    MILESTONE_ACHIEVED = "milestone_achieved"
    ACTION_STARTED = "action_started"
    ACTION_ABANDONED = "action_abandoned"


# Ordered list used for timeline rendering and stage progression checks.
STAGE_ORDER: list[WorkflowStage] = [
    WorkflowStage.DISCOVERY,
    WorkflowStage.DETECTION,
    WorkflowStage.VALIDATION,
    WorkflowStage.LEARNING,
    WorkflowStage.KNOWLEDGE_EXPORT,
    WorkflowStage.RESOLVED,
]

STAGE_LABELS: dict[str, str] = {
    WorkflowStage.DISCOVERY: "Discovery",
    WorkflowStage.DETECTION: "Detection",
    WorkflowStage.VALIDATION: "Validation",
    WorkflowStage.LEARNING: "Learning",
    WorkflowStage.KNOWLEDGE_EXPORT: "Knowledge Export",
    WorkflowStage.RESOLVED: "Resolved",
}

EVENT_TYPE_LABELS: dict[str, str] = {
    EventType.INVESTIGATION_CREATED: "Investigation created",
    EventType.SCAN_STARTED: "Scan started",
    EventType.FINDING_DETECTED: "Finding detected",
    EventType.FINDING_VALIDATED: "Finding validated",
    EventType.LEARNING_PATH_STARTED: "Learning path started",
    EventType.LEARNING_STEP_COMPLETED: "Learning step completed",
    EventType.EVIDENCE_ATTACHED: "Evidence attached",
    EventType.KNOWLEDGE_EXPORTED: "Knowledge exported",
    EventType.STAGE_ADVANCED: "Stage advanced",
    EventType.STATUS_CHANGED: "Status changed",
    EventType.EVIDENCE_CAPTURED: "Evidence captured",
    EventType.GUIDED_ACTION_RECOMMENDED: "Guided action recommended",
    EventType.GUIDED_ACTION_APPROVED: "Guided action approved",
    EventType.GUIDED_ACTION_COMPLETED: "Guided action completed",
    EventType.SKILL_UNLOCKED: "Skill unlocked",
    EventType.SKILL_MASTERED: "Skill mastered",
    EventType.EXPORT_GENERATED: "Export generated",
    EventType.SCAN_QUEUED: "Scan queued",
    EventType.SCAN_COMPLETED: "Scan completed",
    EventType.SCAN_FAILED: "Scan failed",
    EventType.FINDINGS_NORMALIZED: "Findings normalized",
    EventType.TARGET_RESOLVED: "Target resolved",
    EventType.TARGET_REACHABLE: "Target reachable",
    EventType.TARGET_UNREACHABLE: "Target unreachable",
    EventType.TARGET_FINGERPRINTED: "Target fingerprinted",
    EventType.MILESTONE_ACHIEVED: "Milestone achieved",
    EventType.ACTION_STARTED: "Action started",
    EventType.ACTION_ABANDONED: "Action abandoned",
}
