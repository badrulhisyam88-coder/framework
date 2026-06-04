"""GuidedAction domain model — describes a structured investigation step."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class ExecutionMode(StrEnum):
    MANUAL_ONLY = "manual_only"     # Explain only; user does everything independently
    GUIDED_MANUAL = "guided_manual"  # Step-by-step guide; user executes each step
    SIMULATED = "simulated"          # Show expected output for learning context only


class RiskLevel(StrEnum):
    INFORMATIONAL = "informational"  # Read-only, no interaction with target
    LOW = "low"                      # Passive probing; minimal footprint
    MEDIUM = "medium"                # Active testing; sends payloads to target
    HIGH = "high"                    # Significant active interaction


RISK_LEVEL_LABELS: dict[str, str] = {
    RiskLevel.INFORMATIONAL: "Informational",
    RiskLevel.LOW: "Low",
    RiskLevel.MEDIUM: "Medium",
    RiskLevel.HIGH: "High",
}


class GuidedActionStep(BaseModel):
    """One step within a guided action's execution guidance."""
    step_number: int
    instruction: str
    example: str | None = None       # Exact command or payload to copy
    expected_result: str | None = None
    capture_evidence: bool = False   # Prompt user to capture evidence at this step


class GuidedAction(BaseModel):
    action_id: str
    finding_type: str                 # Primary finding type this action targets
    finding_types: list[str]          # All applicable finding types
    title: str
    explanation: str
    why_this_matters: str
    required_skills: list[str] = Field(default_factory=list)
    expected_evidence: str            # What evidence the user should capture
    approval_required: bool = True
    execution_mode: ExecutionMode
    risk_level: RiskLevel
    related_learning_path: str | None = None  # path_id

    # Structured execution guidance (revealed after approval)
    steps: list[GuidedActionStep] = Field(default_factory=list)

    # Context for reasoning
    preconditions: list[str] = Field(default_factory=list)
    outcome_indicators: list[str] = Field(default_factory=list)
    remediation_context: str = ""     # Defensive implication of this finding

    # Phase 17 — distinguishes defensive verification actions from offensive ones
    is_defensive: bool = False
