"""Rule base contract for V1.7 FilterOrchestrator.

Each rule is a callable class with an evaluate() method. Rules never
perform I/O — they transform finding dicts into RuleResult values.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class RuleResult:
    """Outcome returned by a rule's evaluate() call."""

    matched: bool
    status: str | None = None  # 'validated' | 'dropped' | 'incomplete'
    reason: str | None = None  # human-readable validation_reason
    gaps: list[str] | None = None  # enumeration_gaps (only for 'incomplete')
    is_evidence_gap: bool = False  # when True: matched but classification blocked by missing evidence

    @classmethod
    def evidence_gap(cls, reason_text: str) -> "RuleResult":
        """Signal that this rule would classify but a required evidence field is missing."""
        return cls(matched=True, reason=reason_text, is_evidence_gap=True)


@runtime_checkable
class Rule(Protocol):
    """Protocol every rule must satisfy."""

    id: str
    description: str

    def evaluate(self, finding: dict, all_findings: list[dict]) -> RuleResult: ...


@dataclass
class ReinvocationRequest:
    """Request to re-invoke an engine with refined parameters.

    Produced by re-invocation rules; collected by FilterOrchestrator
    and dispatched (deduped) after the first filter pass.
    """

    engine_id: str
    config: dict = field(default_factory=dict)
    source_finding_id: str = ""
    rule_id: str = ""
