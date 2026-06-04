"""Ordered rule registry for FilterOrchestrator.

Evaluation order: drop rules first, then validate, then incomplete.
First match wins per finding.

REINVOCATION_RULES run separately (after first pass, collect requests,
dedup, dispatch).

Ordering note: IncompleteServiceVersionUnknown is injected before
ValidateServiceDetectedWithVersion. Without this, service_detected
findings with version="unknown" (truthy string) would be falsely
validated instead of marked incomplete.
"""
from __future__ import annotations

from apps.conductor.rules.drop_rules import DROPPED_RULES
from apps.conductor.rules.incomplete_rules import INCOMPLETE_RULES, IncompleteServiceVersionUnknown
from apps.conductor.rules.reinvocation_rules import REINVOCATION_RULES
from apps.conductor.rules.validate_rules import VALIDATE_RULES

_svu = IncompleteServiceVersionUnknown()
_validate_insert = next(
    i for i, r in enumerate(VALIDATE_RULES) if r.id == "validate_service_detected_with_version"
)

REGISTERED_RULES = [
    *DROPPED_RULES,
    *VALIDATE_RULES[:_validate_insert],
    _svu,
    *VALIDATE_RULES[_validate_insert:],
    *INCOMPLETE_RULES,
]

__all__ = ["REGISTERED_RULES", "REINVOCATION_RULES"]
