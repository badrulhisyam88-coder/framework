"""User-taught finding suppression.

A `KnownIssue` rule encodes a pattern the operator has marked as not a real
issue in their environment. After a plugin produces a Finding, executor calls
:func:`match_rule` to see if any known_issue silently suppresses it.

`finding_type` on the rule names the type to match. The rule's `match_value`
carries the secondary criterion (port, evidence substring, validation_status,
or CVE id), interpreted by `match_field`.
"""

from __future__ import annotations

from apps.validation.models import (
    Finding,
    KnownIssue,
    KnownIssueMatchField,
    Service,
)


def match_rule(
    finding: Finding,
    rule: KnownIssue,
    service: Service | None = None,
) -> bool:
    """Return True when the rule suppresses this finding."""
    field = rule.match_field

    if field == KnownIssueMatchField.CVE_ID:
        return bool(finding.cve_id) and finding.cve_id == rule.match_value

    if finding.finding_type != rule.finding_type:
        return False

    if field == KnownIssueMatchField.FINDING_TYPE:
        return True

    if field == KnownIssueMatchField.FINDING_TYPE_PORT:
        port = service.port if service else None
        return port is not None and str(port) == str(rule.match_value)

    if field == KnownIssueMatchField.FINDING_TYPE_EVIDENCE_CONTAINS:
        needle = rule.match_value.lower()
        blobs = [
            finding.evidence.sent or "",
            finding.evidence.received or "",
            finding.evidence.raw_output or "",
        ]
        return any(needle in (b or "").lower() for b in blobs)

    if field == KnownIssueMatchField.FINDING_TYPE_VALIDATION_STATUS:
        return str(finding.validation_status) == rule.match_value

    return False


def first_matching_rule(
    finding: Finding,
    rules: list[KnownIssue],
    service: Service | None = None,
) -> KnownIssue | None:
    """First rule that suppresses the finding, or None."""
    for rule in rules:
        if match_rule(finding, rule, service):
            return rule
    return None
