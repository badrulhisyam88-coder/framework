"""Validate vault export documents before writing.

Checks that required frontmatter fields are present, well-formed, and
consistent with EXPORT_STANDARDS.md naming conventions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

_FIND_ID_RE = re.compile(r"^FIND-(WEB|API|NET|CLOUD)-\d{8}-\d{3}$")
_REM_ID_RE = re.compile(r"^REM-(WEB|API|NET|CLOUD)-\d{8}-\d{3}$")
_CHAIN_ID_RE = re.compile(r"^CHAIN-\d{8}-\d{3}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_VALID_CATEGORIES = frozenset({"web", "api", "network", "cloud"})
_VALID_STATUSES = frozenset({"draft", "confirmed", "remediated"})


@dataclass
class ValidationResult:
    valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def fail(self, msg: str) -> None:
        self.valid = False
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def validate_finding_frontmatter(fm: dict) -> ValidationResult:
    result = ValidationResult()

    # Required fields
    _required = (
        "type", "id", "title", "date", "severity", "category",
        "source", "target", "status", "tags",
    )
    for key in _required:
        if key not in fm:
            result.fail(f"Missing required frontmatter field: {key!r}")

    if result.errors:
        return result

    # Type check
    if fm.get("type") != "finding":
        result.fail(f"type must be 'finding', got {fm.get('type')!r}")

    # ID format
    fid = fm.get("id", "")
    if not _FIND_ID_RE.match(str(fid)):
        result.fail(f"id does not match FIND-<CATEGORY>-<YYYYMMDD>-<NNN> format: {fid!r}")

    # Date format
    if not _DATE_RE.match(str(fm.get("date", ""))):
        result.fail(f"date must be YYYY-MM-DD, got {fm.get('date')!r}")

    # Severity
    if fm.get("severity") not in _VALID_SEVERITIES:
        result.fail(f"severity must be one of {_VALID_SEVERITIES}, got {fm.get('severity')!r}")

    # Category
    if fm.get("category") not in _VALID_CATEGORIES:
        result.fail(f"category must be one of {_VALID_CATEGORIES}, got {fm.get('category')!r}")

    # Tags must be a non-empty list
    tags = fm.get("tags", [])
    if not isinstance(tags, list) or not tags:
        result.warn("tags should be a non-empty list")

    return result


def validate_remediation_frontmatter(fm: dict) -> ValidationResult:
    result = ValidationResult()

    for key in ("type", "id", "title", "date", "category", "severity", "status", "tags"):
        if key not in fm:
            result.fail(f"Missing required frontmatter field: {key!r}")

    if result.errors:
        return result

    if fm.get("type") != "remediation":
        result.fail(f"type must be 'remediation', got {fm.get('type')!r}")

    rid = fm.get("id", "")
    if not _REM_ID_RE.match(str(rid)):
        result.fail(f"id does not match REM-<CATEGORY>-<YYYYMMDD>-<NNN> format: {rid!r}")

    if not _DATE_RE.match(str(fm.get("date", ""))):
        result.fail(f"date must be YYYY-MM-DD, got {fm.get('date')!r}")

    return result


def validate_attack_chain_frontmatter(fm: dict) -> ValidationResult:
    result = ValidationResult()

    for key in ("type", "id", "title", "date", "initial_access", "outcome", "tags"):
        if key not in fm:
            result.fail(f"Missing required frontmatter field: {key!r}")

    if result.errors:
        return result

    if fm.get("type") != "attack-chain":
        result.fail(f"type must be 'attack-chain', got {fm.get('type')!r}")

    cid = fm.get("id", "")
    if not _CHAIN_ID_RE.match(str(cid)):
        result.fail(f"id does not match CHAIN-<YYYYMMDD>-<NNN> format: {cid!r}")

    if not _DATE_RE.match(str(fm.get("date", ""))):
        result.fail(f"date must be YYYY-MM-DD, got {fm.get('date')!r}")

    return result


def validate_markdown_content(content: str) -> ValidationResult:
    """Basic structural checks on rendered markdown."""
    result = ValidationResult()

    if not content.startswith("---"):
        result.fail("Document must start with YAML frontmatter (---)")

    closing = content.find("---", 3)
    if closing == -1:
        result.fail("YAML frontmatter closing delimiter (---) not found")

    if "# " not in content:
        result.warn("Document has no H1 heading")

    return result
