"""Tests for DB writer target fix (PR K).

Verifies that _validation_update and _block_reason_update closures in
conductor.py import DB_PATH from apps.validation.database (validation.db),
NOT from the orchestration.db path that the conductor uses internally.
"""
from __future__ import annotations


def _read_conductor_source() -> str:
    with open("apps/conductor/conductor.py") as f:
        return f.read()


def test_validation_update_uses_validation_db():
    """_validation_update must import DB_PATH from apps.validation.database."""
    src = _read_conductor_source()
    # Accept both inline and multi-line parenthesized import forms that ruff may reformat.
    has_import = (
        "from apps.validation.database import DB_PATH" in src
        or ("from apps.validation.database import" in src and "DB_PATH" in src)
    )
    assert has_import, (
        "_validation_update must import DB_PATH from apps.validation.database, "
        "not use the conductor's orchestration.db path."
    )


def test_db_writer_does_not_use_conductor_db_path():
    """_validation_update must NOT connect to the conductor's _db_path closure var.

    The conductor's _db_path is orchestration.db which has no normalized_findings
    table — connecting to it would silently fail on every UPDATE.
    """
    src = _read_conductor_source()
    # The old pattern was: _db_path = db_path, then aiosqlite.connect(_db_path)
    # after the wire_db_writer() call. That binding is the bug.
    # After the fix, _db_path should not appear in the _validation_update closure.
    lines = src.splitlines()
    in_validation_update = False
    in_block_reason_update = False
    for line in lines:
        stripped = line.strip()
        if "async def _validation_update(" in stripped:
            in_validation_update = True
        if "async def _block_reason_update(" in stripped:
            in_block_reason_update = True
        if in_validation_update or in_block_reason_update:
            if "aiosqlite.connect(_db_path)" in stripped:
                raise AssertionError(
                    "DB writer closure still connects to _db_path (orchestration.db). "
                    "Must use DB_PATH from apps.validation.database instead."
                )
            # End of closure detected by the wire call
            if "wire_db_writer" in stripped or "wire_block_reason_writer" in stripped:
                in_validation_update = False
                in_block_reason_update = False
