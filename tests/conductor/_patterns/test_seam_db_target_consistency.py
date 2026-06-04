"""Seam tests: DB writers connect to the DB their readers query.

Pattern: WRONG DB TARGET (PR K bug)
  Bug example: FilterOrchestrator's _validation_update and _block_reason_update
    captured _db_path from the conductor's own _db_path = Path("data/orchestration.db").
    normalized_findings table lives only in /app/data/validation.db.
    Every UPDATE silently no-oped — orchestration.db has no normalized_findings table.
    The bug was invisible to operator UI until live verification.
    Fix: import DB_PATH from apps.validation.database inside the closures.

  Test assertion: every DB writer in the system connects to a DB that the
  corresponding reader can query. Validation writer + reader = same path source.
"""
from __future__ import annotations


def test_validation_writer_uses_validation_db_path():
    """_validation_update and _block_reason_update in conductor.py must import
    DB_PATH from apps.validation.database — not use the conductor's own db_path.

    The conductor's orchestration.db does not contain a normalized_findings table.
    Any UPDATE targeting orchestration.db is a silent no-op.
    """
    with open("apps/conductor/conductor.py") as f:
        src = f.read()

    assert "from apps.validation.database" in src and "DB_PATH" in src, (
        "conductor.py DB writers do not import DB_PATH from apps.validation.database. "
        "They may be targeting orchestration.db which has no normalized_findings table."
    )
    # Ensure the old pattern (closure over _db_path) is gone
    lines = src.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        is_writer = (
            "async def _validation_update(" in stripped
            or "async def _block_reason_update(" in stripped
        )
        if is_writer:
            context = "\n".join(lines[i : i + 15])
            assert "aiosqlite.connect(_db_path)" not in context, (
                f"DB writer on line {i + 1} still connects to _db_path (orchestration.db). "
                "Must use DB_PATH from apps.validation.database."
            )


def test_conductor_and_validation_dbs_are_separate():
    """Conductor orchestration DB and validation DB must be different paths.

    This is by design — the conductor tracks investigation lifecycle state
    while the validation DB tracks findings and their validation status.
    They must not be conflated.

    Uses source inspection to avoid importing aiosqlite (not available on host).
    """
    import re

    with open("apps/conductor/shared.py") as f:
        shared_src = f.read()
    with open("apps/validation/database.py") as f:
        db_src = f.read()

    # Extract orchestration DB path from shared.py
    m = re.search(r'db_path\s*=\s*Path\("([^"]+)"\)', shared_src)
    assert m, "Could not find db_path in apps/conductor/shared.py"
    orchestration_path = m.group(1)

    # Extract validation DB path from database.py
    m2 = re.search(r'DB_PATH\s*=\s*Path\("([^"]+)"\)', db_src)
    assert m2, "Could not find DB_PATH in apps/validation/database.py"
    validation_path = m2.group(1)

    assert orchestration_path != validation_path, (
        f"Conductor DB '{orchestration_path}' and validation DB '{validation_path}' "
        "are the same path. These are separate DBs by design — conflating them "
        "causes table-not-found errors."
    )


def test_validation_db_path_is_absolute_in_container():
    """Validation DB path must be absolute (/app/data/...) not relative.

    A relative path like 'data/validation.db' would resolve differently depending
    on the working directory at import time — a subtle deployment footgun.
    """
    import re

    with open("apps/validation/database.py") as f:
        src = f.read()

    m = re.search(r'DB_PATH\s*=\s*Path\("([^"]+)"\)', src)
    assert m, "Could not find DB_PATH definition in apps/validation/database.py"
    path_str = m.group(1)

    assert path_str.startswith("/"), (
        f"Validation DB_PATH={path_str!r} is relative. "
        "Must be absolute (/app/data/...) to avoid working-directory-dependent resolution."
    )
