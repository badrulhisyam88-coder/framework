"""Category 3 — Static asset reference checks.

Helpers for reading JS/HTML/template source files as text and asserting on
the presence or absence of specific strings. Used after atomic retirements
to verify cleanup is complete on the frontend side.

No external dependencies beyond the standard library. Works in the bare
test environment.

Typical use — verify a retired identifier was removed:
    from tests.frontend.asset_helpers import assert_absent, assert_present

    # After an atomic engine-lift PR retires an action_kind:
    assert_absent("frontend/static/js/exploit-tree.js", "csp_xss_reflected")

    # Verify a required structural element is still there:
    assert_present("frontend/static/js/exploit-tree.js", "CRITICAL_KINDS")
"""
from __future__ import annotations

import pathlib

_PROJECT_ROOT = pathlib.Path(__file__).parents[2]


def _resolve(file_path: str | pathlib.Path) -> pathlib.Path:
    p = pathlib.Path(file_path)
    return p if p.is_absolute() else _PROJECT_ROOT / p


def read_source(file_path: str | pathlib.Path) -> str:
    """Return the full text content of a source file."""
    return _resolve(file_path).read_text(encoding="utf-8")


def grep_source(file_path: str | pathlib.Path, text: str) -> list[int]:
    """Return a list of 1-based line numbers containing text.

    Returns an empty list if text is not found.
    """
    lines = read_source(file_path).splitlines()
    return [i + 1 for i, line in enumerate(lines) if text in line]


def assert_absent(file_path: str | pathlib.Path, text: str) -> None:
    """Assert text does not appear anywhere in the file.

    Raises AssertionError with the offending line numbers if found.
    Used after atomic retirements to verify the frontend cleanup is complete.
    """
    hits = grep_source(file_path, text)
    assert not hits, (
        f"{text!r} still present in {file_path} at line(s) {hits}. "
        "This identifier was retired — remove it from the frontend file."
    )


def assert_present(file_path: str | pathlib.Path, text: str) -> list[int]:
    """Assert text appears at least once in the file.

    Returns the list of matching line numbers.
    Raises AssertionError if text is not found.
    Used to verify that expected structural elements still exist after refactors.
    """
    hits = grep_source(file_path, text)
    assert hits, (
        f"{text!r} not found in {file_path}. "
        "Expected this identifier to be present — check that the file was not accidentally modified."
    )
    return hits


def count_occurrences(file_path: str | pathlib.Path, text: str) -> int:
    """Return the total number of lines in file_path that contain text."""
    return len(grep_source(file_path, text))
