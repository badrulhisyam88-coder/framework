"""Pattern 14 — Import-time Reachability Seam
(test_seam_import_time_reachability.py)

Risk: Deleting a module that has zero call-site usages but is still imported
at module load time by a retained module. The pre-deletion grep audit covers
call-site reachability (no runtime caller invokes the deleted code) but misses
top-level `import` / `from X import Y` statements in retained modules. The app
crashes with ImportError at startup before any HTTP request or runtime caller
would notice.

Originating case: PR VESTIGE-1 (Block C cleanup). Deleted modules in
`scanner_orchestration/` had zero call-site usages. Two retained ACTIVE-LEGACY
modules had top-level imports of the deleted code:
  - apps/scanner_orchestration/api/routes.py imported monitoring, profiles,
    target_resolution.resolver, target_resolution.diagnostics
  - apps/scanner_orchestration/services/orchestration_service.py imported
    execution.run, normalization.pipeline, profiles.scan_profiles, timeline.scan_events
Container crashed with ModuleNotFoundError on startup before any route could be served.

Invariant (post-Pattern-14): Before any deletion PR, pre-deletion grep must verify
BOTH views:
  (1) No call-site reference invokes the deleted code at runtime.
  (2) No module-level `import` or `from X import Y` in any retained module
      references the deleted code.

Static analysis is used for the FastAPI-dependent scanner_orchestration modules
(fastapi/aiosqlite are absent in the bare test environment — same constraint
documented in test_bootstrap_phase_awareness.py for routes.py). Runtime import
checks cover Conductor-path modules that work without those dependencies.
"""
from __future__ import annotations

import importlib
import pathlib

# ── Static analysis: VESTIGE-1 deleted modules must not appear in retained files ──
# Modules deleted by PR VESTIGE-1 (Block C cleanup, docs: /docs/_cleanup/block-c-closeout.md).
# If any retained file re-introduces a top-level import of these, startup crashes.

_VESTIGE_1_DELETED = [
    "apps.scanner_orchestration.monitoring",
    "apps.scanner_orchestration.profiles",
    "apps.scanner_orchestration.timeline",
    "apps.scanner_orchestration.execution.run",
    "apps.scanner_orchestration.target_resolution.resolver",
    "apps.scanner_orchestration.target_resolution.diagnostics",
    "apps.scanner_orchestration.target_resolution.docker",
    "apps.scanner_orchestration.target_resolution.validation",
    "apps.scanner_orchestration.normalization.pipeline",
    "apps.scanner_orchestration.normalization.cve_enricher",
]


def _scan_for_import(src: str, module: str) -> bool:
    """Return True if src contains a module-level (column-0) import of module.

    Only flags lines with no leading whitespace: top-level imports cause ImportError
    at module load time and crash the app on startup. Deferred imports inside
    function bodies (indented, typically wrapped in try/except) fail gracefully at
    call time and are not a startup-crash risk.
    """
    for line in src.splitlines():
        if line.startswith(f"import {module}") or line.startswith(f"from {module}"):
            return True
    return False


def test_routes_does_not_import_deleted_modules():
    """apps/scanner_orchestration/api/routes.py must not import any VESTIGE-1 deleted module.

    routes.py crashed on startup after PR VESTIGE-1 because it had top-level
    imports of monitoring and profiles submodules. If a future deletion leaves
    a top-level import of the deleted code in this file, this test catches it
    before the container is built — the exact failure mode VESTIGE-1 revealed.
    """
    src = pathlib.Path("apps/scanner_orchestration/api/routes.py").read_text()
    violations = [m for m in _VESTIGE_1_DELETED if _scan_for_import(src, m)]
    assert not violations, (
        "apps/scanner_orchestration/api/routes.py imports deleted VESTIGE-1 modules: "
        + ", ".join(violations)
        + ". These modules were deleted by PR VESTIGE-1 and must not appear in module-"
        "level imports of any retained file."
    )


def test_orchestration_service_does_not_import_deleted_modules():
    """apps/scanner_orchestration/services/orchestration_service.py must not import VESTIGE-1 modules.

    orchestration_service.py crashed after VESTIGE-1 deleted execution.run,
    normalization.pipeline, profiles.scan_profiles, timeline.scan_events.
    """
    src = pathlib.Path(
        "apps/scanner_orchestration/services/orchestration_service.py"
    ).read_text()
    violations = [m for m in _VESTIGE_1_DELETED if _scan_for_import(src, m)]
    assert not violations, (
        "apps/scanner_orchestration/services/orchestration_service.py imports deleted "
        "VESTIGE-1 modules: " + ", ".join(violations)
    )


# ── Runtime import checks for Conductor-path modules ──────────────────────────
# These modules do not require FastAPI/aiosqlite and import cleanly in the
# bare test environment.


def _try_import(module_path: str) -> str | None:
    """Return ImportError message if import fails, None on success."""
    try:
        importlib.import_module(module_path)
        return None
    except ImportError as exc:
        return str(exc)


def test_conductor_shared_importable():
    """apps.conductor.shared must import without ImportError."""
    err = _try_import("apps.conductor.shared")
    assert err is None, f"apps.conductor.shared import failed: {err}"


def test_bootstrap_runtime_importable():
    """apps.investigation_workspace.bootstrap.runtime must import without ImportError."""
    err = _try_import("apps.investigation_workspace.bootstrap.runtime")
    assert err is None, (
        f"apps.investigation_workspace.bootstrap.runtime import failed: {err}"
    )


# ── Mechanism validation ───────────────────────────────────────────────────────


def test_static_scanner_detects_column0_import_flags_as_violation():
    """Proves _scan_for_import() catches a column-0 top-level import (the VESTIGE-1 pattern).

    A column-0 `from <deleted_module> import ...` is what caused the startup crash.
    The scanner must flag it.
    """
    synthetic_src = (
        "from apps.scanner_orchestration.monitoring.scanner_monitor import ScanMonitor\n"
        "from apps.scanner_orchestration.profiles.scan_profiles import ALL_PROFILES\n"
    )
    assert _scan_for_import(synthetic_src, "apps.scanner_orchestration.monitoring"), (
        "_scan_for_import() failed to flag a column-0 top-level import — detection broken."
    )


def test_static_scanner_ignores_indented_deferred_import():
    """Proves _scan_for_import() does NOT flag indented deferred imports.

    Indented imports inside function bodies (e.g., inside try/except ImportError)
    fail gracefully at call time rather than crashing startup. They must NOT be
    flagged as violations by the Pattern 14 scanner.
    """
    synthetic_src = (
        "async def _execute(self, scan):\n"
        "    try:\n"
        "        from apps.scanner_orchestration.target_resolution.resolver import TargetResolver\n"
        "    except ImportError as e:\n"
        "        raise RuntimeError('unavailable') from e\n"
    )
    assert not _scan_for_import(synthetic_src, "apps.scanner_orchestration.target_resolution.resolver"), (
        "_scan_for_import() incorrectly flagged an indented deferred import. "
        "Only column-0 top-level imports are startup-crash risks."
    )


def test_import_failure_is_detectable():
    """Proves _try_import() catches ImportError for a non-existent module.

    Synthetic: apps._synthetic_deleted_module_for_pattern14 does not exist.
    If this test passes (err is not None), the runtime mechanism works — a
    re-introduced bad import in a non-FastAPI module would be caught here.
    """
    err = _try_import("apps._synthetic_deleted_module_for_pattern14")
    assert err is not None, (
        "_try_import() returned None for a module that does not exist — "
        "the runtime detection mechanism is broken."
    )
    assert "No module named" in err, (
        f"Expected 'No module named' in the error string; got: {err!r}"
    )
