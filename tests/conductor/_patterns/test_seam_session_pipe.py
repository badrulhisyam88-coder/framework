"""Seam tests: unified investigation-scoped auth store — single owner, single instance.

Pattern: SESSION-PIPE-SEAM (V2.1 auth store merge + V2.1 Step 2b unification)
  Risk (original): Duplicate _API_AUTH_STORE in suggestions/probes.py captures auth
    state in a module-level dict invisible to SessionOrchestrator. V2 engines reading
    from SessionOrchestrator.get_target_auth() would always get None even after a
    successful probe_api_default_creds_auth run.

  Risk (V2.1 Step 2b): Process-level Conductor.session_orch acted as a second
    SessionOrchestrator instance. Probes writing to it could not be read by V2
    engines querying the per-investigation session_orch on _InvestigationContext.

  Unified invariant (post-Step 2b):
    - One SessionOrchestrator per investigation, owned by _InvestigationContext.
    - Conductor has NO process-level session_orch.
    - INVESTIGATION_ID_CTX (set in _runner_from_probe) lets probe functions route
      auth reads/writes to the correct per-investigation store without signature changes.

  Test assertions:
    1. No module-level _API_AUTH_STORE dict exists in investigation_workspace/.
    2. SessionOrchestrator has the target-auth interface (store/get/mark/refresh).
    3. Conductor has NO session_orch attribute (process-level store removed).
    4. INVESTIGATION_ID_CTX is exported from execution/runtime.py.
    5. refresh_target_auth clears the expired flag (no automatic re-auth).
    6. mark_target_expired + get_target_auth still returns the stale entry.
"""
from __future__ import annotations

import ast
import os


def _py_files_under(root: str):
    for dirpath, _, filenames in os.walk(root):
        if "__pycache__" in dirpath:
            continue
        for fname in filenames:
            if fname.endswith(".py"):
                yield os.path.join(dirpath, fname)


def test_no_module_level_api_auth_store_dict_in_workspace():
    """No module-level _API_AUTH_STORE dict may exist in investigation_workspace/.

    The consolidated store lives in SessionOrchestrator. Any module-level dict
    in the workspace layer would be a shadow copy that engines cannot read.
    """
    workspace_root = "apps/investigation_workspace"
    violations = []

    for fpath in _py_files_under(workspace_root):
        try:
            with open(fpath, encoding="utf-8") as f:
                src = f.read()
        except OSError:
            continue

        if "_API_AUTH_STORE" not in src:
            continue

        try:
            tree = ast.parse(src, filename=fpath)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "_API_AUTH_STORE":
                        violations.append(f"{fpath}:{node.lineno}")

    assert not violations, (
        f"Found module-level _API_AUTH_STORE dict in {violations}. "
        "All auth state must live in SessionOrchestrator. "
        "This is the Pattern 4 variant bug: scope capture in a module dict "
        "means V2 engines calling get_target_auth() always see None."
    )


def test_session_orchestrator_has_target_auth_interface():
    """SessionOrchestrator must expose store/get/mark/refresh target auth methods."""
    from apps.conductor.orchestrators.session import SessionOrchestrator

    required = [
        "store_target_auth",
        "get_target_auth",
        "mark_target_expired",
        "is_target_expired",
        "refresh_target_auth",
    ]
    for method in required:
        assert hasattr(SessionOrchestrator, method), (
            f"SessionOrchestrator missing '{method}'. "
            "Probe layer readers/writers depend on this interface."
        )


def test_conductor_has_no_process_level_session_orch():
    """Conductor must NOT have a session_orch attribute.

    Post-Step-2b invariant: auth state lives exclusively in per-investigation
    _InvestigationContext.session_orch instances. A process-level store on
    Conductor is the bug this pattern guards against — probes writing to it
    write to a scope invisible to V2 exploitation engines.
    """
    from apps.conductor.conductor import Conductor

    assert not hasattr(Conductor, "session_orch") or callable(getattr(Conductor, "session_orch", None)), (
        "Conductor has a session_orch class attribute. "
        "The process-level store was removed in V2.1 Step 2b. "
        "All auth must be investigation-scoped via _InvestigationContext.session_orch."
    )
    # Verify instance also has no session_orch
    from unittest.mock import MagicMock, patch
    import sqlite3

    mock_db = MagicMock(spec=sqlite3.Connection)
    mock_db.execute.return_value = mock_db
    mock_db.commit.return_value = None
    with patch("apps.conductor.conductor.init_db", return_value=mock_db):
        c = Conductor()
    assert not hasattr(c, "session_orch"), (
        "Conductor instance has session_orch. "
        "Process-level auth store must not exist after Step 2b. "
        "Auth is investigation-scoped only."
    )


def test_investigation_id_ctx_exported_from_runtime():
    """INVESTIGATION_ID_CTX must be exported from execution/runtime.

    This ContextVar is what lets probe functions (with fixed `target: str`
    signatures) locate the correct per-investigation SessionOrchestrator.
    If it's absent, _get_session_orch() in probes.py falls back to ephemeral
    instances and auth writes are silently discarded in production flow.
    """
    from apps.investigation_workspace.execution import runtime

    assert hasattr(runtime, "INVESTIGATION_ID_CTX"), (
        "INVESTIGATION_ID_CTX missing from execution/runtime.py. "
        "This ContextVar threads investigation_id into probe functions "
        "without changing their signatures. Its absence means auth writes "
        "from probes are silently discarded."
    )
    from contextvars import ContextVar
    assert isinstance(runtime.INVESTIGATION_ID_CTX, ContextVar), (
        "INVESTIGATION_ID_CTX must be a ContextVar instance."
    )


def test_runner_sets_investigation_id_ctx():
    """_runner_from_probe must set INVESTIGATION_ID_CTX before calling the probe.

    Verified structurally: the source of _runner_from_probe must contain
    INVESTIGATION_ID_CTX.set. If absent, all probe auth writes land in
    ephemeral SessionOrchestrator instances and are silently lost.
    """
    import inspect
    from apps.investigation_workspace.execution.runtime import _runner_from_probe

    src = inspect.getsource(_runner_from_probe)
    assert "INVESTIGATION_ID_CTX.set" in src, (
        "_runner_from_probe does not set INVESTIGATION_ID_CTX. "
        "The probe cannot locate the investigation-scoped SessionOrchestrator "
        "without this ContextVar being set before the probe is called."
    )


def test_refresh_clears_expiry_no_auto_reauth():
    """refresh_target_auth must clear the expired flag.

    Critically: it must NOT be called automatically by any non-operator path.
    This test verifies the state machine: mark_expired → still expired →
    refresh_target_auth → no longer expired. The call itself is manual.
    """
    from apps.conductor.orchestrators.session import SessionOrchestrator

    s = SessionOrchestrator()
    base = "http://target.example.com"

    s.store_target_auth(base, {"username": "admin", "session_cookies": {"sid": "abc"}})
    assert not s.is_target_expired(base)

    s.mark_target_expired(base)
    assert s.is_target_expired(base)

    assert s.get_target_auth(base) is not None

    s.refresh_target_auth(base, {"username": "admin", "session_cookies": {"sid": "xyz"}})
    assert not s.is_target_expired(base)
    refreshed = s.get_target_auth(base)
    assert refreshed is not None
    assert refreshed["session_cookies"]["sid"] == "xyz"


def test_mark_expired_does_not_clear_cached_auth():
    """Expiry flag must not delete the cached auth dict.

    The operator UI must still be able to display which user was authenticated
    before the session expired. Clearing the dict on expiry would make the
    admin panel show no entry at all — silent loss of context.
    """
    from apps.conductor.orchestrators.session import SessionOrchestrator

    s = SessionOrchestrator()
    base = "http://target.example.com"
    s.store_target_auth(base, {"username": "wiener", "session_cookies": {"session": "tok"}})
    s.mark_target_expired(base)

    cached = s.get_target_auth(base)
    assert cached is not None, (
        "get_target_auth returned None after mark_target_expired. "
        "The cached entry must survive expiry so the admin panel can display it."
    )
    assert cached["username"] == "wiener"


def test_store_target_auth_implicitly_clears_expiry():
    """Writing new auth via store_target_auth must clear any prior expiry flag.

    A fresh successful login should not land the session immediately in an
    expired state if mark_target_expired was called in a previous session.
    """
    from apps.conductor.orchestrators.session import SessionOrchestrator

    s = SessionOrchestrator()
    base = "http://target.example.com"
    s.store_target_auth(base, {"username": "old"})
    s.mark_target_expired(base)
    assert s.is_target_expired(base)

    s.store_target_auth(base, {"username": "new"})
    assert not s.is_target_expired(base), (
        "is_target_expired still True after store_target_auth. "
        "A fresh auth write must clear the expiry flag."
    )
