"""Pattern 16 — Engine Auth Write Seam (test_seam_engine_auth_write.py)

Risk (V2.2 Step 8): Engines that capture credentials as their exploitation
outcome (e.g., DefaultCredsEngine) must write that auth state back through
OutputChannel.store_auth() so downstream engines can read it via
session_store.get_auth(). Silent failure mode: the engine records a
successful credential capture and emits a finding, but never writes the
credentials to the SessionOrchestrator. Downstream engines call
session_store.get_auth() and receive None; they run unauthenticated and
produce false exhaustion records.

Invariants:
  - OutputChannel exposes store_auth(investigation_id, auth) method
  - store_auth() delegates to SessionOrchestrator.store_auth()
  - After store_auth(), session_store.get_auth(investigation_id) returns
    the stored dict
  - Falsy-but-non-None values (empty dict) write through — engine controls
    success/failure logic, not the channel
  - Unknown investigation_id writes to the store under that key
    (no validation — consistent with store_target_auth() semantics)
"""
from __future__ import annotations

from unittest.mock import MagicMock


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_output_channel(investigation_id: str = "inv_001") -> tuple:
    """Return (channel, session_orch) pair with a real SessionOrchestrator."""
    from apps.conductor.engines.base import OutputChannel
    from apps.conductor.orchestrators.session import SessionOrchestrator

    session_orch = SessionOrchestrator()
    findings_orch = MagicMock()
    channel = OutputChannel(
        investigation_id=investigation_id,
        engine_id="test_engine",
        findings_orch=findings_orch,
        session_orch=session_orch,
    )
    return channel, session_orch


# ── Pattern 16 tests ──────────────────────────────────────────────────────────


def test_output_channel_exposes_store_auth():
    """OutputChannel must have a store_auth(investigation_id, auth) method."""
    from apps.conductor.engines.base import OutputChannel

    assert hasattr(OutputChannel, "store_auth"), (
        "OutputChannel is missing store_auth() — engines that produce auth state "
        "have no path to write credentials to the session store without taking a "
        "direct dependency on SessionOrchestrator."
    )
    assert callable(OutputChannel.store_auth)


def test_store_auth_write_through_returns_via_get_auth():
    """store_auth() delegates to SessionOrchestrator; get_auth() reads it back.

    This is the core invariant: a credential-producing engine calls
    channel.store_auth(inv_id, auth) and a downstream engine calling
    session_store.get_auth(inv_id) receives the same dict.
    """
    channel, session_orch = _make_output_channel("inv_p16_a")
    auth = {"cookies": {"session": "abc123"}, "token": "tok_xyz"}

    channel.store_auth("inv_p16_a", auth)

    result = session_orch.get_auth("inv_p16_a")
    assert result == auth, (
        "store_auth() did not write through to SessionOrchestrator — "
        "downstream engines would receive None from get_auth()."
    )


def test_store_auth_empty_dict_writes_through():
    """store_auth() with an empty dict writes through — no silent no-op for falsy values.

    Engine controls whether credentials are valid. The channel must not
    silently suppress an empty write; the caller decides what constitutes success.
    """
    channel, session_orch = _make_output_channel("inv_p16_b")

    channel.store_auth("inv_p16_b", {})

    result = session_orch.get_auth("inv_p16_b")
    assert result == {}, (
        "store_auth({}) was silently dropped — falsy auth dicts must still write "
        "through so the engine's explicit 'success with empty creds' is preserved."
    )


def test_store_auth_unknown_investigation_id_writes_to_store():
    """store_auth() for an investigation_id not previously seen writes to the store.

    No validation — consistent with store_target_auth() semantics.
    The credential engine may run before any other engine has touched the
    session store for that investigation.
    """
    channel, session_orch = _make_output_channel("inv_p16_c")
    auth = {"cookies": {"admin": "session_token"}}

    channel.store_auth("inv_p16_unknown", auth)

    result = session_orch.get_auth("inv_p16_unknown")
    assert result == auth, (
        "store_auth() rejected an unknown investigation_id — engines must be able "
        "to write auth for an investigation_id regardless of prior store state."
    )
