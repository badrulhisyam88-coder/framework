"""Unit tests for SessionOrchestrator target-auth interface (V2.1 auth store merge).

Tests cover:
  - store/get round-trip
  - expired state transitions
  - operator refresh path
  - get_state() includes target_auth and expired_targets
  - no automatic re-authentication occurs
"""
from __future__ import annotations

import pytest

from apps.conductor.orchestrators.session import SessionOrchestrator


@pytest.fixture
def session():
    return SessionOrchestrator()


def test_store_and_get_target_auth(session):
    auth = {"username": "admin", "session_cookies": {"sid": "abc123"}}
    session.store_target_auth("http://target.local:3000", auth)
    result = session.get_target_auth("http://target.local:3000")
    assert result == auth


def test_get_unknown_target_returns_none(session):
    assert session.get_target_auth("http://unknown.target") is None


def test_mark_expired_sets_flag(session):
    session.store_target_auth("http://t.local", {"username": "u"})
    assert not session.is_target_expired("http://t.local")
    session.mark_target_expired("http://t.local")
    assert session.is_target_expired("http://t.local")


def test_expired_target_auth_still_readable(session):
    """Auth dict survives expiry — admin panel needs it for display."""
    session.store_target_auth("http://t.local", {"username": "alice"})
    session.mark_target_expired("http://t.local")
    cached = session.get_target_auth("http://t.local")
    assert cached is not None
    assert cached["username"] == "alice"


def test_refresh_clears_expiry(session):
    session.store_target_auth("http://t.local", {"username": "alice"})
    session.mark_target_expired("http://t.local")
    session.refresh_target_auth("http://t.local", {"username": "alice2", "session_cookies": {"sid": "new"}})
    assert not session.is_target_expired("http://t.local")
    assert session.get_target_auth("http://t.local")["username"] == "alice2"


def test_refresh_does_not_auto_reauth():
    """refresh_target_auth is a passive store-and-clear; it must not trigger HTTP.

    Verified structurally: refresh_target_auth must contain no http/request calls.
    """
    import inspect
    from apps.conductor.orchestrators.session import SessionOrchestrator

    src = inspect.getsource(SessionOrchestrator.refresh_target_auth)
    for keyword in ("httpx", "requests", "aiohttp", "urllib", "login", "authenticate"):
        assert keyword not in src, (
            f"refresh_target_auth contains '{keyword}' — this looks like automatic "
            "re-authentication, which violates V2 decision 6 (operator-driven refresh only)."
        )


def test_store_target_auth_clears_prior_expiry(session):
    session.store_target_auth("http://t.local", {"username": "u1"})
    session.mark_target_expired("http://t.local")
    session.store_target_auth("http://t.local", {"username": "u2"})
    assert not session.is_target_expired("http://t.local")


def test_get_state_includes_target_auth(session):
    session.store_target_auth("http://t.local", {"username": "admin"})
    state = session.get_state()
    assert "target_auth" in state
    assert "http://t.local" in state["target_auth"]
    assert state["target_auth"]["http://t.local"]["username"] == "admin"


def test_get_state_includes_expired_targets(session):
    session.store_target_auth("http://t.local", {"username": "admin"})
    session.mark_target_expired("http://t.local")
    state = session.get_state()
    assert "expired_targets" in state
    assert "http://t.local" in state["expired_targets"]


def test_get_state_expired_flag_in_target_auth(session):
    session.store_target_auth("http://t.local", {"username": "admin"})
    session.mark_target_expired("http://t.local")
    state = session.get_state()
    assert state["target_auth"]["http://t.local"]["expired"] is True


def test_multiple_targets_independent(session):
    session.store_target_auth("http://a.local", {"username": "alice"})
    session.store_target_auth("http://b.local", {"username": "bob"})
    session.mark_target_expired("http://a.local")
    assert session.is_target_expired("http://a.local")
    assert not session.is_target_expired("http://b.local")


def test_investigation_scoped_store_unaffected(session):
    """Investigation-scoped store must be independent of target-auth store."""
    session.store_auth("inv_001", {"token": "abc"})
    session.store_target_auth("http://t.local", {"username": "admin"})
    assert session.get_auth("inv_001") == {"token": "abc"}
    assert session.get_target_auth("http://t.local")["username"] == "admin"
    # Expiring target does not affect investigation auth
    session.mark_target_expired("http://t.local")
    assert session.get_auth("inv_001") == {"token": "abc"}
