"""Session Orchestrator — canonical auth store, rate limiting, target type detection.

All engines read auth via get_auth() / has_auth(). They NEVER re-authenticate.
Rate limiting uses a simple rolling-window token bucket per target.
Target type detection delegates to target_classification.classify_target() —
the canonical single source of truth shared with NmapEngine and any future
engine that needs to gate on target locality.

Two auth sub-stores, both owned here:
  _api_auth_store   — investigation-scoped; keyed by investigation_id.
                      V2 engines write via store_auth(); read via get_auth().
  _target_auth      — target-URL-scoped; keyed by base URL.
                      ACTIVE-LEGACY probes (suggestions/probes.py) write via
                      store_target_auth(); read via get_target_auth().
                      Operator refresh via refresh_target_auth() clears expiry.
                      Expiry is surfaced in admin UI; refresh is operator-driven only.
"""
from __future__ import annotations

import logging
import time

from apps.conductor.engines.base import SessionStore
from apps.conductor.events.bus import EventBus

logger = logging.getLogger("conductor.orchestrators.session")

_DEFAULT_BUDGET = 100       # requests per window
_WINDOW_SECONDS = 60.0      # rolling window duration
_COOLDOWN_SECONDS = 60.0    # how long to pause after budget exhaustion


class _RateBucket:
    """Per-target token-bucket rate limiter (rolling window)."""

    def __init__(self, budget: int = _DEFAULT_BUDGET, window: float = _WINDOW_SECONDS) -> None:
        self._budget = budget
        self._window = window
        self._requests: list[float] = []   # timestamps of recent requests
        self._cooling_until: float = 0.0

    def is_allowed(self) -> bool:
        now = time.time()
        if now < self._cooling_until:
            return False
        cutoff = now - self._window
        self._requests = [t for t in self._requests if t >= cutoff]
        return len(self._requests) < self._budget

    def record(self) -> None:
        self._requests.append(time.time())

    def enter_cooldown(self, duration: float = _COOLDOWN_SECONDS) -> None:
        self._cooling_until = time.time() + duration

    def wait_seconds(self) -> float:
        remaining = self._cooling_until - time.time()
        return max(0.0, remaining)

    def request_count(self) -> int:
        now = time.time()
        cutoff = now - self._window
        return len([t for t in self._requests if t >= cutoff])


class SessionOrchestrator(SessionStore):
    """Implements SessionStore + rate limiting + target type detection."""

    def __init__(self, bus: EventBus | None = None) -> None:
        self._bus = bus
        # { investigation_id: { "cookies": ..., "tokens": ..., ... } }
        self._api_auth_store: dict[str, dict] = {}
        # { base_url: auth_dict } — ACTIVE-LEGACY probe layer auth store
        self._target_auth: dict[str, dict] = {}
        # base URLs whose session has been marked expired (needs operator refresh)
        self._expired_targets: set[str] = set()
        # { target: _RateBucket }
        self._rate_buckets: dict[str, _RateBucket] = {}
        # { target: type_string }
        self._target_type_cache: dict[str, str] = {}

    # ── SessionStore interface ────────────────────────────────────────────────

    def get_auth(self, investigation_id: str) -> dict | None:
        return self._api_auth_store.get(investigation_id)

    def has_auth(self, investigation_id: str) -> bool:
        return investigation_id in self._api_auth_store

    def store_auth(self, investigation_id: str, auth: dict) -> None:
        self._api_auth_store[investigation_id] = auth
        logger.info("session: stored auth for investigation %s", investigation_id)

    # ── Target-URL auth store (ACTIVE-LEGACY probe layer) ────────────────────

    def store_target_auth(self, target_base: str, auth: dict) -> None:
        """Cache auth state for a target base URL. Called by probe_api_default_creds_auth."""
        self._target_auth[target_base] = auth
        self._expired_targets.discard(target_base)
        logger.info("session: stored target auth for %s", target_base)

    def get_target_auth(self, target_base: str) -> dict | None:
        """Return cached auth for target_base, or None if not authenticated."""
        return self._target_auth.get(target_base)

    def mark_target_expired(self, target_base: str) -> None:
        """Signal that the cached session for target_base was rejected by the target.

        The operator must call refresh_target_auth() to clear this state.
        No automatic re-authentication — per V2 decision 6.
        """
        self._expired_targets.add(target_base)
        logger.warning("session: target auth expired for %s — operator refresh required", target_base)

    def is_target_expired(self, target_base: str) -> bool:
        return target_base in self._expired_targets

    def refresh_target_auth(self, target_base: str, auth: dict) -> None:
        """Operator-driven refresh: replace expired auth and clear expiry flag.

        Only call this in response to explicit operator action — never called
        automatically. Stores new auth and clears the expired flag.
        """
        self._target_auth[target_base] = auth
        self._expired_targets.discard(target_base)
        logger.info("session: operator refreshed target auth for %s", target_base)

    # ── Rate limiting ─────────────────────────────────────────────────────────

    def _bucket(self, target: str) -> _RateBucket:
        if target not in self._rate_buckets:
            self._rate_buckets[target] = _RateBucket()
        return self._rate_buckets[target]

    def is_safe_to_fire(self, target: str) -> bool:
        return self._bucket(target).is_allowed()

    def can_dispatch(self, target: str) -> tuple[bool, float]:
        """Return (allowed, wait_seconds). wait_seconds is 0.0 when allowed."""
        bucket = self._bucket(target)
        if bucket.is_allowed():
            return True, 0.0
        return False, bucket.wait_seconds()

    def record_request(self, target: str) -> None:
        bucket = self._bucket(target)
        bucket.record()
        if not bucket.is_allowed():
            logger.warning("session: rate budget exhausted for %s — entering cooldown", target)
            bucket.enter_cooldown()

    def record_response(self, target: str, status_code: int) -> None:
        if status_code == 429:
            logger.warning("session: 429 received from %s — entering cooldown", target)
            self._bucket(target).enter_cooldown()

    def get_request_count(self, target: str) -> int:
        return self._bucket(target).request_count()

    # ── Target type detection ─────────────────────────────────────────────────

    def detect_target_type(self, target: str) -> str:
        """Stub: classify target as local/private/external. WAF detection deferred."""
        if target in self._target_type_cache:
            return self._target_type_cache[target]

        result = self._classify(target)
        self._target_type_cache[target] = result
        return result

    def _classify(self, target: str) -> str:
        from apps.conductor.engines.target_classification import classify_target
        return classify_target(target).value

    # ── Introspection ─────────────────────────────────────────────────────────

    def get_state(self) -> dict:
        return {
            "orchestrator": "session",
            "auth_investigations": list(self._api_auth_store.keys()),
            "target_auth": {
                t: {
                    "username": v.get("username", "?"),
                    "expired": t in self._expired_targets,
                }
                for t, v in self._target_auth.items()
            },
            "expired_targets": sorted(self._expired_targets),
            "rate_buckets": {
                t: {"requests": b.request_count(), "cooling_until": b._cooling_until}
                for t, b in self._rate_buckets.items()
            },
            "target_types": dict(self._target_type_cache),
        }
