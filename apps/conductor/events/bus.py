"""In-process event bus — sync subscribe, async emit.

Events use the structured format defined in docs/architecture/orchestration.md:
  { orchestrator, event_type, investigation_id, correlation_id, timestamp, payload }

No external broker. No persistence (PR A). Subscribers receive a copy of the
dict on each emit.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

logger = logging.getLogger("conductor.events.bus")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class SubscriptionHandle:
    """Returned by subscribe(); call .cancel() to stop receiving events."""

    def __init__(self, bus: EventBus, callback: Callable[[dict], Any]) -> None:
        self._bus = bus
        self._callback = callback

    def cancel(self) -> None:
        self._bus._unsubscribe(self._callback)


class EventBus:
    """Singleton-friendly in-process pub-sub. Thread-safe for asyncio tasks."""

    def __init__(self) -> None:
        self._subscribers: list[Callable[[dict], Any]] = []

    def subscribe(self, callback: Callable[[dict], Any]) -> SubscriptionHandle:
        """Register *callback* to receive every future event dict."""
        self._subscribers.append(callback)
        return SubscriptionHandle(self, callback)

    def _unsubscribe(self, callback: Callable[[dict], Any]) -> None:
        try:
            self._subscribers.remove(callback)
        except ValueError:
            pass

    async def emit(
        self,
        orchestrator: str,
        event_type: str,
        investigation_id: str,
        payload: dict,
        correlation_id: str | None = None,
    ) -> None:
        """Emit a structured event to all current subscribers."""
        event: dict = {
            "orchestrator": orchestrator,
            "event_type": event_type,
            "investigation_id": investigation_id,
            "correlation_id": correlation_id or str(uuid4()),
            "timestamp": _now_iso(),
            "payload": payload,
        }
        for cb in list(self._subscribers):
            try:
                result = cb(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("event subscriber raised during %s", event_type)


# Module-level singleton — orchestrators share this instance.
bus: EventBus = EventBus()
