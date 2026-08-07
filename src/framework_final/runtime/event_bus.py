"""EventBus: in-process publish/subscribe.

Runtime-owned transport, not a swappable Capability -- everything else in a
running Application depends on Event delivery existing reliably, so it is
foundational plumbing rather than optional infrastructure (see
docs/ARCHITECTURE.md). The underlying transport technology is deliberately
hidden behind this one interface, so it can change later without any
Module or Capability noticing.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

from framework_final.platform.event import Event

EventHandler = Callable[[Event], None]


@dataclass
class EventBus:
    _subscribers: dict[str, list[EventHandler]] = field(default_factory=lambda: defaultdict(list))
    _log: list[Event] = field(default_factory=list)

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        self._subscribers[event_type].append(handler)

    def publish(self, event: Event) -> None:
        self._log.append(event)
        for handler in list(self._subscribers.get(event.event_type, [])):
            handler(event)

    def replay(self, event_type: str | None = None) -> list[Event]:
        """Every Event published so far, in order.

        This is Runtime-only state (see docs/GLOSSARY.md source-of-truth
        taxonomy) -- it carries no architectural authority and is never
        treated as Registry.
        """
        if event_type is None:
            return list(self._log)
        return [e for e in self._log if e.event_type == event_type]
