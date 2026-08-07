"""Event: an immutable statement that something has already happened.

The sole mechanism for one Module to inform others of a state change without
direct coupling. Never updated, never retracted after emission -- a
correction is always a new, later Event.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


@dataclass(frozen=True)
class Event:
    """The envelope Platform owns. `event_type` is the Concept-Model-scoped
    canonical name (e.g. "task.task_created"); `payload` is owned by the
    publishing Module or Capability, not by Platform. Always named in the
    past tense -- a fact that already happened, not a request.
    """

    event_type: str
    payload: Mapping[str, Any]
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    causation_id: str | None = None
    correlation_id: str | None = None
    published_by: str | None = None  # id of the publishing Module or Capability

    def caused(
        self,
        event_type: str,
        payload: Mapping[str, Any],
        published_by: str | None = None,
    ) -> "Event":
        """Build a follow-on Event carrying this Event's causation/correlation
        chain forward, so a downstream trace never has to guess at lineage.
        """
        return Event(
            event_type=event_type,
            payload=payload,
            causation_id=self.id,
            correlation_id=self.correlation_id or self.id,
            published_by=published_by,
        )
