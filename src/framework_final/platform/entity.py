"""Entity: a thing with durable identity and state that persists across time.

Platform defines this type. The Module that declares a concrete Entity (e.g.
"Task", "Patient") owns each instance. State changes are always expressed as
Events -- never silent mutation -- so "update" here means "produce a new
version", not "mutate in place".
"""

from __future__ import annotations

import dataclasses
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EntityLifecycle(str, Enum):
    """The only lifecycle an Entity may be in. Archival is soft: an archived
    Entity is retained, never deleted, so history stays reconstructable.
    """

    CREATED = "created"
    ACTIVE = "active"
    ARCHIVED = "archived"


@dataclass(frozen=True)
class Entity:
    """Base for every domain Entity. Concrete Entities subclass this and add
    their own fields; identity, lifecycle, and versioning are handled here so
    every Module gets them for free and consistently.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version: int = 1
    lifecycle: EntityLifecycle = EntityLifecycle.CREATED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def next_version(self, **changes: Any) -> "Entity":
        """Return a new Entity instance representing the next version.

        Never mutates self -- Entities are immutable snapshots; the Event
        that caused the change is the actual record of what happened.
        """
        return dataclasses.replace(self, version=self.version + 1, **changes)

    def archive(self) -> "Entity":
        return dataclasses.replace(self, lifecycle=EntityLifecycle.ARCHIVED)
