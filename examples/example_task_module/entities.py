"""Task: the one Entity this example Module owns."""

from __future__ import annotations

from dataclasses import dataclass

from framework_final.platform.entity import Entity


@dataclass(frozen=True)
class Task(Entity):
    title: str = ""
    assignee_principal_id: str = ""
    done: bool = False
