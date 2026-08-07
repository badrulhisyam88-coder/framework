"""Marker class for this Module's one Event (`task_created` -> `TaskCreated`)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TaskCreated:
    task_id: str
    title: str
    assignee_principal_id: str
