"""Marker classes for this Module's Contracts -- discoverable by the
Discovery Index so registry.yaml's declared Contracts have matching symbols
(see registry/drift.py's naming convention: `create_task` -> `CreateTask`).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CreateTask:
    title: str
    assignee_principal_id: str


@dataclass(frozen=True)
class ListTasks:
    assignee_principal_id: str | None = None
