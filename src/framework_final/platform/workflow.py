"""Workflow: the sanctioned mechanism for a process to span multiple
Modules' Contracts over time, with orchestration semantics -- retry,
timeout, compensation (Saga-pattern grounded).

The one legitimate place cross-Module coordination beyond a single Event or
Command is allowed to happen, without Modules depending on each other
directly -- every step still goes through a Module's public Contract, never
its internals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from framework_final.platform.contract import Command


class WorkflowStatus(str, Enum):
    INITIATED = "initiated"
    TRANSITIONING = "transitioning"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class WorkflowStep:
    """One step: a Command to run, and the compensating Command to run if a
    *later* step fails and this step must be undone. `compensation` is
    optional only because some steps are naturally non-destructive (e.g. a
    pure read has nothing to compensate).
    """

    name: str
    command: Command
    compensation: Command | None = None


@dataclass(frozen=True)
class WorkflowDefinition:
    id: str
    owner_id: str
    steps: tuple[WorkflowStep, ...]
    timeout_seconds: float | None = None


@dataclass
class WorkflowInstance:
    """Runtime state for one execution of a WorkflowDefinition. Owned by
    whichever Module/Application initiated it; this is Runtime-only state
    (see docs/GLOSSARY.md source-of-truth taxonomy) and never part of
    Registry.
    """

    id: str
    definition_id: str
    status: WorkflowStatus = WorkflowStatus.INITIATED
    completed_steps: list[str] = field(default_factory=list)
    step_results: dict[str, Any] = field(default_factory=dict)
    failure_reason: str | None = None
