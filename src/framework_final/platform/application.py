"""Application: the Meta-Model type. A named composition of Modules and
Capabilities for one business purpose (Project Tracker, Hospital, ERP, ...).
Introduces no business vocabulary of its own -- it selects and configures.
Contains no business logic; that always belongs to a Module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ApplicationStatus(str, Enum):
    INITIALIZED = "initialized"
    COMPOSED = "composed"
    RUNNING = "running"
    RETIRED = "retired"


@dataclass(frozen=True)
class ApplicationManifest:
    id: str
    owner: str
    modules: tuple[str, ...] = field(default_factory=tuple)
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    status: ApplicationStatus = ApplicationStatus.INITIALIZED
