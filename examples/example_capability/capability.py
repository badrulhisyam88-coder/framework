"""example_logging: a minimal, genuinely reusable structured-logging
Capability -- domain-agnostic by construction; it does not know or care
which Module calls it. This is the ONE demonstration Capability. It is not
part of the platform itself -- see docs/ARCHITECTURE.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from framework_final.platform.capability import CapabilityBase
from framework_final.platform.contract import Command


@dataclass(frozen=True)
class LogEvent:
    """The shape of the `log_event` Command's payload -- a discoverable
    symbol matching registry.yaml's declared Contract name (see
    registry/drift.py's naming convention: `log_event` -> `LogEvent`).
    """

    level: str
    message: str
    context: dict[str, Any] = field(default_factory=dict)


class ExampleLoggingCapability(CapabilityBase):
    capability_id = "example_logging"

    def __init__(self) -> None:
        self.entries: list[LogEvent] = []

    def handle_command(self, command: Command) -> dict[str, Any]:
        entry = LogEvent(
            level=command.payload.get("level", "info"),
            message=command.payload["message"],
            context=command.payload.get("context", {}),
        )
        self.entries.append(entry)
        return {"logged": True, "count": len(self.entries)}
