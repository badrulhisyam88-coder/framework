"""TargetContext — resolved, validated target for scanner execution."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ResolutionStrategy(StrEnum):
    DIRECT = "direct"                         # Use as-is (already a non-local address)
    DOCKER_HOST_INTERNAL = "docker_host_internal"  # localhost → host.docker.internal
    UNRESOLVABLE = "unresolvable"             # Could not determine a valid target


class TargetType(StrEnum):
    JUICE_SHOP = "juice_shop"
    DVWA = "dvwa"
    WEBGOAT = "webgoat"
    GENERIC_WEB = "generic_web"
    SSH = "ssh"
    FTP = "ftp"
    DATABASE = "database"
    UNKNOWN = "unknown"


class TargetContext(BaseModel):
    # What the user sees / entered
    display_url: str

    # What the scanner actually uses (may differ from display_url inside Docker)
    scanner_url: str

    # Hostname component only — used by Nmap (which doesn't accept full URLs)
    scanner_host: str

    # Port extracted from the URL
    scanner_port: int | None = None

    # Classification
    target_type: TargetType = TargetType.UNKNOWN
    environment_type: str = "unknown"    # docker_host | bare_metal | remote
    resolution_strategy: ResolutionStrategy = ResolutionStrategy.DIRECT

    # Reachability results (None = not yet checked)
    reachable: bool | None = None
    http_status: int | None = None
    tcp_reachable: bool | None = None
    latency_ms: float | None = None

    # Fingerprint
    fingerprint: str | None = None               # Human-readable label
    fingerprint_confidence: str = "none"         # high | medium | low | none
    server_header: str | None = None
    page_title: str | None = None

    # Free-form diagnostics (error messages, resolution trace, etc.)
    diagnostics: dict[str, Any] = Field(default_factory=dict)
    last_checked: datetime | None = None

    @property
    def is_reachable(self) -> bool:
        return bool(self.reachable)

    @property
    def resolution_note(self) -> str:
        if self.resolution_strategy == ResolutionStrategy.DOCKER_HOST_INTERNAL:
            return (
                "localhost → host.docker.internal "
                "(Docker host routing)"
            )
        if self.resolution_strategy == ResolutionStrategy.DIRECT:
            return "No translation needed"
        return "Could not resolve"
