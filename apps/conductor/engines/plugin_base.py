"""Shared base class for validation-plugin-backed Conductor Engines.

Each subclass wraps one apps/validation/plugins/* module without modifying
the plugin source. Plugin run() functions are DB-dependent (they call
_get_host_ip via QueueItem), so engines call the internal private helper
functions directly, passing host from the parsed target instead.

Gate semantics: plugin engines use VISIBILITY gates (default OFF). When
the gate is OFF the engine is completely invisible — not dispatched, not
in operator UI. This differs from nmap's BEHAVIOR gate (always dispatched;
gate controls internal logic).
"""
from __future__ import annotations

import logging
import time
from abc import abstractmethod

from apps.conductor.engines.base import (
    Engine,
    EngineCapabilities,
    EngineHealth,
    EngineResult,
    OutputChannel,
    SessionStore,
)

logger = logging.getLogger("conductor.engines.plugin_base")


class PluginEngine(Engine):
    """Abstract base for the 7 validation plugin engines."""

    gate_id: str          # Visibility gate — must be overridden in each subclass
    _plugin_name: str = ""  # Human-readable name for finding titles
    _exploitable_severity: str = "high"  # Override for critical cases (SSH, Telnet)

    def __init__(self) -> None:
        # No asyncio primitives — event loop may not exist at registration time.
        self._cancelled: bool = False
        self._running: bool = False
        self._last_heartbeat: float = time.time()

    async def run(
        self,
        target: str,
        config: dict,
        session_store: SessionStore,
        output_channel: OutputChannel,
    ) -> EngineResult:
        from apps.conductor.gates import get_gate

        if not get_gate(self.gate_id):
            return EngineResult(status="skipped", findings_count=0)

        host, port, scheme = self._parse_target(target, config)
        self._config = config  # available to _run_checks subclasses
        self._running = True
        self._cancelled = False
        self._last_heartbeat = time.time()
        findings_count = 0

        try:
            evidence = await self._run_checks(host, port, scheme)
            self._last_heartbeat = time.time()

            if not self._cancelled:
                finding = self._translate_evidence(evidence, host, port, target)
                await output_channel.emit_finding(finding)
                findings_count = 1

            status = "cancelled" if self._cancelled else "success"
            return EngineResult(status=status, findings_count=findings_count)

        except Exception as exc:
            logger.error(
                "%s: run failed for %s:%d: %s", self.engine_id, host, port, exc, exc_info=True
            )
            return EngineResult(status="failed", findings_count=0, error=str(exc))
        finally:
            self._running = False

    @abstractmethod
    async def _run_checks(self, host: str, port: int, scheme: str):
        """Run all plugin checks and return an Evidence instance."""
        ...

    def _parse_target(self, target: str, config: dict) -> tuple[str, int, str]:
        from urllib.parse import urlparse

        service_info = config.get("service_info", {})
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = parsed.hostname or target

        port = (
            service_info.get("port")
            or (parsed.port if parsed.port else None)
            or self._default_port()
        )
        scheme = service_info.get("scheme") or parsed.scheme or "http"
        return host, int(port), str(scheme)

    def _default_port(self) -> int:
        return 80

    def _translate_evidence(self, evidence, host: str, port: int, target: str) -> dict:
        from apps.investigation_workspace.probe.finding_id import generate_finding_id

        ctx = evidence.context or {}
        # Use str() so ValidationStatus StrEnum values compare as plain strings
        # without importing the pydantic-backed models module.
        validation_status = str(ctx.get("validation_status", "cve_matched"))
        explicit_severity = ctx.get("severity")

        if validation_status == "validated_exploitable":
            category = "vulnerability_confirmed"
            severity = explicit_severity or self._exploitable_severity
        elif validation_status == "validated_not_exploitable":
            category = "vulnerability_assessed"
            severity = explicit_severity or "info"
        else:
            category = "service_detected"
            severity = explicit_severity or "info"

        finding_id = generate_finding_id(
            probe_id=self.engine_id,
            target=target,
            path=f"{host}:{port}",
            finding_type=category,
        )

        name = self._plugin_name or self.engine_id.upper()
        env_ctx = ctx.get("environment_context", "")

        return {
            "id": finding_id,
            "probe_id": self.engine_id,
            "phase": "enumeration",
            "category": category,
            "title": f"{name} check on {host}:{port}",
            "path": f"{host}:{port}",
            "severity": severity,
            "confidence": "high" if validation_status == "validated_exploitable" else "medium",
            "description": env_ctx,
            "evidence": {
                "sent": evidence.sent,
                "received": evidence.received,
                **{
                    k: v
                    for k, v in ctx.items()
                    if k not in ("validation_status", "environment_context", "severity")
                },
            },
            "next_actions": [],
        }

    async def cancel(self) -> None:
        self._cancelled = True

    def health_check(self) -> EngineHealth:
        return EngineHealth(
            status="healthy" if self._running else "idle",
            last_heartbeat=self._last_heartbeat,
        )
