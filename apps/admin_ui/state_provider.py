"""Admin UI state provider — bridges to Conductor and engine registry.

Conductor is held as a module-level singleton, lazy-initialised on first
admin request. PR B will revisit this when real engines are wired and
the conductor is properly boot-strapped in the app lifespan.

age_seconds and dispatch_type are not exposed by the current get_state()
contracts; both show "—" and are flagged for spec update in PR B.
"""
from __future__ import annotations

from datetime import UTC, datetime

from apps.conductor.conductor import Conductor
from apps.conductor.engines.base import engine_registry
from apps.conductor.shared import get_shared_conductor

_conductor: Conductor | None = None


def get_conductor() -> Conductor:
    global _conductor
    if _conductor is None:
        _conductor = get_shared_conductor()
    return _conductor


async def get_conductor_panel_data(conductor: Conductor) -> dict:
    """Investigations list shaped for _conductor_table.html."""
    active = await conductor.list_active_investigations()
    investigations = []
    for ctx_state in active:
        orch = ctx_state.get("orchestrators", {})
        phase_st = orch.get("phase", {})
        findings_st = orch.get("findings", {})
        investigations.append({
            "id": ctx_state["investigation_id"],
            "target": ctx_state["target"],
            "state": ctx_state["state"],
            "current_phase": phase_st.get("current_phase"),
            "findings_count": findings_st.get("finding_count", 0),
            "age_seconds": "—",
        })
    target_auth: dict = {}
    expired_set: set = set()
    for ctx_state in active:
        session_st = ctx_state.get("orchestrators", {}).get("session", {})
        for base, info in session_st.get("target_auth", {}).items():
            target_auth[base] = info
            if info.get("expired"):
                expired_set.add(base)
    return {
        "investigations": investigations,
        "target_auth": target_auth,
        "expired_targets": sorted(expired_set),
    }


async def get_execution_panel_data(conductor: Conductor) -> dict:
    """Engine roster + active run instances shaped for _execution_table.html."""
    active = await conductor.list_active_investigations()

    engines = []
    for engine in engine_registry.all_engines():
        h = engine.health_check()
        cap = engine.capabilities
        engines.append({
            "engine_id": engine.engine_id,
            "phases": list(cap.phases),
            "finding_types": list(cap.finding_types),
            "resource_cost": cap.resource_cost,
            "health_status": h.status,
        })

    running_engines = []
    for ctx_state in active:
        inv_id = ctx_state["investigation_id"]
        exec_st = ctx_state.get("orchestrators", {}).get("execution", {})
        for run in exec_st.get("running", []):
            if run["status"] != "running":
                continue
            started = datetime.fromtimestamp(run["started_at"], tz=UTC)
            engine = engine_registry.get(run["engine_id"])
            if engine:
                hb = datetime.fromtimestamp(
                    engine.health_check().last_heartbeat, tz=UTC
                )
                hb_str = hb.strftime("%H:%M:%S")
            else:
                hb_str = "—"
            running_engines.append({
                "investigation_id": inv_id,
                "engine_id": run["engine_id"],
                "started_at_iso": started.strftime("%H:%M:%S"),
                "last_heartbeat_iso": hb_str,
                "dispatch_type": "—",
            })

    return {"engines": engines, "running_engines": running_engines}
