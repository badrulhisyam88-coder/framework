"""Engine package for the conductor framework.

Import this package to get access to the engine_registry and registered engines.

To add domain engines: create a module in this directory, subclass Engine from
apps.conductor.engines.base, decorate with @engine_registry.register("your_engine_id"),
then import the module here so registration fires at startup.

See examples/example_engine.py for the minimal engine contract.
"""
import logging as _logging

from apps.conductor.engines.base import engine_registry as _registry

# Expose for verification: from apps.conductor.engines import _registered_engines
_registered_engines = _registry._engines


def _validate_engine_gate_references() -> None:
    """Verify each engine's gate_id / gate_ids refer to registered gates.

    Engines with any unknown gate are unregistered and an error is logged.
    App still starts — misconfigured engines are blocked, not fatal.
    """
    from apps.conductor.gates import _REGISTERED_GATES

    _log = _logging.getLogger(__name__)
    to_remove = []

    for engine_id, engine in list(_registered_engines.items()):
        gate_id = getattr(engine, "gate_id", None)
        gate_ids: tuple[str, ...] = getattr(engine, "gate_ids", ()) or ()

        if gate_id is not None and gate_id not in _REGISTERED_GATES:
            _log.error(
                "Engine %s declares gate_id=%r but no such gate is registered."
                " Engine will be unregistered.",
                engine_id, gate_id,
            )
            to_remove.append(engine_id)
            continue

        unknown = [gid for gid in gate_ids if gid not in _REGISTERED_GATES]
        if unknown:
            _log.error(
                "Engine %s declares unknown gate_ids=%r. Engine will be unregistered.",
                engine_id, unknown,
            )
            to_remove.append(engine_id)

    for engine_id in to_remove:
        del _registered_engines[engine_id]


_validate_engine_gate_references()
