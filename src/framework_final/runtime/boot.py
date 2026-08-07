"""Runtime.boot: turns an Application's manifest and Registry declarations
into a live, running RuntimeContext.

This is the one place Registry's declared intent becomes an actual running
system -- Runtime enacts what Registry declares, it never decides
architecture itself (see docs/ARCHITECTURE.md). `module_factories` and
`capability_factories` are supplied by the caller (an Application's own
entrypoint), not imported by Runtime itself -- Runtime must never import
concrete example/business code, which would point the dependency arrow the
wrong way.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from framework_final.platform.capability import CapabilityBase
from framework_final.platform.module import ModuleBase
from framework_final.registry.store import RegistryStore
from framework_final.runtime.container import Container
from framework_final.runtime.dispatcher import Dispatcher
from framework_final.runtime.event_bus import EventBus
from framework_final.runtime.policy_enforcer import PolicyEnforcer
from framework_final.runtime.workflow_engine import WorkflowEngine


class BootError(RuntimeError):
    pass


@dataclass
class RuntimeContext:
    store: RegistryStore
    container: Container
    event_bus: EventBus
    dispatcher: Dispatcher
    workflow_engine: WorkflowEngine


def boot(
    application_id: str,
    store: RegistryStore,
    module_factories: dict[str, Callable[[Container], ModuleBase]],
    capability_factories: dict[str, Callable[[], CapabilityBase]],
) -> RuntimeContext:
    app = store.applications.get(application_id)
    if app is None:
        raise BootError(f"Application '{application_id}' is not registered")

    container = Container()
    event_bus = EventBus()

    for cap_id in app.capabilities:
        cap_record = store.capabilities.get(cap_id)
        if cap_record is None:
            raise BootError(f"Application '{application_id}' references unknown Capability '{cap_id}'")
        if cap_record.status != "active":
            raise BootError(f"Capability '{cap_id}' has status '{cap_record.status}', expected 'active'")
        factory = capability_factories.get(cap_id)
        if factory is None:
            raise BootError(f"no factory supplied for Capability '{cap_id}'")
        instance = factory()
        instance.on_activate()
        container.register_capability(instance)

    for mod_id in app.modules:
        mod_record = store.modules.get(mod_id)
        if mod_record is None:
            raise BootError(f"Application '{application_id}' references unknown Module '{mod_id}'")
        if mod_record.status != "active":
            raise BootError(f"Module '{mod_id}' has status '{mod_record.status}', expected 'active'")
        for required in mod_record.required_capabilities:
            if not container.has_capability(required):
                raise BootError(
                    f"Module '{mod_id}' requires Capability '{required}', "
                    f"which is not active in Application '{application_id}'"
                )
        factory = module_factories.get(mod_id)
        if factory is None:
            raise BootError(f"no factory supplied for Module '{mod_id}'")
        # Capabilities are already registered above (capabilities boot
        # first), so a Module's factory can resolve its required
        # Capabilities from the container right now -- it never constructs
        # them itself.
        container.register_module(factory(container))

    policy_enforcer = PolicyEnforcer()
    dispatcher = Dispatcher(container=container, event_bus=event_bus, policy_enforcer=policy_enforcer)
    workflow_engine = WorkflowEngine(dispatcher=dispatcher)

    # Wire Event subscriptions declared in each Module's registry.yaml --
    # Modules never subscribe to each other directly, only through the bus.
    for mod_id in app.modules:
        mod_record = store.modules[mod_id]
        instance = container.module(mod_id)
        for event_type in mod_record.subscribed_events:
            event_bus.subscribe(event_type, instance.on_event)

    return RuntimeContext(
        store=store,
        container=container,
        event_bus=event_bus,
        dispatcher=dispatcher,
        workflow_engine=workflow_engine,
    )
