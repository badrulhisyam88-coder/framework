"""Full end-to-end test: discover Registry, validate, boot Runtime, dispatch
a Command and a Query, verify Event publication, cross-Capability
invocation through the container, and fail-closed Policy enforcement.

This is the test that proves the whole stack -- Platform, Registry,
Discovery Index, Runtime -- works together, not just in isolation.
"""

from pathlib import Path

import pytest

from framework_final.platform.contract import Command, ContractId, Query
from framework_final.platform.principal import Principal, PrincipalStatus
from framework_final.registry.store import RegistryStore
from framework_final.registry.validator import validate
from framework_final.runtime.boot import boot
from framework_final.runtime.dispatcher import CommandDenied

from examples.example_capability.capability import ExampleLoggingCapability
from examples.example_task_module.module import ExampleTaskModule

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples"
SRC = REPO_ROOT / "src"


@pytest.fixture
def runtime_context():
    store = RegistryStore.discover([EXAMPLES])
    findings = validate(store, package_root=SRC, discovery_roots=[EXAMPLES], examples_root=EXAMPLES)
    assert findings == [], findings
    return boot(
        "example_application",
        store,
        module_factories={"example_task_module": lambda c: ExampleTaskModule(c)},
        capability_factories={"example_logging": lambda: ExampleLoggingCapability()},
    )


def test_create_task_command_succeeds_and_publishes_event(runtime_context):
    alice = Principal(id="alice", status=PrincipalStatus.ACTIVE)
    result = runtime_context.dispatcher.dispatch_command(
        Command(
            contract_id=ContractId(owner_id="example_task_module", name="create_task"),
            payload={"title": "Write docs", "assignee_principal_id": "alice"},
        ),
        principal=alice,
    )
    assert "task_id" in result
    events = runtime_context.event_bus.replay("example_task_module.task_created")
    assert len(events) == 1
    assert events[0].payload["title"] == "Write docs"


def test_list_tasks_query_reflects_created_task(runtime_context):
    alice = Principal(id="alice", status=PrincipalStatus.ACTIVE)
    runtime_context.dispatcher.dispatch_command(
        Command(
            contract_id=ContractId(owner_id="example_task_module", name="create_task"),
            payload={"title": "Ship it", "assignee_principal_id": "alice"},
        ),
        principal=alice,
    )
    tasks = runtime_context.dispatcher.dispatch_query(
        Query(contract_id=ContractId(owner_id="example_task_module", name="list_tasks")),
        principal=alice,
    )
    assert any(t["title"] == "Ship it" for t in tasks)


def test_capability_is_invoked_through_the_container_not_imported_directly(runtime_context):
    alice = Principal(id="alice", status=PrincipalStatus.ACTIVE)
    runtime_context.dispatcher.dispatch_command(
        Command(
            contract_id=ContractId(owner_id="example_task_module", name="create_task"),
            payload={"title": "Log me", "assignee_principal_id": "alice"},
        ),
        principal=alice,
    )
    log_capability = runtime_context.container.capability("example_logging")
    assert len(log_capability.entries) == 1


def test_inactive_principal_is_denied_fail_closed(runtime_context):
    bob = Principal(id="bob", status=PrincipalStatus.SUSPENDED)
    with pytest.raises(CommandDenied):
        runtime_context.dispatcher.dispatch_command(
            Command(
                contract_id=ContractId(owner_id="example_task_module", name="create_task"),
                payload={"title": "x", "assignee_principal_id": "bob"},
            ),
            principal=bob,
        )
