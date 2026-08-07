"""Tests for runtime/workflow_engine.py -- Saga execution with reverse-order
compensation on failure."""

from framework_final.platform.contract import Command, ContractId
from framework_final.platform.module import ModuleBase
from framework_final.platform.policy import PolicyResult
from framework_final.platform.principal import Principal
from framework_final.platform.workflow import WorkflowDefinition, WorkflowStatus, WorkflowStep
from framework_final.runtime.container import Container
from framework_final.runtime.dispatcher import Dispatcher
from framework_final.runtime.event_bus import EventBus
from framework_final.runtime.policy_enforcer import PolicyEnforcer
from framework_final.runtime.workflow_engine import WorkflowEngine


class ReserveModule(ModuleBase):
    module_id = "reserve"

    def __init__(self):
        self.reserved = False
        self.released = False

    def handle_command(self, command):
        if command.contract_id.name == "reserve":
            self.reserved = True
            return {"reserved": True}, []
        if command.contract_id.name == "release":
            self.released = True
            return {"released": True}, []
        raise NotImplementedError

    def policy_rules(self):
        allow = lambda p, c, e: PolicyResult.allow()  # noqa: E731
        return {"reserve": allow, "release": allow}


class ChargeModule(ModuleBase):
    module_id = "charge"

    def __init__(self, should_fail: bool):
        self.should_fail = should_fail
        self.charged = False

    def handle_command(self, command):
        if self.should_fail:
            raise RuntimeError("payment declined")
        self.charged = True
        return {"charged": True}, []

    def policy_rules(self):
        return {"charge": lambda p, c, e: PolicyResult.allow()}


def _engine(should_fail: bool):
    container = Container()
    reserve = ReserveModule()
    charge = ChargeModule(should_fail)
    container.register_module(reserve)
    container.register_module(charge)
    dispatcher = Dispatcher(container=container, event_bus=EventBus(), policy_enforcer=PolicyEnforcer())
    return WorkflowEngine(dispatcher=dispatcher), reserve, charge


def _definition() -> WorkflowDefinition:
    return WorkflowDefinition(
        id="book_and_charge",
        owner_id="example",
        steps=(
            WorkflowStep(
                name="reserve",
                command=Command(contract_id=ContractId(owner_id="reserve", name="reserve")),
                compensation=Command(contract_id=ContractId(owner_id="reserve", name="release")),
            ),
            WorkflowStep(
                name="charge",
                command=Command(contract_id=ContractId(owner_id="charge", name="charge")),
            ),
        ),
    )


def test_workflow_completes_when_every_step_succeeds():
    engine, reserve, charge = _engine(should_fail=False)
    instance = engine.run(_definition(), principal=Principal(id="p"))
    assert instance.status == WorkflowStatus.COMPLETED
    assert instance.completed_steps == ["reserve", "charge"]
    assert reserve.reserved is True
    assert charge.charged is True
    assert reserve.released is False


def test_workflow_compensates_completed_steps_on_later_failure():
    engine, reserve, charge = _engine(should_fail=True)
    instance = engine.run(_definition(), principal=Principal(id="p"))
    assert instance.status == WorkflowStatus.FAILED
    assert reserve.reserved is True
    assert reserve.released is True  # compensation ran
    assert charge.charged is False
    assert "payment declined" in instance.failure_reason
