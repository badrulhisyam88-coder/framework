"""Tests for runtime/dispatcher.py -- fail-closed Policy enforcement and the
Command vs Query dispatch pipeline."""

import pytest

from framework_final.platform.capability import CapabilityBase
from framework_final.platform.contract import Command, ContractId, Query
from framework_final.platform.event import Event
from framework_final.platform.module import ModuleBase
from framework_final.platform.policy import PolicyResult
from framework_final.platform.principal import Principal, PrincipalStatus
from framework_final.runtime.container import Container
from framework_final.runtime.dispatcher import CommandDenied, Dispatcher, InvalidDispatch
from framework_final.runtime.event_bus import EventBus
from framework_final.runtime.policy_enforcer import PolicyEnforcer


class EchoModule(ModuleBase):
    module_id = "echo"

    def handle_command(self, command):
        event = Event(event_type="echo.said", payload={"text": command.payload["text"]}, published_by=self.module_id)
        return {"echoed": command.payload["text"]}, [event]

    def handle_query(self, query):
        return {"ok": True}

    def policy_rules(self):
        return {
            "say": lambda principal, command_name, entity: (
                PolicyResult.allow()
                if principal.has_role("speaker")
                else PolicyResult.deny("missing role 'speaker'")
            ),
            "peek": lambda principal, command_name, entity: PolicyResult.allow(),
        }


class DummyCapability(CapabilityBase):
    capability_id = "dummy"

    def handle_command(self, command):
        return {"ok": True}


def _dispatcher():
    container = Container()
    container.register_module(EchoModule())
    event_bus = EventBus()
    return Dispatcher(container=container, event_bus=event_bus, policy_enforcer=PolicyEnforcer()), event_bus


def test_command_allowed_publishes_event_and_returns_result():
    dispatcher, event_bus = _dispatcher()
    speaker = Principal(id="p1", status=PrincipalStatus.ACTIVE, roles=frozenset({"speaker"}))
    result = dispatcher.dispatch_command(
        Command(contract_id=ContractId(owner_id="echo", name="say"), payload={"text": "hi"}), principal=speaker
    )
    assert result == {"echoed": "hi"}
    assert len(event_bus.replay("echo.said")) == 1


def test_command_denied_without_role_publishes_no_event():
    dispatcher, event_bus = _dispatcher()
    stranger = Principal(id="p2", status=PrincipalStatus.ACTIVE)
    with pytest.raises(CommandDenied):
        dispatcher.dispatch_command(
            Command(contract_id=ContractId(owner_id="echo", name="say"), payload={"text": "hi"}), principal=stranger
        )
    assert event_bus.replay() == []


def test_command_with_no_declared_policy_rule_fails_closed():
    dispatcher, _ = _dispatcher()
    someone = Principal(id="p3", status=PrincipalStatus.ACTIVE, roles=frozenset({"speaker"}))
    with pytest.raises(CommandDenied):
        dispatcher.dispatch_command(
            Command(contract_id=ContractId(owner_id="echo", name="undeclared"), payload={}), principal=someone
        )


def test_query_dispatch_checks_policy_too():
    dispatcher, _ = _dispatcher()
    result = dispatcher.dispatch_query(
        Query(contract_id=ContractId(owner_id="echo", name="peek")), principal=Principal(id="p4")
    )
    assert result == {"ok": True}


def test_dispatch_command_rejects_a_capability_owned_contract():
    container = Container()
    container.register_capability(DummyCapability())
    dispatcher = Dispatcher(container=container, event_bus=EventBus(), policy_enforcer=PolicyEnforcer())
    with pytest.raises(InvalidDispatch):
        dispatcher.dispatch_command(
            Command(contract_id=ContractId(owner_id="dummy", name="op")), principal=Principal(id="x")
        )
