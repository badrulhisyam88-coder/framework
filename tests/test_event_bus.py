"""Tests for runtime/event_bus.py."""

from framework_final.platform.event import Event
from framework_final.runtime.event_bus import EventBus


def test_subscribers_receive_only_their_event_type():
    bus = EventBus()
    received = []
    bus.subscribe("a.happened", lambda e: received.append(e))
    bus.publish(Event(event_type="a.happened", payload={}))
    bus.publish(Event(event_type="b.happened", payload={}))
    assert len(received) == 1
    assert received[0].event_type == "a.happened"


def test_publishing_with_no_subscribers_does_not_raise():
    bus = EventBus()
    bus.publish(Event(event_type="nobody.listening", payload={}))  # must not raise


def test_multiple_subscribers_to_the_same_event_all_fire():
    bus = EventBus()
    calls = []
    bus.subscribe("x", lambda e: calls.append("first"))
    bus.subscribe("x", lambda e: calls.append("second"))
    bus.publish(Event(event_type="x", payload={}))
    assert calls == ["first", "second"]


def test_replay_returns_full_log_in_order_and_can_be_filtered():
    bus = EventBus()
    bus.publish(Event(event_type="x", payload={"n": 1}))
    bus.publish(Event(event_type="x", payload={"n": 2}))
    bus.publish(Event(event_type="y", payload={"n": 3}))
    assert [e.payload["n"] for e in bus.replay()] == [1, 2, 3]
    assert [e.payload["n"] for e in bus.replay("x")] == [1, 2]
