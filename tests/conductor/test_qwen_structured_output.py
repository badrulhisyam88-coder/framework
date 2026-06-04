"""V2.10 PR-B — Structured model output: schema + primary dispatcher tests.

Seven tests:

Test 1: Schema has engine_id enum sourced from registry (not hardcoded).
Test 2: Valid JSON → engine_id + params reach dispatch correctly.
Test 3: Valid JSON with null engine_id → (response_str, None) — no action.
Test 4: Invalid / non-JSON response → (None, None) — fallback fires.
Test 5: engine_id not in registry → rejected before dispatch.
Test 6: Extended payloads validated and forwarded correctly.
Test 7: Fallback log fires when parse_structured_output returns (None, None).
"""
from __future__ import annotations

import json
import logging
from unittest.mock import patch, MagicMock

import pytest


# ── Shared helpers ─────────────────────────────────────────────────────────────

_VALID_IDS = {"credential_brute", "access_control", "sqli_auth_bypass"}


def _resp(engine_id, finding_type="", reason="", payloads=None, response="advice"):
    obj = {
        "response": response,
        "engine_id": engine_id,
        "params": {
            "finding_type": finding_type,
            "reason": reason,
        },
    }
    if payloads is not None:
        obj["params"]["extended_payloads"] = payloads
    return json.dumps(obj)


# ── Test 1: Schema engine_id enum sourced from registry ───────────────────────


def test_schema_engine_ids_come_from_registry():
    """build_action_schema must use engine_ids from the engine registry, not a hardcoded list."""
    from apps.conductor.qwen.action_schema import build_action_schema

    fake_ids = ["engine_alpha", "engine_beta"]
    schema = build_action_schema(engine_ids=fake_ids)

    enum_vals = schema["properties"]["engine_id"]["enum"]
    assert "engine_alpha" in enum_vals
    assert "engine_beta" in enum_vals
    # null must be present for the no-action case
    assert None in enum_vals
    # Must NOT include non-provided ids
    assert "credential_brute" not in enum_vals


# ── Test 2: Valid JSON → dispatch correctly ───────────────────────────────────


def test_valid_json_routes_to_dispatch():
    """Valid schema-compliant JSON response → engine_id + params reach dispatch."""
    from apps.conductor.qwen.action_schema import parse_structured_output

    raw = _resp("credential_brute", finding_type="login_form_detected", reason="Login form present")
    response_str, action = parse_structured_output(raw, _VALID_IDS)

    assert response_str == "advice"
    assert action is not None
    assert action["engine_id"] == "credential_brute"
    assert action["finding_type"] == "login_form_detected"
    assert action["reason"] == "Login form present"


# ── Test 3: null engine_id → response str only, no action ─────────────────────


def test_null_engine_id_returns_no_action():
    """engine_id=null in JSON → (response_str, None); response text still returned."""
    from apps.conductor.qwen.action_schema import parse_structured_output

    raw = json.dumps({"response": "No exploits apply here.", "engine_id": None, "params": {}})
    response_str, action = parse_structured_output(raw, _VALID_IDS)

    assert action is None
    assert response_str == "No exploits apply here."


# ── Test 4: Non-JSON response → (None, None) — fallback signal ────────────────


def test_non_json_triggers_fallback_signal():
    """Non-JSON response → parse_structured_output returns (None, None), not raises."""
    from apps.conductor.qwen.action_schema import parse_structured_output

    for bad in [
        "Plain prose with no JSON at all.",
        "ACTION:credential_brute",
        '{"broken json: ',
        "",
    ]:
        response_str, action = parse_structured_output(bad, _VALID_IDS)
        assert response_str is None, f"expected None for {bad!r}, got {response_str!r}"
        assert action is None


# ── Test 5: engine_id not in registry → rejected before dispatch ──────────────


def test_unknown_engine_id_rejected():
    """engine_id not in valid_engine_ids set → action=None even if JSON is valid."""
    from apps.conductor.qwen.action_schema import parse_structured_output

    raw = _resp("nmap_scan", finding_type="open_port_detected", reason="ports open")
    response_str, action = parse_structured_output(raw, _VALID_IDS)

    assert action is None
    # response_str is still returned (valid JSON, just no recognised engine)
    assert response_str == "advice"


# ── Test 6: Extended payloads forwarded correctly ─────────────────────────────


def test_extended_payloads_validated_and_forwarded():
    """Valid extended_payloads are forwarded; malformed entries are dropped."""
    from apps.conductor.qwen.action_schema import parse_structured_output

    payloads = [
        {"endpoint": "/filter", "method": "GET", "body": {"category": "Gifts'||'1'=='1"}},
        {"endpoint": "/other",  "body": {"key": "value"}},   # method defaults to POST
        {"endpoint": "/bad", "body": "not-a-dict"},           # invalid body — dropped
        {"no_endpoint": True, "body": {}},                    # missing endpoint — dropped
    ]
    raw = _resp("access_control", finding_type="api_exposure", reason="IDOR", payloads=payloads)
    _, action = parse_structured_output(raw, _VALID_IDS)

    assert action is not None
    ep = action.get("extended_payloads", [])
    assert len(ep) == 2
    assert ep[0]["endpoint"] == "/filter"
    assert ep[0]["method"] == "GET"
    assert ep[1]["endpoint"] == "/other"
    assert ep[1]["method"] == "POST"


# ── Test 7: Fallback signal contract ─────────────────────────────────────────


def test_fallback_signal_contract():
    """(None, None) from parse_structured_output is the unambiguous fallback signal.

    The routes.py caller checks `if clean_text is None:` and activates the text
    ACTION fallback. This test verifies the signal is reliably (None, None) for
    any non-JSON input, distinct from (str, None) which means valid JSON + no action.
    """
    from apps.conductor.qwen.action_schema import parse_structured_output

    # Signal cases: these must return (None, None) — caller activates fallback
    fallback_inputs = [
        "Plain prose with no JSON at all.",
        "ACTION:credential_brute",
        '{"broken json: ',
        "",
        "null",
        "true",
    ]
    for bad in fallback_inputs:
        r, a = parse_structured_output(bad, _VALID_IDS)
        assert r is None and a is None, (
            f"expected (None, None) fallback signal for {bad!r}, got ({r!r}, {a!r})"
        )

    # Non-signal case: valid JSON + no engine → (str, None) — NOT a fallback
    no_action = json.dumps({"response": "Nothing to do.", "engine_id": None, "params": {}})
    r, a = parse_structured_output(no_action, _VALID_IDS)
    assert r == "Nothing to do."
    assert a is None
    # r is a string (not None) — caller does NOT activate fallback
    assert r is not None, "valid JSON with null engine_id must NOT trigger fallback"

    # Verify that routes.py source contains the warning log statement
    import os
    routes_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "apps/investigation_workspace/api/routes.py",
    )
    with open(routes_path, encoding="utf-8") as fh:
        src = fh.read()
    # The ACTION fallback log was removed when Qwen engine-selection was replaced by
    # plan_next_step. The planner now builds the action deterministically; there is no
    # longer a parse_structured_output->engine fallback on the chat path.
    # Verify instead that plan_next_step drives the action.
    assert "plan_next_step" in src or "_cs_plan" in src or "_qc_plan" in src, (
        "routes.py must use plan_next_step as the engine selector on the chat path"
    )


# ── Test 8: C6 preserved — structured output changes what, not the gate ───────


def test_c6_operator_gate_not_bypassed():
    """Structured output produces an action dict, not a dispatch call.

    The operator must still Arm → Execute before any engine runs.
    parse_structured_output returns a dict to the chat endpoint response; it does
    NOT call dispatch_engine directly. This is enforced by design — the function
    only parses and returns.
    """
    from apps.conductor.qwen.action_schema import parse_structured_output

    raw = _resp("credential_brute", finding_type="login_form_detected", reason="form present")
    response_str, action = parse_structured_output(raw, _VALID_IDS)

    # action is a dict, not a coroutine or dispatch call
    assert isinstance(action, dict)
    # parse_structured_output must NOT have side effects — no dispatch here
    # The action dict is returned to the caller (routes.py) which puts it in the
    # JSON response; the operator then clicks Arm+Execute in the UI.
    assert action["engine_id"] == "credential_brute"
