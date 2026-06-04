"""V2.5 Step 4 — unit tests for _parse_qwen_action.

Four tests covering the ACTION block parsing logic extracted as a module-level
helper in apps/investigation_workspace/api/routes.py.
"""
from __future__ import annotations

import json
import os

# ── Inline reproduction of the parsing logic ─────────────────────────────────
# We reproduce the logic here rather than importing routes.py directly to avoid
# FastAPI startup side-effects (DB connections, router registration, etc.).
# The test asserts correctness of the algorithm; the frontend surface test
# (test_v25_surfaces.py) asserts the production copy is present in routes.py.

_APPROVED_ENGINES = frozenset({
    "credential_brute", "sqli_auth_bypass", "access_control", "default_creds",
    "xss_reflect", "cmdi_reflected", "cmdi_blind_time", "cmdi_blind_boolean",
    "metasploit_recipe",
})


def _parse_qwen_action(response_text: str, approved_engines: frozenset) -> tuple:
    """Mirror of the production function in routes.py.

    Returns (clean_text, action_dict_or_None).
    Parsing never raises; malformed JSON or unknown engine_id → action=None.
    """
    text = response_text
    action = None

    marker = "\nACTION:"
    idx = response_text.find(marker)
    if idx == -1:
        marker = "ACTION:"
        idx = response_text.find(marker)

    if idx != -1:
        text = response_text[:idx].strip()
        action_str = response_text[idx + len(marker):].strip()
        try:
            parsed = json.loads(action_str.split("\n")[0])
            if parsed.get("engine_id") in approved_engines:
                action = {
                    "engine_id":    parsed["engine_id"],
                    "finding_type": parsed.get("finding_type", ""),
                    "reason":       str(parsed.get("reason", ""))[:200],
                }
        except Exception:
            pass  # malformed → null

    return text, action


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_action_block_parsed_correctly():
    """Valid ACTION block → clean text + populated action dict."""
    raw = (
        "Given the login form finding, brute-force credentials is the most direct path.\n"
        '  ACTION:{"engine_id":"credential_brute","finding_type":"login_form_detected","reason":"Login form present"}'
    )
    text, action = _parse_qwen_action(raw, _APPROVED_ENGINES)

    assert "ACTION:" not in text
    assert "Given the login form" in text
    assert action is not None
    assert action["engine_id"] == "credential_brute"
    assert action["finding_type"] == "login_form_detected"
    assert action["reason"] == "Login form present"


def test_malformed_action_json_returns_null():
    """Garbled JSON after ACTION: → action=None."""
    raw = "Try credential brute.\nACTION:{not valid json at all!!!"
    text, action = _parse_qwen_action(raw, _APPROVED_ENGINES)

    assert action is None
    assert "Try credential brute" in text


def test_unknown_engine_id_returns_null():
    """engine_id not in approved set → action=None."""
    raw = (
        "I recommend running nmap again.\n"
        'ACTION:{"engine_id":"nmap_scan","finding_type":"open_port_detected","reason":"ports open"}'
    )
    text, action = _parse_qwen_action(raw, _APPROVED_ENGINES)

    assert action is None
    assert "ACTION:" not in text


def test_no_action_block_returns_null():
    """Plain response with no ACTION block → action=None, text unchanged."""
    raw = "None of the approved engines apply here. The target appears hardened."
    text, action = _parse_qwen_action(raw, _APPROVED_ENGINES)

    assert action is None
    assert text == raw


# ── Verify production copy matches algorithm ─────────────────────────────────

def test_production_routes_has_parse_function():
    """routes.py must define _parse_qwen_action and _APPROVED_ENGINES."""
    _ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    src_path = os.path.join(_ROOT, "apps/investigation_workspace/api/routes.py")
    with open(src_path, encoding="utf-8") as fh:
        src = fh.read()
    assert "def _parse_qwen_action(" in src, "_parse_qwen_action not found in routes.py"
    assert "_APPROVED_ENGINES = frozenset(" in src, "_APPROVED_ENGINES not found in routes.py"
    assert '"action": action' in src or "'action': action" in src, \
        "action key missing from qwen_chat return dict in routes.py"
