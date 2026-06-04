"""V2.10 PR-B — Structured model output schema + primary dispatcher.

Ollama supports a `format` field that constrains model output to a JSON schema.
This module owns:

  _exploitation_engine_ids()   — registry-sourced list; never drifts from truth
  build_action_schema()        — Ollama-compatible JSON schema for model dispatch
  parse_structured_output()    — primary consumer; returns (None, None) on failure
                                 so the caller can activate the text ACTION fallback

Contract:
  parse_structured_output returns (response_str, action_dict | None).
  response_str is None ONLY when JSON parsing failed entirely — that is the signal
  to activate the text ACTION fallback and emit the fallback warning log.
  When response_str is a string (possibly empty), JSON parsed successfully; action
  may still be None if engine_id was null/absent/not in registry.

Never raises.
"""
from __future__ import annotations

import json
import logging

logger = logging.getLogger("conductor.qwen.action_schema")


def _exploitation_engine_ids() -> list[str]:
    """Return sorted list of engine_ids for all registered exploitation engines.

    Reads from engine_registry at call time — never drifts from the canonical
    registry. Falls back to the hardcoded approved set in routes.py if the
    registry is unavailable (e.g. test environments that don't register engines).
    """
    try:
        import apps.conductor.engines  # noqa: F401 — triggers registration
        from apps.conductor.engines.base import engine_registry
        ids = sorted(
            e.engine_id
            for e in engine_registry.engines_for_phase("exploitation")
        )
        if ids:
            return ids
    except Exception as exc:
        logger.debug("action_schema: registry lookup failed: %s", exc)

    # _APPROVED_ENGINES: test-environment fallback ONLY. Must stay in sync with
    # engine_registry.engines_for_phase("exploitation"). Update both together.
    # Never reachable in production (registry always available at runtime).
    return sorted([
        "access_control", "cmdi_blind_boolean", "cmdi_blind_time",
        "cmdi_reflected", "credential_brute", "default_creds",
        "js_spider", "metasploit_recipe", "sqli_auth_bypass",
        "username_enum", "xss_reflected",
    ])


def build_action_schema(engine_ids: list[str] | None = None) -> dict:
    """Return an Ollama-compatible JSON schema for the model's dispatch output.

    The schema enforces:
      - response:   string — human-readable advice shown in the chat panel
      - engine_id:  string (enum of valid engine ids) or null for no-action
      - params:     object — engine parameters (finding_type, reason, extended_payloads)

    Pass engine_ids to override the registry lookup (useful in tests).
    """
    ids = engine_ids if engine_ids is not None else _exploitation_engine_ids()
    # Ollama enum with null: list the string values + null literal
    engine_enum = ids + [None]  # type: ignore[list-item]

    return {
        "type": "object",
        "required": ["response", "engine_id"],
        "properties": {
            "response": {
                "type": "string",
            },
            "engine_id": {
                "type": ["string", "null"],
                "enum": engine_enum,
            },
            "params": {
                "type": "object",
                "properties": {
                    "finding_type": {"type": "string"},
                    "reason":       {"type": "string"},
                    "extended_payloads": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "endpoint": {"type": "string"},
                                "method":   {"type": "string"},
                                "body":     {"type": "object"},
                            },
                            "required": ["endpoint", "body"],
                        },
                    },
                },
            },
        },
    }


def parse_structured_output(
    response_text: str,
    valid_engine_ids: set[str] | None = None,
) -> tuple[str | None, dict | None]:
    """Primary parser for schema-constrained model output.

    Returns:
        (None, None)              — JSON parse failed; caller MUST activate fallback
        (response_str, None)      — JSON valid; engine_id null/absent/not in registry
        (response_str, action)    — fully valid dispatch action

    Never raises.
    """
    if valid_engine_ids is None:
        valid_engine_ids = set(_exploitation_engine_ids())

    # ── Step 1: JSON parse ────────────────────────────────────────────────────
    try:
        parsed = json.loads(response_text.strip())
    except Exception:
        return None, None  # signal caller to activate text fallback

    if not isinstance(parsed, dict):
        return None, None  # not an object — treat as parse failure

    # ── Step 2: Extract response text ────────────────────────────────────────
    # Prefer the "response" field from the parsed JSON; fall back to the raw
    # model output so the operator sees something rather than an empty panel.
    response_str: str = str(parsed.get("response") or response_text)

    # ── Step 3: Validate engine_id ───────────────────────────────────────────
    engine_id = parsed.get("engine_id")
    if not engine_id or engine_id not in valid_engine_ids:
        # No valid action — response text still shown to operator
        return response_str, None

    # ── Step 4: Build action dict ─────────────────────────────────────────────
    params = parsed.get("params") or {}
    if not isinstance(params, dict):
        params = {}

    action: dict = {
        "engine_id":    engine_id,
        "finding_type": str(params.get("finding_type") or ""),
        "reason":       str(params.get("reason") or "")[:200],
    }

    # Validate extended_payloads shape — same rules as text parser
    raw_payloads = params.get("extended_payloads", [])
    if isinstance(raw_payloads, list):
        valid_payloads = [
            {
                "endpoint": p["endpoint"],
                "method":   str(p.get("method", "POST")).upper(),
                "body":     p["body"],
            }
            for p in raw_payloads
            if (
                isinstance(p, dict)
                and isinstance(p.get("endpoint"), str)
                and isinstance(p.get("body"), dict)
            )
        ]
        if valid_payloads:
            action["extended_payloads"] = valid_payloads

    return response_str, action
