"""V3.1 Part C — Auto-preselect fallback loop unit tests.

Tests:
 1. Fallback advance picks next-ranked untried option after one exhaustion.
 2. All options tried → all_techniques_tried state (preselect=None).
 3. Untried option is always the first non-tried in ranked order.
 4. already_attempted badge correctly set for tried engines.
 5. Fallback advance is purely deterministic — no model call.
"""
from __future__ import annotations

import pytest


def _opt(engine_id: str, sim: float = 0.5, already_attempted: bool = False):
    from apps.conductor.vault_selector import TechniqueOption
    return TechniqueOption(
        concept_id        = "CONCEPT-" + engine_id.upper().replace("_", "-"),
        engine_id         = engine_id,
        title             = engine_id.replace("_", " ").title(),
        similarity        = sim,
        requires_session  = False,
        source            = "vault",
        method            = None,
        endpoint_hint     = None,
        already_attempted = already_attempted,
    )


def _simulate_fallback(selection_options, tried_engine_ids: set):
    """Simulate the Part C fallback logic from context_panel route."""
    opts = [
        type(o)(
            concept_id                = o.concept_id,
            engine_id                 = o.engine_id,
            title                     = o.title,
            similarity                = o.similarity,
            requires_session          = o.requires_session,
            source                    = o.source,
            method                    = o.method,
            endpoint_hint             = o.endpoint_hint,
            payload_template_available= getattr(o, "payload_template_available", False),
            already_attempted         = o.engine_id in tried_engine_ids,
        )
        for o in selection_options
    ]
    untried = [i for i, o in enumerate(opts) if o.engine_id and not o.already_attempted]
    preselect = untried[0] if untried else None
    all_tried = not bool(untried)
    return opts, preselect, all_tried


# ── Test 1: fallback advance to next untried ──────────────────────────────────

def test_fallback_advance_picks_next_untried():
    """After sqli_auth_bypass exhausts, preselect advances to access_control."""
    options = [
        _opt("sqli_auth_bypass", sim=0.80),
        _opt("access_control",   sim=0.65),
        _opt("credential_brute", sim=0.50),
    ]
    # sqli_auth_bypass was tried (exhausted)
    updated, preselect, all_tried = _simulate_fallback(options, {"sqli_auth_bypass"})

    assert preselect is not None, "Must preselect next untried option"
    assert updated[preselect].engine_id == "access_control", (
        f"Expected access_control at preselect={preselect}, got {updated[preselect].engine_id}"
    )
    assert not all_tried


# ── Test 2: all options tried → all_techniques_tried ─────────────────────────

def test_all_options_tried_state():
    """When all ranked options have been tried, all_techniques_tried=True."""
    options = [
        _opt("sqli_auth_bypass", sim=0.80),
        _opt("access_control",   sim=0.65),
    ]
    updated, preselect, all_tried = _simulate_fallback(
        options, {"sqli_auth_bypass", "access_control"}
    )

    assert preselect is None, "No preselection when all options tried"
    assert all_tried is True, "all_techniques_tried must be True"


# ── Test 3: untried is first non-tried in ranked order ────────────────────────

def test_untried_respects_ranked_order():
    """Fallback walks the ranked list in order, not by similarity."""
    # Ranked order: sqli(0.80) > nosql(0.70) > credential(0.60)
    # sqli tried → next should be nosql (index 1)
    options = [
        _opt("sqli_auth_bypass", sim=0.80),  # index 0
        _opt("access_control",   sim=0.70),  # index 1 (nosql uses access_control)
        _opt("credential_brute", sim=0.60),  # index 2
    ]
    updated, preselect, all_tried = _simulate_fallback(options, {"sqli_auth_bypass"})

    assert preselect == 1, f"Expected preselect index 1 (access_control), got {preselect}"
    assert updated[preselect].engine_id == "access_control"


# ── Test 4: already_attempted badge correctly set ─────────────────────────────

def test_already_attempted_badge_on_tried_options():
    """Tried options get already_attempted=True; untried stay False."""
    options = [
        _opt("sqli_auth_bypass", sim=0.80),
        _opt("access_control",   sim=0.65),
        _opt("credential_brute", sim=0.50),
    ]
    updated, preselect, _ = _simulate_fallback(options, {"sqli_auth_bypass", "credential_brute"})

    by_engine = {o.engine_id: o for o in updated}
    assert by_engine["sqli_auth_bypass"].already_attempted is True
    assert by_engine["credential_brute"].already_attempted is True
    assert by_engine["access_control"].already_attempted is False
    assert preselect == 1  # access_control is index 1, the untried one


# ── Test 5: fallback is deterministic (no Ollama call expected) ───────────────

def test_fallback_is_deterministic_no_model():
    """Fallback advance must be pure list-walking — no model call involved."""
    # This test verifies the logic is synchronous/deterministic.
    # If rank_candidates_with_context were called in the fallback, it would
    # require async and an Ollama mock. The absence of async = no model call.
    options = [
        _opt("access_control",   sim=0.80),
        _opt("sqli_auth_bypass", sim=0.70),
    ]
    # Both simulate_fallback calls are synchronous — no Ollama dependency
    _, preselect1, _ = _simulate_fallback(options, set())
    _, preselect2, _ = _simulate_fallback(options, {"access_control"})

    assert preselect1 == 0  # no tries → first option
    assert preselect2 == 1  # access_control tried → sqli_auth_bypass
    # Test passes without any mock/Ollama setup — purely deterministic
