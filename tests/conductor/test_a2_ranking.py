"""V3.1 Part A2 — Orchestrated AI ranking unit tests.

Tests:
 1. Valid permutation returned → candidates reordered correctly.
 2. Model returns engine_id NOT in candidates → deterministic order unchanged.
 3. Incomplete permutation → deterministic order unchanged.
 4. Stage 1 or Stage 2 Ollama call fails → deterministic order unchanged, no raise.
 5. Single candidate → (caller should gate; function still handles gracefully).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _opt(engine_id: str, sim: float = 0.5, source: str = "vault"):
    from apps.conductor.vault_selector import TechniqueOption
    return TechniqueOption(
        concept_id="CONCEPT-" + engine_id.upper().replace("_", "-"),
        engine_id=engine_id,
        title=engine_id.replace("_", " ").title(),
        similarity=sim,
        requires_session=False,
        source=source,
        method=None,
        endpoint_hint=None,
    )


def _mock_ollama(stage1_class: str, stage2_order: list[str]):
    """Build an httpx.AsyncClient mock returning stage1 then stage2 responses."""
    import json

    resp1 = MagicMock()
    resp1.status_code = 200
    resp1.json.return_value = {"message": {"content": json.dumps({"class": stage1_class})}}

    resp2 = MagicMock()
    resp2.status_code = 200
    resp2.json.return_value = {
        "message": {"content": json.dumps({"ordered_engine_ids": stage2_order})}
    }

    call_count = [0]

    async def _post(url, **kwargs):
        call_count[0] += 1
        return resp1 if call_count[0] == 1 else resp2

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = _post
    return mock_client, call_count


# ── Test 1: valid permutation → reordered correctly ───────────────────────────


@pytest.mark.asyncio
async def test_valid_permutation_reordered():
    """Model returns valid permutation → candidates reordered per model output."""
    from apps.conductor.model_advisor import rank_candidates_with_context

    candidates = [
        _opt("sqli_auth_bypass", sim=0.75),
        _opt("access_control",   sim=0.60),
        _opt("credential_brute", sim=0.50),
    ]
    # Model ranks: nosql first (access_control), then sqli, then cred
    mock_client, _ = _mock_ollama(
        stage1_class="nosql-injection",
        stage2_order=["access_control", "sqli_auth_bypass", "credential_brute"],
    )

    with patch("apps.conductor.model_advisor.httpx.AsyncClient", return_value=mock_client):
        result = await rank_candidates_with_context(
            "sqli", "Login form injectable", candidates,
            objective="NoSQL MongoDB injection", recent_results=[],
        )

    engine_order = [o.engine_id for o in result if o.engine_id]
    assert engine_order[0] == "access_control", f"Expected access_control first, got {engine_order}"
    assert engine_order[1] == "sqli_auth_bypass"
    assert engine_order[2] == "credential_brute"


# ── Test 2: model returns unknown engine_id → deterministic order unchanged ───


@pytest.mark.asyncio
async def test_invalid_engine_id_returns_deterministic():
    """Model includes unknown engine_id → Stage 3 rejects, original order returned."""
    from apps.conductor.model_advisor import rank_candidates_with_context

    candidates = [
        _opt("sqli_auth_bypass", sim=0.75),
        _opt("access_control",   sim=0.60),
    ]
    # Model hallucinated "nmap_scan" which is not in candidates
    mock_client, _ = _mock_ollama(
        stage1_class="sql-injection",
        stage2_order=["nmap_scan", "sqli_auth_bypass"],  # nmap_scan is invalid
    )

    with patch("apps.conductor.model_advisor.httpx.AsyncClient", return_value=mock_client):
        result = await rank_candidates_with_context(
            "sqli", "Injectable endpoint", candidates,
            objective="SQL injection", recent_results=[],
        )

    # Must be unchanged — same order as input
    engine_order = [o.engine_id for o in result if o.engine_id]
    assert engine_order == ["sqli_auth_bypass", "access_control"], (
        f"Deterministic order must be preserved on invalid permutation, got {engine_order}"
    )


# ── Test 3: incomplete permutation → deterministic order unchanged ────────────


@pytest.mark.asyncio
async def test_incomplete_permutation_returns_deterministic():
    """Model omits an engine_id → Stage 3 rejects (not a permutation), unchanged."""
    from apps.conductor.model_advisor import rank_candidates_with_context

    candidates = [
        _opt("sqli_auth_bypass", sim=0.80),
        _opt("access_control",   sim=0.70),
        _opt("credential_brute", sim=0.60),
    ]
    # Model only returns 2 of 3 — not a complete permutation
    mock_client, _ = _mock_ollama(
        stage1_class="sql-injection",
        stage2_order=["access_control", "credential_brute"],  # missing sqli_auth_bypass
    )

    with patch("apps.conductor.model_advisor.httpx.AsyncClient", return_value=mock_client):
        result = await rank_candidates_with_context(
            "sqli", "Login page", candidates,
            objective=None, recent_results=[],
        )

    engine_order = [o.engine_id for o in result if o.engine_id]
    assert engine_order == ["sqli_auth_bypass", "access_control", "credential_brute"], (
        f"Incomplete permutation must not reorder. Got: {engine_order}"
    )


# ── Test 4: Ollama failure → deterministic order, no raise ────────────────────


@pytest.mark.asyncio
async def test_ollama_failure_returns_deterministic_no_raise():
    """When Ollama call raises, candidates returned unchanged without raising."""
    from apps.conductor.model_advisor import rank_candidates_with_context

    candidates = [
        _opt("access_control",   sim=0.80),
        _opt("sqli_auth_bypass", sim=0.70),
    ]

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(side_effect=ConnectionError("Ollama unreachable"))

    with patch("apps.conductor.model_advisor.httpx.AsyncClient", return_value=mock_client):
        result = await rank_candidates_with_context(
            "sqli", "Injectable login", candidates,
            objective="SQL injection", recent_results=[],
        )

    # Must return unchanged — Ollama failure → deterministic fallback
    assert result == candidates, "On Ollama failure, must return candidates unchanged"


# ── Test 5: two-call pattern (stage 1 + stage 2) ─────────────────────────────


@pytest.mark.asyncio
async def test_exactly_two_ollama_calls_for_ranking():
    """Ranking makes exactly 2 Ollama calls (stage 1 classify + stage 2 order)."""
    from apps.conductor.model_advisor import rank_candidates_with_context

    candidates = [
        _opt("sqli_auth_bypass", sim=0.75),
        _opt("access_control",   sim=0.60),
    ]
    mock_client, call_count = _mock_ollama(
        stage1_class="nosql-injection",
        stage2_order=["access_control", "sqli_auth_bypass"],
    )

    with patch("apps.conductor.model_advisor.httpx.AsyncClient", return_value=mock_client):
        await rank_candidates_with_context(
            "sqli", "Login form", candidates,
            objective="MongoDB NoSQL injection", recent_results=[],
        )

    assert call_count[0] == 2, f"Expected exactly 2 Ollama calls, got {call_count[0]}"
