"""Phase B-1 — Vault Inspection Panel + Dedup tests.

Six tests (all mock-based, no live ChromaDB/Ollama required):

Test 1: GET /admin/vault-inspect renders the form without error.
Test 2: POST /admin/vault-inspect with a sample query returns results partial
        with rank, score, and snippet fields (mock ChromaDB response).
Test 3: POST /admin/vault-inspect when ChromaDB unavailable (empty results from
        inspect_vault) returns the "unavailable" message, not an error.
Test 4: POST /admin/vault-dedup with one near-duplicate pair removes the correct
        document (non-concept file; newer = higher index).
Test 5: POST /admin/vault-dedup with no near-duplicates returns 0 pairs, 0 removed.
Test 6: dedup_vault_entries keeps concept file over non-concept file regardless
        of index order.
"""
from __future__ import annotations

import math
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── availability guard ────────────────────────────────────────────────────────


def _check_fastapi() -> bool:
    try:
        import fastapi  # noqa: F401
        import httpx    # noqa: F401
        return True
    except ImportError:
        return False


# ── shared app fixture ────────────────────────────────────────────────────────


def _make_app():
    from fastapi import FastAPI
    from apps.admin_ui.routes import router
    app = FastAPI()
    app.include_router(router)
    return app


# ── Test 1: GET renders the form ──────────────────────────────────────────────


@pytest.mark.skipif(not _check_fastapi(), reason="fastapi/httpx not on host")
def test_vault_inspect_get_renders_form():
    """GET /admin/vault-inspect returns 200 and contains form fields."""
    from fastapi.testclient import TestClient
    client = TestClient(_make_app())
    resp = client.get("/admin/vault-inspect")
    assert resp.status_code == 200
    html = resp.text
    assert "finding_type" in html
    assert "description" in html
    assert "top_k" in html or "Top-K" in html
    assert "Search Vault" in html
    assert "Run Dedup" in html


# ── Test 2: POST with mock results returns results partial ────────────────────


@pytest.mark.skipif(not _check_fastapi(), reason="fastapi/httpx not on host")
def test_vault_inspect_post_returns_results():
    """POST /admin/vault-inspect with mocked inspect_vault → results table rendered."""
    import asyncio

    _FAKE_RESULTS = [
        {
            "rank": 1,
            "doc_id": "FIND-WEB-20260528-001",
            "title": "Credential brute lab walkthrough",
            "similarity": 0.9234,
            "distance": 0.0766,
            "snippet": "## Credential brute-force against /login endpoint...",
        },
        {
            "rank": 2,
            "doc_id": "CONCEPT-CREDENTIAL-BRUTE",
            "title": "Credential Brute concept",
            "similarity": 0.8801,
            "distance": 0.1199,
            "snippet": "Brute-force login forms using a wordlist...",
        },
    ]

    async def _run():
        with patch(
            "apps.conductor.qwen.vault_embedder.inspect_vault",
            new=AsyncMock(return_value=_FAKE_RESULTS),
        ):
            from fastapi.testclient import TestClient
            client = TestClient(_make_app())
            resp = client.post(
                "/admin/vault-inspect",
                data={"finding_type": "login_form_detected", "description": "Login form at /login", "top_k": "10"},
            )
        return resp

    resp = asyncio.get_event_loop().run_until_complete(_run())
    assert resp.status_code == 200
    html = resp.text
    assert "FIND-WEB-20260528-001" in html
    assert "0.9234" in html
    assert "CONCEPT-CREDENTIAL-BRUTE" in html
    assert "Rank" in html or "rank" in html.lower()


# ── Test 3: POST when vault unavailable → shows unavailable message ───────────


@pytest.mark.skipif(not _check_fastapi(), reason="fastapi/httpx not on host")
def test_vault_inspect_post_unavailable():
    """POST /admin/vault-inspect when inspect_vault returns [] → unavailable message shown."""
    import asyncio

    async def _run():
        with patch(
            "apps.conductor.qwen.vault_embedder.inspect_vault",
            new=AsyncMock(return_value=[]),
        ):
            from fastapi.testclient import TestClient
            client = TestClient(_make_app())
            resp = client.post(
                "/admin/vault-inspect",
                data={"finding_type": "open_port_detected", "description": "", "top_k": "5"},
            )
        return resp

    resp = asyncio.get_event_loop().run_until_complete(_run())
    assert resp.status_code == 200
    html = resp.text
    assert "unavailable" in html.lower() or "empty" in html.lower() or "no results" in html.lower()
    assert "Error:" not in html


# ── Test 4: dedup removes correct document (non-concept, newer) ───────────────


@pytest.mark.asyncio
async def test_dedup_removes_newer_non_concept():
    """Near-duplicate pair (sim > 0.95): non-concept file is deleted when older is also non-concept."""
    from apps.conductor.qwen.vault_embedder import dedup_vault_entries, _cosine_sim_vecs

    # Build two near-identical embeddings (sim should be ~1.0)
    emb_base = [1.0, 0.0, 0.0]
    emb_near = [0.9999, 0.01, 0.0]   # very close
    sim = _cosine_sim_vecs(emb_base, emb_near)
    assert sim > 0.95, f"test setup: sim={sim} must be > 0.95"

    _fake_all = {
        "ids":        ["doc_older", "doc_newer"],
        "embeddings": [emb_base,    emb_near],
        "metadatas":  [{},           {}],
        "documents":  ["older text", "newer text"],
    }

    _deleted: list[str] = []

    class _FakeCollection:
        def count(self):    return 2
        def get(self, **_): return _fake_all
        def delete(self, ids):
            _deleted.extend(ids)

    with patch(
        "apps.conductor.qwen.vault_embedder._get_chroma_collection",
        return_value=(None, _FakeCollection()),
    ), patch(
        "apps.conductor.qwen.vault_embedder._check_chromadb",
        return_value=True,
    ):
        result = await dedup_vault_entries()

    assert result["pairs_found"] == 1
    assert result["removed"] == 1
    # "doc_newer" (index 1, higher = newer) must be the one deleted
    assert "doc_newer" in _deleted
    assert "doc_older" not in _deleted


# ── Test 5: dedup with no near-duplicates → 0 pairs, 0 removed ───────────────


@pytest.mark.asyncio
async def test_dedup_no_near_duplicates():
    """No near-duplicates → pairs_found=0, removed=0."""
    from apps.conductor.qwen.vault_embedder import dedup_vault_entries

    # Two orthogonal embeddings (sim = 0.0)
    _fake_all = {
        "ids":        ["doc_a", "doc_b"],
        "embeddings": [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]],
        "metadatas":  [{}, {}],
        "documents":  ["text a", "text b"],
    }

    class _FakeCollection:
        def count(self):    return 2
        def get(self, **_): return _fake_all
        def delete(self, ids): raise AssertionError("delete must not be called")

    with patch(
        "apps.conductor.qwen.vault_embedder._get_chroma_collection",
        return_value=(None, _FakeCollection()),
    ), patch(
        "apps.conductor.qwen.vault_embedder._check_chromadb",
        return_value=True,
    ):
        result = await dedup_vault_entries()

    assert result["pairs_found"] == 0
    assert result["removed"] == 0
    assert result["removed_ids"] == []


# ── Test 6: dedup keeps concept file over non-concept ─────────────────────────


@pytest.mark.asyncio
async def test_dedup_keeps_concept_file():
    """Concept file (CONCEPT- prefix) is kept over non-concept file regardless of order."""
    from apps.conductor.qwen.vault_embedder import dedup_vault_entries

    emb_a = [1.0, 0.0, 0.0]
    emb_b = [0.9999, 0.01, 0.0]   # near-identical to emb_a

    # Place concept file at index 1 (would be "newer" by position) — it must still be kept
    _fake_all = {
        "ids":        ["FIND-WEB-001",        "CONCEPT-BRUTE-FORCE"],
        "embeddings": [emb_a,                  emb_b],
        "metadatas":  [{},                      {}],
        "documents":  ["regular finding text",  "concept file text"],
    }

    _deleted: list[str] = []

    class _FakeCollection:
        def count(self):    return 2
        def get(self, **_): return _fake_all
        def delete(self, ids):
            _deleted.extend(ids)

    with patch(
        "apps.conductor.qwen.vault_embedder._get_chroma_collection",
        return_value=(None, _FakeCollection()),
    ), patch(
        "apps.conductor.qwen.vault_embedder._check_chromadb",
        return_value=True,
    ):
        result = await dedup_vault_entries()

    assert result["pairs_found"] == 1
    assert result["removed"] == 1
    # Non-concept file must be deleted; concept file must be kept
    assert "FIND-WEB-001" in _deleted
    assert "CONCEPT-BRUTE-FORCE" not in _deleted
