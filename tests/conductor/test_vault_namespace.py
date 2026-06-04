"""Phase 5 — Vault namespace / entry_type metadata tests.

N1.  _extract_meta_from_content: concept content → entry_type="concept".
N2.  _extract_meta_from_content: finding content  → entry_type="finding".
N3.  _extract_meta_from_content: no type field    → entry_type="".
N4.  _do_embed: entry_type included in ChromaDB metadata.
N5.  _do_embed: no frontmatter type → warning logged, entry NOT indexed.
N6.  search_vault_semantic: entry_type filter → where={entry_type:...} passed to chroma.
N7.  search_vault_semantic: no filter         → no where= passed to chroma.
N8.  inspect_vault:         entry_type filter → where={entry_type:...} passed to chroma.
N9.  inspect_vault:         no filter         → no where= passed to chroma.
N10. vault_selector uses entry_type="concept" filter.
N11. context_builder uses entry_type="finding" filter.
"""
from __future__ import annotations

import inspect
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_VAULT_EMBEDDER = Path(__file__).resolve().parents[2] / "apps/conductor/qwen/vault_embedder.py"
_VAULT_SELECTOR = Path(__file__).resolve().parents[2] / "apps/conductor/vault_selector.py"
_CONTEXT_BUILDER = Path(__file__).resolve().parents[2] / "apps/conductor/qwen/context_builder.py"

_CONCEPT_CONTENT = """\
---
type: concept
id: CONCEPT-TEST-NAMESPACE
title: Test Namespace Concept
tags: [test]
---

## Summary

> Test concept for namespace metadata tests.
"""

_FINDING_CONTENT = """\
---
type: finding
id: FIND-WEB-TEST-001
title: Test Finding
tags: [web, auth-bypass]
---

## Summary

> Test finding for namespace metadata tests.
"""

_NO_TYPE_CONTENT = """\
---
id: SOME-ENTRY-WITHOUT-TYPE
title: No Type Entry
tags: [misc]
---

Content without a type field.
"""


# ── N1–N3: _extract_meta_from_content ────────────────────────────────────────

class TestExtractMeta:

    def test_concept_content_returns_entry_type_concept(self):
        """N1: concept frontmatter type → entry_type='concept'."""
        from apps.conductor.qwen.vault_embedder import _extract_meta_from_content
        _, _, _, entry_type = _extract_meta_from_content(_CONCEPT_CONTENT)
        assert entry_type == "concept", f"expected 'concept', got {entry_type!r}"

    def test_finding_content_returns_entry_type_finding(self):
        """N2: finding frontmatter type → entry_type='finding'."""
        from apps.conductor.qwen.vault_embedder import _extract_meta_from_content
        _, _, _, entry_type = _extract_meta_from_content(_FINDING_CONTENT)
        assert entry_type == "finding", f"expected 'finding', got {entry_type!r}"

    def test_no_type_returns_empty_string(self):
        """N3: no 'type' field in frontmatter → entry_type=''."""
        from apps.conductor.qwen.vault_embedder import _extract_meta_from_content
        _, _, _, entry_type = _extract_meta_from_content(_NO_TYPE_CONTENT)
        assert entry_type == "", f"expected '', got {entry_type!r}"


# ── N4–N5: _do_embed metadata contract ────────────────────────────────────────

class TestDoEmbed:

    @pytest.mark.asyncio
    async def test_entry_type_in_chroma_metadata(self):
        """N4: _do_embed includes entry_type in the upsert metadata dict."""
        col = MagicMock()
        col.count.return_value = 0

        with (
            patch("apps.conductor.qwen.vault_embedder._check_chromadb", return_value=True),
            patch("apps.conductor.qwen.vault_embedder._get_chroma_collection", return_value=(MagicMock(), col)),
            patch("apps.conductor.qwen.vault_embedder._get_embedding", new=AsyncMock(return_value=[0.1] * 10)),
        ):
            from apps.conductor.qwen.vault_embedder import _do_embed
            await _do_embed("CONCEPT-TEST-NAMESPACE", _CONCEPT_CONTENT)

        col.upsert.assert_called_once()
        call_kwargs = col.upsert.call_args
        metadatas = call_kwargs.kwargs.get("metadatas") or (call_kwargs.args[3] if len(call_kwargs.args) > 3 else None)
        if metadatas is None:
            # Try positional
            all_args = call_kwargs[0] if call_kwargs[0] else []
            metadatas = all_args[3] if len(all_args) > 3 else None
        assert metadatas is not None, "upsert must receive metadatas"
        meta = metadatas[0] if isinstance(metadatas, list) else metadatas
        assert "entry_type" in meta, f"entry_type must be in metadata, got {meta}"
        assert meta["entry_type"] == "concept", f"entry_type must be 'concept', got {meta['entry_type']!r}"

    @pytest.mark.asyncio
    async def test_no_type_skips_indexing(self):
        """N5: no frontmatter type → upsert NOT called (entry skipped to avoid untyped dilution)."""
        col = MagicMock()
        col.count.return_value = 0

        with (
            patch("apps.conductor.qwen.vault_embedder._check_chromadb", return_value=True),
            patch("apps.conductor.qwen.vault_embedder._get_chroma_collection", return_value=(MagicMock(), col)),
            patch("apps.conductor.qwen.vault_embedder._get_embedding", new=AsyncMock(return_value=[0.1] * 10)),
        ):
            from apps.conductor.qwen.vault_embedder import _do_embed
            await _do_embed("SOME-ENTRY-WITHOUT-TYPE", _NO_TYPE_CONTENT)

        # Entry must not be indexed — it has no frontmatter type and would dilute
        # namespace-filtered queries if indexed without an entry_type metadata field.
        col.upsert.assert_not_called()


# ── N6–N9: retrieval filter contract ─────────────────────────────────────────

class TestRetrievalFilter:

    @pytest.mark.asyncio
    async def test_search_semantic_with_filter_passes_where(self, tmp_path):
        """N6: search_vault_semantic(entry_type='concept') → where={'entry_type':'concept'} in query."""
        col = MagicMock()
        col.count.return_value = 5
        col.query.return_value = {"ids": [[]], "metadatas": [[]], "distances": [[]]}

        with (
            patch("apps.conductor.qwen.vault_embedder._check_chromadb", return_value=True),
            patch("apps.conductor.qwen.vault_embedder._get_chroma_collection", return_value=(MagicMock(), col)),
            patch("apps.conductor.qwen.vault_embedder._get_embedding", new=AsyncMock(return_value=[0.1] * 10)),
            patch("apps.conductor.qwen.vault_embedder.rerank_results", new=AsyncMock(return_value=[])),
            patch("apps.conductor.qwen.vault_embedder.VAULT_PATH", tmp_path),
        ):
            from apps.conductor.qwen.vault_embedder import _search_semantic
            await _search_semantic("test query", top_k=3, entry_type="concept")

        col.query.assert_called_once()
        call_kwargs = col.query.call_args.kwargs
        assert "where" in call_kwargs, "where filter must be passed to collection.query"
        assert call_kwargs["where"] == {"entry_type": "concept"}, (
            f"where must be {{'entry_type': 'concept'}}, got {call_kwargs['where']}"
        )

    @pytest.mark.asyncio
    async def test_search_semantic_without_filter_no_where(self, tmp_path):
        """N7: search_vault_semantic() without filter → no where= passed to collection.query."""
        col = MagicMock()
        col.count.return_value = 5
        col.query.return_value = {"ids": [[]], "metadatas": [[]], "distances": [[]]}

        with (
            patch("apps.conductor.qwen.vault_embedder._check_chromadb", return_value=True),
            patch("apps.conductor.qwen.vault_embedder._get_chroma_collection", return_value=(MagicMock(), col)),
            patch("apps.conductor.qwen.vault_embedder._get_embedding", new=AsyncMock(return_value=[0.1] * 10)),
            patch("apps.conductor.qwen.vault_embedder.rerank_results", new=AsyncMock(return_value=[])),
            patch("apps.conductor.qwen.vault_embedder.VAULT_PATH", tmp_path),
        ):
            from apps.conductor.qwen.vault_embedder import _search_semantic
            await _search_semantic("test query", top_k=3, entry_type=None)

        col.query.assert_called_once()
        call_kwargs = col.query.call_args.kwargs
        assert "where" not in call_kwargs, (
            "where must NOT be passed when entry_type is None (backward compat)"
        )

    @pytest.mark.asyncio
    async def test_inspect_vault_with_filter_passes_where(self):
        """N8: inspect_vault(entry_type='finding') → where={'entry_type':'finding'} in query."""
        col = MagicMock()
        col.count.return_value = 5
        col.query.return_value = {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}

        with (
            patch("apps.conductor.qwen.vault_embedder._check_chromadb", return_value=True),
            patch("apps.conductor.qwen.vault_embedder._get_chroma_collection", return_value=(MagicMock(), col)),
            patch("apps.conductor.qwen.vault_embedder._get_embedding", new=AsyncMock(return_value=[0.1] * 10)),
        ):
            from apps.conductor.qwen.vault_embedder import _do_inspect_vault
            await _do_inspect_vault("test query", top_k=5, entry_type="finding")

        col.query.assert_called_once()
        call_kwargs = col.query.call_args.kwargs
        assert "where" in call_kwargs
        assert call_kwargs["where"] == {"entry_type": "finding"}

    @pytest.mark.asyncio
    async def test_inspect_vault_without_filter_no_where(self):
        """N9: inspect_vault() without filter → no where= passed (backward compat)."""
        col = MagicMock()
        col.count.return_value = 5
        col.query.return_value = {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}

        with (
            patch("apps.conductor.qwen.vault_embedder._check_chromadb", return_value=True),
            patch("apps.conductor.qwen.vault_embedder._get_chroma_collection", return_value=(MagicMock(), col)),
            patch("apps.conductor.qwen.vault_embedder._get_embedding", new=AsyncMock(return_value=[0.1] * 10)),
        ):
            from apps.conductor.qwen.vault_embedder import _do_inspect_vault
            await _do_inspect_vault("test query", top_k=5, entry_type=None)

        col.query.assert_called_once()
        call_kwargs = col.query.call_args.kwargs
        assert "where" not in call_kwargs, "no where when entry_type=None"


# ── N10–N11: caller updates (source inspection) ───────────────────────────────

class TestCallerUpdates:

    def test_vault_selector_uses_concept_filter(self):
        """N10: vault_selector passes entry_type='concept' to inspect_vault."""
        src = _VAULT_SELECTOR.read_text()
        assert 'entry_type="concept"' in src, (
            'vault_selector must pass entry_type="concept" to inspect_vault '
            'to avoid finding/lab dilution in concept-targeted queries'
        )

    def test_context_builder_uses_finding_filter(self):
        """N11: context_builder passes entry_type='finding' to search_vault_semantic."""
        src = _CONTEXT_BUILDER.read_text()
        assert 'entry_type="finding"' in src, (
            'context_builder must pass entry_type="finding" to search_vault_semantic '
            'to retrieve past exploit records, not concept definitions'
        )
