"""V2.8 — Semantic search for the knowledge vault using ChromaDB + Ollama embeddings.

Falls back gracefully at every layer:
  - chromadb not installed → all functions return empty/None silently
  - Ollama nomic-embed-text not available → falls back to TF-IDF similarity
  - Vault not mounted → returns [] silently

ChromaDB collection stored at {VAULT_PATH}/../data/vault_chroma/ so it
persists alongside validation.db.

Never raises — every public function catches all exceptions.
"""
from __future__ import annotations

import logging
import math
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("conductor.qwen.vault_embedder")

VAULT_PATH = Path(os.environ.get("KNOWLEDGE_VAULT_PATH", "/app/knowledge-vault"))
_OLLAMA_BASE = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
_EMBED_MODEL = "nomic-embed-text"
_CHROMA_DIR = Path(os.environ.get("CHROMA_DB_PATH", "/app/data/vault_chroma"))
_COLLECTION_NAME = "vault_findings"

# ── ChromaDB availability check ───────────────────────────────────────────────

_chromadb_available: bool | None = None  # None = not yet checked


def _check_chromadb() -> bool:
    global _chromadb_available
    if _chromadb_available is not None:
        return _chromadb_available
    try:
        import chromadb  # noqa: F401
        _chromadb_available = True
    except ImportError:
        _chromadb_available = False
        logger.debug("vault_embedder: chromadb not installed — semantic search disabled")
    return _chromadb_available


def _get_chroma_collection():
    """Return (client, collection) or raise if unavailable."""
    import chromadb
    _CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(_CHROMA_DIR))
    collection = client.get_or_create_collection(
        name=_COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )
    return client, collection


# ── Ollama availability check ─────────────────────────────────────────────────

_ollama_embed_available: bool | None = None


async def _check_ollama_embed() -> bool:
    """Check if nomic-embed-text is available in Ollama. Cached after first call."""
    global _ollama_embed_available
    if _ollama_embed_available is not None:
        return _ollama_embed_available
    try:
        import httpx
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{_OLLAMA_BASE}/api/tags")
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                if any(_EMBED_MODEL in m for m in models):
                    _ollama_embed_available = True
                    logger.debug("vault_embedder: %s available in Ollama", _EMBED_MODEL)
                    return True
    except Exception as exc:
        logger.debug("vault_embedder: Ollama tag check failed: %s", exc)
    _ollama_embed_available = False
    logger.debug("vault_embedder: %s not available — will use TF-IDF fallback", _EMBED_MODEL)
    return False


# ── Embedding ─────────────────────────────────────────────────────────────────

# ── Execution template stripping ─────────────────────────────────────────────
# EXEC-TEMPLATE blocks are structured YAML that must NOT enter the embedding.
# They are stripped from content before any embedding call so the prose signal
# remains clean. The original content (including the template) is stored in
# ChromaDB for human-readable snippets; only the embedding uses stripped text.

EXEC_TEMPLATE_RE = re.compile(
    r'<!-- EXEC-TEMPLATE-START.*?EXEC-TEMPLATE-END -->',
    re.DOTALL,
)

# EXEC-EXTRACT blocks (oracle extraction templates) must also be excluded from
# embeddings — same rationale as EXEC-TEMPLATE: structured YAML pollutes the
# semantic signal used for concept ranking.
EXEC_EXTRACT_RE = re.compile(
    r'<!-- EXEC-EXTRACT-START.*?EXEC-EXTRACT-END -->',
    re.DOTALL,
)

EXEC_ENUM_RE = re.compile(
    r'<!-- EXEC-ENUM-START.*?EXEC-ENUM-END -->',
    re.DOTALL,
)

EXEC_AUTH_BYPASS_RE = re.compile(
    r'<!-- EXEC-AUTH-BYPASS-START.*?EXEC-AUTH-BYPASS-END -->',
    re.DOTALL,
)

EXEC_WHERE_ENUM_RE = re.compile(
    r'<!-- EXEC-WHERE-ENUM-START.*?EXEC-WHERE-ENUM-END -->',
    re.DOTALL,
)

EXEC_WHERE_EXTRACT_RE = re.compile(
    r'<!-- EXEC-WHERE-EXTRACT-START.*?EXEC-WHERE-EXTRACT-END -->',
    re.DOTALL,
)


def embeddable_text(raw: str) -> str:
    """Strip EXEC-* structured blocks before embedding. Never raises."""
    try:
        cleaned = EXEC_TEMPLATE_RE.sub('', raw)
        cleaned = EXEC_EXTRACT_RE.sub('', cleaned)
        cleaned = EXEC_ENUM_RE.sub('', cleaned)
        cleaned = EXEC_AUTH_BYPASS_RE.sub('', cleaned)
        cleaned = EXEC_WHERE_ENUM_RE.sub('', cleaned)
        cleaned = EXEC_WHERE_EXTRACT_RE.sub('', cleaned)
        return cleaned.strip()
    except Exception:
        return raw


async def _get_embedding(text: str) -> list[float] | None:
    """Get embedding via Ollama nomic-embed-text. Returns None if unavailable."""
    if not await _check_ollama_embed():
        return None
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{_OLLAMA_BASE}/api/embeddings",
                json={"model": _EMBED_MODEL, "prompt": text},
            )
            if resp.status_code == 200:
                data = resp.json()
                embedding = data.get("embedding", [])
                if embedding:
                    return embedding
    except Exception as exc:
        logger.debug("vault_embedder: embedding fetch failed: %s", exc)
    return None


# ── TF-IDF fallback ───────────────────────────────────────────────────────────

def _tokenize(text: str) -> list[str]:
    return re.findall(r"\b[a-z0-9_-]{2,}\b", text.lower())


def _tfidf_score(query_tokens: set[str], doc_text: str) -> float:
    """Simple token overlap score (Jaccard-like)."""
    doc_tokens = set(_tokenize(doc_text))
    if not doc_tokens:
        return 0.0
    overlap = len(query_tokens & doc_tokens)
    union = len(query_tokens | doc_tokens)
    return overlap / union if union else 0.0


def _parse_frontmatter_only(filepath: "Path") -> tuple[dict, str]:
    """Read ONLY the YAML frontmatter block (between --- markers).

    Returns (frontmatter_dict, frontmatter_text). Stops reading after the
    closing --- so large file bodies are never loaded into memory during
    initial scoring. Returns ({}, "") on any parse error.
    """
    try:
        lines: list[str] = []
        with filepath.open(encoding="utf-8", errors="replace") as f:
            first = f.readline()
            if first.strip() != "---":
                return {}, ""
            for line in f:
                if line.strip() == "---":
                    break
                lines.append(line)
        fm_text = "".join(lines)
        import yaml
        fm = yaml.safe_load(fm_text) or {}
        return fm, fm_text
    except Exception:
        return {}, ""


def _frontmatter_bm25_score(query_tokens: set[str], fm: dict, fm_text: str) -> float:
    """Score a document by BM25-like overlap against its frontmatter only.

    Uses title, tags, keywords.*, finding_types, and any string values as
    the document corpus. Frontmatter is ~20–40 lines vs 50–200 for full file,
    so this is ~5-10x faster per file.

    Weight: exact keyword field matches score 3x, title 2x, free text 1x.
    """
    if not fm:
        return 0.0
    weighted_tokens: list[str] = []
    # High-signal fields
    for field in ("finding_types", "artifact_types", "action_kinds"):
        for v in fm.get("keywords", {}).get(field, []) if isinstance(fm.get("keywords"), dict) else []:
            weighted_tokens.extend(_tokenize(str(v)) * 3)
    for tag in fm.get("tags", []):
        weighted_tokens.extend(_tokenize(str(tag)) * 2)
    # Title
    weighted_tokens.extend(_tokenize(str(fm.get("title", ""))) * 2)
    # Full frontmatter text as fallback
    weighted_tokens.extend(_tokenize(fm_text))

    doc_tokens = set(weighted_tokens)
    if not doc_tokens:
        return 0.0
    overlap = len(query_tokens & doc_tokens)
    return overlap / (len(query_tokens) + 0.5) if query_tokens else 0.0


def _tfidf_search(
    query: str,
    top_k: int = 3,
    entry_type: str | None = None,
) -> list[dict]:
    """Frontmatter-first BM25 search over vault markdown files.

    Phase 1 (fast): parse only the YAML frontmatter block for every file
    and compute a BM25-like score. This avoids reading large file bodies.

    Phase 2 (full read): read the complete body of the top (top_k * 3)
    frontmatter candidates to extract Summary hints and refine scores.

    Result: top_k entries by combined score.

    entry_type: optional namespace filter matching the semantic search.
      "concept"       → scans concepts/ only
      "finding"       → scans findings/ subdirs only
      "lab-walkthrough" → scans labs/ only
      None (default)  → cross-directory scan (backward-compatible)
      Unrecognised type → cross-directory scan with a debug log.
    """
    from apps.conductor.qwen.context_builder import _parse_frontmatter_tags
    query_tokens = set(_tokenize(query))
    if not query_tokens or not VAULT_PATH.is_dir():
        return []

    # ── Namespace filter: map entry_type to directories ───────────────────────
    _TYPE_DIR_MAP: dict[str, list] = {
        "concept": [
            VAULT_PATH / "concepts",
        ],
        "finding": [
            VAULT_PATH / "findings" / "web",
            VAULT_PATH / "findings" / "api",
            VAULT_PATH / "findings" / "network",
        ],
        "lab-walkthrough": [
            VAULT_PATH / "labs",
        ],
    }
    if entry_type is None:
        scan_dirs = [
            VAULT_PATH / "findings" / "web",
            VAULT_PATH / "findings" / "api",
            VAULT_PATH / "findings" / "network",
            VAULT_PATH / "labs",
            VAULT_PATH / "concepts",
        ]
    elif entry_type in _TYPE_DIR_MAP:
        scan_dirs = _TYPE_DIR_MAP[entry_type]
    else:
        logger.debug(
            "vault_embedder: TF-IDF filter for entry_type=%r not mapped — returning cross-type",
            entry_type,
        )
        scan_dirs = [
            VAULT_PATH / "findings" / "web",
            VAULT_PATH / "findings" / "api",
            VAULT_PATH / "findings" / "network",
            VAULT_PATH / "labs",
            VAULT_PATH / "concepts",
        ]

    # ── Phase 1: frontmatter-only scoring ────────────────────────────────────
    phase1: list[tuple[float, "Path", dict]] = []
    try:
        for scan_dir in scan_dirs:
            if not scan_dir.is_dir():
                continue
            for filepath in scan_dir.glob("*.md"):
                fm, fm_text = _parse_frontmatter_only(filepath)
                if not fm or not fm.get("id"):
                    continue
                score = _frontmatter_bm25_score(query_tokens, fm, fm_text)
                if score > 0.0:
                    phase1.append((score, filepath, fm))
    except Exception as exc:
        logger.debug("vault_embedder: phase1 scan failed: %s", exc)
        return []

    phase1.sort(key=lambda x: x[0], reverse=True)
    # Keep top candidates for phase 2 (read full body for top N)
    phase2_candidates = phase1[: top_k * 3]

    # ── Phase 2: full-body read for top candidates only ───────────────────────
    results: list[tuple[float, dict]] = []
    for base_score, filepath, fm in phase2_candidates:
        try:
            text = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = ""
        # Refine score with full-body TF-IDF
        body_score = _tfidf_score(query_tokens, text)
        final_score = base_score * 0.7 + body_score * 0.3
        entry: dict = {
            "id": fm["id"],
            "title": fm.get("title", ""),
            "tags": fm.get("tags", []),
            "payload_hint": "",
            "outcome_hint": "",
        }
        m = re.search(r"##\s+Summary\s*\n+>\s*(.+)", text)
        if m:
            entry["outcome_hint"] = m.group(1).strip()[:120]
        # Extract payload hint from concept files
        mp = re.search(r"```[^\n]*\n(.*?)```", text, re.DOTALL)
        if mp:
            entry["payload_hint"] = mp.group(1).strip()[:100]
        results.append((final_score, entry))

    results.sort(key=lambda x: x[0], reverse=True)
    return [entry for _, entry in results[:top_k]]


# ── Public API ────────────────────────────────────────────────────────────────

async def search_vault_semantic(
    query: str,
    top_k: int = 3,
    entry_type: str | None = None,
) -> list[dict]:
    """Semantic search over the knowledge vault.

    Returns list of {id, title, tags, payload_hint, outcome_hint}.
    Falls back to TF-IDF if ChromaDB/Ollama unavailable.
    Returns [] (not raises) on any error or unavailability.

    entry_type: optional namespace filter (e.g. "concept", "finding").
      When provided, only entries with that entry_type in their metadata are returned.
      When None (default), all entry types are returned (backward-compatible).
      NOTE: entries indexed before the namespacing rebuild will not have entry_type
      metadata and will be excluded from filtered queries. Run POST /admin/vault/rebuild
      to ensure all entries are tagged.
    """
    try:
        return await _search_semantic(query, top_k, entry_type=entry_type)
    except Exception as exc:
        logger.debug("vault_embedder.search_vault_semantic failed: %s", exc)
        # Fall back to TF-IDF with entry_type filter preserved
        try:
            return _tfidf_search(query, top_k, entry_type=entry_type)
        except Exception:
            return []


async def _search_semantic(
    query: str,
    top_k: int,
    entry_type: str | None = None,
) -> list[dict]:
    if not _check_chromadb():
        return _tfidf_search(query, top_k, entry_type=entry_type)

    if not VAULT_PATH.exists() or not VAULT_PATH.is_dir():
        return []

    embedding = await _get_embedding(query)
    if embedding is None:
        return _tfidf_search(query, top_k, entry_type=entry_type)

    _, collection = _get_chroma_collection()
    count = collection.count()
    if count == 0:
        logger.debug("vault_embedder: chroma collection empty — falling back to tfidf")
        return _tfidf_search(query, top_k, entry_type=entry_type)

    # Retrieve top-10 candidates then rerank to top_k
    n_candidates = min(max(top_k * 3, 10), count)
    query_kwargs: dict = {
        "query_embeddings": [embedding],
        "n_results":        n_candidates,
        "include":          ["documents", "metadatas", "distances"],
    }
    if entry_type is not None:
        query_kwargs["where"] = {"entry_type": entry_type}
    results = collection.query(**query_kwargs)
    candidates: list[dict] = []
    for i, doc_id in enumerate(results.get("ids", [[]])[0]):
        metadata = (results.get("metadatas", [[]])[0] or [{}])[i] or {}
        dist = ((results.get("distances") or [[]])[0] or [1.0])[i]
        candidates.append({
            "id": metadata.get("finding_id", doc_id),
            "title": metadata.get("title", ""),
            "tags": json_loads_safe(metadata.get("tags", "[]")),
            "payload_hint": "",
            "outcome_hint": metadata.get("outcome_hint", ""),
            "similarity": round(max(0.0, 1.0 - float(dist)), 4),
        })

    # Rerank candidates; fall back to embedding order on any error
    reranked = await rerank_results(query, candidates, top_k=top_k)
    return reranked


# TODO: Reranker: enable when Ollama supports native reranking or
#       sentence-transformers is available in container.
async def _check_reranker() -> bool:
    return False


async def rerank_results(
    query: str,
    candidates: list[dict],
    top_k: int = 3,
) -> list[dict]:
    """Rerank top-N semantic search candidates by cross-encoder relevance.

    Uses qwen3-reranker:0.6B via Ollama if available.
    Falls back to original embedding similarity order if reranker unavailable.
    Never raises.
    """
    try:
        return await _do_rerank(query, candidates, top_k)
    except Exception as exc:
        logger.debug("vault_embedder.rerank_results failed: %s — using original order", exc)
        return candidates[:top_k]


async def _do_rerank(query: str, candidates: list[dict], top_k: int) -> list[dict]:
    if not candidates:
        return []
    if len(candidates) <= top_k:
        return candidates

    if not await _check_reranker():
        return candidates[:top_k]

    import httpx
    scored: list[tuple[float, dict]] = []

    async with httpx.AsyncClient(timeout=5.0) as client:
        for c in candidates:
            doc_text = f"{c.get('title', '')} {c.get('outcome_hint', '')} {' '.join(c.get('tags', []))}"
            prompt = (
                f"Query: {query}\n"
                f"Document: {doc_text}\n"
                f"Is this document relevant to the query? Answer with a number 0-10:"
            )
            try:
                resp = await client.post(
                    f"{_OLLAMA_BASE}/api/generate",
                    json={
                        "model": _RERANKER_MODEL,
                        "prompt": prompt,
                        "stream": False,
                        "options": {"num_predict": 5, "temperature": 0},
                    },
                )
                if resp.status_code == 200:
                    text = resp.json().get("response", "").strip()
                    # Extract first number from response
                    nums = re.findall(r"\b(\d+(?:\.\d+)?)\b", text)
                    score = float(nums[0]) / 10.0 if nums else 0.5
                else:
                    score = c.get("similarity", 0.5)
            except Exception:
                score = c.get("similarity", 0.5)
            scored.append((score, c))

    scored.sort(key=lambda x: x[0], reverse=True)
    logger.debug(
        "vault_embedder: reranked %d candidates → top %d: %s",
        len(candidates), top_k,
        [(round(s, 2), c.get("title", "")[:30]) for s, c in scored[:top_k]],
    )
    return [c for _, c in scored[:top_k]]


def json_loads_safe(value: Any) -> list:
    if isinstance(value, list):
        return value
    try:
        import json
        return json.loads(value)
    except Exception:
        return []


async def embed_vault_entry(finding_id: str, content: str) -> bool:
    """Store an embedding for a vault entry in ChromaDB.

    Returns True if the entry was indexed, False if skipped (no frontmatter type
    field, ChromaDB unavailable, near-duplicate guard, etc.) or if an error occurred.
    Never raises.
    """
    try:
        return await _do_embed(finding_id, content)
    except Exception as exc:
        logger.debug("vault_embedder.embed_vault_entry failed for %s: %s", finding_id, exc)
        return False


def _extract_meta_from_content(content: str) -> tuple[str, str, list[str], str]:
    """Parse title, outcome_hint, tags, and entry_type from markdown content frontmatter.

    Returns (title, outcome_hint, tags, entry_type). All fields are best-effort;
    empty/"" / [] on any parse failure.

    entry_type is read from the frontmatter `type` field (e.g. "concept", "finding",
    "lab-walkthrough"). Returns "" if the field is absent or cannot be parsed.
    """
    import json as _json
    title = ""
    tags: list[str] = []
    outcome_hint = ""
    entry_type = ""
    try:
        lines = content.splitlines()
        if lines and lines[0].strip() == "---":
            fm_lines: list[str] = []
            for line in lines[1:]:
                if line.strip() == "---":
                    break
                fm_lines.append(line)
            import yaml as _yaml
            fm = _yaml.safe_load("\n".join(fm_lines)) or {}
            title = str(fm.get("title", ""))
            raw_tags = fm.get("tags", [])
            tags = list(raw_tags) if isinstance(raw_tags, list) else []
            entry_type = str(fm.get("type", "")).strip()
    except Exception:
        pass
    m = re.search(r"##\s+Summary\s*\n+>\s*(.+)", content)
    if m:
        outcome_hint = m.group(1).strip()[:120]
    return title, outcome_hint, tags, entry_type


async def _do_embed(finding_id: str, content: str) -> bool:
    if not _check_chromadb():
        return False
    # Strip EXEC-TEMPLATE block before embedding — templates must not pollute
    # the retrieval signal. Original content is preserved for ChromaDB snippets.
    embedding = await _get_embedding(embeddable_text(content))
    if embedding is None:
        return False
    _, collection = _get_chroma_collection()

    # Near-duplicate guard: skip if a different entry is within cosine distance 0.05
    if collection.count() > 0:
        try:
            existing = collection.query(
                query_embeddings=[embedding],
                n_results=1,
                include=["distances", "ids"],
            )
            distances = (existing.get("distances") or [[]])[0]
            closest_ids = (existing.get("ids") or [[]])[0]
            if distances and closest_ids:
                dist = float(distances[0])
                closest_id = str(closest_ids[0])
                if dist < 0.05 and closest_id != finding_id:
                    logger.debug(
                        "vault_embedder: skipping near-duplicate %s (dist=%.4f, closest=%s)",
                        finding_id, dist, closest_id,
                    )
                    return False
        except Exception as exc:
            logger.debug("vault_embedder: dedup check failed for %s: %s", finding_id, exc)

    title, outcome_hint, tags, entry_type = _extract_meta_from_content(content)
    if not entry_type:
        logger.warning(
            "vault_embedder: no frontmatter 'type' field for %s — skipping (untyped entry "
            "would dilute namespace-filtered queries). Add 'type:' to the frontmatter.",
            finding_id,
        )
        return False
    import json as _json
    meta: dict = {
        "finding_id":  finding_id,
        "entry_type":  entry_type,   # namespace filter key; value from frontmatter 'type:'
        "outcome_hint": outcome_hint,
    }
    if title:
        meta["title"] = title
    if tags:
        meta["tags"] = _json.dumps(tags)

    collection.upsert(
        ids=[finding_id],
        embeddings=[embedding],
        documents=[content[:2000]],
        metadatas=[meta],
    )
    logger.debug("vault_embedder: embedded %s (entry_type=%r) into chroma", finding_id, entry_type)
    return True


async def rebuild_index() -> int:
    """Rebuild ChromaDB index from all vault markdown files.

    Returns count of entries indexed. Returns 0 on any error or unavailability.
    """
    try:
        return await _do_rebuild_index()
    except Exception as exc:
        logger.warning("vault_embedder.rebuild_index failed: %s", exc)
        return 0


async def _do_rebuild_index() -> int:
    if not _check_chromadb():
        logger.info("vault_embedder: chromadb unavailable — cannot rebuild index")
        return 0
    if not VAULT_PATH.exists() or not VAULT_PATH.is_dir():
        logger.info("vault_embedder: vault not mounted — cannot rebuild index")
        return 0

    scan_dirs = [
        VAULT_PATH / "findings" / "web",
        VAULT_PATH / "findings" / "api",
        VAULT_PATH / "findings" / "network",
        VAULT_PATH / "labs",
        VAULT_PATH / "concepts",  # concept files drive engine recommendation
    ]
    count = 0
    for scan_dir in scan_dirs:
        if not scan_dir.is_dir():
            continue
        for filepath in scan_dir.glob("*.md"):
            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
                # Prefer frontmatter id (uppercase e.g. CONCEPT-CREDENTIAL-BRUTE)
                # over file stem (lowercase concept-credential-brute) so concept_matcher
                # CONCEPT- prefix filter works correctly.
                fm, _ = _parse_frontmatter_only(filepath)
                finding_id = str(fm.get("id") or filepath.stem)
                # Skip entries without a 'type' field — they would be indexed
                # without entry_type metadata, diluting namespace-filtered queries.
                if not str(fm.get("type", "")).strip():
                    logger.warning(
                        "rebuild_index: skipping %s — no frontmatter 'type' field",
                        filepath.name,
                    )
                    continue
                await embed_vault_entry(finding_id, content)
                count += 1
            except Exception as exc:
                logger.debug("rebuild_index: skipping %s: %s", filepath, exc)
    logger.info("vault_embedder: rebuild_index completed — %d entries indexed", count)
    return count


async def get_entry_count() -> int:
    """Return the number of entries currently in the ChromaDB collection.

    Returns 0 if ChromaDB is unavailable or vault not mounted. Never raises.
    """
    try:
        if not _check_chromadb():
            return 0
        _, collection = _get_chroma_collection()
        return collection.count()
    except Exception:
        return 0


# ── Vault inspection (admin tool — read-only) ─────────────────────────────────


async def inspect_vault(
    query: str,
    top_k: int = 10,
    entry_type: str | None = None,
) -> list[dict]:
    """Query the vault and return raw results with similarity scores.

    Returns list of {rank, doc_id, title, similarity, distance, snippet}.
    Returns [] on any error or unavailability. Never raises.
    Admin-only: exposes raw float scores not shown to operators.

    entry_type: optional namespace filter (e.g. "concept", "finding").
      When None (default), all entry types are returned.
    """
    try:
        return await _do_inspect_vault(query, top_k, entry_type=entry_type)
    except Exception as exc:
        logger.debug("vault_embedder.inspect_vault failed: %s", exc)
        return []


async def _do_inspect_vault(
    query: str,
    top_k: int,
    entry_type: str | None = None,
) -> list[dict]:
    if not _check_chromadb():
        return []
    embedding = await _get_embedding(query)
    if embedding is None:
        return []
    _, collection = _get_chroma_collection()
    count = collection.count()
    if count == 0:
        return []
    n_results = min(top_k, count)
    query_kwargs: dict = {
        "query_embeddings": [embedding],
        "n_results":        n_results,
        "include":          ["documents", "metadatas", "distances"],
    }
    if entry_type is not None:
        query_kwargs["where"] = {"entry_type": entry_type}
    results = collection.query(**query_kwargs)
    ids   = (results.get("ids")       or [[]])[0]
    docs  = (results.get("documents") or [[]])[0]
    metas = (results.get("metadatas") or [[]])[0] or []
    dists = (results.get("distances") or [[]])[0]
    rows: list[dict] = []
    for rank, (doc_id, doc, meta, dist) in enumerate(zip(ids, docs, metas, dists), start=1):
        dist_f = float(dist)
        rows.append({
            "rank":       rank,
            "doc_id":     str(doc_id),
            "title":      (meta or {}).get("title", ""),
            "similarity": round(max(0.0, 1.0 - dist_f), 4),
            "distance":   round(dist_f, 4),
            "snippet":    (doc or "")[:200],
        })
    return rows


# ── Vault dedup (admin tool — destructive, operator-triggered only) ────────────


def _cosine_sim_vecs(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two equal-length float vectors. Returns 0.0 on error."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot   = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


async def dedup_vault_entries() -> dict:
    """Find and remove near-duplicate vault entries (cosine similarity > 0.95).

    Keep rule per entry pair:
      - If one is a concept file (ID starts with CONCEPT-) → keep the concept file
      - Otherwise → keep the older document (lower position in get() result)
    Logs each deletion.
    Returns {"pairs_found": N, "removed": N, "removed_ids": [...], "log": [...]}.
    Never raises.
    """
    try:
        return await _do_dedup_vault()
    except Exception as exc:
        logger.warning("vault_embedder.dedup_vault_entries failed: %s", exc)
        return {"pairs_found": 0, "removed": 0, "removed_ids": [], "log": [str(exc)]}


async def _do_dedup_vault() -> dict:
    if not _check_chromadb():
        return {"pairs_found": 0, "removed": 0, "removed_ids": [], "log": ["ChromaDB unavailable"]}
    _, collection = _get_chroma_collection()
    count = collection.count()
    if count == 0:
        return {"pairs_found": 0, "removed": 0, "removed_ids": [], "log": ["Collection is empty"]}

    all_data   = collection.get(include=["embeddings", "documents", "metadatas"])
    ids        = all_data.get("ids", []) or []
    embeddings = all_data.get("embeddings", []) or []
    n          = len(ids)

    if n == 0 or not embeddings:
        return {"pairs_found": 0, "removed": 0, "removed_ids": [], "log": ["No data returned"]}

    # Find near-duplicate pairs
    pairs: list[tuple[int, int, float]] = []
    for i in range(n):
        emb_i = embeddings[i]
        if not emb_i:
            continue
        for j in range(i + 1, n):
            emb_j = embeddings[j]
            if not emb_j:
                continue
            sim = _cosine_sim_vecs(emb_i, emb_j)
            if sim > 0.95:
                pairs.append((i, j, sim))

    to_delete: set[str] = set()
    log: list[str] = []

    for i, j, sim in pairs:
        id_i, id_j = ids[i], ids[j]
        if id_i in to_delete or id_j in to_delete:
            continue
        i_concept = str(id_i).upper().startswith("CONCEPT-")
        j_concept = str(id_j).upper().startswith("CONCEPT-")
        if i_concept and not j_concept:
            delete_id, keep_id = id_j, id_i
        elif j_concept and not i_concept:
            delete_id, keep_id = id_i, id_j
        else:
            # Neither or both are concepts — keep older (lower index)
            delete_id, keep_id = id_j, id_i
        to_delete.add(delete_id)
        log.append(f"sim={sim:.4f} keep={keep_id!r} remove={delete_id!r}")
        logger.info("vault dedup: keep=%r remove=%r sim=%.4f", keep_id, delete_id, sim)

    removed: list[str] = []
    for del_id in to_delete:
        try:
            collection.delete(ids=[del_id])
            removed.append(del_id)
        except Exception as exc:
            log.append(f"delete failed for {del_id!r}: {exc}")
            logger.warning("vault dedup: delete failed for %r: %s", del_id, exc)

    return {
        "pairs_found": len(pairs),
        "removed":     len(removed),
        "removed_ids": removed,
        "log":         log,
    }
