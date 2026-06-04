"""Phase 2 — Graph-derived branch resolver.

Given a finding_type, returns the complete grounded branch set by reading
the Phase-0 knowledge graph (concept .md files in the knowledge vault).

Single source of truth for "what branches grow from a finding": the concept
files. Adding a technique class = edit the concept's grows_from; no code change.

BranchSpec:
  - concept_id, concept_filename, engine_id, engine_exists, executable
  - grows_from (real finding_types only; FUTURE logged, not included)
  - siblings, progression (concept filenames for graph traversal)
  - leaf_type ("terminal" | "can_be_blocked" | "unknown")
  - title, description, when_to_use
  - required_params, produces, preconditions (from manifest for EXISTS engines)

NONE-YET branches: included in the set, executable=False.
FUTURE grows_from edges: skipped and logged as enum-gaps.
UNCERTAIN grows_from: treated as real (AI can reason about them).
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("conductor.graph_resolver")

_VAULT_PATH = Path(os.environ.get("KNOWLEDGE_VAULT_PATH", "/app/knowledge-vault"))

# Engine supplement: concept_ids whose engine binding is not in CONCEPT_ENGINE_MAP.
# oracle_search handles the nosql-operator-injection keys_enumeration + where_extract.
_CONCEPT_ENGINE_SUPPLEMENT: dict[str, str] = {
    "CONCEPT-NOSQL-OPERATOR-INJECTION": "oracle_search",
    "CONCEPT-AUTH-BYPASS-LOGIN":        "auth_bypass_login",
}


@dataclass
class BranchSpec:
    """One branch in the knowledge graph for a given finding_type."""
    concept_id:       str             # CONCEPT-CREDENTIAL-BRUTE
    concept_filename: str             # concept-credential-brute
    engine_id:        str | None      # dispatch key; None = NONE-YET
    engine_exists:    bool            # True if in CONCEPT_ENGINE_MAP or supplement
    executable:       bool            # False = NONE-YET (engine exists but has no impl)
    title:            str             # from frontmatter
    grows_from:       list[str]       # real finding_types this grows from
    siblings:         list[str]       # sibling concept filenames
    progression:      list[str]       # deeper variant concept filenames
    leaf_type:        str             # "terminal" | "can_be_blocked" | "unknown"
    description:      str             # brief from concept body
    when_to_use:      str = ""        # from manifest PrimitiveSpec (if available)
    required_params:  list = field(default_factory=list)   # from manifest
    produces:         str = ""        # from manifest
    preconditions:    tuple = ()      # from manifest (for executability gating)
    # Phase 4: stem engines parsed from concept's "Engine support: EXISTS" lines.
    # [{engine_id, primitive_id, strategy, engine_exists, rationale}]
    stem_engines:     list = field(default_factory=list)


# ── FUTURE-edge log (enum-gap visibility) ─────────────────────────────────────

_future_edges_logged: set[tuple[str, str]] = set()   # (concept_id, finding_type)


def _log_future_edge(concept_id: str, finding_type: str) -> None:
    key = (concept_id, finding_type)
    if key not in _future_edges_logged:
        _future_edges_logged.add(key)
        logger.debug(
            "graph_resolver FUTURE-edge: concept=%s grows_from=%r "
            "(enum does not emit this yet — enum-gap for later phase)",
            concept_id, finding_type,
        )


# ── Frontmatter + Relationships parser ───────────────────────────────────────

def _parse_frontmatter(text: str) -> dict:
    """Extract YAML frontmatter key/value pairs (simple subset: id, title, engine_id)."""
    fm: dict = {}
    if not text.startswith("---"):
        return fm
    end = text.find("\n---", 3)
    if end == -1:
        return fm
    block = text[3:end]
    for line in block.splitlines():
        line = line.rstrip()
        if line.startswith("id:"):
            fm["id"] = line[3:].strip().strip("\"'")
        elif line.startswith("title:"):
            fm["title"] = line[6:].strip().strip("\"'")
        elif line.startswith("engine_id:"):
            val = line[10:].strip().strip("\"'")
            if val and val != "null":
                fm["engine_id"] = val
    return fm


def _parse_relationships(text: str) -> dict:
    """Extract the Relationships section from a concept .md file.

    Returns dict with keys:
      classification, grows_from_real, grows_from_future, siblings,
      progression, leaf_type
    """
    result: dict = {
        "classification":   "",
        "grows_from_real":  [],   # (finding_type, is_uncertain)
        "grows_from_future": [],  # finding_types marked FUTURE
        "siblings":         [],   # concept filenames
        "progression":      [],   # concept filenames
        "leaf_type":        "unknown",
        "stem_engines":     [],   # Phase 4: [{engine_id, primitive_id, strategy, engine_exists, rationale}]
    }

    rel_start = text.find("## Relationships")
    if rel_start == -1:
        return result

    rel_text = text[rel_start:]

    # classification
    m = re.search(r"\*\*Classification:\*\*\s*(.+)", rel_text)
    if m:
        result["classification"] = m.group(1).strip()

    # Extract section bodies
    grows_section    = _section_body(rel_text, "Grows from")
    sibling_section  = _section_body(rel_text, "Sibling branches")
    prog_section     = _section_body(rel_text, "Progression")
    leaf_section     = _section_body(rel_text, "Leaf classification")

    # Parse grows_from
    if grows_section:
        for line in grows_section.splitlines():
            line = line.strip()
            if not line.startswith("-"):
                continue
            # Extract all backtick-wrapped finding_types from this line
            fts = re.findall(r"`([a-z_]+)`", line)
            is_future   = "FUTURE" in line
            is_uncertain = "UNCERTAIN" in line
            for ft in fts:
                # Accept any identifier >= 2 chars that looks like a finding_type.
                # Note: some real finding_types have NO underscores (sqli, xss, xxe, ssrf).
                # Excluded: single chars, obviously-not-finding-types like 'true'/'false'.
                if len(ft) >= 2 and ft not in ("if", "or", "in", "is", "as"):
                    if is_future:
                        result["grows_from_future"].append(ft)
                    else:
                        result["grows_from_real"].append((ft, is_uncertain))

    # Parse sibling branches → extract [[concept-name]] links
    if sibling_section:
        for m in re.finditer(r"\[\[([^\]]+)\]\]", sibling_section):
            fname = m.group(1).strip()
            if fname.startswith("concept-"):
                result["siblings"].append(fname)

    # Parse progression → extract [[concept-name]] links
    if prog_section:
        for m in re.finditer(r"\[\[([^\]]+)\]\]", prog_section):
            fname = m.group(1).strip()
            if fname.startswith("concept-"):
                result["progression"].append(fname)

    # Parse leaf classification — the value may be on the SAME LINE as the header
    # (e.g. "**Leaf classification:** `can_be_blocked`") or in the body below.
    # Search the full Relationships section text for the pattern.
    lm_leaf = re.search(
        r"\*\*Leaf classification[^*]*\*\*[^\n]*`(can_be_blocked|terminal)`",
        rel_text, re.IGNORECASE,
    )
    if not lm_leaf and leaf_section:
        lm_leaf = re.search(r"`(can_be_blocked|terminal)`", leaf_section)
    if lm_leaf:
        result["leaf_type"] = lm_leaf.group(1)

    # Phase 4: Parse stem engines from "Engine support: EXISTS — {engine_id} engine, strategy={strategy}"
    # These appear in the stem/blocked-conditions sections of can_be_blocked concepts.
    stem_engines: list[dict] = []
    # Pattern: "Engine support: **EXISTS** — oracle_search engine, strategy=keys_enumeration"
    for sm in re.finditer(
        r"Engine support:\s*\*?\*?EXISTS\*?\*?\s*[—–-]\s*(\w+)\s+engine,?\s*strategy=(\w+)",
        rel_text, re.IGNORECASE,
    ):
        eid = sm.group(1).strip()
        strategy = sm.group(2).strip()
        primitive_id = f"{eid}.{strategy}"
        rationale_match = re.search(
            rf"\*\*([^*]+)\*\*[^\n]*{re.escape(sm.group(1))}",
            rel_text[:sm.start()],
        )
        rationale = rationale_match.group(1).strip() if rationale_match else strategy
        stem_engines.append({
            "engine_id":    eid,
            "primitive_id": primitive_id,
            "strategy":     strategy,
            "engine_exists": True,
            "rationale":    rationale[:80],
        })
    # Also detect NONE-YET stems
    for sm in re.finditer(
        r"Engine support:\s*NONE\s*YET[^\n]*(\w+)\s+engine",
        rel_text, re.IGNORECASE,
    ):
        eid = sm.group(1).strip()
        stem_engines.append({
            "engine_id":    eid,
            "primitive_id": eid,
            "strategy":     None,
            "engine_exists": False,
            "rationale":    f"NONE-YET: {eid}",
        })
    result["stem_engines"] = stem_engines

    return result


def _section_body(text: str, section_name: str) -> str:
    """Extract the body of a **Section name:** block until the next ** header."""
    # Match patterns like "**Grows from:**" or "**Leaf classification:**"
    pattern = rf"\*\*{re.escape(section_name)}[^*]*?\*\*[^\n]*\n(.*?)(?=\n\*\*[A-Z]|\Z)"
    m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    if m:
        return m.group(1)
    return ""


# ── Brief description extractor ───────────────────────────────────────────────

def _extract_description(text: str) -> str:
    """Pull the > Summary blockquote from the concept body."""
    m = re.search(r"^>\s*(.+)", text, re.MULTILINE)
    if m:
        return m.group(1).strip()[:120]
    # Fallback: first non-blank body line after title
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("---") and len(line) > 10:
            return line[:120]
    return ""


# ── Single concept file parser ────────────────────────────────────────────────

def _parse_concept_file(filepath: Path) -> BranchSpec | None:
    """Parse one concept .md file into a BranchSpec (before manifest enrichment).

    Returns None for cross-cutting concepts (not tree branches).
    """
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        logger.debug("graph_resolver: cannot read %s: %s", filepath, exc)
        return None

    fm   = _parse_frontmatter(text)
    rels = _parse_relationships(text)

    concept_id = fm.get("id", "")
    if not concept_id:
        return None

    # Skip cross-cutting concepts (not tree branches)
    cls = rels["classification"].lower()
    if "cross-cutting" in cls or "not a tree branch" in cls:
        logger.debug("graph_resolver: %s is cross-cutting, skipped", concept_id)
        return None

    # Engine binding: frontmatter engine_id → supplement → CONCEPT_ENGINE_MAP
    engine_id = fm.get("engine_id") or _CONCEPT_ENGINE_SUPPLEMENT.get(concept_id)
    if not engine_id:
        from apps.conductor.constants import CONCEPT_ENGINE_MAP
        engine_id = CONCEPT_ENGINE_MAP.get(concept_id)

    engine_exists = engine_id is not None and engine_id != "null"
    # engine_exists=True means there is an engine mapping; the engine may still
    # have no implementation (NONE-YET in the manifest sense) — we use executable
    # to distinguish post-precondition filtering.
    executable = engine_exists

    grows_real = [ft for ft, _unc in rels["grows_from_real"]]

    return BranchSpec(
        concept_id       = concept_id,
        concept_filename = filepath.stem,
        engine_id        = engine_id if engine_exists else None,
        engine_exists    = engine_exists,
        executable       = executable,
        title            = fm.get("title", concept_id),
        grows_from       = list(dict.fromkeys(grows_real)),   # deduplicate
        siblings         = list(dict.fromkeys(rels["siblings"])),
        progression      = list(dict.fromkeys(rels["progression"])),
        leaf_type        = rels["leaf_type"],
        description      = _extract_description(text),
        stem_engines     = rels["stem_engines"],   # Phase 4: stem steps
    )


# ── Graph index (cached) ─────────────────────────────────────────────────────

_graph_index: dict[str, list[BranchSpec]] | None = None   # {finding_type → [BranchSpec]}
_concept_map: dict[str, BranchSpec] | None = None          # {concept_id → BranchSpec}


def _build_index() -> tuple[dict[str, list[BranchSpec]], dict[str, BranchSpec]]:
    """Read all concept files and build finding_type → [BranchSpec] index."""
    concepts_dir = _VAULT_PATH / "concepts"
    if not concepts_dir.is_dir():
        logger.warning("graph_resolver: concepts dir not found at %s", concepts_dir)
        return {}, {}

    concept_map: dict[str, BranchSpec] = {}
    for md_file in sorted(concepts_dir.glob("*.md")):
        spec = _parse_concept_file(md_file)
        if spec:
            concept_map[spec.concept_id] = spec

    # Build finding_type → branches index
    ft_index: dict[str, list[BranchSpec]] = {}
    for spec in concept_map.values():
        # Log FUTURE edges
        try:
            text = (concepts_dir / f"{spec.concept_filename}.md").read_text(encoding="utf-8")
            rels = _parse_relationships(text)
            for ft in rels["grows_from_future"]:
                _log_future_edge(spec.concept_id, ft)
        except Exception:
            pass

        for ft in spec.grows_from:
            ft_index.setdefault(ft, []).append(spec)

    logger.debug(
        "graph_resolver: indexed %d concepts across %d finding_types",
        len(concept_map), len(ft_index),
    )
    return ft_index, concept_map


def _get_index() -> tuple[dict[str, list[BranchSpec]], dict[str, BranchSpec]]:
    global _graph_index, _concept_map
    if _graph_index is None:
        _graph_index, _concept_map = _build_index()
    return _graph_index, _concept_map


def rebuild_index() -> None:
    """Force rebuild (call after vault changes)."""
    global _graph_index, _concept_map
    _graph_index = None
    _concept_map = None
    _get_index()


# ── Manifest enrichment ───────────────────────────────────────────────────────

def _enrich_from_manifest(spec: BranchSpec) -> BranchSpec:
    """Add manifest PrimitiveSpec fields (when_to_use, required_params, preconditions).

    For EXISTS engines: look up the best PrimitiveSpec from the manifest.
    For NONE-YET engines: leave blank — executable=False already set.
    """
    if not spec.engine_exists or not spec.engine_id:
        return spec

    try:
        from apps.conductor.capability_manifest import get_manifest as _get_manifest
        manifest = _get_manifest()
        # Find the PrimitiveSpec with matching engine_id (pick the first with most data)
        candidates = [p for p in manifest if p.engine_id == spec.engine_id]
        if not candidates:
            return spec
        # Prefer the one with a non-empty when_to_use + preconditions matching the concept
        # Simple heuristic: pick first candidate (they share engine_id so same dispatch)
        best = candidates[0]
        # Return a new BranchSpec with enriched fields
        return BranchSpec(
            concept_id       = spec.concept_id,
            concept_filename = spec.concept_filename,
            engine_id        = spec.engine_id,
            engine_exists    = spec.engine_exists,
            executable       = spec.executable,
            title            = spec.title,
            grows_from       = spec.grows_from,
            siblings         = spec.siblings,
            progression      = spec.progression,
            leaf_type        = spec.leaf_type,
            description      = spec.description,
            stem_engines     = spec.stem_engines,  # Phase 4: preserve stem knowledge
            when_to_use      = best.when_to_use,
            required_params  = [
                {"name": rp.name, "source_hint": rp.source_hint, "description": rp.description}
                for rp in best.required_params
            ],
            produces         = best.produces,
            preconditions    = best.preconditions,
        )
    except Exception as exc:
        logger.debug("graph_resolver: manifest enrichment failed for %s: %s", spec.concept_id, exc)
        return spec


# ── Precondition gating ───────────────────────────────────────────────────────

def _apply_preconditions(spec: BranchSpec, satisfied: "set[str]") -> BranchSpec | None:
    """Return the spec if its preconditions are satisfied, or None if gated out.

    NONE-YET branches (executable=False) bypass precondition gating:
    they are always returned so the AI knows the branch exists.
    """
    if not spec.executable:
        return spec   # NONE-YET: always include (no precondition check)
    if all(p in satisfied for p in spec.preconditions):
        return spec
    return None   # precondition not met → exclude


# ── Public API ────────────────────────────────────────────────────────────────

def resolve_branches(
    finding_type: str,
    satisfied_preconditions: "set[str] | None" = None,
    enrich_from_manifest: bool = True,
) -> list[BranchSpec]:
    """Return the complete grounded branch set for a finding_type from the graph.

    Args:
        finding_type: the real system finding_type string (e.g. "login_form_detected")
        satisfied_preconditions: set of satisfied precondition names (from
          evaluate_preconditions). When None, no precondition gating applied.
        enrich_from_manifest: if True, add when_to_use/required_params/preconditions
          from the manifest PrimitiveSpec for EXISTS engines.

    Returns:
        List of BranchSpec. NONE-YET branches included (executable=False).
        Sorted: executable branches first, NONE-YET last.
        Empty list when finding_type has no known branches in the graph.
    """
    ft_index, _ = _get_index()
    raw = ft_index.get(finding_type, [])

    if not raw:
        logger.debug("graph_resolver: no branches for finding_type=%r", finding_type)
        return []

    results: list[BranchSpec] = []
    for spec in raw:
        if enrich_from_manifest:
            spec = _enrich_from_manifest(spec)

        if satisfied_preconditions is not None:
            spec_out = _apply_preconditions(spec, satisfied_preconditions)
            if spec_out is None:
                continue   # precondition not met → exclude (executable branch)
            spec = spec_out

        results.append(spec)

    # Sort: executable first, NONE-YET last
    results.sort(key=lambda s: (0 if s.executable else 1, s.concept_id))
    logger.debug(
        "graph_resolver: resolved %d branch(es) for %r (exec=%d none_yet=%d)",
        len(results), finding_type,
        sum(1 for s in results if s.executable),
        sum(1 for s in results if not s.executable),
    )
    return results


def branch_to_primitive_dict(spec: BranchSpec) -> dict:
    """Convert a BranchSpec to the applicable_primitives dict format Stage 1+2 expect.

    The 'id' field is the engine_id (for dispatch routing), or the concept_filename
    when engine is NONE-YET (AI can reason about it but can't select it for dispatch).
    """
    prim_id = spec.engine_id or spec.concept_filename
    return {
        "id":             prim_id,
        "description":    spec.description or spec.title,
        "when_to_use":    spec.when_to_use or f"Technique: {spec.title}",
        "required_params": spec.required_params,
        "produces":       spec.produces,
        # Phase 2 additions (available to the AI as context):
        "concept_id":     spec.concept_id,
        "executable":     spec.executable,
        "engine_exists":  spec.engine_exists,
        "progression":    spec.progression,
        "leaf_type":      spec.leaf_type,
        "stem_engines":   spec.stem_engines,   # Phase 4: stem steps for BLOCKED leaves
    }


def get_branch_by_concept(concept_id: str) -> "BranchSpec | None":
    """Look up a BranchSpec by concept_id (for leaf evaluation at result time)."""
    _, cmap = _get_index()
    return cmap.get(concept_id)


def future_edges_for(concept_id: str) -> list[str]:
    """Return the FUTURE grows_from edges for a concept (enum-gap visibility)."""
    concepts_dir = _VAULT_PATH / "concepts"
    _, cmap = _get_index()
    spec = cmap.get(concept_id)
    if not spec:
        return []
    try:
        text = (concepts_dir / f"{spec.concept_filename}.md").read_text(encoding="utf-8")
        rels = _parse_relationships(text)
        return rels["grows_from_future"]
    except Exception:
        return []
