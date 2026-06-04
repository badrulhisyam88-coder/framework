"""Phase C-1 — VaultSelector: vault-driven technique ranking.

Given a finding (finding_type, title, optional endpoint), queries the vault
and returns a ranked list of TechniqueOption objects that the Phase C UI
renders as technique selection cards.

Public API:
  rank_techniques()     — async; queries vault, returns top-K concept options
  suggestions_floor()   — sync; returns SUGGESTIONS catalog floor options
  merge_with_floor()    — sync; merges vault + floor, surfaces conflicts

Design constraints (from Phase C-1 spec):
  - inspect_vault() is the ONLY ChromaDB access path here.
  - SIM_FLOOR is imported but NOT applied internally — the caller decides
    preselection vs model-invoke based on SIM_FLOOR (Phase D).
  - SUGGESTIONS catalog is read-only; VaultSelector never writes to it.
  - Never raises — return [] on any error or vault unavailability.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from apps.conductor.constants import (
    CONCEPT_ENGINE_MAP,
    CONCEPT_TITLES,
    OBJECTIVE_TECH_CONCEPTS,
    SESSION_REQUIRED_ENGINES,
    CONCEPT_PRODUCES,
    CONCEPT_FAMILY,
    FINDING_FAMILY_HINTS,
)

logger = logging.getLogger("conductor.vault_selector")

# Deferred import at module level so tests can patch vault_selector.inspect_vault
# without needing chromadb/Ollama installed on the host.
try:
    from apps.conductor.qwen.vault_embedder import inspect_vault
except ImportError:  # pragma: no cover — only in misconfigured environments
    async def inspect_vault(query: str, top_k: int = 10) -> list[dict]:  # type: ignore[misc]
        return []


@dataclass
class TechniqueOption:
    """One ranked technique option for the operator selection card."""
    concept_id:       str           # CONCEPT-* id, or "" for suggestions-floor entries
    engine_id:        str | None    # engine_id for Conductor dispatch, or None (advisory)
    title:            str           # human-readable technique name
    similarity:       float         # raw cosine similarity; 0.0 for floor entries
    requires_session: bool          # True when engine is in SESSION_REQUIRED_ENGINES
    source:           str           # "vault" | "suggestions" | "model"
    method:           str | None    # HTTP method hint (GET/POST), None if not stored
    endpoint_hint:    str | None    # path hint (e.g. /user/lookup), None if not stored
    payload_template_available: bool = False  # True if concept has an execution template
    already_attempted:          bool = False  # True if this engine was tried on this finding
    work_order_id:              str | None = None  # Set for AI work-order options (Bundle 2)


async def rank_techniques(
    finding_type: str,
    finding_title: str,
    finding_endpoint: str | None = None,
    top_k: int = 5,
) -> list[TechniqueOption]:
    """Embed the finding → query ChromaDB → return ranked TechniqueOptions.

    Query string: "{finding_type} {finding_title}" + endpoint if provided.

    Only CONCEPT-* entries from the vault are returned — FIND-* and FAIL-*
    entries are skipped. Concepts not in CONCEPT_ENGINE_MAP are also skipped.
    Results with engine_id=None (advisory concepts) are included.

    Never raises. Returns [] if vault unavailable or no concept results.
    """
    try:
        return await _rank(finding_type, finding_title, finding_endpoint, top_k)
    except Exception as exc:
        logger.warning("vault_selector.rank_techniques failed: %s", exc)
        return []


def _humanize_concept_id(concept_id: str) -> str:
    """Return the canonical vault title from CONCEPT_TITLES, falling back to humanized id.

    Fix 4: family-augmented options now use the static CONCEPT_TITLES map so operators
    see "NoSQL Injection (MongoDB)" instead of "Nosql Injection".
    Source: constants.CONCEPT_TITLES (populated from each concept file's frontmatter `title:`).
    """
    return CONCEPT_TITLES.get(concept_id,
           concept_id.removeprefix("CONCEPT-").replace("-", " ").title())


def _make_option(concept_id: str, source: str, similarity: float = 0.0,
                 title: str = "") -> TechniqueOption:
    """Build a TechniqueOption from a concept_id, looking up engine_id and template."""
    engine_id = CONCEPT_ENGINE_MAP.get(concept_id)
    template_available = False
    try:
        from apps.conductor.template_executor import load_template
        template_available = load_template(concept_id) is not None
    except Exception:
        pass
    return TechniqueOption(
        concept_id                 = concept_id,
        engine_id                  = engine_id,
        title                      = title or _humanize_concept_id(concept_id),
        similarity                 = similarity,
        requires_session           = engine_id in SESSION_REQUIRED_ENGINES if engine_id else False,
        source                     = source,
        method                     = None,
        endpoint_hint              = None,
        payload_template_available = template_available,
    )


def _produces_filter(options: list[TechniqueOption], finding_type: str) -> list[TechniqueOption]:
    """Remove options whose concept produces the current finding_type.

    Prevents self-recommendation: js_spider should not appear as a suggestion
    for api_endpoint_discovered because js_spider *generates* those findings.
    """
    return [
        o for o in options
        if not (
            o.concept_id in CONCEPT_PRODUCES
            and finding_type in CONCEPT_PRODUCES[o.concept_id]
        )
    ]


def _family_augment(
    options: list[TechniqueOption],
    finding_type: str,
) -> list[TechniqueOption]:
    """Surface family siblings missing from semantic results.

    Collects relevant technique families from:
    1. Families of concepts already in the results
    2. Families hinted for this finding_type (FINDING_FAMILY_HINTS)

    For each concept in those families not already in results, appends it
    with source="family" and similarity=0.0 (below semantic hits).

    Applies the produces filter again so a producer is never re-added.
    """
    existing_concept_ids: set[str] = {o.concept_id for o in options}
    existing_engine_ids:  set[str | None] = {o.engine_id for o in options}

    # Gather relevant families
    relevant_families: set[str] = set()
    for o in options:
        fam = CONCEPT_FAMILY.get(o.concept_id)
        if fam:
            relevant_families.add(fam)
    for fam in FINDING_FAMILY_HINTS.get(finding_type, []):
        relevant_families.add(fam)

    if not relevant_families:
        return options

    augmented = list(options)
    for concept_id in CONCEPT_ENGINE_MAP:
        if concept_id in existing_concept_ids:
            continue  # already present — keep existing (has real similarity)
        fam = CONCEPT_FAMILY.get(concept_id)
        if fam not in relevant_families:
            continue
        # Apply produces filter: don't re-add a concept that generates this finding_type
        if concept_id in CONCEPT_PRODUCES and finding_type in CONCEPT_PRODUCES[concept_id]:
            continue
        augmented.append(_make_option(concept_id, source="family", similarity=0.0))
        existing_concept_ids.add(concept_id)

    return augmented


async def _rank(
    finding_type: str,
    finding_title: str,
    finding_endpoint: str | None,
    top_k: int,
) -> list[TechniqueOption]:
    parts = [finding_type, finding_title]
    if finding_endpoint:
        parts.append(finding_endpoint)
    query = " ".join(p for p in parts if p)

    # Fetch more candidates than top_k to allow for filtering.
    # Filter to concepts only — vault_selector returns only CONCEPT-* entries and
    # concept-targeted retrieval should not be diluted by finding/lab entries.
    raw = await inspect_vault(query, top_k=top_k * 3, entry_type="concept")

    # ── Build initial semantic result list ────────────────────────────────────
    options: list[TechniqueOption] = []
    for entry in raw:
        doc_id = str(entry.get("doc_id", ""))
        if not doc_id.upper().startswith("CONCEPT-"):
            continue                        # skip FIND-* / FAIL-* / other

        concept_id = doc_id.upper()
        if concept_id not in CONCEPT_ENGINE_MAP:
            continue                        # unknown concept — skip

        options.append(_make_option(
            concept_id,
            source     = "vault",
            similarity = float(entry.get("similarity", 0.0)),
            title      = entry.get("title", "") or concept_id,
        ))
        if len(options) >= top_k:
            break

    # ── V3.1 Relationship layer post-processing ───────────────────────────────
    # Step 1: produces filter — remove self-recommendations
    options = _produces_filter(options, finding_type)

    # Step 2: family augment — surface missing siblings
    options = _family_augment(options, finding_type)

    # Deterministic ordering: vault hits (by similarity desc) then family hits
    options.sort(key=lambda o: (0 if o.source == "vault" else 1, -o.similarity))

    return options


def suggestions_floor(finding_type: str) -> list[TechniqueOption]:
    """Return TechniqueOptions from the SUGGESTIONS catalog for this finding_type.

    source="suggestions" on all returned options.
    similarity=0.0 (floor entries carry no vault score).
    Returns [] if no SUGGESTIONS entry for this finding_type.
    """
    try:
        from apps.investigation_workspace.suggestions.catalog import (
            for_finding_type as _fft,
        )
        specs = _fft(finding_type)
    except Exception as exc:
        logger.debug("vault_selector.suggestions_floor: catalog lookup failed: %s", exc)
        return []

    options: list[TechniqueOption] = []
    seen_engine_ids: set[str | None] = set()
    for spec in specs:
        eid = spec.engine_id
        if eid in seen_engine_ids:
            continue
        seen_engine_ids.add(eid)
        options.append(TechniqueOption(
            concept_id       = "",
            engine_id        = eid,
            title            = spec.label,
            similarity       = 0.0,
            requires_session = eid in SESSION_REQUIRED_ENGINES if eid else False,
            source           = "suggestions",
            method           = None,
            endpoint_hint    = None,
        ))
    return options


def merge_with_floor(
    vault_results: list[TechniqueOption],
    floor_results: list[TechniqueOption],
) -> list[TechniqueOption]:
    """Merge vault results with SUGGESTIONS floor options.

    Rules (from Phase C-1 spec):
    - Vault empty → return floor_results.
    - Vault rank-1 engine matches floor rank-1 engine → return vault_results.
    - Vault rank-1 engine conflicts with floor rank-1 engine → return vault_results
      + any floor options whose engine_id is NOT already in vault_results.
      Source="suggestions" preserved on appended floor entries.

    Dedup key: engine_id. If the same engine_id appears in both, keep the vault
    entry (has a real similarity score).
    """
    if not vault_results:
        return list(floor_results)

    vault_engine_ids: set[str | None] = {o.engine_id for o in vault_results}
    vault_top_engine = vault_results[0].engine_id

    if not floor_results:
        return list(vault_results)

    floor_top_engine = floor_results[0].engine_id

    if vault_top_engine == floor_top_engine:
        # Agreement — vault alone is sufficient
        return list(vault_results)

    # Conflict — surface both; append floor options not already covered by vault
    extra = [o for o in floor_results if o.engine_id not in vault_engine_ids]
    return list(vault_results) + extra


def sync_scoped_options(finding_type: str) -> list[TechniqueOption]:
    """Deterministic, no-ChromaDB scoping for a finding_type.

    Uses the existing relationship layer (suggestions_floor → _family_augment →
    _produces_filter) to produce the set of technique options the operator may
    choose at Layer 2 in the mindmap. Never calls the vault. Never raises.

    Result: only finding-justified techniques — not the full catalog.
    login_form_detected → credential-attack + injection-auth families only.
    api_endpoint_discovered → access-test + injection-auth families only.

    Deduplication: suggestions-floor entries take priority when the same engine_id
    appears in both the floor and the family augment (e.g. credential_brute).
    """
    try:
        floor = suggestions_floor(finding_type)
        augmented = _family_augment(floor, finding_type)
        filtered = _produces_filter(augmented, finding_type)
        # Catalog entries (source="suggestions") first, then family siblings
        filtered.sort(key=lambda o: (0 if o.source == "suggestions" else 1, o.title))
        # Deduplicate by engine_id — keep first occurrence (suggestions entry wins)
        seen_engine_ids: set[str | None] = set()
        deduped: list[TechniqueOption] = []
        for o in filtered:
            if o.engine_id not in seen_engine_ids:
                seen_engine_ids.add(o.engine_id)
                deduped.append(o)
        return deduped
    except Exception as exc:
        logger.debug("sync_scoped_options failed for %r: %s", finding_type, exc)
        return []


def objective_tech_override(
    objective: str | None,
    candidates: list,  # list[TechniqueOption]
) -> tuple[list, bool]:
    """Deterministically promote a concept to rank 0 when the objective names ONE technology.

    Rules:
    1. RANKING ONLY — never adds or removes a candidate (by engine_id set).
       When a candidate's concept_id is replaced to align with the target technology,
       a new TechniqueOption instance is created (identity changes, engine_id set does not).
    2. EXACTLY ONE technology family matched — multiple distinct groups → let model decide.
    3. PRESENCE CHECK — tries concept_id match first; falls back to engine_id match.
       If the target concept's engine appears in candidates under a different concept_id
       (e.g. access_control with CONCEPT-ACCESS-CONTROL instead of CONCEPT-NOSQL-INJECTION),
       that candidate is promoted AND its concept_id is replaced with the target concept_id
       so the engine dispatches the correct template.
    4. Returns (reordered, True) when the override fires; (unchanged, False) otherwise.

    Never raises. Graceful drift: unmapped technologies return (unchanged, False).
    """
    if not objective or not candidates:
        return candidates, False

    import re as _re
    from dataclasses import replace as _dc_replace
    obj_lower = objective.lower()

    def _keyword_matches(kw: str, text: str) -> bool:
        """Word-boundary match: 'sql injection' won't match inside 'nosql injection'."""
        pattern = r"\b" + r"\b.*?\b".join(_re.escape(w) for w in kw.split()) + r"\b"
        return bool(_re.search(pattern, text))

    # Collect all distinct concept-id sets matched by keywords
    matched_groups: list[frozenset] = []
    for keyword, concept_ids in OBJECTIVE_TECH_CONCEPTS.items():
        if _keyword_matches(keyword, obj_lower):
            group = frozenset(concept_ids)
            if group not in matched_groups:
                matched_groups.append(group)

    # Exactly-one rule: multiple distinct groups → ambiguous → let model decide
    if len(matched_groups) != 1:
        return candidates, False

    target_concepts: frozenset = matched_groups[0]

    # Pass 1: concept_id exact match (common case — vault returned the right concept)
    candidate_concept_ids = {o.concept_id for o in candidates}
    promotable_by_cid = target_concepts & candidate_concept_ids

    # Pass 2: engine_id fallback — when the vault returns access_control with
    # CONCEPT-ACCESS-CONTROL but the target is CONCEPT-NOSQL-INJECTION, the
    # engine_id (access_control) still matches. Promote and swap concept_id.
    target_engine_ids: set[str] = set()
    for tcid in target_concepts:
        eid = CONCEPT_ENGINE_MAP.get(tcid)
        if eid:
            target_engine_ids.add(eid)

    if promotable_by_cid:
        # Exact concept match — reorder without mutation
        promoted    = [o for o in candidates if o.concept_id in promotable_by_cid]
        not_promoted = [o for o in candidates if o.concept_id not in promotable_by_cid]
        reordered   = promoted + not_promoted
        logger.debug(
            "objective_tech_override: promoted %s to rank 0 (concept_id match)",
            [o.concept_id for o in promoted],
        )
    elif target_engine_ids:
        # Engine_id fallback — swap concept_id on matching candidates
        # Pick the best-matching target concept for each engine match
        engine_to_target_cid: dict[str, str] = {}
        for tcid in target_concepts:
            eid = CONCEPT_ENGINE_MAP.get(tcid)
            if eid and eid in target_engine_ids:
                engine_to_target_cid[eid] = tcid

        promoted_eids = {o.engine_id for o in candidates if o.engine_id in target_engine_ids}
        if not promoted_eids:
            return candidates, False

        reordered = []
        for o in candidates:
            if o.engine_id in promoted_eids and o.engine_id in engine_to_target_cid:
                new_cid = engine_to_target_cid[o.engine_id]
                try:
                    reordered.insert(0, _dc_replace(o, concept_id=new_cid))
                except Exception:
                    reordered.insert(0, o)
            else:
                reordered.append(o)
        logger.debug(
            "objective_tech_override: promoted engine_ids %s to rank 0 (engine_id fallback); "
            "concept_id swapped to target",
            list(promoted_eids),
        )
    else:
        return candidates, False

    # HARD INVARIANT: count and engine_id set unchanged
    assert len(reordered) == len(candidates), (
        f"objective_tech_override: candidate count changed {len(candidates)} → {len(reordered)}"
    )
    result_eids = {o.engine_id for o in reordered}
    source_eids = {o.engine_id for o in candidates}
    assert result_eids == source_eids, (
        f"objective_tech_override: engine_id set changed {source_eids} → {result_eids}"
    )
    return reordered, True
