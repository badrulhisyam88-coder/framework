"""Phase D2 — Model advisor: post-execution next-step suggestions.

The model is the advisor of LAST RESORT — not on the hot path.
Invoked only:
  - Post-execution: after an engine returns success/partial result
  - Low-confidence: when vault similarity < SIM_FLOOR (context_panel gate)

Uses the SAME structured output path as routes.py:
  build_action_schema() + parse_structured_output() from action_schema.py.
No second Ollama client is introduced.

C6 preserved: model advises, operator selects and executes.
"""
from __future__ import annotations

import logging

import httpx as httpx  # module-level so tests can patch apps.conductor.model_advisor.httpx

logger = logging.getLogger("conductor.model_advisor")

# ── A2 ranking system prompt additions ────────────────────────────────────────
_RANKING_SYSTEM_SUFFIX = (
    "\n\nRanking guidance:\n"
    "- access_control handles NoSQL operator injection ($ne, $regex, $gt) via GET/POST "
    "parameters, AND is the correct engine for api_endpoint_discovered findings.\n"
    "- js_spider fires automatically after credential_brute — never rank it as a manual step.\n"
    "- Read the objective for technology signals: MongoDB/NoSQL→NoSQL injection; "
    "MySQL/SQLite→SQL injection; JWT→jwt_attacks; etc.\n"
    "- Prefer the technique that matches the objective's stated technology over a "
    "generic semantic match.\n"
)

# System prompt additions that address the bakeoff failure modes:
# - access_control handles NoSQL injection ($ne, $regex, $gt) AND api_endpoint_discovered
# - js_spider fires automatically after credential_brute — don't suggest manually
_ADVISOR_SYSTEM_SUFFIX = (
    "\n\nAdditional engine guidance:\n"
    "- access_control: handles broken access control, IDOR, mass assignment, NoSQL operator "
    "injection ($ne, $regex, $gt), GET/POST parameter injection, AND is the correct engine "
    "for api_endpoint_discovered findings (test the discovered endpoint for auth failures).\n"
    "- js_spider: fires AUTOMATICALLY after credential_brute succeeds — do NOT suggest it "
    "as a manual next step; it has already run or will run automatically.\n"
    "- If a technique was just executed and produced a result, suggest the NEXT logical step "
    "in the attack chain, not the same technique again.\n"
)


async def advise_next_step(
    session: dict | None,
    technique_used: str | None,
    parsed_result,  # ParsedResult | None
    vault_context: list,  # list[TechniqueOption]
) -> object | None:  # TechniqueOption | None
    """Call Qwen with full context. Returns a TechniqueOption suggestion or None.

    Returns None if:
    - engine_id is None in the parsed response
    - The suggested engine_id matches technique_used (avoid repeat)
    - parse_structured_output returns (None, None) — text fallback fired
    - Any exception
    """
    try:
        return await _advise(session, technique_used, parsed_result, vault_context)
    except Exception as exc:
        logger.debug("model_advisor.advise_next_step failed: %s", exc)
        return None


async def _advise(
    session: dict | None,
    technique_used: str | None,
    parsed_result,
    vault_context: list,
) -> object | None:
    import httpx
    from apps.conductor.qwen.action_schema import (
        _exploitation_engine_ids,
        build_action_schema,
        parse_structured_output,
    )
    from apps.conductor.qwen.client import MODEL, OLLAMA_BASE_URL
    from apps.conductor.vault_selector import TechniqueOption

    engine_ids = _exploitation_engine_ids()
    schema     = build_action_schema(engine_ids)
    valid_ids  = set(engine_ids)

    # Build context block for the prompt
    context_lines = []
    if parsed_result is not None:
        context_lines.append(
            f"Just executed: {getattr(parsed_result, 'engine_id', technique_used or 'unknown')}"
        )
        context_lines.append(
            f"Result status: {getattr(parsed_result, 'status', 'unknown')}"
        )
        summary = getattr(parsed_result, "summary", "")
        if summary:
            context_lines.append(f"Summary: {summary}")
        findings = getattr(parsed_result, "key_findings", [])
        if findings:
            context_lines.append("Key findings: " + "; ".join(findings[:3]))

    if vault_context:
        top3 = [o for o in vault_context[:3] if o.engine_id]
        if top3:
            context_lines.append(
                "Vault suggestions: " + ", ".join(o.engine_id for o in top3)
            )

    if session:
        context_lines.append(
            f"Session available: username={session.get('username', '?')}"
        )

    context_str = "\n".join(context_lines) if context_lines else "No additional context."

    # System prompt = standard VaultSelector prompt + advisor suffix
    system_prompt = (
        "You are a security testing assistant. "
        "Respond ONLY with a valid JSON object — no markdown, no prose outside JSON. "
        "JSON fields:\n"
        '  "response": string — concise actionable advice for the operator\n'
        '  "engine_id": one of ' + str(engine_ids) + " or null if no engine applies\n"
        '  "params": object with "finding_type" (string), "reason" (string ≤200 chars)'
        + _ADVISOR_SYSTEM_SUFFIX
    )

    user_message = (
        f"Context:\n{context_str}\n\n"
        "What is the best next exploitation step? "
        "Select the most appropriate engine or null if none applies."
    )

    payload: dict = {
        "model":    MODEL,
        "messages": [
            {"role": "system",  "content": system_prompt},
            {"role": "user",    "content": user_message},
        ],
        "stream":  False,
        "format":  schema,
        "options": {"temperature": 0.2, "num_ctx": 8192, "num_predict": 200},
    }

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload)
    if resp.status_code >= 400:
        logger.debug("model_advisor: Ollama HTTP %s", resp.status_code)
        return None

    content = resp.json().get("message", {}).get("content", "")
    response_str, action = parse_structured_output(content, valid_ids)

    if response_str is None:
        logger.warning("model_advisor: structured output parse failed — fallback fired")
        return None
    if action is None:
        return None

    suggested_engine = action.get("engine_id")
    if not suggested_engine:
        return None
    if technique_used and suggested_engine == technique_used:
        logger.debug("model_advisor: suggestion %r same as last technique — skipping", suggested_engine)
        return None

    reason    = action.get("reason", "")
    adv_title = f"[AI] {response_str[:80]}" if response_str.strip() else f"[AI] Try {suggested_engine}"

    from apps.conductor.constants import SESSION_REQUIRED_ENGINES
    return TechniqueOption(
        concept_id                = "",
        engine_id                 = suggested_engine,
        title                     = adv_title,
        similarity                = 0.0,
        requires_session          = suggested_engine in SESSION_REQUIRED_ENGINES,
        source                    = "model",
        method                    = None,
        endpoint_hint             = None,
        payload_template_available= False,
    )


# ── A2: Orchestrated candidate ranking ────────────────────────────────────────


async def rank_candidates_with_context(
    finding_type: str,
    finding_title: str,
    candidates: list,           # list[TechniqueOption] from Part A
    objective: str | None,
    recent_results: list[str],
) -> list:                      # list[TechniqueOption] — reordered or unchanged
    """Orchestrated, staged reasoning to reorder the candidate list.

    STAGE 1 (classify): what vulnerability class best fits this finding + objective?
    STAGE 2 (order): given the class, return engine_ids ordered most-likely first.
    STAGE 3 (validate): reject ordering if it contains engine_ids not in candidates.

    Returns candidates reordered, or unchanged on any failure. Never raises.
    Two Ollama calls total (stages 1 and 2), constrained to existing candidates.
    """
    try:
        return await _rank_candidates(finding_type, finding_title, candidates,
                                      objective, recent_results)
    except Exception as exc:
        logger.debug("rank_candidates_with_context failed: %s — returning deterministic order", exc)
        return candidates


async def _rank_candidates(
    finding_type: str,
    finding_title: str,
    candidates: list,
    objective: str | None,
    recent_results: list[str],
) -> list:
    from apps.conductor.qwen.client import MODEL, OLLAMA_BASE_URL

    if not candidates:
        return candidates

    # Valid engine_ids in input — Stage 3 validates against this
    valid_input_engines = [o.engine_id for o in candidates if o.engine_id]
    if not valid_input_engines:
        return candidates

    context_parts = []
    if objective:
        context_parts.append(f"Operator objective: {objective[:300]}")
    if recent_results:
        context_parts.append("Recent results: " + "; ".join(recent_results[:3]))
    context_str = "\n".join(context_parts) if context_parts else "No additional context."

    # ── Stage 1: classify vulnerability class ─────────────────────────────────
    s1_system = (
        "You are a security technique classifier. "
        "Given a finding and operator objective, return ONLY a JSON object: "
        '{"class": "<vulnerability_class>"} '
        "Where class is one of: nosql-injection, sql-injection, xss, command-injection, "
        "idor-access-control, credential-attack, path-traversal, ssrf, xxe, "
        "file-upload, deserialization, jwt-attack, other"
        + _RANKING_SYSTEM_SUFFIX
    )
    s1_user = (
        f"Finding type: {finding_type}\n"
        f"Finding title: {finding_title}\n"
        f"{context_str}\n\n"
        "Return the vulnerability class JSON."
    )
    s1_payload = {
        "model": MODEL, "messages": [
            {"role": "system", "content": s1_system},
            {"role": "user",   "content": s1_user},
        ],
        "stream": False,
        "options": {"temperature": 0.1, "num_ctx": 4096, "num_predict": 50},
    }

    vuln_class = "other"
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r1 = await c.post(f"{OLLAMA_BASE_URL}/api/chat", json=s1_payload)
        if r1.status_code == 200:
            import json
            content1 = r1.json().get("message", {}).get("content", "")
            try:
                parsed1 = json.loads(content1.strip())
                vuln_class = str(parsed1.get("class", "other"))
            except Exception:
                # Try to extract class from text
                import re
                m = re.search(r'"class"\s*:\s*"([^"]+)"', content1)
                if m:
                    vuln_class = m.group(1)
    except Exception as exc:
        logger.debug("rank_candidates stage1 failed: %s", exc)
        return candidates  # fallback: deterministic order

    logger.debug("rank_candidates: classified as %r for %s", vuln_class, finding_type)

    # ── Stage 2: order candidates ──────────────────────────────────────────────
    # Use bare engine_id strings in description — not key=value format.
    # The model was copying "engine_id='x'" literally, causing Stage 3 validation failure.
    candidates_desc = "\n".join(
        f"  {i+1}. {o.engine_id} ({o.title})"
        for i, o in enumerate(candidates)
        if o.engine_id
    )
    valid_eids_list = [o.engine_id for o in candidates if o.engine_id]
    s2_system = (
        "You are a security technique ranker. "
        "Return ONLY a JSON object with this exact structure: "
        '{"ordered_engine_ids": ["id1", "id2"]} '
        "where each value is a bare identifier string (no quotes around the whole list item, "
        "no key= prefix). List ALL provided identifiers ordered most-likely-correct first. "
        "Include every identifier exactly once. Do not add new identifiers. "
        f"Valid identifiers are: {valid_eids_list}"
        + _RANKING_SYSTEM_SUFFIX
    )
    s2_user = (
        f"Vulnerability class: {vuln_class}\n"
        f"Finding: {finding_type} — {finding_title}\n"
        f"{context_str}\n\n"
        f"Candidate techniques (identifier — title):\n{candidates_desc}\n\n"
        f"Order these identifiers most-to-least likely for this vulnerability: {valid_eids_list}\n"
        "Return JSON: {\"ordered_engine_ids\": [...]}"
    )
    s2_payload = {
        "model": MODEL, "messages": [
            {"role": "system", "content": s2_system},
            {"role": "user",   "content": s2_user},
        ],
        "stream": False,
        "options": {"temperature": 0.1, "num_ctx": 4096, "num_predict": 100},
    }

    ordered_ids: list[str] = []
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r2 = await c.post(f"{OLLAMA_BASE_URL}/api/chat", json=s2_payload)
        if r2.status_code == 200:
            import json
            content2 = r2.json().get("message", {}).get("content", "")
            try:
                parsed2 = json.loads(content2.strip())
                ordered_ids = list(parsed2.get("ordered_engine_ids", []))
            except Exception:
                import re
                m2 = re.search(r'"ordered_engine_ids"\s*:\s*(\[.*?\])', content2, re.DOTALL)
                if m2:
                    ordered_ids = json.loads(m2.group(1))
    except Exception as exc:
        logger.debug("rank_candidates stage2 failed: %s", exc)
        return candidates

    # ── Stage 3 (deterministic): validate the ordering ────────────────────────
    input_ids_set = set(valid_input_engines)
    returned_ids_set = set(str(x) for x in ordered_ids)

    # Reject if any returned engine_id is NOT in the input candidates
    invalid = returned_ids_set - input_ids_set
    if invalid:
        logger.warning(
            "rank_candidates: model returned unknown engine_ids %r — rejecting, using deterministic order",
            invalid,
        )
        return candidates

    # Reject if the returned list doesn't cover the input (incomplete permutation)
    if returned_ids_set != input_ids_set:
        logger.debug(
            "rank_candidates: incomplete permutation returned — using deterministic order"
        )
        return candidates

    # Reorder candidates per the model's ordering
    engine_to_option = {o.engine_id: o for o in candidates if o.engine_id}
    # Non-engine options (advisory, None engine_id) stay at the end
    advisory = [o for o in candidates if not o.engine_id]
    reordered = []
    for eid in ordered_ids:
        if eid in engine_to_option:
            reordered.append(engine_to_option[eid])
    reordered.extend(advisory)

    logger.debug(
        "rank_candidates: reordered [%s] (class=%s)",
        ", ".join(o.engine_id or "?" for o in reordered[:5]),
        vuln_class,
    )
    return reordered


# ── Bundle 2: Findings context packager + work-order generator ────────────────


from dataclasses import dataclass, field as _field


@dataclass
class FindingsContext:
    """Structured facts handed to the AI for work-order generation.

    Every field is sourced deterministically from existing system data —
    no free-text summarisation. The AI reasons over this, not a prose prompt.

    Sources (cited):
      objective          — InvestigationState.objective (set by qwen_chat route)
      finding_type       — NormalizedFinding.finding_type (DB)
      finding_title      — NormalizedFinding.title (DB)
      finding_endpoint   — NormalizedFinding.endpoint (DB)
      session_present    — exploitation_branches: any succeeded + artifact_type="captured_session"
      target_account     — extract_target_account(objective) from template_executor
      injection_confirmed— exploitation_branches: any oracle_search or access_control succeeded
      recent_results     — InvestigationState.attempt_tree[-3:] technique titles + statuses
      applicable_primitives — manifest filtered by evaluate_preconditions(session, injection, ...)
    """
    objective:              str | None
    finding_type:           str
    finding_title:          str
    finding_endpoint:       str
    session_present:        bool
    target_account:         str | None
    injection_confirmed:    bool
    recent_results:         list[str]
    applicable_primitives:  list[dict]   # [{id, description, required_params, produces}]
    # Decision signals — enriched by _package; default to safe values for manual construction
    account_locked:         bool = False   # auth bypass succeeded but login is locked
    discovered_fields:      list[str] = _field(default_factory=list)  # from keys_enumeration artifact
    # Phase 1 — vault ranking as AI input signal (not the decider; AI decides from applicable_primitives)
    # [{engine_id, concept_id, title, similarity}] top-K from semantic vault query
    vault_candidates:       list[dict] = _field(default_factory=list)


@dataclass
class WorkOrder:
    """A validated, executable work order produced by the AI.

    Produced by generate_work_order(); stored in InvestigationState.pending_work_orders
    and referenced by TechniqueOption.work_order_id on the selection card.
    The operator selects and executes it (C6) — the AI never auto-runs it.
    """
    id:             str    # UUID for state lookup
    primitive_id:   str    # e.g. "oracle_search.dictionary_scan"
    engine_id:      str    # dispatch key (e.g. "oracle_search")
    params:         dict   # filled params {strategy, concept_id, target_account, ...}
    rationale:      str    # AI's short reasoning shown in the card
    finding_id:     str    # the finding this work order targets
    source:         str = "ai"


async def package_findings_context(
    investigation_id: str,
    finding_id: str,
    finding_type: str,
    finding_title: str,
    finding_endpoint: str,
) -> FindingsContext:
    """Assemble structured facts about the current state for the AI.

    Deterministic — no model calls. Sources cited in FindingsContext docstring.
    Never raises — returns a minimal context on any error.
    """
    try:
        return await _package(
            investigation_id, finding_id,
            finding_type, finding_title, finding_endpoint,
        )
    except Exception as exc:
        logger.debug("package_findings_context failed: %s", exc)
        return FindingsContext(
            objective=None, finding_type=finding_type, finding_title=finding_title,
            finding_endpoint=finding_endpoint, session_present=False,
            target_account=None, injection_confirmed=False,
            recent_results=[], applicable_primitives=[],
        )


async def _package(
    investigation_id: str,
    finding_id: str,
    finding_type: str,
    finding_title: str,
    finding_endpoint: str,
) -> FindingsContext:
    from apps.conductor.capability_manifest import (
        evaluate_preconditions, filter_by_preconditions, get_manifest,
    )
    from apps.conductor.exploitation.branch_store import BranchReader
    from apps.conductor.investigation_state import load_state_async
    from apps.conductor.template_executor import extract_target_account

    # ── InvestigationState fields ──────────────────────────────────────────────
    state = await load_state_async(investigation_id)
    objective     = state.objective
    target_account = extract_target_account(objective or "") if objective else None

    recent_results = [
        f"{a.get('technique_title', a.get('engine_id', '?'))}:{a.get('status', '?')}"
        for a in state.attempt_tree[-3:]
    ]

    # ── Branch reader facts ────────────────────────────────────────────────────
    branches = await BranchReader().list_for_investigation(investigation_id)
    session_present = any(
        b.state == "succeeded" and b.artifact_type == "captured_session"
        for b in branches
    )
    injection_confirmed = any(
        b.state == "succeeded" and b.engine_id in (
            "oracle_search", "access_control", "sqli_auth_bypass",
            "auth_bypass_login",  # operator injection bypass also confirms the surface
        )
        for b in branches
    )
    login_form_present = any(
        b.engine_id == "credential_brute" or finding_type == "login_form_detected"
        for b in branches
    ) or finding_type == "login_form_detected"

    # ── Decision signals — surfaces KEY facts that drive primitive selection ───
    # account_locked: auth_bypass_login succeeded means the account was found but
    # is locked — password alone will not solve an objective that requires login.
    account_locked = any(
        b.state == "succeeded" and b.engine_id == "auth_bypass_login"
        for b in branches
    )
    # discovered_fields: read from the most recent successful keys_enumeration artifact
    discovered_fields: list[str] = []
    for b in reversed(branches):
        if (b.state == "succeeded" and b.engine_id == "oracle_search"
                and b.artifact_type == "oracle_keys_enumeration_result"):
            # The BranchRow artifact is stored as a dict; extract discovered_fields
            artifact = getattr(b, "artifact", None) or {}
            if isinstance(artifact, dict):
                discovered_fields = artifact.get("discovered_fields", [])
            break

    # ── Phase 2: graph-derived branch set (replaces static manifest for this finding) ──
    # The knowledge graph (concept files' Relationships sections) defines the branch SET.
    # The manifest provides param/precondition mechanics for EXISTS engines.
    satisfied = evaluate_preconditions(
        session_present=session_present,
        injection_confirmed=injection_confirmed,
        login_form_present=login_form_present,
    )

    applicable_dicts: list[dict] = []
    _graph_source = False
    try:
        from apps.conductor.graph_resolver import resolve_branches, branch_to_primitive_dict
        graph_branches = resolve_branches(
            finding_type              = finding_type,
            satisfied_preconditions   = satisfied,
            enrich_from_manifest      = True,
        )
        if graph_branches:
            applicable_dicts = [branch_to_primitive_dict(b) for b in graph_branches]
            _graph_source = True
            logger.debug(
                "_package: graph resolver returned %d branch(es) for %r "
                "(exec=%d none_yet=%d)",
                len(graph_branches), finding_type,
                sum(1 for b in graph_branches if b.executable),
                sum(1 for b in graph_branches if not b.executable),
            )
    except Exception as _gr_exc:
        logger.debug("_package: graph resolver failed for %r: %s — falling back to manifest", finding_type, _gr_exc)

    # Fallback: when graph has no branches for this finding_type (e.g. a recon finding),
    # fall back to the static manifest. This preserves full coverage across all findings.
    if not _graph_source:
        manifest = get_manifest()
        applicable = filter_by_preconditions(manifest, satisfied)
        applicable_dicts = [
            {
                "id":          p.id,
                "description": p.description,
                "when_to_use": p.when_to_use,
                "required_params": [
                    {"name": rp.name, "source_hint": rp.source_hint}
                    for rp in p.required_params
                ],
                "produces":    p.produces,
            }
            for p in applicable
        ]

    # ── Phase 1: vault ranking as AI context signal ───────────────────────────
    # The semantic vault query surfaces which techniques the knowledge graph considers
    # most relevant for this finding. This feeds the AI as a SIGNAL (not the decider).
    # The AI selects from applicable_primitives; vault_candidates inform that choice.
    vault_candidates: list[dict] = []
    try:
        from apps.conductor.vault_selector import rank_techniques as _rank_vault
        _vault_hits = await _rank_vault(
            finding_type     = finding_type,
            finding_title    = finding_title,
            finding_endpoint = finding_endpoint or None,
            top_k            = 3,
        )
        vault_candidates = [
            {
                "engine_id":  o.engine_id,
                "concept_id": o.concept_id or "",
                "title":      o.title,
                "similarity": round(o.similarity, 3),
            }
            for o in _vault_hits if o.engine_id
        ]
    except Exception as _vc_exc:
        logger.debug("vault_candidates query failed (non-fatal): %s", _vc_exc)

    return FindingsContext(
        objective           = objective,
        finding_type        = finding_type,
        finding_title       = finding_title,
        finding_endpoint    = finding_endpoint,
        session_present     = session_present,
        target_account      = target_account,
        injection_confirmed = injection_confirmed,
        recent_results      = recent_results,
        applicable_primitives = applicable_dicts,
        account_locked      = account_locked,
        discovered_fields   = discovered_fields,
        vault_candidates    = vault_candidates,
    )


def _stage3_validate(
    prim: object,
    filled_params: dict,
    ctx: "FindingsContext",
) -> "tuple[bool, str, str]":
    """Validate Stage 2 params deterministically.

    Returns (ok, reject_reason, correct_hint).
    When ok=True, reason and hint are empty strings.
    When ok=False, reason names the failure and hint gives corrective guidance
    that is fed back into the next Stage 2 retry.
    """
    from apps.conductor.capability_manifest import PrimitiveSpec
    assert isinstance(prim, PrimitiveSpec)

    # 3a. All required params present and non-empty
    for rp in prim.required_params:
        val = filled_params.get(rp.name, "")
        if not isinstance(val, str) or not val.strip():
            hint = f"Provide a non-empty string value for the '{rp.name}' parameter. {rp.description}"
            return False, f"missing_required_param:{rp.name}", hint

    # 3b. concept_id: must start with CONCEPT- if provided
    concept_id_val = filled_params.get("concept_id", "")
    if concept_id_val and not concept_id_val.upper().startswith("CONCEPT-"):
        hint = (
            f"'{concept_id_val}' looks like a finding_type or engine_id, not a concept_id. "
            f"concept_id must start with 'CONCEPT-' (e.g. 'CONCEPT-NOSQL-OPERATOR-INJECTION'). "
            f"Read the primitive's description — it names the expected concept_id in parentheses."
        )
        return False, f"invalid_concept_id:{concept_id_val!r}", hint

    return True, "", ""


async def generate_work_order(
    investigation_id: str,
    finding_id: str,
    context: FindingsContext,
    exclude: "frozenset[str] | None" = None,
) -> "tuple[WorkOrder | None, str]":
    """Generate one validated, executable work order from findings context.

    Three staged calls:
      STAGE 1 (model): select ONE primitive_id from applicable list (minus exclude set)
      STAGE 2 (model): fill required_params from findings
      STAGE 3 (deterministic): validate — primitive in manifest, params present +
        type-correct, values consistent with findings

    exclude: frozenset of work-order signatures (primitive_id:params_json) already tried.
             Stage 1 only receives applicable primitives NOT in the exclude set.
             This enables the autonomous loop to walk DISTINCT paths.

    Returns (WorkOrder, "") on success or (None, reason_string) on any failure.
    Never raises. Ollama failure → (None, "ollama_unavailable").
    """
    try:
        return await _generate_work_order(investigation_id, finding_id, context, exclude)
    except Exception as exc:
        logger.debug("generate_work_order failed: %s", exc)
        return None, f"exception: {exc}"


async def _generate_work_order(
    investigation_id: str,
    finding_id: str,
    ctx: FindingsContext,
    exclude: "frozenset[str] | None" = None,
) -> "tuple[WorkOrder | None, str]":
    import json as _json
    import uuid as _uuid
    from apps.conductor.capability_manifest import get_primitive, primitive_ids
    from apps.conductor.qwen.client import MODEL, OLLAMA_BASE_URL

    if not ctx.applicable_primitives:
        return None, "no_applicable_primitives"
    if not ctx.objective:
        return None, "no_objective"

    # Filter out already-tried primitives (for autonomous loop exclusion).
    # The exclude set contains work-order signatures (primitive_id:params_json).
    # We only know which primitive_ids are in exclude when params match; since params
    # aren't known yet (stage 2 fills them), we filter by primitive_id prefix only
    # when a primitive appears in ALL exclude signatures with that id — conservative
    # but safe. The stage-3 signature check in the loop is the final dedup guard.
    excluded_primitive_ids: set[str] = set()
    if exclude:
        for sig in exclude:
            pid = sig.split(":")[0] if ":" in sig else sig
            excluded_primitive_ids.add(pid)

    available_all = [
        p for p in ctx.applicable_primitives
        if p["id"] not in excluded_primitive_ids
    ]
    if not available_all:
        return None, "no_applicable_primitives:all_excluded"

    # Phase 2: separate executable branches from NONE-YET.
    # NONE-YET branches are shown to the AI as context (so it knows the branch exists)
    # but are NOT in the selectable enum — the AI cannot dispatch them.
    available  = [p for p in available_all if p.get("executable", True)]
    none_yet   = [p for p in available_all if not p.get("executable", True)]

    if not available:
        return None, "no_applicable_primitives:only_none_yet"

    applicable_ids = [p["id"] for p in available]

    # ── Enrich available primitives with when_to_use from manifest (canonical) ─
    # ctx.applicable_primitives may be built without when_to_use (e.g. manual test
    # construction) — always read from manifest to ensure the signal is present.
    available_enriched = []
    for p in available:
        prim_spec = get_primitive(p["id"])
        available_enriched.append({
            **p,
            "when_to_use": (prim_spec.when_to_use if prim_spec else p.get("when_to_use", "")),
        })

    # ── Derive decision signals from context ──────────────────────────────────
    login_injectable = (
        ctx.injection_confirmed or
        getattr(ctx, "account_locked", False) or
        any(kw in (ctx.objective or "").lower()
            for kw in ("nosql", "sqli", "sql injection", "operator injection", "injection"))
    )
    account_locked_signal = (
        getattr(ctx, "account_locked", False) or
        any("auth_bypass_login:succeeded" in r for r in ctx.recent_results)
    )
    discovered_fields = list(getattr(ctx, "discovered_fields", []))
    field_name_signal = (
        f"KNOWN — discovered fields: {discovered_fields}"
        if discovered_fields
        else "UNKNOWN — must run keys_enumeration or dictionary_scan before value extraction"
    )
    where_available = ctx.injection_confirmed

    # ── Build context summary ─────────────────────────────────────────────────
    context_summary = (
        f"Objective: {(ctx.objective or '')[:200]}\n"
        f"Finding: {ctx.finding_type} — {ctx.finding_title}\n"
        f"Endpoint: {ctx.finding_endpoint or 'unknown'}\n"
        f"Session present: {ctx.session_present}\n"
        f"Injection confirmed: {ctx.injection_confirmed}\n"
        f"Target account: {ctx.target_account or 'not extracted'}\n"
        f"Recent results: {'; '.join(ctx.recent_results) or 'none'}"
    )
    # Phase 1: vault ranking as an explicit AI input signal
    _vc = list(getattr(ctx, "vault_candidates", []))
    vault_signal = (
        "\nVault knowledge ranking (semantic match — use as signal, not as the answer):\n"
        + "\n".join(f"  {v['engine_id']} ({v.get('concept_id','')}) similarity={v.get('similarity',0)}" for v in _vc)
    ) if _vc else "\nVault ranking: not available (use manifest primitives below)"

    decision_signals = (
        f"Login injectable (NoSQL/SQLi surface or confirmed): {login_injectable}\n"
        f"Account locked (auth bypass succeeded but login blocked): {account_locked_signal}\n"
        f"Target field name: {field_name_signal}\n"
        f"$where injection available: {where_available}"
        + vault_signal
    )
    primitives_summary = "\n".join(
        f"  {p['id']}:\n"
        f"    Description: {p['description']}\n"
        f"    WHEN TO USE: {p.get('when_to_use', 'General use.')}\n"
        f"    Produces: {p['produces']}"
        + (f"\n    Progression: {p['progression']}" if p.get("progression") else "")
        for p in available_enriched
    )

    # Phase 2: inform AI about NONE-YET branches (knowledge exists, no engine yet)
    none_yet_summary = ""
    if none_yet:
        none_yet_summary = (
            "\n=== BRANCHES KNOWN BUT NOT YET EXECUTABLE (no engine yet) ===\n"
            + "\n".join(
                f"  {p['id']} ({p.get('concept_id','')}) — {p.get('description','')[:60]}"
                for p in none_yet
            )
            + "\nDo NOT select these — they are listed for awareness only."
        )

    # ── STAGE 1: select one primitive ─────────────────────────────────────────
    s1_system = (
        "You are a security testing work-order selector. "
        "Read the DECISION SIGNALS and each primitive's WHEN TO USE before selecting. "
        "Return ONLY valid JSON: {\"primitive_id\": \"<id>\", \"rationale\": \"<one sentence>\"} "
        f"Valid ids: {applicable_ids}"
    )
    s1_user = (
        f"=== INVESTIGATION CONTEXT ===\n{context_summary}\n\n"
        f"=== DECISION SIGNALS ===\n{decision_signals}\n\n"
        f"=== AVAILABLE PRIMITIVES (select from these) ===\n{primitives_summary}\n"
        + (f"{none_yet_summary}\n" if none_yet_summary else "")
        + f"\n=== INSTRUCTION ===\n"
        f"Select exactly ONE primitive_id that best advances the objective given the signals above.\n"
        f"Consult the WHEN TO USE for each primitive — it tells you when to prefer each one.\n"
        f"If account is LOCKED, password extraction alone cannot satisfy an objective requiring login.\n"
        f"If target field name is UNKNOWN, run schema enumeration before attempting value extraction.\n"
        f"Return: {{\"primitive_id\": \"<id from valid ids>\", \"rationale\": \"<reasoning>\"}}"
    )

    s1_schema = {
        "type": "object",
        "required": ["primitive_id"],
        "properties": {
            "primitive_id": {"type": "string", "enum": applicable_ids},
            "rationale":    {"type": "string"},
        },
    }
    s1_payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": s1_system},
            {"role": "user",   "content": s1_user},
        ],
        "stream": False,
        "format": s1_schema,
        "options": {"temperature": 0.1, "num_ctx": 8192, "num_predict": 150},
    }

    primitive_id = ""
    rationale = ""
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r1 = await c.post(f"{OLLAMA_BASE_URL}/api/chat", json=s1_payload)
        if r1.status_code >= 400:
            return None, f"ollama_stage1_http_{r1.status_code}"
        s1_content = r1.json().get("message", {}).get("content", "")
        s1_parsed = _json.loads(s1_content.strip())
        primitive_id = str(s1_parsed.get("primitive_id", ""))
        rationale    = str(s1_parsed.get("rationale", ""))[:200]
    except Exception as exc:
        logger.debug("work_order stage1 failed: %s", exc)
        return None, "ollama_stage1_failed"

    # Stage 3 validation (preliminary) — primitive must be in manifest
    prim = get_primitive(primitive_id)
    if prim is None:
        logger.warning("work_order: stage1 returned unknown primitive_id=%r", primitive_id)
        return None, f"stage3_unknown_primitive:{primitive_id}"

    # ── STAGE 2 + STAGE 3: fill params with bounded self-correction retry ─────
    # Stage 3 may reject params (e.g. invalid concept_id). When it does, build
    # corrective feedback and retry Stage 2 up to _MAX_S2_ATTEMPTS times before
    # giving up. This prevents a single bad param from dead-ending the loop.
    _MAX_S2_ATTEMPTS = 3
    filled_params: dict = {}
    correction_feedback = ""

    req_desc = "\n".join(
        f"  {rp.name} ({rp.type}, {rp.source_hint}): {rp.description}"
        for rp in prim.required_params
    )
    opt_desc = "\n".join(
        f"  {rp.name} ({rp.type}, optional): {rp.description}"
        for rp in prim.optional_params
    )

    s2_base_user = (
        f"Chosen primitive: {primitive_id}\n"
        f"Rationale: {rationale}\n\n"
        f"Context:\n{context_summary}\n\n"
        f"Required parameters:\n{req_desc}\n"
        + (f"\nOptional parameters:\n{opt_desc}" if opt_desc else "")
        + "\n\nFill the required parameters. Leave optional ones empty if unclear.\n"
        f"IMPORTANT: concept_id must start with 'CONCEPT-' (e.g. CONCEPT-NOSQL-OPERATOR-INJECTION). "
        f"It is NOT a finding_type or engine_id."
    )

    for s2_attempt in range(_MAX_S2_ATTEMPTS):
        if not prim.required_params:
            filled_params = {}
            break

        s2_user = s2_base_user
        if correction_feedback:
            s2_user = (
                f"CORRECTION (retry {s2_attempt}): {correction_feedback}\n\n"
                + s2_base_user
            )

        s2_system = (
            "You are a security testing parameter filler. "
            "Given the investigation context and a chosen primitive, fill all required parameters. "
            "Use the source_hint: from_finding=use finding endpoint/type, "
            "from_objective=parse from objective text, operator=leave empty string. "
            "Return ONLY valid JSON: {\"params\": {\"param_name\": \"value\", ...}}"
        )
        param_names = [rp.name for rp in prim.required_params] + [rp.name for rp in prim.optional_params]
        s2_schema = {
            "type": "object",
            "required": ["params"],
            "properties": {
                "params": {
                    "type": "object",
                    "properties": {n: {"type": "string"} for n in param_names},
                }
            },
        }
        s2_payload = {
            "model": MODEL,
            "messages": [
                {"role": "system", "content": s2_system},
                {"role": "user",   "content": s2_user},
            ],
            "stream": False,
            "format": s2_schema,
            "options": {"temperature": 0.1, "num_ctx": 4096, "num_predict": 150},
        }

        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r2 = await c.post(f"{OLLAMA_BASE_URL}/api/chat", json=s2_payload)
            if r2.status_code >= 400:
                return None, f"ollama_stage2_http_{r2.status_code}"
            s2_content = r2.json().get("message", {}).get("content", "")
            s2_parsed  = _json.loads(s2_content.strip())
            filled_params = dict(s2_parsed.get("params", {}))
        except Exception as exc:
            logger.debug("work_order stage2 failed: %s", exc)
            return None, "ollama_stage2_failed"

        # Stage 3 validation — returns (ok, reason, hint) for corrective retry
        ok, reject_reason, correct_hint = _stage3_validate(prim, filled_params, ctx)
        if ok:
            break
        logger.debug(
            "work_order stage3 rejected attempt=%d reason=%r hint=%r",
            s2_attempt, reject_reason, correct_hint,
        )
        if s2_attempt < _MAX_S2_ATTEMPTS - 1:
            correction_feedback = f"{reject_reason}. {correct_hint}"
        else:
            return None, f"stage3_failed_after_retries:{reject_reason}"

    # ── Deterministic param corrections (always applied, not retried) ─────────
    # target_account: if provided, must match the objective-extracted account
    ta_val = filled_params.get("target_account", "")
    if ta_val and ctx.target_account and ta_val.lower() != ctx.target_account.lower():
        logger.warning(
            "work_order: stage3 target_account mismatch: ai=%r vs findings=%r — correcting",
            ta_val, ctx.target_account,
        )
        filled_params["target_account"] = ctx.target_account

    # binary_search: default target_field to "password" when not specified
    if primitive_id == "oracle_search.binary_search":
        filled_params.setdefault("target_field", "password")

    # Inject strategy if the primitive has one (deterministic — not from model)
    if prim.strategy:
        filled_params["strategy"] = prim.strategy

    # ── Build WorkOrder ────────────────────────────────────────────────────────
    wo = WorkOrder(
        id           = str(_uuid.uuid4()),
        primitive_id = primitive_id,
        engine_id    = prim.engine_id,
        params       = filled_params,
        rationale    = rationale or f"AI selected {primitive_id} for {ctx.finding_type}",
        finding_id   = finding_id,
    )
    logger.info(
        "work_order: generated primitive=%r params=%r rationale=%r",
        primitive_id, filled_params, rationale[:80],
    )
    return wo, ""


def work_order_to_technique_option(wo: WorkOrder) -> object:
    """Convert a WorkOrder into a TechniqueOption for the selection card.

    The option carries work_order_id so the execute route can look up the full
    WorkOrder from InvestigationState.pending_work_orders.
    Source is set to 'work_order' so the card renders it with an [AI] badge.
    """
    from apps.conductor.vault_selector import TechniqueOption
    return TechniqueOption(
        concept_id                = wo.params.get("concept_id", ""),
        engine_id                 = wo.engine_id,
        title                     = f"[AI] {wo.primitive_id} — {wo.rationale[:60]}",
        similarity                = 0.0,
        requires_session          = False,
        source                    = "work_order",
        method                    = None,
        endpoint_hint             = None,
        payload_template_available= False,
        already_attempted         = False,
        work_order_id             = wo.id,
    )
