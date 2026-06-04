"""Capability manifest for the AI work-order generator (Bundle 2).

Machine-readable inventory of what the system can execute. The AI reads this
manifest to know its available action space; it can ONLY emit invocations of
manifest entries.

Design:
  - Engine ID set is DERIVED from engine_registry — never drifts from truth.
  - Semantic metadata (descriptions, params, preconditions) is declared in
    _STATIC_SUPPLEMENTS, keyed by primitive_id.
  - oracle_search expands into TWO primitives (binary_search + dictionary_scan)
    because it has two distinct strategies.

MAINTENANCE RULE: when a new engine is added to engine_registry or a new
strategy is added to oracle_search_engine.py, add a corresponding entry to
_STATIC_SUPPLEMENTS below. The maintenance comment on _STATIC_SUPPLEMENTS
is intentional — keeping it co-located prevents silent drift.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger("conductor.capability_manifest")


# ── Param and Primitive dataclasses ───────────────────────────────────────────

@dataclass(frozen=True)
class ParamSpec:
    """One parameter for a primitive invocation."""
    name:        str
    type:        str    # "str" | "int" | "bool" | "list"
    source_hint: str    # "from_finding" | "from_objective" | "operator"
    description: str = ""


@dataclass(frozen=True)
class PrimitiveSpec:
    """One callable primitive in the manifest.

    id is unique. Multiple primitives may share an engine_id (e.g. oracle_search
    has two: binary_search and dictionary_scan).
    """
    id:              str                    # "oracle_search.binary_search"
    engine_id:       str                    # registry engine_id → dispatch key
    description:     str                    # one-line human summary
    required_params: tuple[ParamSpec, ...]  # must be present and type-correct
    optional_params: tuple[ParamSpec, ...]  # may be absent
    produces:        str                    # finding_type emitted on success
    preconditions:   tuple[str, ...]        # semantic names the packager checks
    strategy:        str | None = None      # extra_config["strategy"] for multi-strat engines
    when_to_use:     str = ""               # SELECTION CRITERIA — when to choose this over others


# ── Static supplements ─────────────────────────────────────────────────────────
# MAINTENANCE NOTE: keep this dict in sync with:
#   engine_registry.engines_for_phase("exploitation")  [apps/conductor/engines/__init__.py]
#   oracle_search_engine.py strategies                  [strategy arg to run()]
# When adding a new engine: add its engine_id here.
# When adding a new oracle_search strategy: add a new entry keyed "oracle_search.<strategy>".
_STATIC_SUPPLEMENTS: dict[str, dict] = {
    # ── oracle_search: two primitives for two strategies ──────────────────────
    "oracle_search.dictionary_scan": {
        "description": "Dictionary-scan oracle: enumerate which field names exist on the target account.",
        "when_to_use": (
            "Use ONLY when $where injection is NOT available. Guesses field names from a fixed "
            "wordlist — CANNOT discover custom or application-specific field names (e.g. reset "
            "tokens, application-defined attributes) that are not in the list. "
            "Inferior to keys_enumeration; avoid if where_injection_confirmed."
        ),
        "required_params": (
            ParamSpec("concept_id", "str", "from_finding",
                      "EXEC-ENUM concept id (e.g. CONCEPT-NOSQL-OPERATOR-INJECTION)"),
            ParamSpec("target_account", "str", "from_objective",
                      "Username to enumerate fields for (e.g. 'carlos')"),
        ),
        "optional_params": (),
        "produces": "oracle_enumeration_confirmed",
        "preconditions": ("injection_confirmed",),
        "strategy": "dictionary_scan",
    },
    "oracle_search.binary_search": {
        "description": "Character-by-character oracle extraction of a field value.",
        "when_to_use": (
            "Use to extract the VALUE of an already-KNOWN field. The target_field param must "
            "name a specific field that is already known to exist. Do NOT use to discover field "
            "names — use keys_enumeration first if the field name is unknown."
        ),
        "required_params": (
            ParamSpec("concept_id", "str", "from_finding",
                      "EXEC-EXTRACT concept id (e.g. CONCEPT-NOSQL-OPERATOR-INJECTION)"),
            ParamSpec("target_account", "str", "from_objective",
                      "Username to extract from (e.g. 'carlos')"),
        ),
        "optional_params": (
            ParamSpec("target_field", "str", "from_finding",
                      "Field name to extract (overrides template default)"),
        ),
        "produces": "oracle_extraction_confirmed",
        "preconditions": ("injection_confirmed",),
        "strategy": "binary_search",
    },
    # ── simple engines (single primitive = engine_id) ─────────────────────────
    "access_control": {
        "description": "Single-shot injection test (IDOR, NoSQL operator bypass, mass assignment).",
        "when_to_use": "Use for access control and privilege escalation tests (IDOR, mass assignment, parameter tampering).",
        "required_params": (),
        "optional_params": (
            ParamSpec("concept_id", "str", "from_finding", "Technique concept id"),
        ),
        "produces": "access_control_confirmed",
        "preconditions": (),
        "strategy": None,
    },
    "credential_brute": {
        "description": "Brute-force credential attack against a detected HTML login form.",
        "when_to_use": (
            "Use when brute-forcing standard username/password patterns against a login form. "
            "Not useful when the account is locked or when the attack surface is injection-based. "
            "Do not select instead of auth_bypass_login when the objective mentions injection."
        ),
        "required_params": (),
        "optional_params": (),
        "produces": "credentials_obtained",
        "preconditions": ("login_form_present",),
        "strategy": None,
    },
    "js_spider": {
        "description": "Spider JavaScript sources to discover hidden API endpoints (auto-fires after credential_brute).",
        "when_to_use": "Use after obtaining a session to discover hidden API endpoints embedded in JavaScript files.",
        "required_params": (),
        "optional_params": (),
        "produces": "api_endpoint_discovered",
        "preconditions": ("session_present",),
        "strategy": None,
    },
    "sqli_auth_bypass": {
        "description": "SQL injection authentication bypass.",
        "when_to_use": "Use when the login form is vulnerable to SQL injection (SQLi), not NoSQL.",
        "required_params": (),
        "optional_params": (ParamSpec("concept_id", "str", "from_finding", ""),),
        "produces": "sqli_auth_bypass_confirmed",
        "preconditions": (),
        "strategy": None,
    },
    "xss_reflect": {
        "description": "Reflected XSS via GET/POST parameter injection.",
        "when_to_use": "Use when the finding indicates a reflected XSS surface (parameter echoed unsanitized).",
        "required_params": (),
        "optional_params": (ParamSpec("concept_id", "str", "from_finding", ""),),
        "produces": "xss_reflect_confirmed",
        "preconditions": (),
        "strategy": None,
    },
    "cmdi_reflected": {
        "description": "Reflected command injection (immediate output in response).",
        "when_to_use": "Use when the finding indicates a command injection surface with output visible in the response.",
        "required_params": (),
        "optional_params": (ParamSpec("concept_id", "str", "from_finding", ""),),
        "produces": "cmdi_reflected_confirmed",
        "preconditions": (),
        "strategy": None,
    },
    "cmdi_blind_time": {
        "description": "Blind command injection via timing differential (sleep payloads).",
        "when_to_use": "Use for blind command injection when no output is visible but timing side-channels are observable.",
        "required_params": (),
        "optional_params": (),
        "produces": "cmdi_blind_time_confirmed",
        "preconditions": (),
        "strategy": None,
    },
    "cmdi_blind_boolean": {
        "description": "Blind command injection via boolean-based side channel.",
        "when_to_use": "Use for blind command injection when a boolean response difference is observable (true/false).",
        "required_params": (),
        "optional_params": (),
        "produces": "cmdi_blind_boolean_confirmed",
        "preconditions": (),
        "strategy": None,
    },
    "default_creds": {
        "description": "Test default/common credential pairs against a login endpoint.",
        "when_to_use": (
            "Last resort fallback — use after injection-based bypass methods (auth_bypass_login, "
            "sqli_auth_bypass) have been tried or are not applicable. "
            "Do NOT select ahead of auth_bypass_login when the objective or finding type suggests "
            "an injectable login surface."
        ),
        "required_params": (),
        "optional_params": (),
        "produces": "credentials_obtained",
        "preconditions": (),
        "strategy": None,
    },
    "metasploit_recipe": {
        "description": "Execute a Metasploit module recipe (requires msfrpcd).",
        "when_to_use": "Use when a known Metasploit module covers the vulnerability and msfrpcd is running.",
        "required_params": (),
        "optional_params": (),
        "produces": "exploit_confirmed",
        "preconditions": ("msfrpcd_available",),
        "strategy": None,
    },
    "oracle_search.keys_enumeration": {
        "description": "Enumerate MongoDB document field names via $where Object.keys() injection (reads actual schema, not wordlist).",
        "when_to_use": (
            "Use when the TARGET FIELD NAME IS UNKNOWN and $where injection is confirmed. "
            "Reads the REAL document schema by calling Object.keys() — discovers ALL fields "
            "including application-specific ones (e.g. reset tokens, custom attributes) that "
            "a fixed wordlist cannot guess. ALWAYS prefer over dictionary_scan when $where works. "
            "Use this BEFORE binary_search or where_extract to discover which fields exist."
        ),
        "required_params": (
            ParamSpec("concept_id", "str", "from_finding",
                      "Concept with EXEC-WHERE-ENUM block (e.g. CONCEPT-NOSQL-OPERATOR-INJECTION)"),
            ParamSpec("target_account", "str", "from_objective",
                      "Username of the target account (e.g. 'carlos')"),
        ),
        "optional_params": (),
        "produces": "keys_enumeration_confirmed",
        "preconditions": ("where_injection_confirmed",),
        "strategy": "keys_enumeration",
    },
    "oracle_search.where_extract": {
        "description": "Extract a field value character-by-character via $where JavaScript injection (.match oracle).",
        "when_to_use": (
            "Use to extract the VALUE of a KNOWN field via $where .match() oracle. "
            "The target_field param must name a field that is already known to exist "
            "(run keys_enumeration first if unsure which fields are present). "
            "Equivalent to binary_search but over the $where channel."
        ),
        "required_params": (
            ParamSpec("concept_id", "str", "from_finding",
                      "Concept with EXEC-WHERE-EXTRACT block"),
            ParamSpec("target_account", "str", "from_objective",
                      "Username of the target account"),
        ),
        "optional_params": (
            ParamSpec("target_field", "str", "from_finding", "Field to extract (from keys_enumeration)"),
        ),
        "produces": "oracle_extraction_confirmed",
        "preconditions": ("where_injection_confirmed",),
        "strategy": "where_extract",
    },
    "auth_bypass_login": {
        "description": "Authenticate via operator-injection bypass when literal credentials fail. Iterates a vault-defined payload list (varies-method).",
        "when_to_use": (
            "PREFER when the login endpoint is injectable (NoSQL/SQLi) and literal credentials "
            "are not expected to succeed. Select BEFORE default_creds on injectable login forms. "
            "Not needed if you already have a valid session for the target account."
        ),
        "required_params": (
            ParamSpec("concept_id", "str", "from_finding",
                      "Concept with EXEC-AUTH-BYPASS block (e.g. CONCEPT-NOSQL-OPERATOR-INJECTION)"),
        ),
        "optional_params": (
            ParamSpec("target_account", "str", "from_objective",
                      "Username to attempt bypass for (from objective)"),
        ),
        "produces": "credentials_obtained",
        "preconditions": ("login_form_present",),
        "strategy": None,
    },
    "username_enum": {
        "description": "Two-phase username enumeration via response differential (oracle strategy selectable), then targeted password brute-force.",
        "when_to_use": (
            "Use when the login form returns DIFFERENT responses for valid vs invalid usernames. "
            "Phase 1 enumerates the valid username via an oracle strategy; Phase 2 brutes only "
            "that user's password — much more efficient than joint pair-scanning. "
            "The oracle_strategy parameter controls which differential signal Phase 1 reads: "
            "'message' (default) — body text differs (e.g. 'Incorrect password' vs 'Invalid username'); "
            "'length' — response length is an outlier among all candidates (subtle labs differ here); "
            "'status' — status code differs from the baseline majority; "
            "'timing' — RESPONSE TIME is the signal: valid user triggers slow bcrypt/argon2 hash check "
            "server-side while invalid usernames short-circuit early, producing a measurable time gap. "
            "The orchestrator auto-advances through message→length→status→timing on exhaustion. "
            "Use 'timing' explicitly when the lab description mentions response-time differences. "
            "IP-spoof headers (X-Forwarded-For etc.) are always active to bypass IP rate-limiting. "
            "If 'message' exhausts with no match, retry with oracle_strategy='length' — "
            "many labs use a length-based difference, not a text-based one."
        ),
        "required_params": (),
        "optional_params": (
            ParamSpec("concept_id", "str", "from_finding",
                      "Concept id (e.g. CONCEPT-USERNAME-ENUMERATION)"),
            ParamSpec("user_exists_signal", "str", "from_finding",
                      "Response body string that signals the username EXISTS (e.g. 'Incorrect password'). "
                      "Only used when oracle_strategy='message'."),
            ParamSpec("oracle_strategy", "str", "from_finding",
                      "Differential oracle strategy: 'message' (body text differs, default), "
                      "'length' (response-length outlier), 'status' (status-code outlier), "
                      "'timing' (response-time outlier — multi-sample median, noise-aware). "
                      "Auto-progression: message→length→status→timing on exhaustion. "
                      "If 'message' exhausts with no match, retry with oracle_strategy='length'."),
            ParamSpec("timing_samples", "int", "from_finding",
                      "Number of timing samples per candidate for the timing oracle (default 4). "
                      "Higher = more noise resistance; lower = faster but noisier."),
        ),
        "produces": "credentials_obtained",
        "preconditions": ("login_form_present",),
        "strategy": None,
    },
}


# ── Manifest builder ───────────────────────────────────────────────────────────

def build_manifest() -> list[PrimitiveSpec]:
    """Build the capability manifest from the engine registry + static supplements.

    Engine ID SET is authoritative from registry — supplements add semantics.
    oracle_search expands into two primitives (binary_search, dictionary_scan).
    Engines without a supplement get a minimal spec derived from capabilities.
    Never raises — returns [] on any error.
    """
    try:
        return _build()
    except Exception as exc:
        logger.warning("capability_manifest.build_manifest failed: %s", exc)
        return []


def _build() -> list[PrimitiveSpec]:
    import apps.conductor.engines  # noqa: F401 — triggers registration
    from apps.conductor.engines.base import engine_registry

    exploitation_engines = {
        e.engine_id: e
        for e in engine_registry.engines_for_phase("exploitation")
    }

    primitives: list[PrimitiveSpec] = []

    for engine_id, engine in sorted(exploitation_engines.items()):
        if engine_id == "oracle_search":
            # Expand oracle_search into all strategy-primitives
            for suffix in ("binary_search", "dictionary_scan", "keys_enumeration", "where_extract"):
                prim_id = f"oracle_search.{suffix}"
                supp = _STATIC_SUPPLEMENTS.get(prim_id, {})
                primitives.append(PrimitiveSpec(
                    id              = prim_id,
                    engine_id       = "oracle_search",
                    description     = supp.get("description", f"oracle_search ({suffix})"),
                    when_to_use     = supp.get("when_to_use", ""),
                    required_params = supp.get("required_params", ()),
                    optional_params = supp.get("optional_params", ()),
                    produces        = supp.get("produces", "oracle_search_result"),
                    preconditions   = supp.get("preconditions", ()),
                    strategy        = supp.get("strategy", suffix),
                ))
        else:
            supp = _STATIC_SUPPLEMENTS.get(engine_id, {})
            # Derive minimal metadata from capabilities when supplement is absent
            caps = engine.capabilities
            primitives.append(PrimitiveSpec(
                id              = engine_id,
                engine_id       = engine_id,
                description     = supp.get("description",
                                           f"{engine_id}: {', '.join(caps.finding_types[:2])}"),
                when_to_use     = supp.get("when_to_use", ""),
                required_params = supp.get("required_params", ()),
                optional_params = supp.get("optional_params", ()),
                produces        = supp.get("produces",
                                           caps.finding_types[0] if caps.finding_types else "unknown"),
                preconditions   = supp.get("preconditions", ()),
                strategy        = supp.get("strategy", None),
            ))

    return primitives


# ── Precondition evaluation ────────────────────────────────────────────────────

def filter_by_preconditions(
    primitives: list[PrimitiveSpec],
    satisfied: set[str],
) -> list[PrimitiveSpec]:
    """Return primitives whose preconditions are all satisfied.

    A primitive with no preconditions is always included.
    """
    return [
        p for p in primitives
        if all(cond in satisfied for cond in p.preconditions)
    ]


def evaluate_preconditions(
    session_present: bool,
    injection_confirmed: bool,
    login_form_present: bool,
    msfrpcd_available: bool = False,
) -> set[str]:
    """Map boolean facts to a set of satisfied precondition names."""
    satisfied: set[str] = set()
    if session_present:
        satisfied.add("session_present")
    if injection_confirmed:
        satisfied.add("injection_confirmed")
        # $where injection uses the same surface — any confirmed operator injection
        # also satisfies the $where precondition (same MongoDB endpoint, same transport).
        satisfied.add("where_injection_confirmed")
    if login_form_present:
        satisfied.add("login_form_present")
    if msfrpcd_available:
        satisfied.add("msfrpcd_available")
    return satisfied


# ── Manifest singleton (build once, cache) ─────────────────────────────────────

_manifest_cache: list[PrimitiveSpec] | None = None


def get_manifest(force_rebuild: bool = False) -> list[PrimitiveSpec]:
    """Return the capability manifest, building it once and caching.

    Pass force_rebuild=True in tests to pick up freshly registered engines.
    """
    global _manifest_cache
    if _manifest_cache is None or force_rebuild:
        _manifest_cache = build_manifest()
    return _manifest_cache


def get_primitive(primitive_id: str) -> PrimitiveSpec | None:
    """Look up one primitive by id. Returns None if absent."""
    return next((p for p in get_manifest() if p.id == primitive_id), None)


def primitive_ids() -> list[str]:
    """Return all primitive ids in the manifest."""
    return [p.id for p in get_manifest()]
