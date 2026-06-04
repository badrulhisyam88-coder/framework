"""Static suggestion catalog — finding_type → suggested next actions.

Each SuggestionSpec carries:
  - action_kind: stable id used in URLs to route the execute click
  - label:       button text the operator sees
  - reasoning:   one-line "why this is a useful next step"
  - probe_runner: the async generator that performs the real probe work
  - guidance_only: when True, the entry renders as an info-only card
                   in the "Manual investigation paths" panel section
                   with NO Execute button. For real techniques that
                   don't have an automated probe yet.

Phase 59b — canned-script execution removed. Every SuggestionSpec is
either probe-backed (has probe_runner, renders an Execute button in
the "Automated actions" section) or guidance-only (guidance_only=True,
renders without an Execute button in the "Manual investigation paths"
section). The previous Script-field "canned animation" mechanism is
gone — the choice is now: real probe, or honest "do this manually."
"""
from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass

from apps.investigation_workspace.suggestions import probes


@dataclass(frozen=True)
class SuggestionSpec:
    action_kind: str
    label:       str
    reasoning:   str
    # Probe runner — when set, clicking Execute runs this real probe.
    # When None, guidance_only must be True (no Execute button rendered),
    # or engine_id must be set for V2 engine dispatch.
    probe_runner:  Callable[[str], AsyncIterator] | None = None
    # When True, the spec renders as an info-only card with no Execute
    # button. Used for real techniques without automated probes.
    guidance_only: bool = False
    # V2 engine id — when set, Execute dispatches via Conductor.exec_orch
    # instead of running a probe. Mutually exclusive with probe_runner.
    engine_id: str | None = None


# ── CSP gap ─────────────────────────────────────────────────────────────
# csp_xss_reflected retired — lifted to XssReflectedEngine (V2.2 Step 1).
_CSP_SUGGESTIONS = (
    SuggestionSpec(
        action_kind  = "csp_inspect_origins",
        label        = "Inspect cross-origin script loads",
        reasoning    = "Map which origins CSP would otherwise restrict",
        probe_runner = probes.probe_csp_inspect_origins,
    ),
    SuggestionSpec(
        action_kind  = "csp_check_meta",
        label        = "Check for <meta> CSP tag",
        reasoning    = "Header absent does not exclude a meta-equivalent CSP",
        probe_runner = probes.probe_csp_check_meta,
    ),
)


# ── HSTS gap ────────────────────────────────────────────────────────────
# Phase 59b — both entries are guidance-only (real techniques, no probe yet).
_HSTS_SUGGESTIONS = (
    SuggestionSpec(
        action_kind   = "hsts_http_downgrade",
        label         = "Test HTTP downgrade behavior",
        reasoning     = (
            "HSTS absent — issue a cleartext request and check whether the "
            "server forces an upgrade. Try: curl -I http://<target>/ and "
            "look for a 30x redirect to https:// (or its absence)."
        ),
        guidance_only = True,
    ),
    SuggestionSpec(
        action_kind   = "hsts_redirect_chain",
        label         = "Trace redirect chain",
        reasoning     = (
            "Follow the 30x redirect chain from cleartext to verify or "
            "disconfirm the http→https hop. Try: curl -ILs http://<target>/ "
            "| grep -i 'location:' to enumerate hops."
        ),
        guidance_only = True,
    ),
)


# ── Referrer-Policy gap ────────────────────────────────────────────────
# Phase 59b — guidance-only (manual investigation, no probe yet).
_REFERRER_SUGGESTIONS = (
    SuggestionSpec(
        action_kind   = "referrer_check_outbound",
        label         = "Inspect outbound link policy",
        reasoning     = (
            "Without a Referrer-Policy header, full URLs (including any "
            "query-string secrets) leak to third-party origins. Enumerate "
            "outbound links in the page (anchor href + script/img src) and "
            "estimate exposure: are any pointing at unrelated origins?"
        ),
        guidance_only = True,
    ),
)


# ── HTTP service ────────────────────────────────────────────────────────
_HTTP_SVC_SUGGESTIONS = (
    SuggestionSpec(
        action_kind   = "svc_fingerprint_deep",
        label         = "Deep fingerprint server stack",
        reasoning     = (
            "Beyond the basic banner grab, identify the framework/runtime "
            "to enable CVE matching. Compare response signatures against "
            "known stacks (cookie naming, header order, body markers). "
            "Manual investigation today; no automated probe yet."
        ),
        guidance_only = True,
    ),
    SuggestionSpec(
        action_kind  = "svc_robots_check",
        label        = "Check robots.txt + sitemap",
        reasoning    = "Reveal paths the site discloses publicly",
        probe_runner = probes.probe_robots_check,
    ),
)


# sqli_auth_bypass retired V2.2 Step 7 — dispatched to SqliAuthBypassEngine.
_SQLI_SUGGESTIONS = (
    SuggestionSpec(
        action_kind = "sqli_auth_bypass",
        label       = "Test SQL injection auth bypass",
        reasoning   = "SqliAuthBypassEngine tests boolean-tautology payloads against the login endpoint",
        engine_id   = "sqli_auth_bypass",
    ),
)


# brute_force_login retired in V2.2 Step 3 — replaced by CredentialBruteEngine.
# login_form_detected findings are now dispatched to CredentialBruteEngine directly.

# API security — IDOR/BOLA via OpenAPI spec discovery + authenticated enumeration.
# purchase_flow retired V2.4 Step 1 — SqliAuthBypassEngine bookmarklet is the V2 replacement.
# api_exploit retired V2.2 Step 11 — replaced by AccessControlEngine (D4=Option A).
# api_idor_execute removed V2.2 Step 11 — probe_api_exploit retired.
# api_idor_mutate removed V2.2 Step 11 consolidated cleanup — probe retired.
_API_SUGGESTIONS: tuple = ()


# Phase 60 — command injection. Three distinct exploitation techniques,
# each backed by a real probe. The recon probe emits finding_type
# "command_injection"; the bindings layer maps that to the
# injection.command exploitation path.
_CMDI_SUGGESTIONS = (
    # cmdi_reflected retired V2.2 Step 4 — dispatched to CmdiReflectedEngine.
    SuggestionSpec(
        action_kind = "cmdi_reflected",
        label       = "Test reflected command injection",
        reasoning   = "CmdiReflectedEngine: marker-based payload reflects OS command output in HTTP response",
        engine_id   = "cmdi_reflected",
    ),
    # cmdi_blind_time retired V2.2 Step 5 — dispatched to CmdiBlindTimeEngine.
    SuggestionSpec(
        action_kind = "cmdi_blind_time",
        label       = "Test time-based blind command injection",
        reasoning   = "CmdiBlindTimeEngine: sleep payload reveals OS execution when output is suppressed",
        engine_id   = "cmdi_blind_time",
    ),
    # cmdi_blind_boolean retired V2.2 Step 6 — dispatched to CmdiBlindBooleanEngine.
    SuggestionSpec(
        action_kind = "cmdi_blind_boolean",
        label       = "Test boolean-based blind command injection",
        reasoning   = "CmdiBlindBooleanEngine: differential response confirms OS execution without output capture",
        engine_id   = "cmdi_blind_boolean",
    ),
)


# V2 exploitation engines — no probe_runner; engine_id routes dispatch via Conductor.

_XSS_ENGINE_SUGGESTIONS = (
    SuggestionSpec(
        action_kind = "xss_reflect",
        label       = "Test reflected XSS payload",
        reasoning   = "XssReflectedEngine: marker-based payload confirms inline script execution through CSP gap",
        engine_id   = "xss_reflect",
    ),
)

_CREDENTIAL_BRUTE_SUGGESTIONS = (
    SuggestionSpec(
        action_kind = "credential_brute",
        label       = "Brute-force credentials",
        reasoning   = "CredentialBruteEngine: tests SecLists credential pairs against the detected login form",
        engine_id   = "credential_brute",
    ),
)

_USERNAME_ENUM_SUGGESTIONS = (
    SuggestionSpec(
        action_kind = "username_enum",
        label       = "Enumerate username via response differential",
        reasoning   = "UsernameEnumEngine: Phase 1 enumerates valid username via response-differential oracle; Phase 2 brutes that user's password",
        engine_id   = "username_enum",
    ),
)

_ACCESS_CONTROL_ENGINE_SUGGESTIONS = (
    SuggestionSpec(
        action_kind = "default_creds",
        label       = "Try default credentials",
        reasoning   = "DefaultCredsEngine: tests SecLists credential pairs against API authentication endpoints",
        engine_id   = "default_creds",
    ),
    SuggestionSpec(
        action_kind = "access_control",
        label       = "Test IDOR / broken access control",
        reasoning   = "AccessControlEngine: probes horizontal privilege escalation via BOLA/IDOR patterns",
        engine_id   = "access_control",
    ),
)

_MSF_ENGINE_SUGGESTIONS = (
    SuggestionSpec(
        action_kind = "metasploit_recipe",
        label       = "Run Metasploit recipe modules",
        reasoning   = "MetasploitRecipeEngine: maps detected service to curated MSF modules and attempts exploitation",
        engine_id   = "metasploit_recipe",
    ),
)


# API endpoint discovery — V1 probes retired V2.4 Step 1.
# api_full_discovery, api_authed_recon, api_endpoint_enum, api_method_enum,
# api_browser_recon — all retired from SUGGESTIONS catalog (probes remain active
# for direct recon/enum phase dispatch; they write only to in-memory _RUNS, not
# exploitation_branches, so they cannot appear in the exploitation mindmap).
# api_default_creds_auth retired V2.2 Step 9 — handled by DefaultCredsEngine.
_API_ENUM_SUGGESTIONS: tuple = ()


# Public lookup table.
SUGGESTIONS: dict[str, tuple[SuggestionSpec, ...]] = {
    # CSP gap + XSS engine available off missing header or confirmed XSS findings.
    "missing_csp_header":      _CSP_SUGGESTIONS + _XSS_ENGINE_SUGGESTIONS,
    "xss_reflected":           _XSS_ENGINE_SUGGESTIONS,
    "xss":                     _XSS_ENGINE_SUGGESTIONS,
    "missing_hsts_header":     _HSTS_SUGGESTIONS,
    "missing_referrer_policy": _REFERRER_SUGGESTIONS,
    "http_service_detected":   _HTTP_SVC_SUGGESTIONS,
    # SQLi auth-bypass engine available off any SQLi-bound finding.
    "sqli":                    _SQLI_SUGGESTIONS,
    "sqli_error_based":        _SQLI_SUGGESTIONS,
    "sqli_blind":              _SQLI_SUGGESTIONS,
    # Command injection. Three V2 engines, no canned fallback.
    "command_injection":       _CMDI_SUGGESTIONS,
    # Credential brute-force + JS spider off confirmed login form.
    "login_form_detected":     _CREDENTIAL_BRUTE_SUGGESTIONS + _USERNAME_ENUM_SUGGESTIONS + (
        SuggestionSpec(
            action_kind = "js_spider",
            label       = "Spider JS for hidden endpoints",
            reasoning   = "JSSpiderEngine: fetches pages with captured session, extracts endpoints from fetch()/XHR/axios calls",
            engine_id   = "js_spider",
        ),
    ),
    # JS-discovered endpoints → access_control engine for injection testing.
    "api_endpoint_discovered": _ACCESS_CONTROL_ENGINE_SUGGESTIONS,
    # API security — IDOR/BOLA + access control engines.
    "api_exposure":            _API_SUGGESTIONS + _API_ENUM_SUGGESTIONS + _ACCESS_CONTROL_ENGINE_SUGGESTIONS,
    "api_idor":                _API_SUGGESTIONS + _API_ENUM_SUGGESTIONS + _ACCESS_CONTROL_ENGINE_SUGGESTIONS,
    "api_bola":                _API_SUGGESTIONS + _API_ENUM_SUGGESTIONS + _ACCESS_CONTROL_ENGINE_SUGGESTIONS,
    # Infrastructure exposure — MetasploitRecipeEngine off service and port findings.
    "service_banner_disclosed": _MSF_ENGINE_SUGGESTIONS,
    "open_port_detected":       _MSF_ENGINE_SUGGESTIONS,
    # Oracle extraction result → oracle_search available for follow-up extractions.
    # Primary trigger is the Layer 3 execute-variant route, not the suggestion panel.
    "oracle_extraction_confirmed": (
        SuggestionSpec(
            action_kind = "oracle_search",
            label       = "Re-run oracle extraction",
            reasoning   = "OracleSearchEngine: oracle-driven blind field extraction via binary-search charset",
            engine_id   = "oracle_search",
        ),
    ),
    # Oracle enumeration result → oracle_search for extraction of a discovered field.
    "oracle_enumeration_confirmed": (
        SuggestionSpec(
            action_kind = "oracle_search",
            label       = "Extract value of discovered field",
            reasoning   = "OracleSearchEngine: extract the value of a field found by dictionary_scan enumeration",
            engine_id   = "oracle_search",
        ),
    ),
    # Auth bypass — triggered off login_form_detected when literal creds fail.
    # Primary use: operator-injection labs where credential_brute exhausts.
    # $where keys_enumeration result → oracle_search for token value extraction
    "keys_enumeration_confirmed": (
        SuggestionSpec(
            action_kind = "oracle_search",
            label       = "Extract token value via $where",
            reasoning   = "OracleSearchEngine keys_enumeration: discovered token field; extract value via $where injection",
            engine_id   = "oracle_search",
        ),
    ),
    "auth_bypass_confirmed": (
        SuggestionSpec(
            action_kind = "auth_bypass_login",
            label       = "Retry bypass with extended payload list",
            reasoning   = "AuthBypassLoginEngine: operator-injection bypass with varies-method payload list",
            engine_id   = "auth_bypass_login",
        ),
    ),
}


def for_finding_type(finding_type: str) -> tuple[SuggestionSpec, ...]:
    """Return the suggestion list for this finding type (empty tuple if none)."""
    return SUGGESTIONS.get(finding_type, ())


# Sentinel for api_method_* dynamic action_kinds produced by probe_api_method_enum.
# Each (method, path) combo gets a unique action_kind (base64url-encoded) so the
# execute route can resolve the correct probe runner without a static entry.
# Points to probe_api_method_execute — the single mutating probe that reads
# ACTION_ID_CTX for the decoded endpoint and OPERATOR_INPUTS_CTX for body fields.
_API_METHOD_DYNAMIC_SPEC = SuggestionSpec(
    action_kind  = "api_method",   # sentinel — prefix is what matters
    label        = "Execute operator-constructed request on discovered endpoint",
    reasoning    = (
        "Sends the operator-filled body to the error-probed endpoint using "
        "the method confirmed by method enumeration"
    ),
    probe_runner = probes.probe_api_method_execute,
)


def find_spec(action_kind: str) -> SuggestionSpec | None:
    """Look up a single SuggestionSpec by action_kind across the catalog."""
    for specs in SUGGESTIONS.values():
        for s in specs:
            if s.action_kind == action_kind:
                return s
    # Sentinels for action_kinds that surface only in structured-evidence panels
    # (not as initial ghost nodes) so no static catalog entry is needed.
    # api_idor_execute removed V2.2 Step 11 (probe_api_exploit retired).
    # api_idor_mutate_* removed V2.2 Step 11 consolidated cleanup (probe retired).
    if action_kind.startswith("api_method_"):
        return _API_METHOD_DYNAMIC_SPEC
    return None
