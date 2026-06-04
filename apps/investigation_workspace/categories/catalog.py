"""Static finding-category catalog.

Each Category groups related finding_types under one container node on the
topology. Future labs (SQL injection, XSS) add entries here; no code
changes elsewhere are needed to surface them as a new top-level node.

Deterministic: same finding_type always lands in the same category. No
LLM, no scoring, no heuristics — explicit mapping.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Category:
    """One investigation domain that groups related finding_types."""
    category_id: str           # stable id used in node ids and lookups
    label:       str           # what the operator sees
    description: str           # one-line subtitle on the category node
    severity_hint: str         # info | low | medium | high | critical
                               # — drives the category card's accent color


# ── Category definitions ────────────────────────────────────────────────


SECURITY_MISCONFIGURATION = Category(
    category_id   = "security_misconfiguration",
    label         = "Security Misconfiguration",
    description   = "Missing or weak baseline security controls",
    severity_hint = "medium",
)

INFORMATION_DISCLOSURE = Category(
    category_id   = "information_disclosure",
    label         = "Information Disclosure",
    description   = "Server reveals data that aids further attack",
    severity_hint = "low",
)

INFRASTRUCTURE_EXPOSURE = Category(
    category_id   = "infrastructure_exposure",
    label         = "Infrastructure Exposure",
    description   = "Reachable services and surfaces",
    severity_hint = "info",
)

SQL_INJECTION = Category(
    category_id   = "sql_injection",
    label         = "SQL Injection",
    description   = "Inputs interpreted as SQL",
    severity_hint = "high",
)

COMMAND_INJECTION = Category(
    category_id   = "command_injection",
    label         = "Command Injection",
    description   = "Inputs interpreted as shell commands",
    severity_hint = "critical",
)

CROSS_SITE_SCRIPTING = Category(
    category_id   = "cross_site_scripting",
    label         = "Cross-Site Scripting",
    description   = "Inputs reflected/stored into rendered output",
    severity_hint = "high",
)

AUTHENTICATION = Category(
    category_id   = "authentication",
    label         = "Authentication",
    description   = "Identity verification weaknesses",
    severity_hint = "high",
)

API_SECURITY = Category(
    category_id   = "api_security",
    label         = "API Security",
    description   = "Exposed API surfaces and broken access control",
    severity_hint = "critical",
)

UNCATEGORIZED = Category(
    category_id   = "uncategorized",
    label         = "Uncategorized",
    description   = "Findings without a registered category",
    severity_hint = "info",
)

AI_ACTIONS = Category(
    category_id   = "ai_actions",
    label         = "AI Actions",
    description   = "Engine executions triggered by AI recommendations",
    severity_hint = "info",
)


# ── finding_type → category mapping ─────────────────────────────────────


FINDING_TYPE_TO_CATEGORY: dict[str, Category] = {
    # Header / baseline-policy gaps
    "missing_csp_header":              SECURITY_MISCONFIGURATION,
    "missing_hsts_header":             SECURITY_MISCONFIGURATION,
    "missing_x_frame_options":         SECURITY_MISCONFIGURATION,
    "missing_x_content_type_options":  SECURITY_MISCONFIGURATION,
    "missing_referrer_policy":         SECURITY_MISCONFIGURATION,
    "missing_permissions_policy":      SECURITY_MISCONFIGURATION,
    "weak_csp_directive":              SECURITY_MISCONFIGURATION,

    # Info-disclosure family
    "verbose_error_response":          INFORMATION_DISCLOSURE,
    "server_version_leaked":           INFORMATION_DISCLOSURE,
    "directory_listing":               INFORMATION_DISCLOSURE,
    "stack_trace_leaked":              INFORMATION_DISCLOSURE,

    # Infra / reachability
    "http_service_detected":           INFRASTRUCTURE_EXPOSURE,
    "open_port_detected":              INFRASTRUCTURE_EXPOSURE,
    "service_banner_disclosed":        INFRASTRUCTURE_EXPOSURE,

    # Vulnerability families (future labs)
    "sqli":                            SQL_INJECTION,
    "sqli_error_based":                SQL_INJECTION,
    "sqli_blind":                      SQL_INJECTION,
    "command_injection":               COMMAND_INJECTION,
    "xss":                             CROSS_SITE_SCRIPTING,
    "xss_reflected":                   CROSS_SITE_SCRIPTING,
    "xss_stored":                      CROSS_SITE_SCRIPTING,
    "xss_dom":                         CROSS_SITE_SCRIPTING,
    "auth_bypass":                     AUTHENTICATION,
    "weak_credentials":                AUTHENTICATION,
    "default_credentials":             AUTHENTICATION,
    "login_form_detected":             AUTHENTICATION,
    # API security family
    "api_exposure":                    API_SECURITY,
    "api_idor":                        API_SECURITY,
    "api_bola":                        API_SECURITY,
    "api_endpoint_discovered":         API_SECURITY,
    # Exploitation-phase confirmed findings (V2 engines)
    "xss_reflected":                   CROSS_SITE_SCRIPTING,
    "credentials_obtained":            AUTHENTICATION,
    "valid_username_confirmed":        AUTHENTICATION,   # Pre-V5: username-enum Phase 1 result
    "command_injection_confirmed":     COMMAND_INJECTION,
    "sqli_auth_bypass_confirmed":      SQL_INJECTION,
    "default_creds_authenticated":     AUTHENTICATION,
    "idor_confirmed":                  API_SECURITY,
    "access_control_note":             API_SECURITY,
    "msf_session_opened":              INFRASTRUCTURE_EXPOSURE,
    "msf_module_success":              INFRASTRUCTURE_EXPOSURE,
    # AI-triggered probe findings (V2.5 Step 4B)
    "ai_probe":                        AI_ACTIONS,
}


def for_finding_type(finding_type: str) -> Category:
    """Return the Category for this finding_type, or UNCATEGORIZED."""
    return FINDING_TYPE_TO_CATEGORY.get(finding_type or "", UNCATEGORIZED)


def all_categories() -> list[Category]:
    """All distinct categories referenced in the mapping (deterministic order)."""
    seen: dict[str, Category] = {}
    for cat in FINDING_TYPE_TO_CATEGORY.values():
        seen.setdefault(cat.category_id, cat)
    seen.setdefault(UNCATEGORIZED.category_id, UNCATEGORIZED)
    return list(seen.values())
