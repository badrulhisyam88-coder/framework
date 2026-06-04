"""Mapping from finding_type → investigation category.

Categories are the unit of maturity assessment. A user can be "advanced" in
SQL injection investigations while still "beginner" in hardening reviews.

Stable IDs are kept short and machine-friendly; human labels live alongside.
"""

from __future__ import annotations

CATEGORY_MAP: dict[str, str] = {
    # SQL Injection family
    "sqli":               "sql_injection",
    "sql_injection":      "sql_injection",
    "sqli_error_based":   "sql_injection",
    "sqli_blind":         "sql_injection",

    # Cross-Site Scripting family
    "xss":           "xss",
    "reflected_xss": "xss",
    "xss_reflected": "xss",
    "stored_xss":    "xss",
    "xss_stored":    "xss",
    "dom_xss":       "xss",

    # Authentication family
    "auth_bypass":            "authentication",
    "weak_credentials":       "authentication",
    "default_credentials":    "authentication",
    "credential_exposure":    "authentication",
    "cleartext_transmission": "authentication",

    # Hardening / misconfig
    "security_misconfiguration": "hardening",
    "information_disclosure":    "hardening",
    "http_only_site":            "hardening",
    "broken_access_control":     "hardening",
    "tls_weakness":              "hardening",
    "ssl_weak":                  "hardening",

    # Recon surface
    "open_port_detected":     "recon",
    "http_service_detected":  "recon",
    "service_banner_disclosed": "recon",

    # Vulnerability management
    "cve_matched":         "vulnerability_management",
    "known_vulnerability": "vulnerability_management",
}

CATEGORY_LABELS: dict[str, str] = {
    "sql_injection":            "SQL Injection",
    "xss":                      "Cross-Site Scripting",
    "authentication":           "Authentication",
    "hardening":                "Security Hardening",
    "recon":                    "Reconnaissance",
    "vulnerability_management": "Vulnerability Management",
    "other":                    "Other",
}


def category_for_finding_type(finding_type: str) -> str:
    """Return the category for a finding type, or 'other' if unmapped."""
    return CATEGORY_MAP.get(finding_type, "other")


def category_label(category: str) -> str:
    return CATEGORY_LABELS.get(category, category.replace("_", " ").title())
