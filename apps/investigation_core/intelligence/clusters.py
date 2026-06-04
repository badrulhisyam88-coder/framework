"""Static root-cause cluster registry.

Each cluster represents a structural weakness pattern. Finding types may belong
to multiple clusters (e.g. `sqli_error_based` belongs to both `unsafe_input_handling`
and `excessive_disclosure` — both are correct interpretations).

The user can always trace why a theme appeared: read this file and grep the
finding_types list.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RootCauseCluster:
    """A deterministic root-cause grouping over finding types."""
    cluster_id: str
    label: str
    description: str
    finding_types: tuple[str, ...]
    remediation_concepts: tuple[str, ...]
    related_skill_prefixes: tuple[str, ...] = field(default_factory=tuple)
    # Threshold for theme emergence: at least this many distinct findings
    # within an investigation must belong to the cluster.
    emerging_threshold: int = 2
    established_threshold: int = 4
    strong_threshold: int = 8


# Confidence labels surfaced in UI.
CONFIDENCE_EMERGING    = "emerging"
CONFIDENCE_ESTABLISHED = "established"
CONFIDENCE_STRONG      = "strong"


CLUSTERS: dict[str, RootCauseCluster] = {

    "weak_hardening_posture": RootCauseCluster(
        cluster_id="weak_hardening_posture",
        label="Weak Hardening Posture",
        description=(
            "Multiple hardening controls (response headers, transport, "
            "access control) are missing or weakly applied. Each finding alone "
            "is low impact; the cluster represents a permissive defensive baseline."
        ),
        finding_types=(
            "security_misconfiguration",
            "information_disclosure",
            "http_only_site",
            "tls_weakness",
            "ssl_weak",
            "broken_access_control",
        ),
        remediation_concepts=(
            "Content-Security-Policy",
            "Strict-Transport-Security (HSTS)",
            "Cookie security flags (HttpOnly, Secure, SameSite)",
            "TLS 1.2+ with modern cipher suites",
            "Server-side authorisation enforcement",
            "Defence-in-depth: combine headers + transport + access control",
        ),
        related_skill_prefixes=("hardening", "tls"),
    ),

    "unsafe_input_handling": RootCauseCluster(
        cluster_id="unsafe_input_handling",
        label="Unsafe Input Handling",
        description=(
            "User input flows into query construction, output rendering, or "
            "command execution without parameterisation or context-appropriate "
            "encoding. Root cause: input treated as code, not data."
        ),
        finding_types=(
            "sqli",
            "sql_injection",
            "sqli_error_based",
            "sqli_blind",
            "xss",
            "reflected_xss",
            "xss_reflected",
            "stored_xss",
            "xss_stored",
            "dom_xss",
        ),
        remediation_concepts=(
            "Parameterised queries / prepared statements",
            "Output context encoding (HTML / JS / URL / CSS)",
            "Input allowlist validation at the application boundary",
            "ORM safe-default usage",
            "Content-Security-Policy as XSS defence-in-depth",
        ),
        related_skill_prefixes=("sqli", "xss"),
    ),

    "weak_authentication": RootCauseCluster(
        cluster_id="weak_authentication",
        label="Weak Authentication Architecture",
        description=(
            "Authentication can be bypassed, defaults remain in place, "
            "credentials are exposed, or transport lacks encryption. "
            "Root cause: trust boundaries not enforced on the login path."
        ),
        finding_types=(
            "auth_bypass",
            "weak_credentials",
            "default_credentials",
            "credential_exposure",
            "cleartext_transmission",
        ),
        remediation_concepts=(
            "Parameterised queries on authentication paths",
            "Rotate vendor defaults during deployment",
            "Account-lockout and rate-limiting",
            "Multi-factor authentication",
            "HTTPS-only transport with HSTS for credential submission",
            "Generic error messaging on failed logins",
        ),
        related_skill_prefixes=("auth", "sqli"),
    ),

    "excessive_disclosure": RootCauseCluster(
        cluster_id="excessive_disclosure",
        label="Excessive Information Disclosure",
        description=(
            "Service banners, error pages, and exposed ports reveal product "
            "names, version numbers, and internal paths useful for targeted attack."
        ),
        finding_types=(
            "information_disclosure",
            "service_banner_disclosed",
            "open_port_detected",
            "sqli_error_based",
        ),
        remediation_concepts=(
            "Banner suppression on production services",
            "Generic error pages with logs redirected to backend",
            "Minimum-exposure firewall posture",
            "Production-mode framework configuration",
        ),
        related_skill_prefixes=("hardening", "recon"),
    ),

    "insecure_legacy_services": RootCauseCluster(
        cluster_id="insecure_legacy_services",
        label="Insecure Legacy Services",
        description=(
            "Deprecated protocols, cleartext channels, or known-vulnerable "
            "service versions are still accepted by the target. Root cause: "
            "lack of deprecation discipline + patch hygiene."
        ),
        finding_types=(
            "http_only_site",
            "cleartext_transmission",
            "ssl_weak",
            "tls_weakness",
            "known_vulnerability",
            "cve_matched",
        ),
        remediation_concepts=(
            "Deprecate cleartext protocols (HTTP, FTP, Telnet)",
            "TLS 1.2+ only with modern cipher suites",
            "Patch hygiene: track vendor advisories + automate updates",
            "Sunset roadmap for deprecated services",
        ),
        related_skill_prefixes=("tls", "hardening"),
    ),
}


# Cluster → defensive verification actions (deterministic mapping)
CLUSTER_TO_DEFENSIVE_ACTIONS: dict[str, tuple[str, ...]] = {
    "weak_hardening_posture":   ("verify_csp_policy", "verify_hsts_header",
                                  "verify_cookie_security_flags",
                                  "verify_error_page_genericness"),
    "unsafe_input_handling":    ("verify_parameterised_queries", "verify_csp_policy"),
    "weak_authentication":      ("verify_parameterised_queries",
                                  "verify_cookie_security_flags",
                                  "verify_hsts_header"),
    "excessive_disclosure":     ("verify_error_page_genericness",),
    "insecure_legacy_services": ("verify_hsts_header", "verify_tls_configuration"),
}


def defensive_action_ids_for_finding_type(finding_type: str) -> list[str]:
    """Aggregate defensive verification action_ids across all clusters of a finding type."""
    seen: list[str] = []
    for cluster in clusters_for_finding_type(finding_type):
        for aid in CLUSTER_TO_DEFENSIVE_ACTIONS.get(cluster.cluster_id, ()):
            if aid not in seen:
                seen.append(aid)
    return seen


def clusters_for_finding_type(finding_type: str) -> list[RootCauseCluster]:
    """Return all clusters this finding type belongs to (may be 0, 1, or more)."""
    return [c for c in CLUSTERS.values() if finding_type in c.finding_types]


def confidence_for_count(cluster: RootCauseCluster, finding_count: int) -> str | None:
    """Map a finding count to a confidence label, or None if below emerging."""
    if finding_count >= cluster.strong_threshold:
        return CONFIDENCE_STRONG
    if finding_count >= cluster.established_threshold:
        return CONFIDENCE_ESTABLISHED
    if finding_count >= cluster.emerging_threshold:
        return CONFIDENCE_EMERGING
    return None
