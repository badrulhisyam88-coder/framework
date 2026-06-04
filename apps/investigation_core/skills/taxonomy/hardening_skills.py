# ruff: noqa: E501
"""Defensive hardening skill tree — covers the finding types ZAP & Nuclei
commonly produce that have no specific exploit chain but inform defensive
posture: missing security headers, information disclosure, TLS weakness,
broken access control, and cleartext transmission.

These skills make the Skills / Actions / Learning tabs populated after a
typical web scan (which is otherwise dominated by these finding types).
"""

from apps.investigation_core.skills.models.skill import (
    EvidenceRequirement,
    Skill,
    SkillCategory,
    SkillDifficulty,
)

HARDENING_SKILLS = [
    Skill(
        skill_id="security_header_review",
        category=SkillCategory.HARDENING,
        title="Security Header Review",
        description=(
            "Identify which HTTP security headers are missing or misconfigured on "
            "a target (CSP, X-Frame-Options, HSTS, X-Content-Type-Options, "
            "Referrer-Policy, Permissions-Policy) and explain the protection each provides."
        ),
        difficulty=SkillDifficulty.BEGINNER,
        prerequisites=[],
        related_findings=[
            "security_misconfiguration",
            "information_disclosure",
        ],
        related_learning_paths=["web_hardening_beginner_01"],
        related_guided_actions=["security_headers_audit"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="note",
                minimum_count=1,
                description="Audit note: list of missing or weak headers with the protection each provides.",
            ),
            EvidenceRequirement(
                artifact_type="http_response",
                minimum_count=1,
                description="At least one captured response showing the header gap.",
            ),
        ],
        remediation_concepts=[
            "Content-Security-Policy restricts which sources can be loaded, mitigating XSS impact.",
            "X-Frame-Options or CSP frame-ancestors prevents clickjacking via iframe embedding.",
            "Strict-Transport-Security forces HTTPS and prevents downgrade attacks.",
            "Cookies should set HttpOnly (no JS access), Secure (HTTPS-only), and SameSite (CSRF defence).",
        ],
        wiki_link="Web Security Headers",
    ),
    Skill(
        skill_id="information_disclosure_assessment",
        category=SkillCategory.HARDENING,
        title="Information Disclosure Assessment",
        description=(
            "Determine what an application accidentally reveals about its internals: "
            "version banners, debug data, stack traces, internal paths, employee names "
            "in source comments, and configuration details. Assess how disclosed info "
            "enables further attacks."
        ),
        difficulty=SkillDifficulty.BEGINNER,
        prerequisites=[],
        related_findings=[
            "information_disclosure",
            "security_misconfiguration",
        ],
        related_learning_paths=["web_hardening_beginner_01"],
        related_guided_actions=["info_disclosure_inspect"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="note",
                minimum_count=1,
                description="Inventory of disclosed info: each leak + what it enables an attacker to do.",
            ),
        ],
        remediation_concepts=[
            "Disable verbose errors and stack traces in production builds.",
            "Strip version banners from HTTP headers (Server, X-Powered-By).",
            "Review source comments and removed code before deployment.",
            "Map every disclosed detail to a corresponding production hardening control.",
        ],
        wiki_link="Information Disclosure",
    ),
    Skill(
        skill_id="tls_configuration_review",
        category=SkillCategory.HARDENING,
        title="TLS Configuration Review",
        description=(
            "Assess the TLS posture of a target: protocol versions accepted, cipher suites, "
            "certificate validity, mixed content, and whether HTTP is offered alongside HTTPS. "
            "Map weaknesses to known attack techniques (BEAST, POODLE, SWEET32, downgrade)."
        ),
        difficulty=SkillDifficulty.BEGINNER,
        prerequisites=[],
        related_findings=[
            "tls_weakness",
            "ssl_weak",
            "cleartext_transmission",
            "http_only_site",
        ],
        related_learning_paths=["web_hardening_beginner_01"],
        related_guided_actions=["tls_config_audit"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="note",
                minimum_count=1,
                description="TLS audit note: supported protocols, ciphers, cert details, mixed-content findings.",
            ),
        ],
        remediation_concepts=[
            "Disable SSL 3.0 and TLS 1.0/1.1 — only TLS 1.2 and 1.3 are considered safe.",
            "Remove cipher suites with NULL, RC4, MD5, or 3DES.",
            "Use HSTS with includeSubDomains and a long max-age to lock clients to HTTPS.",
            "Redirect all HTTP traffic to HTTPS; never serve credentials over plain HTTP.",
        ],
        wiki_link="TLS Hardening",
    ),
    Skill(
        skill_id="access_control_validation",
        category=SkillCategory.HARDENING,
        title="Access Control Validation",
        description=(
            "Test whether the application enforces authorisation on every protected resource: "
            "horizontal access (one user accessing another user's data), vertical access "
            "(low-privilege user reaching admin endpoints), and direct object references."
        ),
        difficulty=SkillDifficulty.BEGINNER,
        prerequisites=[],
        related_findings=[
            "broken_access_control",
            "information_disclosure",
        ],
        related_learning_paths=["web_hardening_beginner_01"],
        related_guided_actions=["access_control_probe"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="note",
                minimum_count=1,
                description="Access-control audit note: each tested endpoint + result (enforced, bypassed, partial).",
            ),
            EvidenceRequirement(
                artifact_type="http_response",
                minimum_count=1,
                description="At least one captured response where authorisation was missing or weak.",
            ),
        ],
        remediation_concepts=[
            "Enforce authorisation on the server side for every protected resource — never rely on hidden UI controls.",
            "Use opaque identifiers (UUIDs) rather than sequential integers for sensitive objects.",
            "Validate the authenticated principal can access the requested resource on every request, not just on login.",
            "Apply the principle of least privilege — users get only the access they need.",
        ],
        wiki_link="Access Control",
    ),
]
