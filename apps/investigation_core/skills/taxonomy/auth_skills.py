"""Authentication weakness skill tree — beginner → intermediate → advanced."""

from apps.investigation_core.skills.models.skill import (
    EvidenceRequirement,
    Skill,
    SkillCategory,
    SkillDifficulty,
)

AUTH_SKILLS = [
    Skill(
        skill_id="auth_surface_enumeration",
        category=SkillCategory.AUTHENTICATION,
        title="Authentication Surface Enumeration",
        description=(
            "Systematically identify every authentication endpoint on a target: "
            "web forms, SSH, FTP, admin panels, API endpoints with credentials."
        ),
        difficulty=SkillDifficulty.BEGINNER,
        prerequisites=[],
        related_findings=[
            "auth_bypass",
            "weak_credentials",
            "default_credentials",
            "ssh_cred",
            "credential_exposure",
        ],
        related_learning_paths=["auth_beginner_01"],
        related_guided_actions=["auth_default_cred_test"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="note",
                minimum_count=1,
                description=(
                    "Inventory of all authentication surfaces: port, protocol, "
                    "service, and authentication type for each."
                ),
            ),
        ],
        remediation_concepts=[
            "Attack surface reduction: disable unnecessary authentication services.",
            "Network segmentation limits access to internal authentication endpoints.",
        ],
        wiki_link="Authentication Surface Enumeration",
    ),
    Skill(
        skill_id="auth_default_credentials",
        category=SkillCategory.AUTHENTICATION,
        title="Default Credential Testing",
        description=(
            "Test target services against vendor default and commonly-reused credential "
            "pairs to confirm weak authentication configuration."
        ),
        difficulty=SkillDifficulty.BEGINNER,
        prerequisites=["auth_surface_enumeration"],
        related_findings=["default_credentials", "weak_credentials", "ssh_cred"],
        related_learning_paths=["auth_beginner_01"],
        related_guided_actions=["auth_default_cred_test"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="http_response",
                minimum_count=1,
                description=(
                    "Server response showing successful authentication "
                    "with default credentials."
                ),
            ),
            EvidenceRequirement(
                artifact_type="note",
                minimum_count=1,
                description="List of credential pairs tested and outcomes.",
            ),
        ],
        remediation_concepts=[
            "Change all default credentials during initial system setup.",
            "Enforce minimum password complexity and length requirements.",
            "Implement account lockout after N failed attempts.",
        ],
        wiki_link="Default Credential Testing",
    ),
    Skill(
        skill_id="auth_session_security",
        category=SkillCategory.AUTHENTICATION,
        title="Session Token Security Analysis",
        description=(
            "Inspect session token transport and cookie security flags to identify "
            "weaknesses that enable session hijacking independent of password strength."
        ),
        difficulty=SkillDifficulty.INTERMEDIATE,
        prerequisites=["auth_surface_enumeration"],
        related_findings=["cleartext_transmission", "auth_bypass", "credential_exposure"],
        related_learning_paths=["auth_beginner_01"],
        related_guided_actions=["auth_session_analysis"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="http_response",
                minimum_count=1,
                description=(
                    "Set-Cookie header showing token flags "
                    "(Secure, HttpOnly, SameSite documented)."
                ),
            ),
        ],
        remediation_concepts=[
            "Set Secure flag to prevent cookie transmission over HTTP.",
            "Set HttpOnly flag to prevent JavaScript cookie access.",
            "Use SameSite=Strict to prevent CSRF-based token theft.",
            "Enforce HTTPS sitewide with HSTS.",
        ],
        wiki_link="Session Token Security",
    ),
    Skill(
        skill_id="auth_policy_analysis",
        category=SkillCategory.AUTHENTICATION,
        title="Password Policy Analysis",
        description=(
            "Test whether password complexity and length requirements are enforced "
            "server-side, identifying policies that permit trivially-guessable passwords."
        ),
        difficulty=SkillDifficulty.INTERMEDIATE,
        prerequisites=["auth_default_credentials"],
        related_findings=["weak_credentials", "auth_bypass"],
        related_learning_paths=["auth_beginner_01"],
        related_guided_actions=[],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="note",
                minimum_count=1,
                description=(
                    "Policy enforcement test results: minimum length, "
                    "complexity rules, server-side vs client-side enforcement."
                ),
            ),
            EvidenceRequirement(
                artifact_type="response_diff",
                minimum_count=1,
                description=(
                    "Server responses to weak-password registration attempts: "
                    "400 (enforced) vs 200 (bypassed)."
                ),
            ),
        ],
        remediation_concepts=[
            "Enforce password policy server-side — client-side enforcement is bypassable.",
            "Minimum 12 characters with mixed case, digits, and special characters.",
            "Consider passphrase policies over complex short passwords.",
        ],
        wiki_link="Password Policy Analysis",
    ),
    Skill(
        skill_id="auth_bypass_techniques",
        category=SkillCategory.AUTHENTICATION,
        title="Authentication Bypass Techniques",
        description=(
            "Combine understanding of credential weaknesses and session token flaws to "
            "demonstrate authentication bypass without valid credentials."
        ),
        difficulty=SkillDifficulty.ADVANCED,
        prerequisites=["auth_default_credentials", "auth_session_security"],
        related_findings=["auth_bypass", "default_credentials"],
        related_learning_paths=["auth_beginner_01"],
        related_guided_actions=["auth_default_cred_test", "auth_session_analysis"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="note",
                minimum_count=1,
                description=(
                    "Documented bypass technique: which weakness was exploited "
                    "and what access level was achieved."
                ),
            ),
            EvidenceRequirement(
                artifact_type="http_response",
                minimum_count=1,
                description=(
                    "HTTP response confirming authenticated access without valid credentials."
                ),
            ),
        ],
        remediation_concepts=[
            "Multi-factor authentication prevents most credential-based bypass.",
            "Combine strong passwords, session security, and rate limiting.",
            "Zero-trust architecture assumes breach and verifies every request.",
        ],
        wiki_link="Authentication Bypass",
    ),
]
