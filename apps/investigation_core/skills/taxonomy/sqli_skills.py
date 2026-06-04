"""SQL Injection skill tree — beginner → intermediate → advanced."""

from apps.investigation_core.skills.models.skill import (
    EvidenceRequirement,
    Skill,
    SkillCategory,
    SkillDifficulty,
)

SQLI_SKILLS = [
    Skill(
        skill_id="sqli_fundamentals",
        category=SkillCategory.SQL_INJECTION,
        title="SQL Injection Fundamentals",
        description=(
            "Understand why SQL injection occurs and how to identify vulnerable parameters "
            "using basic single-quote and error-observation techniques."
        ),
        difficulty=SkillDifficulty.BEGINNER,
        prerequisites=[],
        related_findings=["sqli", "sql_injection", "sqli_error_based", "sqli_blind"],
        related_learning_paths=["sqli_beginner_01"],
        related_guided_actions=["sqli_injection_probe"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="payload_attempt",
                minimum_count=1,
                description="Single-quote payload with observed server response change.",
            ),
            EvidenceRequirement(
                artifact_type="http_response",
                minimum_count=1,
                description="Server response showing database error or changed output.",
            ),
        ],
        remediation_concepts=[
            "Parameterised queries prevent SQL injection at the database layer.",
            "User input must never be concatenated into SQL strings.",
            "Stored procedures do not protect against injection unless also parameterised.",
        ],
        wiki_link="SQL Injection Fundamentals",
    ),
    Skill(
        skill_id="sqli_boolean_testing",
        category=SkillCategory.SQL_INJECTION,
        title="Boolean-Based Confirmation",
        description=(
            "Confirm SQL injection by demonstrating a reliable true/false response "
            "difference, ruling out false positives from generic error handling."
        ),
        difficulty=SkillDifficulty.BEGINNER,
        prerequisites=["sqli_fundamentals"],
        related_findings=["sqli", "sql_injection"],
        related_learning_paths=["sqli_beginner_01"],
        related_guided_actions=["sqli_boolean_confirmation"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="response_diff",
                minimum_count=1,
                description=(
                    "Side-by-side comparison of true-condition (AND 1=1) and "
                    "false-condition (AND 1=2) responses."
                ),
            ),
        ],
        remediation_concepts=[
            "Boolean injection bypasses input filters that only block error-producing payloads.",
            "Prepared statements are immune to boolean injection.",
        ],
        wiki_link="Boolean SQL Injection",
    ),
    Skill(
        skill_id="sqli_union_extraction",
        category=SkillCategory.SQL_INJECTION,
        title="UNION-Based Data Extraction",
        description=(
            "Use UNION SELECT to extract database metadata — version, schema, table names — "
            "as the standard non-destructive proof of data extraction capability."
        ),
        difficulty=SkillDifficulty.INTERMEDIATE,
        prerequisites=["sqli_fundamentals", "sqli_boolean_testing"],
        related_findings=["sqli", "sql_injection", "sqli_error_based"],
        related_learning_paths=["sqli_beginner_01"],
        related_guided_actions=["sqli_version_extraction"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="http_response",
                minimum_count=1,
                description="Response body containing extracted database version string.",
            ),
            EvidenceRequirement(
                artifact_type="terminal_output",
                minimum_count=1,
                description="Column enumeration steps (ORDER BY results).",
            ),
        ],
        remediation_concepts=[
            "UNION injection is only possible when output is reflected in the response.",
            "Column count and data type matching are required for UNION to work.",
            "Parameterised queries prevent UNION injection entirely.",
        ],
        wiki_link="UNION SQL Injection",
    ),
    Skill(
        skill_id="sqli_auth_bypass",
        category=SkillCategory.SQL_INJECTION,
        title="Authentication Bypass via SQL Injection",
        description=(
            "Demonstrate how SQL injection in a login form allows bypassing authentication "
            "without valid credentials, using classic payloads like ' OR '1'='1."
        ),
        difficulty=SkillDifficulty.INTERMEDIATE,
        prerequisites=["sqli_fundamentals"],
        related_findings=["sqli", "sql_injection", "auth_bypass"],
        related_learning_paths=["sqli_beginner_01"],
        related_guided_actions=["sqli_injection_probe"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="note",
                minimum_count=1,
                description="Description of authentication bypass and access level achieved.",
            ),
            EvidenceRequirement(
                artifact_type="http_response",
                minimum_count=1,
                description="HTTP response showing authenticated state without valid credentials.",
            ),
        ],
        remediation_concepts=[
            "Authentication queries must use parameterised statements.",
            "Do not construct WHERE clauses from user-supplied username/password strings.",
        ],
        wiki_link="SQLi Authentication Bypass",
    ),
    Skill(
        skill_id="sqli_blind_techniques",
        category=SkillCategory.SQL_INJECTION,
        title="Blind SQL Injection Techniques",
        description=(
            "Identify and exploit SQL injection when no data is directly returned in the "
            "response — using time-based or inference-based techniques."
        ),
        difficulty=SkillDifficulty.ADVANCED,
        prerequisites=["sqli_union_extraction", "sqli_boolean_testing"],
        related_findings=["sqli_blind", "sqli"],
        related_learning_paths=[],
        related_guided_actions=[],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="response_diff",
                minimum_count=2,
                description="Multiple response comparisons demonstrating blind inference.",
            ),
            EvidenceRequirement(
                artifact_type="note",
                minimum_count=1,
                description="Documentation of the blind injection methodology used.",
            ),
        ],
        remediation_concepts=[
            "Blind injection is harder to detect but equally exploitable.",
            "Time-based injection (SLEEP/WAITFOR) works even when no data is reflected.",
            "Parameterised queries prevent all blind injection variants.",
        ],
        wiki_link="Blind SQL Injection",
    ),
]
