"""XSS skill tree — beginner → intermediate → advanced."""

from apps.investigation_core.skills.models.skill import (
    EvidenceRequirement,
    Skill,
    SkillCategory,
    SkillDifficulty,
)

XSS_SKILLS = [
    Skill(
        skill_id="xss_fundamentals",
        category=SkillCategory.XSS,
        title="XSS Fundamentals",
        description=(
            "Understand how cross-site scripting occurs and identify where user input "
            "is reflected in HTML responses without encoding."
        ),
        difficulty=SkillDifficulty.BEGINNER,
        prerequisites=[],
        related_findings=["xss", "reflected_xss", "xss_reflected", "stored_xss", "xss_stored"],
        related_learning_paths=["xss_beginner_01"],
        related_guided_actions=["xss_reflection_probe"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="http_response",
                minimum_count=1,
                description="Page source showing probe string reflected without HTML encoding.",
            ),
        ],
        remediation_concepts=[
            "XSS occurs when user input reaches HTML output without encoding.",
            "Input sanitisation alone is insufficient — output encoding is required.",
            "The correct encoding depends on the HTML context (body, attribute, JS).",
        ],
        wiki_link="XSS Fundamentals",
    ),
    Skill(
        skill_id="xss_context_analysis",
        category=SkillCategory.XSS,
        title="HTML Context Analysis",
        description=(
            "Determine the precise HTML context where input is reflected "
            "(tag body, attribute, JavaScript string, CSS) to select an appropriate payload."
        ),
        difficulty=SkillDifficulty.BEGINNER,
        prerequisites=["xss_fundamentals"],
        related_findings=["xss", "reflected_xss"],
        related_learning_paths=["xss_beginner_01"],
        related_guided_actions=["xss_reflection_probe"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="note",
                minimum_count=1,
                description=(
                    "Documentation of the reflection context with surrounding HTML structure."
                ),
            ),
            EvidenceRequirement(
                artifact_type="http_response",
                minimum_count=1,
                description="Page source with reflection context highlighted/noted.",
            ),
        ],
        remediation_concepts=[
            "Each HTML context requires different encoding: entity encoding, "
            "JS escaping, URL encoding.",
            "Template engine auto-escaping must be context-aware.",
        ],
        wiki_link="XSS Context Analysis",
    ),
    Skill(
        skill_id="xss_execution_proof",
        category=SkillCategory.XSS,
        title="JavaScript Execution Proof",
        description=(
            "Confirm JavaScript execution in the target origin using alert(document.domain) "
            "as the standard benign proof of XSS exploitability."
        ),
        difficulty=SkillDifficulty.INTERMEDIATE,
        prerequisites=["xss_context_analysis"],
        related_findings=["xss", "reflected_xss", "stored_xss"],
        related_learning_paths=["xss_beginner_01"],
        related_guided_actions=["xss_execution_confirm"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="screenshot",
                minimum_count=1,
                description=(
                    "Browser screenshot showing alert dialogue with document.domain."
                ),
            ),
        ],
        remediation_concepts=[
            "Confirmed JS execution means an attacker can steal cookies, "
            "redirect users, or modify page content.",
            "HttpOnly cookies mitigate cookie theft but not all XSS impacts.",
        ],
        wiki_link="XSS Execution Proof",
    ),
    Skill(
        skill_id="xss_impact_assessment",
        category=SkillCategory.XSS,
        title="XSS Impact Assessment",
        description=(
            "Assess the real-world impact of the XSS vulnerability: who is affected, "
            "what data is accessible, and how the CVSS score should be rated."
        ),
        difficulty=SkillDifficulty.INTERMEDIATE,
        prerequisites=["xss_execution_proof"],
        related_findings=["xss", "stored_xss"],
        related_learning_paths=["xss_beginner_01"],
        related_guided_actions=[],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="note",
                minimum_count=1,
                description=(
                    "Impact assessment: roles affected, auth context, "
                    "HttpOnly cookie status, stored vs reflected."
                ),
            ),
        ],
        remediation_concepts=[
            "Stored XSS is critical — it affects every user who views the page.",
            "Reflected XSS requires social engineering to deliver the payload.",
            "CSP (Content Security Policy) can reduce but not eliminate XSS impact.",
        ],
        wiki_link="XSS Impact Assessment",
    ),
    Skill(
        skill_id="xss_stored_exploitation",
        category=SkillCategory.XSS,
        title="Stored XSS Persistence",
        description=(
            "Demonstrate stored XSS where the payload persists server-side and executes "
            "for every user who views the affected page."
        ),
        difficulty=SkillDifficulty.ADVANCED,
        prerequisites=["xss_execution_proof"],
        related_findings=["stored_xss", "xss_stored"],
        related_learning_paths=[],
        related_guided_actions=["xss_execution_confirm"],
        evidence_requirements=[
            EvidenceRequirement(
                artifact_type="http_response",
                minimum_count=1,
                description=(
                    "Response showing stored payload present after page reload "
                    "without the crafted URL."
                ),
            ),
            EvidenceRequirement(
                artifact_type="note",
                minimum_count=1,
                description="Persistence confirmation: payload survives across sessions.",
            ),
        ],
        remediation_concepts=[
            "Stored XSS requires sanitisation at both input and output.",
            "Markdown/rich-text editors require allowlist-based HTML sanitisation.",
            "DOMPurify is the recommended client-side sanitisation library.",
        ],
        wiki_link="Stored XSS",
    ),
]
