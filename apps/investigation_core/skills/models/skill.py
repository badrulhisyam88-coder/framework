"""Skill domain model — a node in the skill dependency graph."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class SkillCategory(StrEnum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    FUNDAMENTALS = "fundamentals"
    HARDENING = "hardening"      # security headers, TLS, info disclosure, access control


class SkillDifficulty(StrEnum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"


DIFFICULTY_ORDER: dict[str, int] = {
    SkillDifficulty.BEGINNER: 0,
    SkillDifficulty.INTERMEDIATE: 1,
    SkillDifficulty.ADVANCED: 2,
}

CATEGORY_LABELS: dict[str, str] = {
    SkillCategory.SQL_INJECTION: "SQL Injection",
    SkillCategory.XSS: "Cross-Site Scripting",
    SkillCategory.AUTHENTICATION: "Authentication",
    SkillCategory.NETWORK: "Network",
    SkillCategory.FUNDAMENTALS: "Fundamentals",
    SkillCategory.HARDENING: "Defensive Hardening",
}


class EvidenceRequirement(BaseModel):
    """Minimum evidence artifacts required to demonstrate mastery."""
    artifact_type: str     # matches ArtifactType string values
    minimum_count: int = 1
    description: str = ""  # what this evidence should show


class Skill(BaseModel):
    skill_id: str
    category: SkillCategory
    title: str
    description: str
    difficulty: SkillDifficulty
    prerequisites: list[str] = Field(default_factory=list)  # skill_ids

    # Connections to other subsystems
    related_findings: list[str] = Field(default_factory=list)      # finding_type strings
    related_learning_paths: list[str] = Field(default_factory=list)  # path_ids
    related_guided_actions: list[str] = Field(default_factory=list)  # action_ids

    # What evidence demonstrates mastery
    evidence_requirements: list[EvidenceRequirement] = Field(default_factory=list)

    # Defensive understanding — what the learner should know about prevention
    remediation_concepts: list[str] = Field(default_factory=list)

    # Obsidian wiki-link label (defaults to title)
    wiki_link: str = ""

    def model_post_init(self, __context: object) -> None:
        if not self.wiki_link:
            object.__setattr__(self, "wiki_link", self.title)
