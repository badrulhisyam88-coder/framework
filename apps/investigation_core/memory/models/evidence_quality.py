"""Evidence quality scoring — deterministic, explainable, no AI."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ArtifactQualityScore:
    """Per-artifact quality assessment with traceable strengths and weaknesses."""
    evidence_id: str
    artifact_type: str
    score: int                     # 0–100
    strengths: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)

    @property
    def grade(self) -> str:
        if self.score >= 80:
            return "strong"
        if self.score >= 55:
            return "adequate"
        if self.score >= 30:
            return "thin"
        return "weak"


@dataclass
class EvidenceQualitySnapshot:
    """Aggregate quality summary across all evidence in an investigation."""
    total_artifacts: int = 0
    overall_score: int = 0           # 0–100, weighted average across artifacts
    by_type_avg: dict[str, int] = field(default_factory=dict)
    strong_types: list[str] = field(default_factory=list)
    weak_types: list[str] = field(default_factory=list)
    type_diversity: int = 0          # distinct artifact_type count
    reasons: list[str] = field(default_factory=list)
    per_artifact: list[ArtifactQualityScore] = field(default_factory=list)

    @property
    def grade(self) -> str:
        if self.overall_score >= 80:
            return "strong"
        if self.overall_score >= 55:
            return "adequate"
        if self.overall_score >= 30:
            return "thin"
        return "weak"
