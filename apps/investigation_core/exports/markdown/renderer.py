"""MarkdownRenderer — renders investigation exports using Jinja2 templates."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from apps.investigation_core.models.investigation import Investigation
from apps.investigation_core.progression.models.mastery import SkillMastery
from apps.investigation_core.skills.graph.skill_graph import skill_graph
from apps.investigation_core.taxonomy.stages import STAGE_LABELS

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
_TEMPLATE_NAME = "investigation_report.md.j2"

# Tags derived from skill categories
_CATEGORY_TAGS: dict[str, str] = {
    "sql_injection": "sql-injection",
    "xss": "xss",
    "authentication": "authentication",
    "network": "network",
    "fundamentals": "fundamentals",
}


class MarkdownRenderer:
    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            undefined=StrictUndefined,
            autoescape=False,  # markdown, not HTML
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )

    def render(
        self,
        investigation: Investigation,
        target: str,
        *,
        findings: list[Any],
        evidence: list[Any],
        mastery_records: list[SkillMastery],
        completed_path_objects: list[Any],
        active_path_objects: list[Any],
        completed_action_objects: list[Any],
        timeline_events: list[Any],
        themes: list[Any] | None = None,
        theme_cross_links: dict[str, list[Any]] | None = None,
    ) -> str:
        skills_by_id = {s.skill_id: s for s in skill_graph.all_skills()}

        # Tags
        tags = ["investigation"]
        skill_categories: set[str] = set()
        for m in mastery_records:
            skill = skills_by_id.get(m.skill_id)
            if skill:
                skill_categories.add(str(skill.category))
        for cat in skill_categories:
            tag = _CATEGORY_TAGS.get(cat, cat)
            if tag not in tags:
                tags.append(tag)
        # Finding-type tags
        finding_type_tags: set[str] = {
            f.finding_type.lower().replace("_", "-")
            for f in findings
            if hasattr(f, "finding_type")
        }
        tags.extend(sorted(finding_type_tags)[:5])

        # Skills unlocked / mastered
        skills_unlocked = [
            m.skill_id for m in mastery_records
            if str(m.status) in ("available", "in_progress", "completed", "mastered")
        ]
        skills_mastered = [
            m.skill_id for m in mastery_records
            if str(m.status) == "mastered"
        ]

        # Exploitable findings
        exploitable_findings = [
            f for f in findings
            if hasattr(f, "validation_status")
            and str(f.validation_status) == "validated_exploitable"
        ]

        # Normalised findings rows for template.
        # Supports both legacy Finding (has .service.port) and NormalizedFinding (has .port).
        finding_rows = []
        for f in findings:
            # Port: NormalizedFinding stores port directly; legacy Finding via .service
            if getattr(f, "port", None) is not None:
                port = str(f.port)
            elif getattr(f, "service", None) is not None and f.service:
                port = str(f.service.port)
            else:
                port = "—"

            # Severity: may be a StrEnum (.value) or a plain string
            raw_sev = getattr(f, "severity", "unknown")
            severity = raw_sev.value if hasattr(raw_sev, "value") else str(raw_sev)

            # Endpoint: NormalizedFinding has .endpoint; legacy does not
            endpoint = getattr(f, "endpoint", None) or ""

            # CVE enrichment from NormalizedFinding.raw_data (if available)
            raw_data = getattr(f, "raw_data", {}) or {}
            cve_info = raw_data.get("cve_enrichment", {})
            max_cvss = cve_info.get("max_cvss")

            finding_rows.append({
                "severity": severity,
                "finding_type": getattr(f, "finding_type", "unknown"),
                "port": port,
                "endpoint": endpoint,
                "validation_status": str(getattr(f, "validation_status", "—")),
                "status": str(getattr(f, "status", "—")),
                "max_cvss": f"{max_cvss:.1f}" if max_cvss else "",
                "related_cves": getattr(f, "related_cves", []),
            })

        # Remediation concepts from mastered/completed skills
        remediation: list[str] = []
        seen_concepts: set[str] = set()
        for m in mastery_records:
            if str(m.status) in ("completed", "mastered"):
                skill = skills_by_id.get(m.skill_id)
                if skill:
                    for concept in skill.remediation_concepts:
                        if concept not in seen_concepts:
                            seen_concepts.add(concept)
                            remediation.append(concept)

        # Timeline highlights — milestones and meaningful investigation events.
        # Scan-level lifecycle events included for narrative continuity.
        important_types = {
            # Investigation milestones
            "finding_detected", "finding_validated", "evidence_captured",
            "guided_action_completed", "skill_unlocked", "skill_mastered",
            "knowledge_exported",
            # Scan lifecycle (investigation narrative context)
            "target_reachable", "target_fingerprinted", "target_unreachable",
            "scan_completed", "scan_failed", "findings_normalized",
        }
        highlights = [
            e for e in timeline_events
            if str(getattr(e, "event_type", "")) in important_types
        ][:25]

        # Related wiki links from completed skills
        wiki_links: list[str] = []
        for m in mastery_records:
            skill = skills_by_id.get(m.skill_id)
            if skill and str(m.status) in ("completed", "mastered"):
                if skill.wiki_link and skill.wiki_link not in wiki_links:
                    wiki_links.append(skill.wiki_link)

        # Summary text
        exploitable_count = len(exploitable_findings)
        mastered_count = len(skills_mastered)
        summary_text = (
            f"This investigation of `{target}` identified {len(findings)} finding(s)"
        )
        if exploitable_count:
            summary_text += f", {exploitable_count} confirmed exploitable"
        if mastered_count:
            summary_text += f". {mastered_count} skill(s) mastered"
        summary_text += "."

        # Theme + cross-link view-models for the markdown template
        themes = themes or []
        theme_cross_links = theme_cross_links or {}
        theme_rows = [
            {
                "label": t.label,
                "wikilink": f"Theme — {t.label}",
                "confidence": t.confidence,
                "matching_finding_count": t.matching_finding_count,
                "matching_finding_types": t.matching_finding_types,
                "remediation_concepts": t.remediation_concepts,
                "remediation_documented": t.remediation_documented,
                "why": t.why,
                "description": t.description,
                "cross_links": [
                    {
                        "investigation_id": cl.investigation_id,
                        "title": cl.title,
                        "matching_finding_count": cl.matching_finding_count,
                    }
                    for cl in theme_cross_links.get(t.theme_id, [])
                ],
            }
            for t in themes
        ]

        # Add theme tags
        for t in themes:
            tag = f"theme-{t.theme_id.replace('_', '-')}"
            if tag not in tags:
                tags.append(tag)

        template = self._env.get_template(_TEMPLATE_NAME)
        return template.render(
            investigation=investigation,
            target=target,
            export_date=datetime.utcnow().strftime("%Y-%m-%d"),
            tags=tags,
            stage_label=STAGE_LABELS.get(
                str(investigation.workflow_stage), str(investigation.workflow_stage)
            ),
            findings=finding_rows,
            exploitable_findings=exploitable_findings,
            evidence=evidence,
            mastery_records=mastery_records,
            skills_by_id=skills_by_id,
            skills_unlocked=skills_unlocked,
            skills_mastered=skills_mastered,
            completed_paths=completed_path_objects,
            active_paths=active_path_objects,
            completed_actions=completed_action_objects,
            timeline_highlights=highlights,
            remediation_concepts=remediation,
            related_wiki_links=wiki_links,
            summary_text=summary_text,
            themes=theme_rows,
        )
