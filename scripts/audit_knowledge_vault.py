#!/usr/bin/env python3
"""Knowledge Vault Quality Auditor.

Reads investigation exports from the knowledge vault and produces a
structured quality report: YAML frontmatter completeness, wiki-link presence,
section coverage, Obsidian compatibility, and NotebookLM usefulness signal.

Usage:
  python scripts/audit_knowledge_vault.py [--vault-path PATH] [--verbose]

Options:
  --vault-path PATH  Path to knowledge-vault root (default: auto-detect)
  --verbose          Show per-file detail

Exit codes:
  0 — all exports meet quality threshold
  1 — some exports below threshold
  2 — vault not found or no exports
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Quality thresholds ─────────────────────────────────────────────────────

REQUIRED_FRONTMATTER_KEYS = {"title", "date", "tags", "target", "stage", "investigation_id"}
REQUIRED_SECTIONS = {"## Summary", "## Findings", "## Evidence Captured", "## Skill Progression", "## Remediation Notes"}
MIN_WIKI_LINKS = 0          # 0 = OK if no skills mastered yet
QUALITY_PASS_THRESHOLD = 60  # out of 100


# ── Report types ───────────────────────────────────────────────────────────

@dataclass
class FileQuality:
    path: Path
    score: int = 0
    frontmatter_keys: set[str] = field(default_factory=set)
    missing_frontmatter: set[str] = field(default_factory=set)
    sections_present: set[str] = field(default_factory=set)
    missing_sections: set[str] = field(default_factory=set)
    wiki_link_count: int = 0
    tag_count: int = 0
    findings_count: int = 0
    has_remediation: bool = False
    issues: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.score >= QUALITY_PASS_THRESHOLD


# ── Frontmatter parser ──────────────────────────────────────────────────────

def _parse_frontmatter(content: str) -> dict[str, Any]:
    if not content.startswith("---"):
        return {}
    end = content.find("\n---", 3)
    if end == -1:
        return {}
    fm_text = content[3:end].strip()
    keys: dict[str, Any] = {}
    current_key = None
    current_list: list[str] = []
    for line in fm_text.splitlines():
        if line.startswith("  - "):  # list item
            if current_list is not None:
                current_list.append(line.strip("- ").strip())
        elif ": " in line and not line.startswith(" "):
            if current_key and current_list:
                keys[current_key] = current_list
            k, _, v = line.partition(": ")
            current_key = k.strip()
            v = v.strip()
            if v:
                keys[current_key] = v
                current_list = None
            else:
                current_list = []
                keys[current_key] = current_list
        elif line.endswith(":") and not line.startswith(" "):
            if current_key and current_list:
                keys[current_key] = current_list
            current_key = line.rstrip(":").strip()
            current_list = []
            keys[current_key] = current_list
    return keys


def audit_file(path: Path) -> FileQuality:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as e:
        q = FileQuality(path=path, score=0)
        q.issues.append(f"Cannot read file: {e}")
        return q

    q = FileQuality(path=path)
    score = 0

    # Frontmatter (25 pts)
    fm = _parse_frontmatter(content)
    q.frontmatter_keys = set(fm.keys())
    q.missing_frontmatter = REQUIRED_FRONTMATTER_KEYS - q.frontmatter_keys
    fm_score = int((len(REQUIRED_FRONTMATTER_KEYS) - len(q.missing_frontmatter))
                   / len(REQUIRED_FRONTMATTER_KEYS) * 25)
    score += fm_score
    if q.missing_frontmatter:
        q.issues.append(f"Missing frontmatter: {', '.join(sorted(q.missing_frontmatter))}")

    # Tags (10 pts)
    tags = fm.get("tags", [])
    if isinstance(tags, list):
        q.tag_count = len(tags)
        if q.tag_count >= 3:
            score += 10
        elif q.tag_count >= 1:
            score += 5
        else:
            q.issues.append("No tags in frontmatter")
    else:
        q.tag_count = 1 if tags else 0

    # Required sections (30 pts — 6 pts each)
    for section in REQUIRED_SECTIONS:
        if section in content:
            q.sections_present.add(section)
            score += 6
        else:
            q.missing_sections.add(section)
    if q.missing_sections:
        q.issues.append(f"Missing sections: {', '.join(sorted(q.missing_sections))}")

    # Wiki-links (15 pts)
    wikilinks = re.findall(r"\[\[([^\]]+)\]\]", content)
    q.wiki_link_count = len(wikilinks)
    if q.wiki_link_count >= 3:
        score += 15
    elif q.wiki_link_count >= 1:
        score += 8
    else:
        if "## Skill Progression" in content and "No skill mastery recorded" not in content:
            q.issues.append("No wiki-links despite skill progression section")

    # Findings table (10 pts)
    findings_rows = re.findall(r"^\| .+ \|$", content, re.MULTILINE)
    q.findings_count = max(0, len(findings_rows) - 2)  # subtract header + separator
    if q.findings_count > 0:
        score += 10
    else:
        if "No findings recorded" not in content:
            q.issues.append("Findings table appears empty or missing")

    # Remediation present (10 pts)
    if "## Remediation Notes" in content and "No remediation concepts" not in content:
        q.has_remediation = True
        score += 10

    q.score = min(score, 100)
    return q


def find_vault_root() -> Path | None:
    """Auto-detect vault root from environment or default location."""
    env = os.environ.get("KNOWLEDGE_VAULT_PATH")
    if env:
        p = Path(env).resolve()
        if p.exists():
            return p
    # Default: sibling of ai-assist-tool repo
    candidates = [
        Path(__file__).parent.parent / "knowledge-vault",
        Path.home() / "projects" / "conductor-framework" / "knowledge-vault",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--vault-path", help="Path to knowledge-vault root")
    parser.add_argument("--verbose", action="store_true", help="Show per-file detail")
    args = parser.parse_args()

    if args.vault_path:
        vault = Path(args.vault_path)
    else:
        vault = find_vault_root()

    if not vault or not vault.exists():
        print("ERROR: knowledge-vault not found. Use --vault-path or set KNOWLEDGE_VAULT_PATH.", file=sys.stderr)
        return 2

    inv_dir = vault / "investigations"
    if not inv_dir.exists():
        print(f"No investigations directory in vault: {vault}", file=sys.stderr)
        return 2

    exports = sorted(inv_dir.rglob("*.md"))
    if not exports:
        print(f"No markdown exports found in {inv_dir}")
        return 2

    print(f"\nKnowledge Vault Quality Audit")
    print(f"  Vault:   {vault}")
    print(f"  Exports: {len(exports)} file(s)\n")

    results: list[FileQuality] = []
    for p in exports:
        q = audit_file(p)
        results.append(q)

        if args.verbose or not q.passed:
            icon = "✓" if q.passed else "✗"
            print(f"  {icon} {p.relative_to(vault)}  [score: {q.score}/100]")
            if args.verbose or not q.passed:
                print(f"      tags={q.tag_count}  wiki-links={q.wiki_link_count}  "
                      f"findings={q.findings_count}  remediation={'yes' if q.has_remediation else 'no'}")
                for issue in q.issues:
                    print(f"      ⚠ {issue}")

    # Aggregate report
    passed = [q for q in results if q.passed]
    avg_score = sum(q.score for q in results) / len(results) if results else 0
    total_wiki = sum(q.wiki_link_count for q in results)
    total_findings = sum(q.findings_count for q in results)

    print(f"\n  {'='*50}")
    print(f"  Aggregate Quality Report")
    print(f"  {'='*50}")
    print(f"  Files audited:      {len(results)}")
    print(f"  Passing (≥{QUALITY_PASS_THRESHOLD}/100):  {len(passed)}/{len(results)}")
    print(f"  Average score:      {avg_score:.0f}/100")
    print(f"  Total wiki-links:   {total_wiki}")
    print(f"  Total findings:     {total_findings}")

    # Obsidian quality signal
    if total_wiki >= len(results) * 2:
        print(f"  Obsidian graph:     ✓ Good link density ({total_wiki} links across {len(results)} docs)")
    elif total_wiki > 0:
        print(f"  Obsidian graph:     ⚠ Low link density ({total_wiki} links) — skill mastery needed")
    else:
        print(f"  Obsidian graph:     ✗ No wiki-links — no skill progression recorded yet")

    # NotebookLM usefulness signal
    if avg_score >= 75 and total_findings > 0:
        print(f"  NotebookLM signal:  ✓ Exports contain structured findings + remediation — good synthesis material")
    elif avg_score >= 50:
        print(f"  NotebookLM signal:  ⚠ Partial structure — some exports may lack context for synthesis")
    else:
        print(f"  NotebookLM signal:  ✗ Incomplete exports — synthesis quality will be low")

    print(f"  {'='*50}\n")

    return 0 if len(passed) == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
