"""Relative markdown link generation between vault folders.

All paths are relative to the vault root using POSIX separators so that
Obsidian, NotebookLM, and plain-text tools all resolve them correctly.
"""

from __future__ import annotations

import os
from pathlib import PurePosixPath

# ---------------------------------------------------------------------------
# Vault folder slugs (relative to vault root)
# ---------------------------------------------------------------------------

FOLDER_FINDINGS_WEB = "findings/web"
FOLDER_FINDINGS_API = "findings/api"
FOLDER_FINDINGS_NETWORK = "findings/network"
FOLDER_FINDINGS_CLOUD = "findings/cloud"
FOLDER_REMEDIATION = "remediation"
FOLDER_ATTACK_CHAINS = "attack-chains"
FOLDER_CONCEPTS = "concepts"
FOLDER_LABS = "labs"
FOLDER_BLUE_TEAM = "blue-team"
FOLDER_LEARNING_PATHS = "learning-paths"
FOLDER_JOURNALS = "journals"

_CATEGORY_TO_FOLDER = {
    "web": FOLDER_FINDINGS_WEB,
    "api": FOLDER_FINDINGS_API,
    "network": FOLDER_FINDINGS_NETWORK,
    "cloud": FOLDER_FINDINGS_CLOUD,
}


def _relative(from_folder: str, to_folder: str, filename: str) -> str:
    """Compute a POSIX relative path from one vault folder to a file in another."""
    from_path = PurePosixPath(from_folder) / "_placeholder.md"
    to_path = PurePosixPath(to_folder) / filename
    rel = os.path.relpath(str(to_path), str(from_path.parent))
    return PurePosixPath(rel).as_posix()


# ---------------------------------------------------------------------------
# Public link builders — return markdown link strings
# ---------------------------------------------------------------------------


def finding_to_remediation(
    finding_category: str,
    remediation_filename: str,
    link_text: str,
) -> str:
    """Return a relative markdown link from a finding to a remediation file."""
    src_folder = _CATEGORY_TO_FOLDER.get(finding_category, FOLDER_FINDINGS_WEB)
    rel = _relative(src_folder, FOLDER_REMEDIATION, remediation_filename)
    return f"[{link_text}]({rel})"


def finding_to_concept(
    finding_category: str,
    concept_filename: str,
    link_text: str,
) -> str:
    """Return a relative markdown link from a finding to a concept file."""
    src_folder = _CATEGORY_TO_FOLDER.get(finding_category, FOLDER_FINDINGS_WEB)
    rel = _relative(src_folder, FOLDER_CONCEPTS, concept_filename)
    return f"[{link_text}]({rel})"


def finding_to_lab(
    finding_category: str,
    lab_filename: str,
    link_text: str,
) -> str:
    """Return a relative markdown link from a finding to a lab walkthrough."""
    src_folder = _CATEGORY_TO_FOLDER.get(finding_category, FOLDER_FINDINGS_WEB)
    rel = _relative(src_folder, FOLDER_LABS, lab_filename)
    return f"[{link_text}]({rel})"


def chain_to_finding(
    finding_category: str,
    finding_filename: str,
    link_text: str,
) -> str:
    """Return a relative markdown link from an attack chain to a finding."""
    src_folder = FOLDER_ATTACK_CHAINS
    dest_folder = _CATEGORY_TO_FOLDER.get(finding_category, FOLDER_FINDINGS_WEB)
    rel = _relative(src_folder, dest_folder, finding_filename)
    return f"[{link_text}]({rel})"


def lab_to_finding(
    finding_category: str,
    finding_filename: str,
    link_text: str,
) -> str:
    """Return a relative markdown link from a lab walkthrough to a finding."""
    rel = _relative(
        FOLDER_LABS,
        _CATEGORY_TO_FOLDER.get(finding_category, FOLDER_FINDINGS_WEB),
        finding_filename,
    )
    return f"[{link_text}]({rel})"


def lab_to_remediation(
    remediation_filename: str,
    link_text: str,
) -> str:
    rel = _relative(FOLDER_LABS, FOLDER_REMEDIATION, remediation_filename)
    return f"[{link_text}]({rel})"


def blue_team_to_finding(
    finding_category: str,
    finding_filename: str,
    link_text: str,
) -> str:
    rel = _relative(
        FOLDER_BLUE_TEAM,
        _CATEGORY_TO_FOLDER.get(finding_category, FOLDER_FINDINGS_WEB),
        finding_filename,
    )
    return f"[{link_text}]({rel})"


def wikilink(slug: str) -> str:
    """Return an Obsidian-style wikilink (strip .md extension)."""
    if slug.endswith(".md"):
        slug = slug[:-3]
    return f"[[{slug}]]"
