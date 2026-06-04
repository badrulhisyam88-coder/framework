"""Tests for V2.7 vault_writer module.

Covers:
- _next_finding_id sequence generation (empty vault → 001, existing → 002)
- export_finding: writes markdown with correct frontmatter
- export_finding: returns None when vault not mounted
- _search_vault_by_tags: returns matches from a real vault entry
- _search_vault_by_tags: returns [] when vault not mounted
- vault_embedder: graceful fallback when chromadb unavailable
"""
from __future__ import annotations

import asyncio
import importlib
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _reload_vault_writer(vault_path: Path):
    """Reload vault_writer with a patched VAULT_PATH."""
    import apps.conductor.qwen.vault_writer as vw
    vw.VAULT_PATH = vault_path
    return vw


def _reload_context_builder(vault_path: Path):
    """Reload context_builder with a patched _VAULT_PATH."""
    import apps.conductor.qwen.context_builder as cb
    cb._VAULT_PATH = vault_path
    return cb


# ── Tests: _next_finding_id ───────────────────────────────────────────────────

def test_next_finding_id_starts_at_001_with_empty_vault(tmp_path):
    """Empty findings/web/ dir → returns 001."""
    findings_dir = tmp_path / "findings" / "web"
    findings_dir.mkdir(parents=True)

    vw = _reload_vault_writer(tmp_path)

    date_str = "20261201"
    result = vw._next_finding_id(date_str)
    assert result == f"FIND-WEB-{date_str}-001"


def test_next_finding_id_increments_from_existing(tmp_path):
    """One existing FIND-WEB-YYYYMMDD-001_*.md → returns 002."""
    findings_dir = tmp_path / "findings" / "web"
    findings_dir.mkdir(parents=True)

    date_str = "20261201"
    # Create a fake existing file
    (findings_dir / f"FIND-WEB-{date_str}-001_sqli_auth_bypass.md").write_text("---\ntype: finding\n---\n")

    vw = _reload_vault_writer(tmp_path)
    result = vw._next_finding_id(date_str)
    assert result == f"FIND-WEB-{date_str}-002"


def test_next_finding_id_ignores_different_dates(tmp_path):
    """Files from a different date don't affect the sequence."""
    findings_dir = tmp_path / "findings" / "web"
    findings_dir.mkdir(parents=True)

    (findings_dir / "FIND-WEB-20261130-001_sqli.md").write_text("---\ntype: finding\n---\n")

    vw = _reload_vault_writer(tmp_path)
    date_str = "20261201"
    result = vw._next_finding_id(date_str)
    assert result == f"FIND-WEB-{date_str}-001"


# ── Tests: export_finding ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_export_finding_writes_markdown_file(tmp_path):
    """export_finding with credential_brute artifact writes correct markdown."""
    vw = _reload_vault_writer(tmp_path)
    # Create findings/web/ dir
    (tmp_path / "findings" / "web").mkdir(parents=True)

    artifact = {
        "artifact_type": "captured_credentials",
        "username": "admin",
        "password": "password123",
        "endpoint": "http://target.example.com/login",
    }

    result = await vw.export_finding(
        investigation_id="test-inv-001",
        engine_id="credential_brute",
        finding_type="brute_force",
        target_url="http://target.example.com",
        artifact=artifact,
        branch_id="exb_abc123",
    )

    assert result is not None
    assert result.exists()
    assert result.suffix == ".md"
    assert "credential_brute" in result.name

    content = result.read_text()

    # Frontmatter checks
    assert "type: finding" in content
    assert "FIND-WEB-" in content
    assert "auth-bypass" in content or "brute-force" in content  # tags present
    assert "owasp-a07" in content
    assert "source: ai-assist" in content
    assert "status: confirmed" in content
    assert "http://target.example.com" in content

    # Body checks
    assert "## Summary" in content
    assert "## Proof of Concept" in content
    assert "## MITRE ATT&CK Mapping" in content
    assert "T1110" in content


@pytest.mark.asyncio
async def test_export_finding_returns_none_when_vault_not_mounted():
    """VAULT_PATH = /nonexistent → returns None, no exception."""
    import apps.conductor.qwen.vault_writer as vw
    vw.VAULT_PATH = Path("/nonexistent/path/that/does/not/exist")

    result = await vw.export_finding(
        investigation_id="test-inv-002",
        engine_id="sqli_auth_bypass",
        finding_type="sqli",
        target_url="http://target.example.com",
        artifact={"artifact_type": "auth_bypass"},
        branch_id="exb_xyz789",
    )

    assert result is None


@pytest.mark.asyncio
async def test_export_finding_truncates_sensitive_values(tmp_path):
    """Sensitive fields (password, token) are truncated in the output."""
    vw = _reload_vault_writer(tmp_path)
    (tmp_path / "findings" / "web").mkdir(parents=True)

    artifact = {
        "artifact_type": "captured_credentials",
        "username": "admin",
        "password": "supersecretpassword123",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.longtoken",
    }

    result = await vw.export_finding(
        investigation_id="test-inv-003",
        engine_id="credential_brute",
        finding_type="brute_force",
        target_url="http://target.example.com",
        artifact=artifact,
        branch_id="exb_def456",
    )

    assert result is not None
    content = result.read_text()

    # Full sensitive values must not appear
    assert "supersecretpassword123" not in content
    # Truncated form must appear
    assert "supersec..." in content


# ── Tests: export_lab_walkthrough ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_export_lab_walkthrough_writes_file(tmp_path):
    """export_lab_walkthrough writes a lab walkthrough markdown."""
    vw = _reload_vault_writer(tmp_path)
    (tmp_path / "labs").mkdir(parents=True)

    findings = [
        {"finding_type": "sqli", "title": "SQL Injection", "severity": "high", "endpoint": "/login"},
    ]
    succeeded = [
        {"engine_id": "sqli_auth_bypass", "artifact": {"artifact_type": "auth_bypass", "endpoint": "/login"}},
    ]

    result = await vw.export_lab_walkthrough(
        investigation_id="test-inv-lab-001",
        target_url="http://target.example.com",
        findings=findings,
        succeeded_branches=succeeded,
    )

    assert result is not None
    assert result.exists()
    content = result.read_text()
    assert "type: lab-walkthrough" in content
    assert "LAB-PORTSWIGGER-" in content
    assert "sqli_auth_bypass" in content


@pytest.mark.asyncio
async def test_export_lab_walkthrough_returns_none_when_vault_not_mounted():
    """Vault not mounted → returns None."""
    import apps.conductor.qwen.vault_writer as vw
    vw.VAULT_PATH = Path("/nonexistent/vault/path")

    result = await vw.export_lab_walkthrough(
        investigation_id="test-inv-lab-002",
        target_url="http://target.example.com",
        findings=[],
        succeeded_branches=[],
    )

    assert result is None


# ── Tests: _search_vault_by_tags ──────────────────────────────────────────────

def test_search_vault_by_tags_returns_matches(tmp_path):
    """Write a minimal vault finding with sqli tag → _search_vault_by_tags returns it."""
    findings_dir = tmp_path / "findings" / "web"
    findings_dir.mkdir(parents=True)

    # Write a minimal finding with sqli tag
    finding_content = """\
---
type: finding
id: FIND-WEB-20261201-001
title: SQL Injection Test
date: "2026-12-01"
severity: high
category: web
source: ai-assist
platform: real-world
target: test-target
status: confirmed
tags:
  - sqli
  - auth-bypass
  - owasp-a03
related_labs: []
related_concepts: []
related_findings: []
remediation_ref: ""
---

# SQL Injection Test

## Summary

> SQL injection on the login endpoint allows authentication bypass.
"""
    (findings_dir / "FIND-WEB-20261201-001_sqli.md").write_text(finding_content)

    cb = _reload_context_builder(tmp_path)
    results = cb._search_vault_by_tags(["sqli"])

    assert len(results) >= 1
    ids = [r["id"] for r in results]
    assert "FIND-WEB-20261201-001" in ids

    # Check outcome hint is extracted from Summary
    hit = next(r for r in results if r["id"] == "FIND-WEB-20261201-001")
    assert "auth bypass" in hit.get("outcome_hint", "").lower() or "sql injection" in hit.get("outcome_hint", "").lower()


def test_search_vault_by_tags_returns_empty_when_vault_not_mounted():
    """VAULT_PATH = /nonexistent → returns [], no exception."""
    import apps.conductor.qwen.context_builder as cb
    cb._VAULT_PATH = Path("/nonexistent/vault")

    results = cb._search_vault_by_tags(["sqli", "auth-bypass"])
    assert results == []


def test_search_vault_by_tags_returns_empty_with_no_overlap(tmp_path):
    """Finding with non-matching tags → not returned."""
    findings_dir = tmp_path / "findings" / "web"
    findings_dir.mkdir(parents=True)

    finding_content = """\
---
type: finding
id: FIND-WEB-20261201-002
title: Unrelated Finding
date: "2026-12-01"
severity: info
category: web
source: ai-assist
platform: real-world
target: test-target
status: confirmed
tags:
  - ssl-misconfiguration
  - info
related_labs: []
related_concepts: []
related_findings: []
remediation_ref: ""
---

# Unrelated Finding

## Summary

> SSL certificate misconfiguration.
"""
    (findings_dir / "FIND-WEB-20261201-002_ssl.md").write_text(finding_content)

    cb = _reload_context_builder(tmp_path)
    results = cb._search_vault_by_tags(["sqli"])

    # Should not return the SSL finding
    ids = [r["id"] for r in results]
    assert "FIND-WEB-20261201-002" not in ids


# ── Tests: vault_embedder fallback ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_vault_embedder_falls_back_on_chromadb_unavailable():
    """Mock chromadb import to raise ImportError → search_vault_semantic returns []."""
    import apps.conductor.qwen.vault_embedder as ve
    # Reset cached state
    ve._chromadb_available = None

    with patch.dict(sys.modules, {"chromadb": None}):
        # Force re-evaluation of chromadb availability
        ve._chromadb_available = None

        # Patch the import inside _check_chromadb
        original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        import builtins
        original_builtin_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "chromadb":
                raise ImportError("chromadb not installed")
            return original_builtin_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            ve._chromadb_available = None  # force re-check
            result = ve._check_chromadb()
            assert result is False

        # search_vault_semantic must not raise
        ve._chromadb_available = False
        results = await ve.search_vault_semantic("sqli auth bypass", top_k=3)
        assert isinstance(results, list)  # returns [] or tfidf results, never raises


@pytest.mark.asyncio
async def test_vault_embedder_search_returns_empty_when_vault_not_mounted():
    """Vault not mounted → search_vault_semantic returns []."""
    import apps.conductor.qwen.vault_embedder as ve
    ve.VAULT_PATH = Path("/nonexistent/vault")
    ve._chromadb_available = False  # force tfidf path

    results = await ve.search_vault_semantic("sqli auth bypass", top_k=3)
    assert results == []
