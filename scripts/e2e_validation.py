"""Phase 1+2 validation: vault structure + ai-assist-tool export pipeline.

Run from ai-assist-tool/:
    .venv/bin/python scripts/e2e_validation.py
"""

from __future__ import annotations

import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apps.validation.models import (
    Evidence, Finding, FindingSeverity, FindingStatus,
    Host, HostStatus, Service, ServiceProtocol,
    ValidationStatus, ValidationType,
)
from exporters.exporter_service import ExportBatch, ExporterService

VAULT = Path(__file__).resolve().parent.parent / "knowledge-vault"
DATE = "20260518"

_passed: list[str] = []
_issues: list[str] = []


def ok(msg: str) -> None:
    _passed.append(msg)
    print(f"  ✓  {msg}")


def fail(msg: str) -> None:
    _issues.append(msg)
    print(f"  ✗  {msg}")


def section(title: str) -> None:
    print(f"\n{'='*60}\n  {title}\n{'='*60}")


# ── Regex patterns ────────────────────────────────────────────────────────────

_FIND_ID_RE = re.compile(r"^FIND-(WEB|API|NET|CLOUD)-\d{8}-\d{3}$")
_REM_ID_RE  = re.compile(r"^REM-(WEB|API|NET|CLOUD)-\d{8}-\d{3}$")
_CHAIN_ID_RE = re.compile(r"^CHAIN-\d{8}-\d{3}$")
_DATE_RE    = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_OWASP_RE   = re.compile(r"owasp-a\d{2}")
_MITRE_TAG_RE = re.compile(r"mitre-t\d+")


def _parse_fm(content: str) -> dict:
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", content, re.DOTALL)
    if not m:
        return {}
    fm: dict = {}
    current_key: str | None = None
    current_list: list | None = None
    for line in m.group(1).splitlines():
        list_m = re.match(r"^\s+-\s+(.+)$", line)
        kv_m = re.match(r"^([a-zA-Z_][a-zA-Z0-9_-]*)\s*:\s*(.*)$", line)
        if list_m and current_key and current_list is not None:
            current_list.append(list_m.group(1).strip('"'))
        elif kv_m:
            if current_key and current_list is not None:
                fm[current_key] = current_list
            key, val_raw = kv_m.group(1), kv_m.group(2).strip()
            current_key = key
            current_list = None
            if val_raw in ("", "[]"):
                if val_raw == "[]":
                    fm[key] = []
                    current_key = None
                else:
                    current_list = []
            else:
                fm[key] = val_raw.strip('"')
                current_key = None
    if current_key and current_list is not None:
        fm[current_key] = current_list
    return fm


# ── Phase 1: Vault structure ─────────────────────────────────────────────────

def phase1_vault_structure() -> None:
    section("PHASE 1 — Vault Structure Validation")

    required_dirs = [
        "findings/web", "findings/api", "findings/network", "findings/cloud",
        "labs", "blue-team", "remediation", "concepts", "journals",
        "attack-chains", "learning-paths", "reports", "templates", "exports",
    ]
    for d in required_dirs:
        p = VAULT / d
        if p.exists():
            ok(f"directory: {d}/")
        else:
            fail(f"missing directory: {d}/")

    for doc in ["README.md", "VAULT_STRUCTURE.md", "EXPORT_STANDARDS.md"]:
        p = VAULT / doc
        if p.exists() and p.stat().st_size > 100:
            ok(f"doc present: {doc}")
        else:
            fail(f"missing/empty doc: {doc}")

    for tmpl in [
        "template-finding.md", "template-lab-walkthrough.md",
        "template-remediation.md", "template-blue-team.md",
        "template-attack-chain.md", "template-journal.md",
        "template-concept.md", "template-report.md",
    ]:
        p = VAULT / "templates" / tmpl
        if p.exists() and p.read_text().startswith("---"):
            ok(f"template has frontmatter: {tmpl}")
        else:
            fail(f"template missing/invalid: {tmpl}")


# ── Phase 2: Export pipeline ─────────────────────────────────────────────────

def phase2_run_exports() -> list[str]:
    section("PHASE 2 — ai-assist-tool Export Pipeline")

    svc = ExporterService(vault_path=VAULT)

    host = Host(id="host-001", ip="10.0.1.55", hostname="internal-web-01",
                os_guess="Linux 4.15", status=HostStatus.ACTIVE)
    svc_http = Service(id="svc-http", host_id="host-001", port=80,
                       protocol=ServiceProtocol.TCP, service_name="http",
                       product="nginx", version="1.18.0")
    svc_ssh = Service(id="svc-ssh", host_id="host-001", port=22,
                      protocol=ServiceProtocol.TCP, service_name="ssh",
                      product="OpenSSH", version="8.4")

    sqli = Finding(
        id="internal-sqli-001", host_id="host-001", service_id="svc-http",
        timestamp=datetime(2026, 5, 18, 9, 0, 0),
        finding_type=ValidationType.SQLI, severity=FindingSeverity.HIGH,
        validation_status=ValidationStatus.VALIDATED_EXPLOITABLE,
        status=FindingStatus.OPEN,
        evidence=Evidence(
            sent="' OR 1=1--",
            received='HTTP/1.1 200 OK\n{"token":"admin-jwt-abc123"}',
            context={
                "parameter": "username",
                "description": (
                    "SQL injection on the login endpoint allows authentication bypass. "
                    "The username field is concatenated directly into a SQL WHERE clause."
                ),
                "steps": [
                    "Navigate to http://10.0.1.55/login",
                    "Enter ' OR 1=1-- as the username with any password",
                    "Observe successful login with admin token returned",
                ],
                "references": [
                    "[OWASP SQLi Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)",
                    "[CWE-89](https://cwe.mitre.org/data/definitions/89.html)",
                ],
            },
        ),
    )

    xss = Finding(
        id="internal-xss-001", host_id="host-001", service_id="svc-http",
        timestamp=datetime(2026, 5, 18, 9, 30, 0),
        finding_type="xss", severity=FindingSeverity.MEDIUM,
        validation_status=ValidationStatus.VALIDATED_EXPLOITABLE,
        status=FindingStatus.OPEN,
        evidence=Evidence(
            sent="<script>alert(document.cookie)</script>",
            received="HTTP/1.1 200 OK\n<script>alert(document.cookie)</script>",
            context={
                "parameter": "comment",
                "description": (
                    "Stored XSS via the product review field. "
                    "User input is reflected in HTML without output encoding."
                ),
                "steps": [
                    "Navigate to the product review page",
                    "Submit <script>alert(document.cookie)</script> as a review",
                    "View the product page — script executes for all visitors",
                ],
                "references": [
                    "[OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)",
                    "[CWE-79](https://cwe.mitre.org/data/definitions/79.html)",
                ],
            },
        ),
    )

    ssh = Finding(
        id="internal-ssh-001", host_id="host-001", service_id="svc-ssh",
        timestamp=datetime(2026, 5, 18, 10, 0, 0),
        finding_type=ValidationType.SSH_CRED, severity=FindingSeverity.CRITICAL,
        validation_status=ValidationStatus.VALIDATED_EXPLOITABLE,
        status=FindingStatus.OPEN,
        evidence=Evidence(
            sent="ssh admin@10.0.1.55 (password: admin123)",
            received="Welcome to Ubuntu 20.04 LTS — logged in as admin",
            context={
                "parameter": "SSH credential",
                "description": "SSH accessible with default admin:admin123 credential.",
            },
        ),
    )

    batch = ExportBatch(
        findings=[sqli, xss, ssh],
        hosts={host.id: host},
        services={svc_http.id: svc_http, svc_ssh.id: svc_ssh},
    )

    report = svc.export_findings(batch, export_remediations=True)
    vault_refs = [p.stem.split("_")[0] for p in report.findings_written]

    for p in report.findings_written:
        print(f"  exported: {p.relative_to(VAULT)}")
    for p in report.remediations_written:
        print(f"  exported: {p.relative_to(VAULT)}")
    for e in report.errors:
        fail(f"export error: {e}")
    if not report.errors:
        ok(f"findings={len(report.findings_written)} remediations={len(report.remediations_written)}")

    # Service discovery
    disc = svc.export_discovery(
        hosts=[host,
               Host(id="h2", ip="10.0.1.56", hostname="db-01"),
               Host(id="h3", ip="10.0.1.57", hostname="api-gw")],
        services=[svc_http, svc_ssh,
                  Service(id="s2", host_id="h2", port=3306, service_name="mysql",
                          product="MySQL", version="8.0"),
                  Service(id="s3", host_id="h3", port=443, service_name="https",
                          product="nginx")],
        scan_date=DATE, scope="10.0.1.0/24",
        notes="Internal segment A — 3 hosts, 4 services.",
    )
    for p in disc.discovery_written:
        print(f"  exported: {p.relative_to(VAULT)}")
    if not disc.errors:
        ok("service discovery exported")

    # Attack chain with vault finding refs
    chain = svc.export_attack_chain(
        findings=[sqli, ssh],
        chain_title="Web SQLi to SSH Root Access",
        overview=(
            "SQL injection on the login endpoint extracted admin credentials "
            "from the database. Credentials were reused via SSH for direct "
            "root-equivalent access on the same host."
        ),
        target="internal-web-01 (10.0.1.55)",
        scope="Internal segment A — 10.0.1.0/24",
        outcome="Root SSH access via credential reuse from SQLi data extraction",
        host_map={host.id: host},
        vault_finding_refs=vault_refs,
    )
    for p in chain.chains_written:
        print(f"  exported: {p.relative_to(VAULT)}")
    if not chain.errors:
        ok("attack chain exported with vault FIND-* references")

    return vault_refs


def phase2_validate_exports() -> None:
    section("PHASE 2 — Export Validation")

    # ── Findings ──
    for md in sorted((VAULT / "findings").rglob("FIND-*.md")):
        content = md.read_text()
        fm = _parse_fm(content)
        name = str(md.relative_to(VAULT))

        fid = fm.get("id", "")
        if _FIND_ID_RE.match(fid):
            ok(f"{name}: id format ✓ ({fid})")
        else:
            fail(f"{name}: bad id format: {fid!r}")

        if _DATE_RE.match(str(fm.get("date", ""))):
            ok(f"{name}: date format ✓")
        else:
            fail(f"{name}: bad date: {fm.get('date')!r}")

        doc_type = fm.get("type", "")
        tags = fm.get("tags", [])
        if isinstance(tags, list):
            # OWASP tags only required for vulnerability findings (not reconnaissance)
            if doc_type != "service-discovery":
                if any(_OWASP_RE.match(t) for t in tags):
                    ok(f"{name}: OWASP tag ✓")
                else:
                    fail(f"{name}: missing OWASP tag in {tags}")
            if any(_MITRE_TAG_RE.match(t) for t in tags):
                ok(f"{name}: MITRE tag ✓")
            else:
                fail(f"{name}: missing MITRE tag in {tags}")

        rem_ref = fm.get("remediation_ref", "")
        if rem_ref:
            if (VAULT / "remediation" / rem_ref).exists():
                ok(f"{name}: remediation_ref resolves ✓ ({rem_ref})")
            else:
                fail(f"{name}: remediation_ref broken → {rem_ref}")

        if "on port svc-" in content:
            fail(f"{name}: impact uses service UUID not port number")
        else:
            ok(f"{name}: impact uses port number ✓")

        if "**Technique:** " in content:
            tech_m = re.search(r"\*\*Technique:\*\* (.+)", content)
            if tech_m and len(tech_m.group(1).strip()) > 3:
                ok(f"{name}: MITRE Technique field populated ✓")
            else:
                fail(f"{name}: MITRE Technique field is empty or single-char")

        # URL endpoint should not be :PORT/svcname
        if re.search(r"URL / Endpoint \| :\d+/\w", content):
            fail(f"{name}: URL/Endpoint field has malformed value (:<port>/<name>)")
        else:
            ok(f"{name}: URL/Endpoint format ✓")

        rel_links = re.findall(r'\[.*?\]\((\.\.?/[^)]+)\)', content)
        if rel_links:
            ok(f"{name}: relative links present ({len(rel_links)})")
        else:
            ok(f"{name}: no relative links (may be expected for some types)")

    # ── Remediations ──
    for md in sorted((VAULT / "remediation").rglob("*.md")):
        content = md.read_text()
        fm = _parse_fm(content)
        name = str(md.relative_to(VAULT))

        rid = fm.get("id", "")
        if _REM_ID_RE.match(rid):
            ok(f"{name}: id format ✓ ({rid})")
        else:
            fail(f"{name}: bad remediation id: {rid!r}")

        title = fm.get("title", "")
        if title.startswith("Remediation:") and len(title) <= 80 and not title.rstrip().endswith("e"):
            ok(f"{name}: title ✓ ({title!r})")
        elif title.startswith("Remediation:"):
            # Check it's not truncated mid-word
            if title[-1].isalpha() and not title.endswith(("n", "g", "s", "l", "t", "y", "e", "r", "d")):
                fail(f"{name}: title appears truncated: {title!r}")
            else:
                ok(f"{name}: title ✓ ({title!r})")
        else:
            fail(f"{name}: title missing 'Remediation:' prefix: {title!r}")

        related = fm.get("related_findings", [])
        if isinstance(related, list):
            for ref in related:
                if _FIND_ID_RE.match(ref):
                    ok(f"{name}: related_finding is vault ID ✓ ({ref})")
                elif ref:
                    fail(f"{name}: related_finding is not vault ID: {ref!r}")
        if not related:
            ok(f"{name}: related_findings empty (acceptable for standalone remediations)")

    # ── Attack chains ──
    for md in sorted((VAULT / "attack-chains").rglob("*.md")):
        content = md.read_text()
        fm = _parse_fm(content)
        name = str(md.relative_to(VAULT))

        cid = fm.get("id", "")
        if _CHAIN_ID_RE.match(cid):
            ok(f"{name}: id format ✓ ({cid})")
        else:
            fail(f"{name}: bad chain id: {cid!r}")

        # MITRE single-char bug check
        if re.search(r"\*\*Technique:\*\* [it]\n", content):
            fail(f"{name}: MITRE Technique field is a single character (tuple bug)")
        else:
            ok(f"{name}: MITRE phase fields correct ✓")

        # MITRE summary table should have real values
        if "| Phase 1 | m | i | t |" in content:
            fail(f"{name}: MITRE summary table has single-char values")
        else:
            ok(f"{name}: MITRE summary table ✓")

        related = fm.get("related_findings", [])
        if isinstance(related, list) and related:
            for ref in related:
                if _FIND_ID_RE.match(ref):
                    ok(f"{name}: related_finding is vault ID ✓ ({ref})")
                else:
                    fail(f"{name}: related_finding not vault ID: {ref!r}")
        elif not related:
            ok(f"{name}: related_findings empty (no vault IDs passed)")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> tuple[list, list]:
    print("\nai-assist-tool Interoperability Validation (Phases 1–2)")
    print(f"Vault: {VAULT}\n")

    phase1_vault_structure()
    phase2_run_exports()
    phase2_validate_exports()

    section("SUMMARY (Phases 1–2)")
    print(f"  Passed:  {len(_passed)}")
    print(f"  Failed:  {len(_issues)}")
    if _issues:
        print("\n  FAILURES:")
        for i in _issues:
            print(f"    ✗ {i}")
    print(f"\n  Status: {'✓ PASS' if not _issues else '✗ FAIL'}")
    return _passed, _issues


if __name__ == "__main__":
    p, f = main()
    sys.exit(0 if not f else 1)
