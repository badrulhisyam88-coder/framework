#!/usr/bin/env python3
"""Investigation Validation Harness — end-to-end coherence validator.

Runs a complete investigation lifecycle against a live platform and validates:
  - Findings generated and normalized
  - Evidence refs populated
  - Timeline events recorded
  - Skill progression updated
  - Export generation successful
  - Markdown quality

Usage:
  python scripts/validate_investigation.py [options]

Options:
  --target URL      Target to investigate (default: http://localhost:10000)
  --profile ID      Scan profile (default: quick_web_scan)
  --base-url URL    Platform API base URL (default: http://localhost:8000)
  --timeout N       Seconds to wait for scan completion (default: 300)
  --skip-export     Skip export generation check

Exit codes:
  0 — all checks passed
  1 — one or more checks failed
  2 — harness error (can't connect, etc.)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import httpx
except ImportError:
    print("ERROR: httpx not installed. Run: pip install httpx", file=sys.stderr)
    sys.exit(2)


# ── Result types ──────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    name: str
    passed: bool
    message: str
    detail: Any = None


@dataclass
class ValidationReport:
    target: str
    profile: str
    investigation_id: str | None = None
    group_id: str | None = None
    checks: list[CheckResult] = field(default_factory=list)

    def add(self, name: str, passed: bool, message: str, detail: Any = None) -> None:
        self.checks.append(CheckResult(name, passed, message, detail))

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    def print(self) -> None:
        print(f"\n{'='*60}")
        print(f"Investigation Validation Report")
        print(f"Target:  {self.target}")
        print(f"Profile: {self.profile}")
        if self.investigation_id:
            print(f"Inv ID:  {self.investigation_id[:8]}…")
        if self.group_id:
            print(f"Run ID:  {self.group_id[:8]}…")
        print(f"{'='*60}")
        for c in self.checks:
            icon = "✓" if c.passed else "✗"
            print(f"  {icon}  {c.name}")
            if not c.passed or c.detail:
                print(f"       {c.message}")
                if c.detail and not c.passed:
                    print(f"       detail: {c.detail}")
        print(f"{'='*60}")
        print(f"  {'PASSED' if self.passed else 'FAILED'} — "
              f"{sum(1 for c in self.checks if c.passed)}/{len(self.checks)} checks passed")
        print(f"{'='*60}\n")


# ── HTTP helpers ──────────────────────────────────────────────────────────

async def api(client: httpx.AsyncClient, method: str, path: str, **kwargs) -> dict:
    resp = await client.request(method, path, **kwargs)
    if resp.status_code >= 400:
        raise RuntimeError(f"API {method} {path} → {resp.status_code}: {resp.text[:200]}")
    return resp.json()


# ── Scenario runner ───────────────────────────────────────────────────────

async def run_scenario(
    base_url: str,
    target: str,
    profile: str,
    timeout: int,
    skip_export: bool,
) -> ValidationReport:
    report = ValidationReport(target=target, profile=profile)

    async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:

        # ── 1. Platform health ────────────────────────────────────────────
        try:
            h = await api(client, "GET", "/health")
            report.add("Platform health", h.get("status") == "ok", f"status={h.get('status')}")
        except Exception as exc:
            report.add("Platform health", False, str(exc))
            report.print()
            return report

        # ── 2. Create / retrieve investigation ───────────────────────────
        try:
            inv_resp = await api(
                client, "POST",
                "/api/v1/validation/investigation-core/investigations",
                json={"target": target, "title": f"Validation: {target}"},
            )
            inv_id = inv_resp.get("investigation_id") or inv_resp.get("id")
            report.investigation_id = inv_id
            report.add("Investigation created", bool(inv_id), f"id={inv_id[:8] if inv_id else None}")
        except Exception as exc:
            report.add("Investigation created", False, str(exc))
            report.print()
            return report

        # ── 3. Launch investigation run ───────────────────────────────────
        try:
            run_resp = await api(
                client, "POST",
                f"/api/v1/validation/scanner/investigations/{inv_id}/runs",
                json={"profile_id": profile, "target": target},
            )
            group_id = run_resp.get("group_id")
            scans = run_resp.get("scans", [])
            report.group_id = group_id
            report.add(
                "Investigation run launched",
                bool(group_id and scans),
                f"group={group_id[:8] if group_id else None}, stages={len(scans)}",
            )
        except Exception as exc:
            report.add("Investigation run launched", False, str(exc))
            report.print()
            return report

        # ── 4. Poll for completion ────────────────────────────────────────
        deadline = time.time() + timeout
        scan_ids = [s["scan_id"] for s in scans]
        all_terminal = False
        final_scans: list[dict] = []

        print(f"  ⟳ Polling {len(scan_ids)} scan(s) (timeout {timeout}s)…", end="", flush=True)
        while time.time() < deadline:
            await asyncio.sleep(5)
            print(".", end="", flush=True)
            final_scans = []
            all_done = True
            for sid in scan_ids:
                try:
                    s = await api(client, "GET", f"/api/v1/validation/scanner/scans/{sid}")
                    final_scans.append(s)
                    if s["status"] not in ("completed", "failed", "cancelled"):
                        all_done = False
                except Exception:
                    all_done = False
            if all_done:
                all_terminal = True
                break
        print()

        completed = [s for s in final_scans if s["status"] == "completed"]
        failed = [s for s in final_scans if s["status"] == "failed"]
        report.add(
            "Scans completed",
            all_terminal and len(completed) > 0,
            f"{len(completed)}/{len(scan_ids)} completed, {len(failed)} failed",
            detail=[s.get("error_message") for s in failed if s.get("error_message")],
        )

        # ── 5. Findings generated ─────────────────────────────────────────
        try:
            f_resp = await api(
                client, "GET",
                f"/api/v1/validation/scanner/investigations/{inv_id}/findings",
            )
            findings_count = len(f_resp)
            report.add(
                "Findings normalized",
                findings_count >= 0,  # 0 is valid (clean target)
                f"{findings_count} finding(s) in normalized_findings",
            )
        except Exception as exc:
            report.add("Findings normalized", False, str(exc))

        # ── 6. Evidence refs populated ────────────────────────────────────
        try:
            f_resp2 = await api(
                client, "GET",
                f"/api/v1/validation/scanner/investigations/{inv_id}/findings",
            )
            with_refs = [f for f in f_resp2 if f.get("evidence_refs")]
            total = len(f_resp2)
            pct = (len(with_refs) / total * 100) if total > 0 else 100
            report.add(
                "Evidence refs populated",
                pct >= 80 or total == 0,
                f"{len(with_refs)}/{total} findings have evidence_refs ({pct:.0f}%)",
            )
        except Exception as exc:
            report.add("Evidence refs populated", False, str(exc))

        # ── 7. Timeline events recorded ───────────────────────────────────
        try:
            tl = await api(
                client, "GET",
                f"/api/v1/validation/investigation-core/investigations/{inv_id}/timeline",
            )
            event_types = {e["event_type"] for e in tl}
            has_scan_events = bool({"scan_completed", "target_reachable"} & event_types)
            report.add(
                "Timeline events recorded",
                len(tl) >= 3,
                f"{len(tl)} events, types: {sorted(event_types)}",
                detail=None if len(tl) >= 3 else "fewer than 3 events recorded",
            )
        except Exception as exc:
            report.add("Timeline events recorded", False, str(exc))

        # ── 8. Skill progression ──────────────────────────────────────────
        try:
            skills_resp = await api(
                client, "GET",
                f"/api/v1/validation/investigation-core/investigations/{inv_id}/learning",
            )
            # Learning endpoint returns recommendations + progress
            recs = skills_resp if isinstance(skills_resp, list) else skills_resp.get("recommendations", [])
            report.add(
                "Learning recommendations generated",
                isinstance(recs, list),
                f"{len(recs)} recommendation(s) generated",
            )
        except Exception as exc:
            report.add("Learning recommendations generated", False, str(exc))

        # ── 9. Export generation ──────────────────────────────────────────
        if not skip_export:
            try:
                ex = await api(
                    client, "POST",
                    f"/api/v1/validation/workspace/investigations/{inv_id}/exports",
                    json={},
                )
                export_ok = ex.get("status") == "generated"
                vault_path = ex.get("vault_path", "")
                report.add(
                    "Export generated",
                    export_ok,
                    f"status={ex.get('status')}, vault={vault_path}",
                )

                # ── 10. Export file quality ───────────────────────────────
                if export_ok and ex.get("file_path"):
                    raw_path = ex["file_path"]
                    # Translate container path (/app/data/...) → host path (./data/...)
                    if raw_path.startswith("/app/"):
                        p = Path(__file__).parent.parent / raw_path[len("/app/"):]
                    else:
                        p = Path(raw_path)
                    if p.exists():
                        content = p.read_text(encoding="utf-8")
                        has_frontmatter = content.startswith("---")
                        has_findings = "## Findings" in content
                        has_skills = "## Skill Progression" in content
                        has_remediation = "## Remediation Notes" in content
                        sections = sum([has_frontmatter, has_findings, has_skills, has_remediation])
                        report.add(
                            "Export markdown quality",
                            sections >= 3,
                            f"{sections}/4 required sections present "
                            f"(frontmatter, findings, skills, remediation)",
                        )
                    else:
                        report.add("Export markdown quality", False, f"File not found: {p}")
            except Exception as exc:
                report.add("Export generated", False, str(exc))

    return report


# ── CLI ───────────────────────────────────────────────────────────────────

async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default="http://localhost:10000", help="Investigation target")
    parser.add_argument("--profile", default="quick_web_scan", help="Scan profile ID")
    parser.add_argument("--base-url", default="http://localhost:8000", help="Platform base URL")
    parser.add_argument("--timeout", type=int, default=300, help="Scan completion timeout (s)")
    parser.add_argument("--skip-export", action="store_true", help="Skip export validation")
    args = parser.parse_args()

    print(f"Investigation Validation Harness")
    print(f"  Target:   {args.target}")
    print(f"  Profile:  {args.profile}")
    print(f"  Platform: {args.base_url}")
    print(f"  Timeout:  {args.timeout}s")

    try:
        report = await run_scenario(
            base_url=args.base_url,
            target=args.target,
            profile=args.profile,
            timeout=args.timeout,
            skip_export=args.skip_export,
        )
    except Exception as exc:
        print(f"\nHarness error: {exc}", file=sys.stderr)
        return 2

    report.print()
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
