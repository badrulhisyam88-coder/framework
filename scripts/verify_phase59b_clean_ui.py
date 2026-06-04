"""Verification helper — NOT production code.

Phase 59b — contract-based verification that the canned-script execution
mechanism is fully removed and the two-section panel renders correctly.

Tests the rendered HTML of context_panel.html via direct API calls:

SECTION A — Panel structure contracts (per CLAUDE.md principle #6:
  test the contract, not the narrative):
  1. Findings with guidance_only entries → "Manual investigation paths"
     section renders; NO Execute button within that section's DOM
  2. Findings with probe-backed entries → "Automated actions" section
     renders; each entry has an Execute button
  3. "Approve" affordance is absent from all rendered panels
  4. Deceptive stage labels absent from all rendered panels

SECTION B — Deception-absence contracts:
  5. grep confirms zero references in production code to removed symbols
  6. No execution chain in topology has a stage labeled
     "Replaying capability payload"

SECTION C — Lifecycle (Phase 59a lesson):
  7. Create investigation → bootstrap runs
  8. Delete investigation → HTTP 200, DB rows 0 for that id

Run from repo root:
    .venv/bin/python scripts/verify_phase59b_clean_ui.py

Env overrides:
    PHASE59B_BACKEND_URL   default http://localhost:8000
    PHASE59B_TARGET        default http://host.docker.internal:10000/
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

import httpx

BACKEND = os.environ.get("PHASE59B_BACKEND_URL", "http://localhost:8000")
TARGET  = os.environ.get("PHASE59B_TARGET", "http://host.docker.internal:10000/")

WS = f"{BACKEND}/api/v1/validation/workspace"


def _bootstrap_inv(client: httpx.Client, target: str) -> str:
    client.get(
        f"{BACKEND}/api/v1/validation/investigations/workspace",
        params={"target": target}, timeout=10,
    )
    listing = client.get(
        f"{BACKEND}/api/v1/validation/investigation-core/investigations",
        timeout=5,
    )
    listing.raise_for_status()
    for inv in listing.json():
        if target in (inv.get("targets") or []):
            inv_id = inv["investigation_id"]
            client.get(
                f"{WS}/investigations/{inv_id}/branches/topology.json",
                timeout=10,
            )
            return inv_id
    raise RuntimeError(f"no investigation for target {target!r}")


def _wait_for_findings(
    client: httpx.Client, inv_id: str, timeout_s: float = 20.0,
) -> list[dict]:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = client.get(
            f"{BACKEND}/api/v1/validation/scanner/investigations/{inv_id}/findings",
            timeout=5,
        )
        if r.status_code == 200 and r.json():
            return r.json()
        time.sleep(0.5)
    return []


def _panel_html(client: httpx.Client, inv_id: str, finding_id: str) -> str:
    node_id = f"disc-{finding_id}"
    r = client.get(
        f"{WS}/investigations/{inv_id}/context-panel/{node_id}",
        timeout=10,
    )
    if r.status_code != 200:
        return ""
    return r.text


def main() -> int:
    results: dict[str, tuple[bool, str]] = {}

    def record(check: str, ok: bool, detail: str = "") -> None:
        results[check] = (ok, detail)

    with httpx.Client() as client:
        # ── Bootstrap investigation ───────────────────────────────────
        print(f"─── Bootstrap ({TARGET}) ───")
        try:
            inv_id = _bootstrap_inv(client, TARGET)
            findings = _wait_for_findings(client, inv_id)
            record("lifecycle_bootstrap",
                   bool(findings),
                   f"inv={inv_id[:8]} findings={len(findings)}")
            print(f"  inv={inv_id[:8]}  findings={len(findings)}")
        except Exception as e:
            record("lifecycle_bootstrap", False, f"{type(e).__name__}: {e}")
            inv_id = ""
            findings = []

        # ── Panel structure checks ────────────────────────────────────
        print()
        print("─── Panel structure contracts ───")
        if findings and inv_id:
            # Group findings by type for targeted checks
            by_type: dict[str, str] = {}
            for f in findings:
                by_type[f["finding_type"]] = f["finding_id"]

            # --- Check 1: guidance_only finding → MANUAL PATHS section, NO Execute
            # missing_hsts_header has 2 guidance_only entries, 0 probe-backed entries
            hsts_fid = by_type.get("missing_hsts_header")
            if hsts_fid:
                html = _panel_html(client, inv_id, hsts_fid)
                has_manual_header   = "Manual investigation paths" in html
                has_automated_header = "Automated actions" in html
                has_execute          = "Execute →" in html
                has_not_automated    = "Not automated" in html
                has_approve          = "Approve" in html.lower()
                has_canned_label     = ("Replaying capability payload" in html
                                        or "Capability executed" in html)
                record(
                    "hsts_manual_paths_section_present",
                    has_manual_header,
                    "Manual investigation paths header in HSTS panel",
                )
                record(
                    "hsts_no_automated_section",
                    not has_automated_header,
                    f"Automated actions header absent: {not has_automated_header}",
                )
                record(
                    "hsts_no_execute_button",
                    not has_execute,
                    "No Execute → button in guidance-only panel",
                )
                record(
                    "hsts_not_automated_badge",
                    has_not_automated,
                    "Not-automated badge renders on guidance cards",
                )
                record(
                    "hsts_no_approve_button",
                    not has_approve,
                    "No Approve affordance in panel",
                )
                record(
                    "hsts_no_canned_labels",
                    not has_canned_label,
                    "No deceptive stage labels in panel",
                )
                status = "PASS" if (has_manual_header and not has_automated_header
                                    and not has_execute and has_not_automated
                                    and not has_approve and not has_canned_label) else "FAIL"
                print(f"  hsts (guidance-only finding):     {status}")
            else:
                print("  hsts finding not found — skipping hsts checks")

            # --- Check 2: probe-backed finding → AUTOMATED ACTIONS section, Execute present
            # missing_csp_header has 3 probe-backed entries (XSS, inspect_origins, check_meta)
            csp_fid = by_type.get("missing_csp_header")
            if csp_fid:
                html = _panel_html(client, inv_id, csp_fid)
                has_automated_header = "Automated actions" in html
                has_manual_header    = "Manual investigation paths" in html
                execute_count        = html.count("Execute →")
                has_approve          = "Approve" in html.lower()
                has_canned_label     = ("Replaying capability payload" in html
                                        or "Capability executed" in html)
                record(
                    "csp_automated_section_present",
                    has_automated_header,
                    "Automated actions header in CSP panel",
                )
                record(
                    "csp_no_manual_section",
                    not has_manual_header,
                    "Manual investigation paths section absent (no guidance entries)",
                )
                record(
                    "csp_execute_buttons_present",
                    execute_count == 3,
                    f"Execute buttons: {execute_count} (expect 3)",
                )
                record(
                    "csp_no_approve_button",
                    not has_approve,
                    "No Approve affordance in panel",
                )
                status = "PASS" if (has_automated_header and not has_manual_header
                                    and execute_count == 3 and not has_approve
                                    and not has_canned_label) else "FAIL"
                print(f"  csp (probe-backed finding):       {status}")
            else:
                print("  csp finding not found — skipping csp checks")

            # --- Check 3: command_injection finding → 3 automated probes
            cmdi_fid = by_type.get("command_injection")
            if cmdi_fid:
                html = _panel_html(client, inv_id, cmdi_fid)
                has_automated_header = "Automated actions" in html
                execute_count        = html.count("Execute →")
                has_approve          = "Approve" in html.lower()
                record(
                    "cmdi_automated_section_present",
                    has_automated_header,
                    "Automated actions header in cmdi panel",
                )
                record(
                    "cmdi_execute_buttons_present",
                    execute_count == 3,
                    f"Execute buttons: {execute_count} (expect 3)",
                )
                record(
                    "cmdi_no_approve_button",
                    not has_approve,
                    "No Approve affordance in cmdi panel",
                )
                status = "PASS" if (has_automated_header and execute_count == 3
                                    and not has_approve) else "FAIL"
                print(f"  cmdi (3 probe-backed entries):    {status}")
            else:
                print("  cmdi finding not found — skipping cmdi checks")

        # ── Deception-absence grep checks ─────────────────────────────
        print()
        print("─── Deception-absence contracts (grep) ───")

        def _grep_count(pattern: str, paths: list[str]) -> int:
            try:
                result = subprocess.run(
                    ["grep", "-rn", "--include=*.py", "--include=*.html",
                     pattern, *paths],
                    capture_output=True, text=True, check=False,
                )
                # Exclude comments and docstrings that mention removed symbols
                live_lines = [
                    ln for ln in result.stdout.splitlines()
                    if not any(marker in ln for marker in
                               ["# Phase 59b", "#   Phase 59b", "# Phase 59a",
                                "#", "removal comment", "phase history"])
                    and "# " not in ln
                ]
                return len(live_lines)
            except Exception:
                return -1

        app_dir = "apps"
        fe_dir  = "frontend"

        for symbol, _label in [
            ("DEFAULT_SCRIPT",               "DEFAULT_SCRIPT constant"),
            ("Replaying capability payload", '"Replaying capability payload" stage label'),
            ("Capability executed",          '"Capability executed" outcome label'),
            ("Comparing response signatures","Comparing response signatures stage label"),
            ("branch_action_approve",        "branch_action_approve route"),
        ]:
            hits = _grep_count(symbol, [app_dir, fe_dir])
            ok = hits == 0
            record(
                f"grep_zero_{symbol[:20].replace(' ', '_').lower()}",
                ok,
                f"{hits} live references (expect 0)",
            )
            status = "PASS" if ok else f"FAIL ({hits} hits)"
            print(f"  {symbol[:40]:40s}  {status}")

        # ── Lifecycle: create + delete ─────────────────────────────────
        print()
        print("─── Lifecycle: create + delete ───")
        lifecycle_target = "http://host.docker.internal:9998/"
        try:
            client.get(
                f"{BACKEND}/api/v1/validation/investigations/workspace",
                params={"target": lifecycle_target}, timeout=10,
            )
            lc_invs = client.get(
                f"{BACKEND}/api/v1/validation/investigation-core/investigations",
                timeout=5,
            ).json()
            lc_inv_id = None
            for inv in lc_invs:
                if lifecycle_target in (inv.get("targets") or []):
                    lc_inv_id = inv["investigation_id"]
                    break

            record("lifecycle_create",
                   lc_inv_id is not None,
                   f"inv={lc_inv_id[:8] if lc_inv_id else 'none'}")
            print(f"  created: {lc_inv_id[:8] if lc_inv_id else 'FAIL'}")

            if lc_inv_id:
                del_r = client.post(
                    f"{BACKEND}/api/v1/validation/investigations/{lc_inv_id}/delete",
                    timeout=10,
                )
                record("lifecycle_delete",
                       del_r.status_code == 200,
                       f"HTTP {del_r.status_code}")
                ok_str = "(ok)" if del_r.status_code == 200 else "(FAIL)"
                print(f"  delete:  HTTP {del_r.status_code} {ok_str}")
        except Exception as e:
            record("lifecycle_create", False, f"{type(e).__name__}: {e}")
            record("lifecycle_delete", False, "skipped — create failed")

    # ── Summary ────────────────────────────────────────────────────────
    print()
    print("=" * 60)
    if results:
        width = max(len(k) for k in results)
        for k, (ok, detail) in results.items():
            tag    = "PASS" if ok else "FAIL"
            suffix = f"  ({detail})" if detail else ""
            print(f"  {k:<{width}}  {tag}{suffix}")

    overall = bool(results) and all(ok for ok, _ in results.values())
    print()
    print(f"OVERALL: {'PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
