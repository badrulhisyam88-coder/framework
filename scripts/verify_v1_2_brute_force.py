"""Verification helper — NOT production code.

V1.2 — contract-based verification of the brute-force login probe
against DVWA. Mirrors verify_phase60_cmdi.py shape: lifecycle ops +
probe run + artifact assertions + negative case.

Run from repo root:
    .venv/bin/python scripts/verify_v1_2_brute_force.py

Env overrides:
    V12_BACKEND_URL   default http://localhost:8000
    V12_TARGET        default http://host.docker.internal:10000/
"""
from __future__ import annotations

import os
import sys
import time

import httpx

BACKEND = os.environ.get("V12_BACKEND_URL", "http://localhost:8000")
TARGET  = os.environ.get("V12_TARGET", "http://host.docker.internal:10000/")

WS = f"{BACKEND}/api/v1/validation/workspace"


def _fresh_investigation(client: httpx.Client, target: str) -> str:
    """Delete any existing investigation for target, create a fresh one."""
    # Delete existing to avoid stale capture nodes confusing the test.
    listing = client.get(
        f"{BACKEND}/api/v1/validation/investigation-core/investigations",
        timeout=5,
    )
    for inv in (listing.json() if listing.status_code == 200 else []):
        if target in (inv.get("targets") or []):
            client.post(
                f"{BACKEND}/api/v1/validation/investigations/{inv['investigation_id']}/delete",
                timeout=10,
            )

    # Create fresh
    client.get(
        f"{BACKEND}/api/v1/validation/investigations/workspace",
        params={"target": target}, timeout=10,
    )
    listing2 = client.get(
        f"{BACKEND}/api/v1/validation/investigation-core/investigations",
        timeout=5,
    )
    for inv in (listing2.json() if listing2.status_code == 200 else []):
        if target in (inv.get("targets") or []):
            inv_id = inv["investigation_id"]
            client.get(
                f"{WS}/investigations/{inv_id}/branches/topology.json",
                timeout=10,
            )
            return inv_id
    raise RuntimeError(f"no investigation for target {target!r}")


def _wait_for_finding(
    client: httpx.Client, inv_id: str, finding_type: str,
    timeout_s: float = 40.0,
) -> str | None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = client.get(
            f"{BACKEND}/api/v1/validation/scanner/investigations/{inv_id}/findings",
            timeout=5,
        )
        if r.status_code == 200:
            for f in r.json():
                if f.get("finding_type") == finding_type:
                    return f["finding_id"]
        time.sleep(0.5)
    return None


def _kick_off(client: httpx.Client, inv_id: str, fid: str) -> str:
    url = (
        f"{WS}/investigations/{inv_id}/finding/{fid}/suggest/"
        f"brute_force_login/execute"
    )
    r = client.post(
        url, params={"exploit_path_id": "auth.brute_force"}, timeout=10,
    )
    r.raise_for_status()
    return r.headers.get("x-run-id", "")


def _wait_for_new_capture(
    client: httpx.Client, inv_id: str,
    existing_ids: set[str], timeout_s: float = 120.0,
) -> str | None:
    """Poll topology until a capture node appears whose bundle_id is NOT in existing_ids."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = client.get(
            f"{WS}/investigations/{inv_id}/branches/topology.json",
            timeout=10,
        )
        if r.status_code == 200:
            for n in r.json()["nodes"]:
                if n["type"] == "capture":
                    bid = n["data"].get("bundle_id")
                    if bid and bid not in existing_ids:
                        return bid
        time.sleep(0.5)
    return None


def _existing_bundle_ids(client: httpx.Client, inv_id: str) -> set[str]:
    r = client.get(
        f"{WS}/investigations/{inv_id}/branches/topology.json", timeout=10,
    )
    if r.status_code != 200:
        return set()
    return {
        n["data"].get("bundle_id")
        for n in r.json()["nodes"]
        if n["type"] == "capture" and n["data"].get("bundle_id")
    }


def main() -> int:
    results: dict[str, tuple[bool, str]] = {}

    def record(check: str, ok: bool, detail: str = "") -> None:
        results[check] = (ok, detail)

    with httpx.Client() as client:
        # ── Lifecycle: fresh investigation + wait for login_form_detected
        print(f"─── Lifecycle: fresh investigation ({TARGET}) ───")
        try:
            inv_id    = _fresh_investigation(client, TARGET)
            login_fid = _wait_for_finding(client, inv_id, "login_form_detected")
            record(
                "lifecycle_login_form_detected",
                login_fid is not None,
                f"inv={inv_id[:8]} fid={(login_fid or '?')[:8]}",
            )
            print(f"  inv={inv_id[:8]} login_form_detected={(login_fid or '?')[:8]}")
        except Exception as e:
            record("lifecycle_login_form_detected", False,
                   f"{type(e).__name__}: {e}")
            login_fid = None
            inv_id = ""

        # ── Suggestion panel contract ──────────────────────────────────
        if login_fid and inv_id:
            print()
            print("─── Action card contract ───")
            node_id = f"disc-{login_fid}"
            panel_r = client.get(
                f"{WS}/investigations/{inv_id}/context-panel/{node_id}",
                timeout=10,
            )
            panel_html = panel_r.text if panel_r.status_code == 200 else ""

            has_action_section = "Automated actions" in panel_html
            has_card_label     = "Brute force login" in panel_html
            has_execute_btn    = "brute_force_login/execute" in panel_html
            exact_reasoning    = (
                "Attempts known default credentials against the detected login "
                "form. Real HTTP requests" in panel_html
            )
            record("panel_automated_actions_section", has_action_section,
                   "Automated actions section present")
            record("panel_brute_force_card", has_card_label,
                   "'Brute force login' card in panel")
            record("panel_execute_button", has_execute_btn,
                   "Execute button with brute_force_login/execute href")
            record("panel_exact_reasoning_text", exact_reasoning,
                   "Action card reasoning matches exact wording")
            status = "PASS" if all([has_action_section, has_card_label,
                                    has_execute_btn, exact_reasoning]) else "FAIL"
            print(f"  Action card in context panel: {status}")

        # ── Execute + capture ─────────────────────────────────────────
        bundle_id = None
        if login_fid and inv_id:
            print()
            print("─── Execute brute_force_login ───")
            prior_bundles = _existing_bundle_ids(client, inv_id)
            try:
                run_id = _kick_off(client, inv_id, login_fid)
                record("kickoff", bool(run_id), f"run_id={run_id}")
                print(f"  kicked off: {run_id}")
            except Exception as e:
                record("kickoff", False, f"{type(e).__name__}: {e}")
                run_id = ""

            if run_id:
                bundle_id = _wait_for_new_capture(
                    client, inv_id, prior_bundles, timeout_s=120,
                )
            record("capture_emitted", bundle_id is not None,
                   f"bundle_id={bundle_id}")
            print(f"  bundle_id={bundle_id}")

        # ── Bundle artifact contract ──────────────────────────────────
        if bundle_id:
            meta = client.get(f"{WS}/bundles/{bundle_id}", timeout=10)
            if meta.status_code == 200:
                arts  = meta.json().get("artifacts", [])
                names = {a["filename"] for a in arts}
                required = {
                    "HOW_TO_REPRODUCE.md", "exploit_request.txt",
                    "exploit_response.txt", "session.txt", "credentials.txt",
                }
                record("standard_artifacts_present",
                       required.issubset(names),
                       f"missing: {sorted(required - names) or 'none'}")
                no_cmdi_extras = not any(
                    n in names
                    for n in ("whoami_output.txt", "id_output.txt",
                              "detected_separator.txt")
                )
                record("no_cmdi_artifacts", no_cmdi_extras,
                       "cmdi-specific artifacts absent (correct)")

            # credentials.txt: actual value, not hardcoded
            r_creds = client.get(
                f"{WS}/bundles/{bundle_id}/files/credentials.txt", timeout=10,
            )
            creds_text  = r_creds.text.strip() if r_creds.status_code == 200 else ""
            creds_valid = bool(creds_text) and ":" in creds_text
            record("credentials_txt_non_empty", creds_valid,
                   f"content={creds_text!r}")
            print(f"  credentials.txt: {creds_text!r}")

            # HOW_TO_REPRODUCE.md must reference the actual credentials
            r_md = client.get(
                f"{WS}/bundles/{bundle_id}/files/HOW_TO_REPRODUCE.md", timeout=10,
            )
            md_text = r_md.text if r_md.status_code == 200 else ""
            if ":" in creds_text:
                user_part, pass_part = creds_text.split(":", 1)
                narrative_matches = user_part in md_text and pass_part in md_text
            else:
                narrative_matches = False
            record("readme_references_actual_credentials",
                   narrative_matches,
                   f"narrative contains {creds_text!r}")

        # ── Negative case: probe in-process against unreachable host ─────
        # Run brute_force_login directly in the backend container against
        # a target that has no login form and no default credentials, to
        # confirm the probe emits confirmed=False and no bundle is created.
        print()
        print("─── Negative case: probe against non-DVWA target ───")
        neg_code = "\n".join([
            "import asyncio, sys; sys.path.insert(0,'/app')",
            "async def m():",
            "  from apps.investigation_workspace.execution.runtime import kick_off",
            "  from apps.investigation_workspace.suggestions.probes import probe_brute_force_login",
            "  from apps.investigation_workspace.capture import bundles_for_investigation",
            "  INV = 'v12-neg-test'",
            # Use the backend's own health URL — returns 200 JSON, no login form
            "  run = await kick_off(",
            "    investigation_id=INV,",
            "    action_id='suggestion:brute_force_login',",
            "    parent_node_id='disc-x',",
            "    probe_runner=probe_brute_force_login,",
            "    canonical_target='http://localhost:8000/',",
            "    exploit_path_id='auth.brute_force',",
            "  )",
            "  for _ in range(120):",
            "    await asyncio.sleep(0.5)",
            "    if run.completed_at: break",
            "  r = run.results[0] if run.results else None",
            "  bundles = bundles_for_investigation(INV)",
            "  if r:",
            "    a = r.payload.get('analysis', {})",
            "    print('NEG_CONFIRMED=' + str(a.get('confirmed')))",
            "    print('NEG_SEVERITY='  + str(a.get('severity')))",
            "    print('NEG_BUNDLES='   + str(len(bundles)))",
            "asyncio.run(m())",
        ])
        import subprocess
        proc = subprocess.run(
            ["docker", "compose", "exec", "-T", "backend",
             "python", "-c", neg_code],
            capture_output=True, text=True, timeout=120, check=False,
        )
        out = proc.stdout
        neg_ok = (
            "NEG_CONFIRMED=False" in out
            and "NEG_SEVERITY=info" in out
            and "NEG_BUNDLES=0" in out
        )
        record("negative_no_credentials_found", neg_ok,
               "confirmed=False & severity=info & bundles=0")
        print(f"  localhost:8000 (no login form): {'PASS' if neg_ok else 'FAIL'}")

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
