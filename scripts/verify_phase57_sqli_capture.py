"""Verification helper — NOT production code.

Phase 57 end-to-end regression for the SQLi auth-bypass probe +
post-exploit artifact bundler + Capture node pipeline.

Drives the live backend (FastAPI on http://localhost:8000) and the
target lab (Juice Shop at http://host.docker.internal:10000 by
default). Runs entirely in-process via httpx — no headless browser
needed (unlike verify_phase56_browser.py, which exercises React Flow
UX). Same docker / env assumptions: backend healthy on :8000, Juice
Shop reachable from inside the backend container.

Configurable via env vars:
    PHASE57_BACKEND_URL    default http://localhost:8000
    PHASE57_TARGET         default http://host.docker.internal:10000/
    PHASE57_ADMIN_EMAIL    default admin@juice-sh.op
                           — local Juice Shop seeds may differ;
                             override if your instance uses another
                             value.

Run from repo root:
    .venv/bin/python scripts/verify_phase57_sqli_capture.py

Exit code 0 = all PASS, 1 = any FAIL.
"""
from __future__ import annotations

import os
import sys
import time
import uuid

import httpx

BACKEND      = os.environ.get("PHASE57_BACKEND_URL", "http://localhost:8000")
TARGET       = os.environ.get("PHASE57_TARGET",
                              "http://host.docker.internal:10000/")
ADMIN_EMAIL  = os.environ.get("PHASE57_ADMIN_EMAIL", "admin@juice-sh.op")
NEG_TARGET   = os.environ.get("PHASE57_NEG_TARGET", "https://example.com/")

# Some routes are namespaced under /api/v1/validation/workspace/.
WS = f"{BACKEND}/api/v1/validation/workspace"


def _create_investigation(client: httpx.Client, target: str) -> str:
    """Bootstrap (or fetch existing) investigation for the target.

    Returns the investigation_id. Phase 58 — actually triggering the
    bootstrap requires hitting the topology endpoint, not just the
    HTML shell. The topology endpoint auto-fires bootstrap when the
    investigation is empty.
    """
    # Step 1: ensure an investigation row exists. The HTML shell route
    # is what the operator's browser hits; it calls InvestigationService.
    # get_or_create internally as part of rendering.
    client.get(
        f"{BACKEND}/api/v1/validation/investigations/workspace",
        params={"target": target}, timeout=10,
    )
    # Step 2: find the just-(re)created investigation id.
    resp = client.get(
        f"{BACKEND}/api/v1/validation/investigation-core/investigations",
        timeout=5,
    )
    inv_id = None
    if resp.status_code == 200:
        for inv in resp.json():
            if target in (inv.get("targets") or []):
                inv_id = inv["investigation_id"]
                break
    if inv_id is None:
        raise RuntimeError(
            f"could not locate investigation for target {target!r} "
            f"(listing status={resp.status_code})"
        )
    # Step 3: hit the topology endpoint to AUTO-FIRE the bootstrap
    # probe. If the investigation is already populated this is a
    # cheap no-op; if it's empty, the bootstrap runner spawns
    # asynchronously.
    client.get(
        f"{WS}/investigations/{inv_id}/branches/topology.json",
        timeout=10,
    )
    return inv_id


def _wait_for_bootstrap(
    client: httpx.Client, investigation_id: str,
    *, want_finding_type: str | None = None,
    timeout_s: float = 25.0,
) -> list[dict]:
    """Phase 58 — poll the findings listing until either:
      • a finding with the requested `want_finding_type` appears, OR
      • the timeout elapses.
    Returns the latest findings list. When `want_finding_type` is None,
    waits until at least one finding exists (legacy behavior).

    The recon probe runs SECOND in the bootstrap sequence, so its
    finding arrives after the passive probe's first emissions. A naive
    "wait for N findings" gives a false positive against the partial
    state. Wait for the type we actually care about.
    """
    deadline = time.time() + timeout_s
    findings: list[dict] = []
    while time.time() < deadline:
        resp = client.get(
            f"{BACKEND}/api/v1/validation/scanner/investigations/"
            f"{investigation_id}/findings",
            timeout=5,
        )
        if resp.status_code == 200:
            findings = resp.json()
            if want_finding_type is not None:
                if any(f.get("finding_type") == want_finding_type
                       for f in findings):
                    return findings
            elif findings:
                return findings
        time.sleep(0.6)
    return findings


def _find_sqli_or_csp_finding(
    client: httpx.Client, investigation_id: str,
) -> tuple[str, bool]:
    """Phase 58 — prefer a finding_type='sqli' finding (the recon probe's
    output). Fall back to any other finding if recon didn't produce one,
    printing a warning since that path uses the route's permissive
    action-dispatch (the back-door the Phase 58 investigation flagged).

    Returns (finding_id, is_sqli_finding).
    """
    findings = _wait_for_bootstrap(
        client, investigation_id, want_finding_type="sqli",
    )
    fallback_id = None
    for f in findings:
        if f.get("finding_type") == "sqli":
            return f["finding_id"], True
        if fallback_id is None:
            fallback_id = f["finding_id"]
    if fallback_id is None:
        raise RuntimeError("no findings on investigation")
    print("  WARN: no sqli-typed finding present — using fallback "
          f"finding {fallback_id[:8]}… via permissive route dispatch")
    return fallback_id, False
    raise RuntimeError("no findings on investigation")


def _kick_off_sqli(
    client: httpx.Client, investigation_id: str, finding_id: str,
) -> str:
    """POST the execute_suggestion route. Returns the X-Run-Id header."""
    url = (
        f"{WS}/investigations/{investigation_id}"
        f"/finding/{finding_id}/suggest/sqli_auth_bypass/execute"
    )
    resp = client.post(
        url, params={"exploit_path_id": "injection.sql"}, timeout=10,
    )
    resp.raise_for_status()
    return resp.headers.get("x-run-id", "")


def _wait_for_capture(
    client: httpx.Client, investigation_id: str,
    *, timeout_s: float = 30.0,
) -> tuple[str | None, dict]:
    """Poll the topology until a Capture node appears (or timeout).
    Returns (bundle_id, topology_dict)."""
    deadline = time.time() + timeout_s
    last_topo: dict = {}
    while time.time() < deadline:
        resp = client.get(
            f"{WS}/investigations/{investigation_id}/branches/topology.json",
            timeout=10,
        )
        if resp.status_code == 200:
            last_topo = resp.json()
            for n in last_topo["nodes"]:
                if n["type"] == "capture":
                    return n["data"].get("bundle_id"), last_topo
        time.sleep(0.5)
    return None, last_topo


def _fetch_bundle_meta(client: httpx.Client, bundle_id: str) -> dict:
    resp = client.get(f"{WS}/bundles/{bundle_id}", timeout=10)
    resp.raise_for_status()
    return resp.json()


def _fetch_file(client: httpx.Client, bundle_id: str, filename: str) -> tuple[int, str]:
    resp = client.get(f"{WS}/bundles/{bundle_id}/files/{filename}", timeout=10)
    return resp.status_code, resp.text


# ──────────────────────────────────────────────────────────────────────


def main() -> int:
    results: dict[str, tuple[bool, str]] = {}

    def record(check: str, ok: bool, detail: str = ""):
        results[check] = (ok, detail)

    with httpx.Client() as client:
        # ── Positive case ───────────────────────────────────────────
        print(f"─── Positive case ({TARGET}) ───")
        try:
            inv_id = _create_investigation(client, TARGET)
            finding_id, is_sqli = _find_sqli_or_csp_finding(client, inv_id)
            record(
                "pos_sqli_finding_emitted",
                is_sqli,
                "sqli-typed finding present from recon probe",
            )
            run_id = _kick_off_sqli(client, inv_id, finding_id)
            record("pos_kickoff", bool(run_id), f"run_id={run_id}")
            print(f"  investigation: {inv_id}")
            print(f"  finding:       {finding_id} (sqli={is_sqli})")
            print(f"  run_id:        {run_id}")
        except Exception as e:
            record("pos_kickoff", False, f"{type(e).__name__}: {e}")
            print(f"  FAIL kickoff: {e}")
            inv_id = finding_id = run_id = ""

        bundle_id = None
        if results.get("pos_kickoff", (False, ""))[0]:
            bundle_id, _ = _wait_for_capture(client, inv_id)
            record(
                "pos_capture_node_emitted",
                bundle_id is not None,
                f"bundle_id={bundle_id}",
            )
            print(f"  Capture node bundle_id: {bundle_id}")

        if bundle_id:
            # Metadata endpoint
            try:
                meta = _fetch_bundle_meta(client, bundle_id)
                arts = meta.get("artifacts", [])
                names = {a["filename"] for a in arts}
                record(
                    "pos_metadata_returned",
                    len(arts) >= 3,
                    f"{len(arts)} artifact(s)",
                )
                expected_standard = {
                    "exploit_request.txt",
                    "exploit_response.txt",
                    "session.txt",
                }
                record(
                    "pos_standard_artifacts_present",
                    expected_standard.issubset(names),
                    f"missing: {sorted(expected_standard - names) or 'none'}",
                )
                # Metadata MUST NOT include the content field
                has_content = any("content" in a for a in arts)
                record(
                    "pos_metadata_excludes_content",
                    not has_content,
                    f"has_content={has_content}",
                )
            except Exception as e:
                record("pos_metadata_returned", False,
                       f"{type(e).__name__}: {e}")

            # exploit_response.txt content
            status, content = _fetch_file(client, bundle_id, "exploit_response.txt")
            record(
                "pos_file_content_200",
                status == 200,
                f"status={status}",
            )
            record(
                "pos_exploit_response_contains_umail",
                '"umail"' in content,
                f"len={len(content)}",
            )
            record(
                "pos_exploit_response_contains_admin",
                ADMIN_EMAIL in content,
                f"looking for {ADMIN_EMAIL!r}",
            )

            # api_Users_response.json — redundant location
            status_u, content_u = _fetch_file(client, bundle_id, "api_Users_response.json")
            record(
                "pos_users_response_present",
                status_u == 200,
                f"status={status_u}",
            )
            if status_u == 200:
                record(
                    "pos_users_response_contains_admin",
                    ADMIN_EMAIL in content_u,
                    f"looking for {ADMIN_EMAIL!r}",
                )

            # Phase 57c — HOW_TO_REPRODUCE.md presence + content checks
            readme_present = "HOW_TO_REPRODUCE.md" in names
            record(
                "pos_reproduction_artifact_present",
                readme_present,
                "HOW_TO_REPRODUCE.md in artifact list",
            )
            if readme_present:
                status_r, content_r = _fetch_file(
                    client, bundle_id, "HOW_TO_REPRODUCE.md",
                )
                record(
                    "pos_reproduction_mentions_admin",
                    ADMIN_EMAIL in content_r,
                    f"looking for {ADMIN_EMAIL!r}",
                )
                no_password_phrases = (
                    "not recovered",
                    "does NOT recover",
                    "password is not recovered",
                )
                record(
                    "pos_reproduction_clarifies_no_password",
                    any(p in content_r for p in no_password_phrases),
                    "phrase in HOW_TO_REPRODUCE.md",
                )
                record(
                    "pos_reproduction_includes_curl",
                    "curl" in content_r and "/rest/user/login" in content_r,
                    "curl + endpoint in markdown",
                )
                # Bonus: confirm it's the FIRST artifact in metadata order
                first_filename = (arts[0]["filename"]
                                  if arts else "<no artifacts>")
                record(
                    "pos_reproduction_first_in_metadata",
                    first_filename == "HOW_TO_REPRODUCE.md",
                    f"first artifact: {first_filename}",
                )

            # Bad-input 404 spot-check
            bad_bundle = uuid.uuid4().hex[:12]
            r_bad = client.get(f"{WS}/bundles/{bad_bundle}", timeout=5)
            record("pos_404_bad_bundle_id", r_bad.status_code == 404,
                   f"status={r_bad.status_code}")
            r_bad_file = client.get(
                f"{WS}/bundles/{bundle_id}/files/does_not_exist.txt", timeout=5,
            )
            record("pos_404_bad_filename", r_bad_file.status_code == 404,
                   f"status={r_bad_file.status_code}")

        # ── Negative case ───────────────────────────────────────────
        # We use the in-process kick_off because triggering execute_suggestion
        # on a NEG_TARGET investigation requires bootstrapping one. Most
        # important assertion: no bundle was created.
        print()
        print(f"─── Negative case ({NEG_TARGET}) ───")
        # Reuse the same investigation but probe a different target via
        # direct runtime call. Since the HTTP route routes by
        # investigation's canonical_target (which is the positive case's
        # target), we can't easily redirect from the route. Instead we
        # check the bundle registry directly by counting bundles before
        # and after a NEG kickoff via the runtime API.
        try:
            # Spawn a fresh sub-process via docker exec to drive the
            # runtime against NEG_TARGET. Path of least resistance.
            import subprocess
            probes_mod  = "apps.investigation_workspace.suggestions.probes"
            capture_mod = "apps.investigation_workspace.capture"
            runtime_mod = "apps.investigation_workspace.execution.runtime"
            cmd_lines = [
                "import asyncio, sys; sys.path.insert(0,'/app')",
                "async def m():",
                f"  from {runtime_mod} import kick_off",
                f"  from {probes_mod} import probe_sqli_auth_bypass",
                f"  from {capture_mod} import bundles_for_investigation",
                "  INV = 'phase57-verify-neg'",
                "  run = await kick_off(",
                "    investigation_id=INV,",
                "    action_id='suggestion:sqli_auth_bypass',",
                "    parent_node_id='disc-x',",
                "    probe_runner=probe_sqli_auth_bypass,",
                f"    canonical_target={NEG_TARGET!r},",
                "    exploit_path_id='injection.sql',",
                "  )",
                "  for _ in range(60):",
                "    await asyncio.sleep(0.5)",
                "    if run.completed_at: break",
                "  res = run.results[0] if run.results else None",
                "  bundles = bundles_for_investigation(INV)",
                "  a = res.payload['analysis'] if res else None",
                "  label = res.label if res else 'NONE'",
                "  conf  = str(a['confirmed']) if a else 'NONE'",
                "  sev   = a['severity']       if a else 'NONE'",
                "  print('NEG_RESULT_LABEL=' + label)",
                "  print('NEG_CONFIRMED=' + conf)",
                "  print('NEG_SEVERITY=' + sev)",
                "  print('NEG_BUNDLES=' + str(len(bundles)))",
                "asyncio.run(m())",
            ]
            cmd = "\n".join(cmd_lines)
            proc = subprocess.run(
                ["docker", "compose", "exec", "-T", "backend",
                 "python", "-c", cmd],
                capture_output=True, text=True, timeout=60, check=False,
            )
            out = proc.stdout
            confirmed_line = next(
                (line for line in out.splitlines()
                 if line.startswith("NEG_CONFIRMED=")), "",
            )
            severity_line = next(
                (line for line in out.splitlines()
                 if line.startswith("NEG_SEVERITY=")), "",
            )
            bundles_line  = next(
                (line for line in out.splitlines()
                 if line.startswith("NEG_BUNDLES=")), "",
            )
            print(f"  {confirmed_line}")
            print(f"  {severity_line}")
            print(f"  {bundles_line}")
            record("neg_confirmed_false",
                   "NEG_CONFIRMED=False" in out,
                   confirmed_line.strip())
            record("neg_severity_info",
                   "NEG_SEVERITY=info" in out,
                   severity_line.strip())
            record("neg_no_bundle_created",
                   "NEG_BUNDLES=0" in out,
                   bundles_line.strip())
        except Exception as e:
            record("neg_run", False, f"{type(e).__name__}: {e}")

    # ── Report ─────────────────────────────────────────────────────
    print()
    print("=" * 60)
    width = max(len(k) for k in results) if results else 30
    for k, (ok, detail) in results.items():
        tag = "PASS" if ok else "FAIL"
        suffix = f"  ({detail})" if detail else ""
        print(f"  {k:<{width}}  {tag}{suffix}")
    print()
    overall = all(ok for ok, _ in results.values()) and results
    print(f"OVERALL: {'PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
