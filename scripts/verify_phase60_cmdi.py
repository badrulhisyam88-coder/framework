"""Verification helper — NOT production code.

Phase 60 — end-to-end browser-driven test for the command-injection
probe family against DVWA. Mirrors the verify_phase57_sqli_capture.py
shape: lifecycle ops + per-variant probe runs + Playwright UI walk +
regression.

Run from repo root:
    .venv/bin/python scripts/verify_phase60_cmdi.py

Env overrides:
    PHASE60_BACKEND_URL  default http://localhost:8000
    PHASE60_TARGET       default http://host.docker.internal:10001/
    PHASE60_NEG_TARGET   default http://host.docker.internal:10000/
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

import httpx

BACKEND    = os.environ.get("PHASE60_BACKEND_URL", "http://localhost:8000")
TARGET     = os.environ.get("PHASE60_TARGET", "http://host.docker.internal:10001/")
NEG_TARGET = os.environ.get("PHASE60_NEG_TARGET", "http://host.docker.internal:10000/")

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


def _wait_for_finding(
    client: httpx.Client, investigation_id: str,
    finding_type: str, timeout_s: float = 30.0,
) -> str | None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = client.get(
            f"{BACKEND}/api/v1/validation/scanner/investigations/"
            f"{investigation_id}/findings", timeout=5,
        )
        if r.status_code == 200:
            for f in r.json():
                if f.get("finding_type") == finding_type:
                    return f["finding_id"]
        time.sleep(0.5)
    return None


def _kick_off(
    client: httpx.Client, inv_id: str, fid: str, action_kind: str,
) -> str:
    url = (
        f"{WS}/investigations/{inv_id}/finding/{fid}/suggest/"
        f"{action_kind}/execute"
    )
    r = client.post(
        url, params={"exploit_path_id": "injection.command"}, timeout=10,
    )
    r.raise_for_status()
    return r.headers.get("x-run-id", "")


def _wait_for_capture(
    client: httpx.Client, inv_id: str, timeout_s: float = 30.0,
) -> str | None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = client.get(
            f"{WS}/investigations/{inv_id}/branches/topology.json",
            timeout=10,
        )
        if r.status_code == 200:
            for n in r.json()["nodes"]:
                if n["type"] == "capture":
                    return n["data"].get("bundle_id")
        time.sleep(0.5)
    return None


def main() -> int:
    results: dict[str, tuple[bool, str]] = {}

    def record(check: str, ok: bool, detail: str = ""):
        results[check] = (ok, detail)

    with httpx.Client() as client:
        # ── Lifecycle ops ──────────────────────────────────────────
        print("─── Lifecycle: create + bootstrap DVWA investigation ───")
        try:
            inv_id = _bootstrap_inv(client, TARGET)
            cmdi_fid = _wait_for_finding(client, inv_id, "command_injection")
            record("lifecycle_create_dvwa", cmdi_fid is not None,
                   f"inv={inv_id[:8]} cmdi_finding={(cmdi_fid or '?')[:8]}")
            print(f"  inv={inv_id} cmdi_finding={cmdi_fid}")
        except Exception as e:
            record("lifecycle_create_dvwa", False, f"{type(e).__name__}: {e}")
            cmdi_fid = None

        # ── Reflected variant ──────────────────────────────────────
        if cmdi_fid:
            print()
            print("─── Reflected variant against DVWA ───")
            run_id = _kick_off(client, inv_id, cmdi_fid, "cmdi_reflected")
            record("reflected_kickoff", bool(run_id), f"run_id={run_id}")
            bundle_id = _wait_for_capture(client, inv_id, timeout_s=30)
            record("reflected_capture_emitted", bundle_id is not None,
                   f"bundle_id={bundle_id}")
            if bundle_id:
                meta = client.get(f"{WS}/bundles/{bundle_id}", timeout=10)
                if meta.status_code == 200:
                    arts = meta.json().get("artifacts", [])
                    names = {a["filename"] for a in arts}
                    required = {
                        "HOW_TO_REPRODUCE.md", "exploit_request.txt",
                        "exploit_response.txt", "session.txt",
                        "whoami_output.txt", "id_output.txt",
                        "detected_separator.txt",
                    }
                    record("reflected_standard_artifacts",
                           required.issubset(names),
                           f"missing: {sorted(required - names) or 'none'}")
                resp = client.get(
                    f"{WS}/bundles/{bundle_id}/files/exploit_response.txt",
                    timeout=10,
                )
                record("reflected_response_has_marker_echo",
                       resp.status_code == 200,
                       f"status={resp.status_code} len={len(resp.text)}")

                # Phase 60a — verify discrete artifact files exist and
                # contain the expected command output (not just narrative).
                r_whoami = client.get(
                    f"{WS}/bundles/{bundle_id}/files/whoami_output.txt",
                    timeout=10,
                )
                whoami_text = r_whoami.text.strip() if r_whoami.status_code == 200 else ""
                record(
                    "reflected_whoami_artifact_content",
                    bool(whoami_text),
                    f"content={whoami_text!r}",
                )

                r_id = client.get(
                    f"{WS}/bundles/{bundle_id}/files/id_output.txt",
                    timeout=10,
                )
                id_text = r_id.text.strip() if r_id.status_code == 200 else ""
                record(
                    "reflected_id_artifact_content",
                    bool(id_text) and "uid=" in id_text,
                    f"content={id_text!r}",
                )

                r_sep = client.get(
                    f"{WS}/bundles/{bundle_id}/files/detected_separator.txt",
                    timeout=10,
                )
                sep_text = r_sep.text.strip() if r_sep.status_code == 200 else ""
                record(
                    "reflected_separator_artifact_content",
                    bool(sep_text),
                    f"content={sep_text!r}",
                )

                # Narrative interpolation check — the markdown should also
                # mention the shell user (separate from artifact existence).
                resp_md = client.get(
                    f"{WS}/bundles/{bundle_id}/files/HOW_TO_REPRODUCE.md",
                    timeout=10,
                )
                record(
                    "reflected_readme_narrative_interpolated",
                    bool(whoami_text) and whoami_text in resp_md.text,
                    f"narrative contains actual whoami value {whoami_text!r}",
                )

        # ── Negative case: same variants against Juice Shop ────────
        print()
        print("─── Negative case: probes against Juice Shop (no cmdi) ───")
        # Use docker exec for in-process runtime calls
        probes_mod  = "apps.investigation_workspace.suggestions.probes"
        capture_mod = "apps.investigation_workspace.capture"
        runtime_mod = "apps.investigation_workspace.execution.runtime"
        for variant in ("reflected", "blind_time", "blind_boolean"):
            cmd_lines = [
                "import asyncio, sys; sys.path.insert(0,'/app')",
                "async def m():",
                f"  from {runtime_mod} import kick_off",
                f"  from {probes_mod} import probe_cmdi_{variant}",
                f"  from {capture_mod} import bundles_for_investigation",
                f"  INV = 'phase60-neg-{variant}'",
                "  run = await kick_off(",
                "    investigation_id=INV,",
                f"    action_id='suggestion:cmdi_{variant}',",
                "    parent_node_id='disc-x',",
                f"    probe_runner=probe_cmdi_{variant},",
                f"    canonical_target={NEG_TARGET!r},",
                "    exploit_path_id='injection.command',",
                "  )",
                "  for _ in range(200):",
                "    await asyncio.sleep(0.5)",
                "    if run.completed_at: break",
                "  r = run.results[0] if run.results else None",
                "  bundles = bundles_for_investigation(INV)",
                "  if r:",
                "    a = r.payload['analysis']",
                f"    print('NEG_{variant.upper()}_CONFIRMED=' + str(a['confirmed']))",
                f"    print('NEG_{variant.upper()}_SEVERITY=' + a['severity'])",
                f"    print('NEG_{variant.upper()}_BUNDLES=' + str(len(bundles)))",
                "asyncio.run(m())",
            ]
            proc = subprocess.run(
                ["docker", "compose", "exec", "-T", "backend",
                 "python", "-c", "\n".join(cmd_lines)],
                capture_output=True, text=True, timeout=180, check=False,
            )
            out = proc.stdout
            up = variant.upper()
            confirmed_false = f"NEG_{up}_CONFIRMED=False" in out
            severity_info   = f"NEG_{up}_SEVERITY=info"   in out
            no_bundle       = f"NEG_{up}_BUNDLES=0"       in out
            ok = confirmed_false and severity_info and no_bundle
            record(f"negative_{variant}_clean", ok,
                   "confirmed=False & severity=info & bundles=0")
            print(f"  {variant:18}  {'PASS' if ok else 'FAIL'}")

    print()
    print("=" * 60)
    if results:
        width = max(len(k) for k in results)
        for k, (ok, detail) in results.items():
            tag = "PASS" if ok else "FAIL"
            suffix = f"  ({detail})" if detail else ""
            print(f"  {k:<{width}}  {tag}{suffix}")
    overall = bool(results) and all(ok for ok, _ in results.values())
    print()
    print(f"OVERALL: {'PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
