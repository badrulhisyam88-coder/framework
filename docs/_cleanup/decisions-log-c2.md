# PR VESTIGE-2 — Tasks, Adapters, Adaptive + CVE Archive

**Date:** 2026-05-26
**Outcome:** DOCUMENT-ONLY — zero file changes. All targets reclassified from VESTIGE to ACTIVE-LEGACY.
**Precedent:** See decisions-log-c1.md for AMBIGUOUS-RETAINED handling.

---

## Classification: ACTIVE-LEGACY

**Definition:** Code that is old, does not fit the current Conductor architecture, and has no
role in the V1.7+ pipeline — but still has live callers from `validation/api/` or
`validation/services/` routes that operators can reach. It cannot be deleted without first
removing or redirecting those callers.

Distinct from:
- **VESTIGE:** Confirmed dead — zero callers anywhere. Safe to delete.
- **AMBIGUOUS-RETAINED (C1 precedent):** Had callers, but callers themselves may be legacy. Not yet traced to a live route.
- **ACTIVE-LEGACY (this PR):** Traced all the way to a live operator-facing endpoint. Callers are confirmed active.

The stage-2 audit used architecture-fit heuristics (no Conductor pipeline callers) to classify
these modules as VESTIGE. It did not trace callers within the legacy `validation/` stack. The
pre-deletion grep caught the mismatch.

---

## Pre-deletion test baseline

1 failed, 396 passed, 11 skipped, 17 errors
(Identical to post-C1 baseline. The 1 failure and 17 errors are pre-existing — pydantic/fastapi
not installed outside Docker.)

---

## Safety check results — all targets reclassified ACTIVE-LEGACY

### ACTIVE-LEGACY: `apps/validation/tasks/`

| Caller | Line | Import |
|--------|------|--------|
| `apps/validation/api/queue.py` | 16 | `from apps.validation.tasks import run_lifecycle_once` |

`run_lifecycle_once` is called at queue.py:218 inside a live `POST /queue/run-lifecycle`
endpoint visible to operators. The tasks/ directory drives the finding expiry lifecycle.

**Why reclassified:** Not a Conductor-pipeline module, but `queue.py` is an active API route.
Deleting `tasks/` produces `ImportError` at that endpoint.

**Next step:** Decide whether the lifecycle endpoint should be retained or removed. If removed,
`tasks/expiry_worker.py` can be deleted with it.

---

### ACTIVE-LEGACY: `apps/validation/adapters/`

| Caller | Line | Import |
|--------|------|--------|
| `apps/validation/services/scanner.py` | 20 | `from apps.validation.adapters.nmap import NmapAdapter` |
| `apps/validation/services/recon.py` | 11 | `from apps.validation.adapters.recon_ng import ReconNgAdapter` |

`scanner.py` and `recon.py` are live validation service modules.

**Why reclassified:** The adapters wrap nmap and recon-ng for the pre-Conductor scan path.
That path is still reachable from `validation/api/` routes. These are not dead wrappers —
they are live wrappers around legacy tooling.

**Next step:** Trace `scanner.py` and `recon.py` callers to determine whether any live API
routes reach them. If their entire call chain is legacy-only and the endpoints can be removed,
the whole chain (`adapters/` + `services/scanner.py` + `services/recon.py`) can be deleted
together.

---

### ACTIVE-LEGACY: `apps/investigation_workspace/adaptive/`

| Caller | Line | Import |
|--------|------|--------|
| `apps/investigation_workspace/feed/builder.py` | 25 | `from apps.investigation_workspace.adaptive.guidance import ...` |
| `apps/investigation_workspace/feed/builder.py` | 29 | `from apps.investigation_workspace.adaptive.insights import generate_insights` |

`generate_insights` is called at builder.py:416. `FeedBuilder` is part of the live
investigation workspace feed API.

**Why reclassified:** `adaptive/` pre-dates the Conductor learning/mastery stack. Its guidance
and insight generation is still wired into `FeedBuilder`, which runs on every feed request.
This is not orphaned code — it runs on every investigation workspace page load.

**Next step:** Replace `adaptive/guidance` and `adaptive/insights` calls in `FeedBuilder` with
equivalents from the `investigation_core` learning stack, or confirm they can be dropped
without degrading the feed response. Then delete.

---

### ACTIVE-LEGACY: `apps/validation/engines/cve_matcher.py` (archive target)

| Caller | Line | Import |
|--------|------|--------|
| `apps/validation/api/known_issues.py` | 18 | `from apps.validation.engines.cve_matcher import CVEMatcher` |
| `apps/validation/services/correlator.py` | 25 | `from apps.validation.engines.cve_matcher import CVEMatch, CVEMatcher` |

**Why reclassified:** The CVE matcher chain was dropped as a Conductor feature (PR G) — the
infrastructure was parked, not unwired. `known_issues.py` and `correlator.py` still import
and use `CVEMatcher`. Moving `cve_matcher.py` to `/files/_archived_code/` would break both.

**Next step:** Remove `CVEMatcher` usage from `known_issues.py` and `correlator.py`, then archive.

---

### ACTIVE-LEGACY: `apps/validation/engines/nvd_sync.py` (archive target)

| Caller | Line | Import |
|--------|------|--------|
| `apps/validation/api/settings_router.py` | 21 | `from apps.validation.engines.nvd_sync import InvalidNVDApiKey, NVDSyncEngine` |

`NVDSyncEngine` is used in a live NVD sync trigger endpoint (`POST /settings/nvd-sync`)
visible in the admin Settings panel.

**Why reclassified:** The NVD sync feature was not explicitly dropped in any PR. It is operator-
visible and reachable. Archiving `nvd_sync.py` would break the Settings panel.

**Next step:** Decide whether to retain the NVD sync feature, disable it behind a gate, or
remove the endpoint and then archive.

---

### KEEP (confirmed active): `apps/validation/engines/fingerprint_normalizer.py`

| Caller | Line | Import |
|--------|------|--------|
| `apps/validation/services/correlator.py` | 26 | `from apps.validation.engines.fingerprint_normalizer import FingerprintNormalizer` |
| `apps/validation/api/known_issues.py` | 19 | `from apps.validation.engines.fingerprint_normalizer import FingerprintNormalizer` |

2 active callers. Also imported internally by `cve_matcher.py` (itself ACTIVE-LEGACY).
Not archived, not deleted. Status unchanged.

---

## Summary table

| Target | Classification | Blocker |
|--------|---------------|---------|
| `validation/tasks/` | ACTIVE-LEGACY | `queue.py:16` — live endpoint |
| `validation/adapters/nmap.py` | ACTIVE-LEGACY | `scanner.py:20` — live service |
| `validation/adapters/recon_ng.py` | ACTIVE-LEGACY | `recon.py:11` — live service |
| `investigation_workspace/adaptive/guidance.py` | ACTIVE-LEGACY | `feed/builder.py:25` — every feed load |
| `investigation_workspace/adaptive/insights.py` | ACTIVE-LEGACY | `feed/builder.py:29` — every feed load |
| `validation/engines/cve_matcher.py` | ACTIVE-LEGACY | `known_issues.py:18`, `correlator.py:25` |
| `validation/engines/nvd_sync.py` | ACTIVE-LEGACY | `settings_router.py:21` — Settings panel |
| `validation/engines/fingerprint_normalizer.py` | KEEP | 2 active callers |

---

## Architecture doc check

`docs/architecture/system.md` and `docs/architecture/seams.md` checked.
Neither references any C2 target by module path. No architecture doc updates required.

---

## Path to a future VESTIGE-3

Each ACTIVE-LEGACY module requires a redirect PR before deletion:

1. `validation/tasks/` — remove or retain the `/queue/run-lifecycle` endpoint
2. `validation/adapters/` — trace and drop `scanner.py` / `recon.py` caller chain
3. `investigation_workspace/adaptive/` — replace or drop calls in `FeedBuilder`
4. `cve_matcher.py` — unwire from `known_issues.py` and `correlator.py`
5. `nvd_sync.py` — gate-disable or remove the `/settings/nvd-sync` endpoint

That redirect work touches 7 files across active API routes and is a correctness change,
not a vestige cleanup. Out of scope until operator decides which legacy routes to retain.
