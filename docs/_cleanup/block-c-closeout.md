# Block C Closeout — VESTIGE Deletion Phase

**Date:** 2026-05-26
**Result:** Block C complete. ~1,400 lines deleted (C1 only). C2, C3, and C4 reclassified as
ACTIVE-LEGACY documentation. Zero additional deletions.

---

## Summary table

| PR | Target | Lines deleted | Outcome |
|----|--------|--------------|---------|
| C1 | `scanner_orchestration/` non-active subdirs | ~1,400 | Verified deletion |
| C2 | `validation/tasks/`, `validation/adapters/`, `investigation_workspace/adaptive/`, CVE engines | 0 | All targets ACTIVE-LEGACY — documented-only |
| C3 | `investigation_core/`* (11 subdirs) + `investigation_workspace/feed/` | 0 | All targets ACTIVE-LEGACY — documented-only |
| C4 | `validation/services/` (minus metasploit) | 0 | SKIPPED — predicted ACTIVE-LEGACY based on C2/C3 pattern; not attempted |

---

## What was deleted (C1)

10 modules deleted from `apps/scanner_orchestration/`. Full detail in `decisions-log-c1.md`.

| Deleted | Reason |
|---------|--------|
| `monitoring/` | Zero external callers |
| `profiles/` | Zero external callers |
| `timeline/` | Zero external callers |
| `execution/run.py` | Zero external callers (`models.py` kept) |
| `target_resolution/docker.py` | Zero external callers |
| `target_resolution/resolver.py` | Zero external callers |
| `target_resolution/diagnostics.py` | Zero external callers |
| `target_resolution/validation.py` | Zero external callers |
| `normalization/pipeline.py` | Zero external callers |
| `normalization/cve_enricher.py` | Zero external callers |

Retained with documented callers: `services/orchestration_service.py` (4 callers),
`target_resolution/ssrf_guard.py` (1 caller).

---

## What was reclassified (C2 + C3)

19 modules reclassified from VESTIGE to ACTIVE-LEGACY. Full caller maps in `decisions-log-c2.md`
and `decisions-log-c3.md`.

**C2 — 7 modules:**

| Module | Strongest caller |
|--------|----------------|
| `validation/tasks/` | `queue.py` → live `POST /queue/run-lifecycle` |
| `validation/adapters/nmap.py` | `services/scanner.py` |
| `validation/adapters/recon_ng.py` | `services/recon.py` |
| `investigation_workspace/adaptive/guidance.py` | `feed/builder.py` → live workspace API |
| `investigation_workspace/adaptive/insights.py` | `feed/builder.py` → live workspace API |
| `validation/engines/cve_matcher.py` | `known_issues.py` + `correlator.py` |
| `validation/engines/nvd_sync.py` | `settings_router.py` → live Settings panel |

**C3 — 12 modules:**

| Module | Strongest caller |
|--------|----------------|
| `investigation_core/progression/` | `skill_routes.py` (live) + `scanner_orchestration/api` |
| `investigation_core/lifecycle/` | `investigation_service.py` → live routes |
| `investigation_core/taxonomy/` | `investigation_core/api/routes.py` (live) |
| `investigation_core/models/` | All live investigation_core services |
| `investigation_core/campaigns/` | `campaign_routes.py` (live route) |
| `investigation_core/memory/` | `feed/builder.py`, `adaptive/` |
| `investigation_core/learning/` | `investigation_core/api/routes.py` (live) |
| `investigation_core/defensive/` | `investigation_workspace/api/routes.py` × 9 call sites |
| `investigation_core/evidence/` | `investigation_workspace/api/routes.py` × 6, `scanner_orchestration`, `validation/api` |
| `investigation_core/skills/` | `skill_routes.py` (live route) |
| `investigation_core/intelligence/` | `investigation_workspace/api/routes.py`, `branch/assembler.py` × 5 |
| `investigation_workspace/feed/` | `investigation_workspace/api/routes.py` × 2 |

---

## ACTIVE-LEGACY definition (canonical)

Code that doesn't fit current Conductor architecture but is wired into live API or service routes.
Cannot be safely deleted without first removing or refactoring the consuming routes.

Distinct from:
- **VESTIGE** — zero callers anywhere. Safe to delete with pre-deletion grep verification.
- **AMBIGUOUS-RETAINED** — callers confirmed, but call chain not yet fully traced to a live route.
- **ACTIVE-LEGACY** — call chain traced all the way to an operator-accessible endpoint.
- **DORMANT_V2** — planned for V2.x activation per CLAUDE.md roadmap.

---

## Audit failure mode

The stage-2 code audit (`/docs/audits/legacy-classification.md`) used architecture-fit heuristics
to classify modules as VESTIGE: if a module had no Conductor pipeline callers, it was flagged for
deletion. This missed two critical registration points:

**C2 miss:** `validation/api/` routes (`queue.py`, `settings_router.py`, `known_issues.py`, etc.)
directly use `validation/tasks/`, `validation/adapters/`, `validation/engines/` (CVE), and
`investigation_workspace/adaptive/`. These are live operator-visible routes.

**C3 miss:** `investigation_core_router` is registered in `validation/api/__init__.py:22`:
```python
from apps.investigation_core.api import router as investigation_core_router
validation_router.include_router(investigation_core_router)
```
This makes all 6 sub-routers under `/api/v1/validation/investigation-core/` live, pulling in
`campaigns/`, `evidence/`, `skills/`, `progression/`, and transitively every module they import.

Without pre-deletion grep checks, C2 and C3 would have deleted **~5,295 lines of live code**,
breaking the Settings panel, the skills/evidence/campaign routes, and the workspace feed.

**Operational rule established:** Pre-deletion grep against the full codebase is mandatory for any
cleanup PR. Architecture-fit heuristics are not sufficient evidence for VESTIGE classification.

---

## Future work: Legacy Workspace Deprecation Sprint

The ACTIVE-LEGACY discoveries identify the legacy investigation workspace as the real cleanup
target. Its scope:

- `apps/investigation_workspace/api/routes.py` (~2,600 lines)
- All routes under `/api/v1/validation/investigation-core/` (campaigns, evidence, skills, exports, guided actions, core)
- 19 ACTIVE-LEGACY backend modules documented in `decisions-log-c2.md` and `decisions-log-c3.md`
- Frontend templates that consume these routes (queue, assets, known_issues, changes, custom_report, history, settings)

Approach when the sprint is scheduled:
1. Identify which legacy workspace pages the operator actively uses (currently unknown)
2. Migrate needed functionality to current Conductor architecture
3. Deprecate legacy routes one by one as functionality moves
4. Delete the underlying ACTIVE-LEGACY code only after its consuming routes are removed

**Not scheduled.** Will be addressed when V2 design surfaces the need, likely V2.5+ scope.

---

## What this means for V2

The codebase splits cleanly into three zones:

| Zone | Contents | Action |
|------|----------|--------|
| **Current Conductor** | `apps/conductor/`, `apps/scanner_orchestration/adapters/`, `apps/admin_ui/`, Conductor parts of `investigation_workspace/` | Extend for V2 |
| **ACTIVE-LEGACY** | `validation/api/`, `validation/services/` (incl. Metasploit stack — routes live, operator-driven), `investigation_core/*` (incl. `guided_actions/` — live via `investigation_core_router`), `investigation_workspace/api/`, `investigation_workspace/suggestions/` (live exploitation execution layer), `investigation_workspace/probe/` | Leave alone; deprecation sprint deferred |
| **DORMANT_V2** | `exports/vault/`, `exporters/` | Activate as V2.x milestones arrive |

_Corrections from V2 design audit (2026-05-26):_ `guided_actions/` was incorrectly listed as DORMANT_V2 above — C3 confirmed it is ACTIVE-LEGACY (live via `investigation_core_router`). Metasploit infrastructure was incorrectly listed as DORMANT_V2 — C4 predicted ACTIVE-LEGACY and V2 audit confirmed the routes and operator UI are live. `investigation_workspace/suggestions/` (the active exploitation probe layer, 5,400+ lines) was unlisted — it is ACTIVE-LEGACY, dispatched by `investigation_workspace/api/routes.py`.

V2 work must NOT attempt to delete ACTIVE-LEGACY modules incidentally. Any such deletion
requires a redirect PR first (remove the consuming routes, then delete the modules). That work
belongs in the deprecation sprint, not in V2 feature PRs.
