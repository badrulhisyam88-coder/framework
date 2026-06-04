# PR VESTIGE-3 — Investigation Core Category 3 Vestiges

**Date:** 2026-05-26
**Outcome:** DOCUMENT-ONLY — zero file changes. All 12 targets reclassified ACTIVE-LEGACY.
**Precedent:** decisions-log-c1.md (AMBIGUOUS-RETAINED), decisions-log-c2.md (ACTIVE-LEGACY).

---

## Classification taxonomy

- **VESTIGE**: zero callers. Safe to delete.
- **AMBIGUOUS-RETAINED**: callers found, call chain not fully traced.
- **ACTIVE-LEGACY**: callers found in live API or service layer.
- **DORMANT_V2**: planned for V2.x activation per CLAUDE.md roadmap.

---

## Pre-deletion test baseline

1 failed, 396 passed, 11 skipped, 17 errors
(Unchanged from C1/C2 baselines. The 1 failure and 17 errors are pre-existing.)

---

## Critical finding: investigation_core/api/ IS registered

The stage-2 audit assumed investigation_core/api/ routes were unregistered (dead).
This is wrong. `apps/validation/api/__init__.py:3–22` shows:

```python
from apps.investigation_core.api import router as investigation_core_router
validation_router.include_router(investigation_core_router)
```

`investigation_core_router` itself composes 6 sub-routers (from `investigation_core/api/__init__.py`):
- `routes.py` → core routes
- `evidence_routes.py` → imports from `evidence/`
- `guided_action_routes.py` → imports from `guided_actions/` (stage-2 audit label: DORMANT_V2 — overridden by C3; current classification: ACTIVE-LEGACY)
- `skill_routes.py` → imports from `skills/`, `progression/`
- `export_routes.py` → imports from `exports/` (stage-2 audit label: DORMANT_V2 — overridden by C3; current classification: ACTIVE-LEGACY)
- `campaign_routes.py` → imports from `campaigns/`

All 6 are mounted under `/api/v1/validation/investigation-core`.
Every module those routes import is at minimum ACTIVE-LEGACY.

This also explains why investigation_workspace/api/routes.py has so many callers of `evidence/`,
`defensive/`, `intelligence/` — the workspace API is also registered through `validation_router`.

---

## Per-target classification

### `apps/investigation_core/progression/` — ACTIVE-LEGACY

| Caller (external) | Line | Source |
|---|---|---|
| `apps/validation/api/investigations.py` | 663 | `progression.storage.mastery_repo.MasteryRepository` |
| `apps/scanner_orchestration/api/routes.py` | 341 | `progression.storage.mastery_repo.MasteryRepository` |
| `apps/scanner_orchestration/services/orchestration_service.py` | 465 | `progression.tracking.mastery_tracker` |
| `apps/investigation_core/api/skill_routes.py` | 12–13 | `progression.models.mastery`, `progression.tracking.mastery_tracker` (live route) |

Also called by: `evidence_service.py`, `guided_actions/`, `exports/`, `memory_service.py`, `feed/builder.py`.

---

### `apps/investigation_core/lifecycle/` — ACTIVE-LEGACY

| Caller (external) | Line | Source |
|---|---|---|
| `apps/investigation_core/services/investigation_service.py` | 10 | `lifecycle.state_machine.InvestigationStateMachine` |

`investigation_service.py` is used by `investigation_core/api/routes.py` (live endpoint) and
`validation/api/investigations.py` (live). Lifecycle is transitively live.

---

### `apps/investigation_core/taxonomy/` — ACTIVE-LEGACY

| Caller (external) | Line | Source |
|---|---|---|
| `apps/investigation_core/api/routes.py` | 18 | `taxonomy.stages` (live route) |
| `apps/investigation_core/storage/timeline_repo.py` | 11 | `taxonomy.stages.EventType` (live storage) |
| `apps/investigation_core/services/investigation_service.py` | 21 | `taxonomy.stages` (live service) |

Also used by: `models/timeline.py`, `progression/`, `evidence_service.py`, `lifecycle/`,
`exports/`, `guided_actions/`, `timeline/recorder.py`.

---

### `apps/investigation_core/models/` — ACTIVE-LEGACY

Used by investigation_core `learning/`, `storage/`, `services/`, `timeline/recorder.py` — all
transitively live. No direct external app caller, but every live investigation_core service
depends on models/investigation.py, models/timeline.py, models/learning.py.

---

### `apps/investigation_core/campaigns/` — ACTIVE-LEGACY

| Caller (external) | Line | Source |
|---|---|---|
| `apps/investigation_core/api/campaign_routes.py` | 14–264 | `campaigns.models`, `campaigns.services.campaign_service` (live route) |

`campaign_routes.py` is mounted and served at `/api/v1/validation/investigation-core/campaigns/…`.

---

### `apps/investigation_core/memory/` — ACTIVE-LEGACY

| Caller (external) | Line | Source |
|---|---|---|
| `apps/investigation_workspace/feed/builder.py` | 73 | `memory.services.memory_service.MemoryService` |
| `apps/investigation_workspace/adaptive/insights.py` | 10 | `memory.models.memory` |
| `apps/investigation_workspace/adaptive/guidance.py` | 12–13 | `memory.categories`, `memory.models.memory` |

`feed/builder.py` and `adaptive/` are ACTIVE-LEGACY (themselves called from live workspace routes).
`defensive/` also calls `memory/` (posture_service, maturity_calculator).

---

### `apps/investigation_core/learning/` — ACTIVE-LEGACY

| Caller (external) | Line | Source |
|---|---|---|
| `apps/investigation_workspace/feed/builder.py` | 72 | `learning.path_registry` |
| `apps/investigation_core/api/routes.py` | 16 | `learning.path_registry` (live route) |
| `apps/investigation_core/services/investigation_service.py` | 9, 193, 217 | `learning.recommendation_engine`, `learning.path_registry` |

---

### `apps/investigation_core/defensive/` — ACTIVE-LEGACY (high-traffic)

| Caller (external) | Line | Source |
|---|---|---|
| `apps/investigation_workspace/api/routes.py` | 2161, 2162, 2201, 2202, 2467, 2468, 2506, 2507, 2536 | `defensive.models.posture`, `defensive.services.posture_service` |
| `apps/investigation_workspace/branch/assembler.py` | 71, 74 | `defensive.models.posture`, `defensive.services.posture_service` |

**9 call sites in the live workspace API alone.** Operator prediction ("likely VESTIGE") was
significantly wrong — defensive is deeply wired into active workspace routes.

---

### `apps/investigation_core/evidence/` — ACTIVE-LEGACY (high-traffic)

| Caller (external) | Line | Source |
|---|---|---|
| `apps/investigation_workspace/api/routes.py` | 51, 1113, 2253, 2360–2364, 2620 | `evidence.models.artifact`, `evidence.services.evidence_service`, `evidence.validation.rules` |
| `apps/scanner_orchestration/services/orchestration_service.py` | 12, 13, 458 | `evidence.models.artifact`, `evidence.services.evidence_service`, `evidence.storage.artifact_repo` |
| `apps/investigation_workspace/branch/assembler.py` | 78 | `evidence.storage.artifact_repo` |
| `apps/validation/api/investigations.py` | 660 | `evidence.storage.artifact_repo` |
| `apps/investigation_core/api/evidence_routes.py` | 10–15 | (live route) |
| `apps/investigation_workspace/feed/lifecycle.py` | 20 | `evidence.models.artifact.EvidenceArtifact` |

Evidence is the most-called target: live workspace API, live scanner_orchestration, live validation
API, and a dedicated live route. Cannot be deleted without removing the workspace itself.

---

### `apps/investigation_core/skills/` — ACTIVE-LEGACY

| Caller (external) | Line | Source |
|---|---|---|
| `apps/investigation_core/api/skill_routes.py` | 15–16 | `skills.graph.skill_graph`, `skills.recommendations.skill_recommender` (live route) |
| `apps/investigation_core/progression/` | internal | `skills.graph.skill_graph`, `skills.models.skill` |

Live route at `/api/v1/validation/investigation-core/skills/…`.

---

### `apps/investigation_core/intelligence/` — ACTIVE-LEGACY (high-traffic)

| Caller (external) | Line | Source |
|---|---|---|
| `apps/investigation_workspace/api/routes.py` | 2565 | `intelligence.engine` (live route) |
| `apps/investigation_workspace/branch/assembler.py` | 87, 91, 184, 249, 416 | `intelligence.clusters`, `intelligence.engine` |
| `apps/investigation_workspace/branch/corridors.py` | 104, 146 | `intelligence.clusters` |
| `apps/investigation_workspace/feed/builder.py` | 432, 433 | `intelligence.clusters`, `intelligence.engine` |

---

### `apps/investigation_workspace/feed/` — ACTIVE-LEGACY

| Caller (external) | Line | Source |
|---|---|---|
| `apps/investigation_workspace/api/routes.py` | 2067, 2263 | `feed.unlock_rules`, `feed.interpretations` |
| `apps/investigation_workspace/branch/assembler.py` | 37, 38 | `feed.interpretations`, `feed.lifecycle` |
| `apps/investigation_core/memory/services/memory_service.py` | 276, 322 | `feed.interpretations` |
| `apps/investigation_workspace/adaptive/guidance.py` | 17, 92 | `feed.models`, `feed.interpretations` |

Operator prediction ("likely VESTIGE") was wrong — live workspace routes at lines 2067 and 2263
depend on `feed.unlock_rules` and `feed.interpretations` directly.

---

## Summary table

| Target | Classification | Key callers | Action |
|--------|---------------|-------------|--------|
| `investigation_core/progression/` | ACTIVE-LEGACY | `skill_routes.py` (live), `investigations.py`, `scanner_orchestration/api` | RETAIN |
| `investigation_core/lifecycle/` | ACTIVE-LEGACY | `investigation_service.py` → live routes | RETAIN |
| `investigation_core/taxonomy/` | ACTIVE-LEGACY | `api/routes.py` (live), storage, services | RETAIN |
| `investigation_core/models/` | ACTIVE-LEGACY | All live investigation_core services | RETAIN |
| `investigation_core/campaigns/` | ACTIVE-LEGACY | `campaign_routes.py` (live route) | RETAIN |
| `investigation_core/memory/` | ACTIVE-LEGACY | `feed/builder.py`, `adaptive/` (both ACTIVE-LEGACY) | RETAIN |
| `investigation_core/learning/` | ACTIVE-LEGACY | `api/routes.py` (live), `feed/builder.py` | RETAIN |
| `investigation_core/defensive/` | ACTIVE-LEGACY | `workspace/api/routes.py` ×9 (live) | RETAIN |
| `investigation_core/evidence/` | ACTIVE-LEGACY | `workspace/api/routes.py` ×6, live scanner_orch, validation | RETAIN |
| `investigation_core/skills/` | ACTIVE-LEGACY | `skill_routes.py` (live route) | RETAIN |
| `investigation_core/intelligence/` | ACTIVE-LEGACY | `workspace/api/routes.py`, `branch/assembler.py` | RETAIN |
| `investigation_workspace/feed/` | ACTIVE-LEGACY | `workspace/api/routes.py` ×2 (live) | RETAIN |

Zero deletions. All 12 targets reclassified ACTIVE-LEGACY.

---

## investigation_core/storage/ status

`investigation_repo.py`, `learning_repo.py`, `timeline_repo.py` confirmed ACTIVE-LEGACY:
- `scanner_orchestration/api/routes.py` (live) uses `timeline_repo`
- `scanner_orchestration/services/orchestration_service.py` uses `learning_repo`
- `validation/api/investigations.py` (live) uses `investigation_repo`

---

## investigation_core/timeline/recorder.py status

`TimelineRecorder` is used by: `evidence_service.py`, `services/investigation_service.py`,
`exports/export_service.py`, `guided_actions/approval_service.py`, `progression/mastery_tracker.py`.

No direct external-app callers, but all callers are transitively ACTIVE-LEGACY.
`timeline/` (including `recorder.py`) is ACTIVE-LEGACY. Do not delete.

---

## scanner_orchestration/services/ re-evaluation

Feed/ was NOT deleted in C3 (it's ACTIVE-LEGACY). `feed/builder.py` still calls
`OrchestrationService` at line 76.

Callers of `scanner_orchestration/services/orchestration_service.py` are unchanged:
- `validation/api/investigations.py:368` — ACTIVE-LEGACY (live route)
- `validation/api/investigations.py:666` — ACTIVE-LEGACY (live route)
- `investigation_workspace/feed/builder.py:76` — ACTIVE-LEGACY
- `investigation_workspace/branch/assembler.py:93` — ACTIVE-LEGACY

`scanner_orchestration/services/` remains **ACTIVE-LEGACY**. Status unchanged from C1.

---

## Root cause

Same as C2: the stage-2 audit used architecture-fit heuristics (not a live caller graph).
The learning-platform code (`evidence/`, `defensive/`, `intelligence/`, etc.) is deeply wired
into the live investigation workspace API (`investigation_workspace/api/routes.py`), which is
registered and serving traffic through `validation_router`. The audit missed the
`investigation_core_router` registration in `validation/api/__init__.py`.

**Operator predictions vs actual:**

| Module | Prediction | Actual |
|--------|-----------|--------|
| `progression/`, `lifecycle/`, `taxonomy/`, `models/`, `memory/`, `learning/`, `skills/`, `intelligence/` | VESTIGE | ACTIVE-LEGACY |
| `defensive/` | VESTIGE | ACTIVE-LEGACY (9 live workspace call sites) |
| `campaigns/`, `evidence/` | possibly ACTIVE-LEGACY | ACTIVE-LEGACY (confirmed) |
| `feed/` | VESTIGE | ACTIVE-LEGACY (2 live workspace call sites) |

---

## Architecture doc check

`docs/architecture/system.md` and `docs/architecture/seams.md` do not reference
investigation_core sub-modules by path. No architecture doc updates required.

---

## Path to a future VESTIGE-4

No module in investigation_core/ can be deleted without first unwiring its callers from:
1. `investigation_workspace/api/routes.py` (the main workspace route, ~2,600 lines)
2. `investigation_core/api/` (live sub-routers for campaigns, evidence, skills, exports)
3. `investigation_workspace/branch/assembler.py` and `corridors.py`

Deletion of investigation_core learning-platform code would require removing the investigation
workspace entirely or replacing all of its feature dependencies. That is full-product scope,
not vestige cleanup. No VESTIGE-4 path is available without a product decision to remove the
legacy workspace features.
