# PR VESTIGE-1 — Scanner Orchestration Cleanup

**Date:** 2026-05-26
**Scope:** `apps/scanner_orchestration/` vestige removal (Option 1 — confirmed-clean only)

---

## Deleted

| Path | Reason |
|------|--------|
| `apps/scanner_orchestration/monitoring/` | Zero external callers. Dead since Conductor replaced the legacy scan loop. |
| `apps/scanner_orchestration/profiles/` | Zero external callers. Scan profile config superseded by engine gate registry. |
| `apps/scanner_orchestration/timeline/` | Zero external callers. Timeline events superseded by EventBus. |
| `apps/scanner_orchestration/execution/run.py` | Zero external callers. Execution path superseded by ExecutionOrchestrator. `execution/models.py` kept. |
| `apps/scanner_orchestration/target_resolution/docker.py` | Zero external callers. |
| `apps/scanner_orchestration/target_resolution/resolver.py` | Zero external callers. `TargetResolver` removed from `target_resolution/__init__.py`. |
| `apps/scanner_orchestration/target_resolution/diagnostics.py` | Zero external callers. |
| `apps/scanner_orchestration/target_resolution/validation.py` | Zero external callers. |
| `apps/scanner_orchestration/normalization/pipeline.py` | Zero external callers. `NormalizationPipeline` removed from `normalization/__init__.py`. |
| `apps/scanner_orchestration/normalization/cve_enricher.py` | Zero external callers. CVE chain dropped in PR G. |

**Also updated:** `target_resolution/__init__.py`, `normalization/__init__.py` — removed dead re-exports.

---

## Retained (AMBIGUOUS — active external callers)

### `apps/scanner_orchestration/services/` (entire directory)

**Reason retained:** `orchestration_service.py` has 4 active external callers.

| Caller | What it calls |
|--------|--------------|
| `apps/validation/api/investigations.py:368` | `OrchestrationService.list_runs()`, `list_run_findings()` — backfills `investigation_id` on legacy summary cards |
| `apps/validation/api/investigations.py:666` | Same, second code path |
| `apps/investigation_workspace/feed/builder.py:76` | `OrchestrationService` used in `FeedBuilder` for finding data |
| `apps/investigation_workspace/branch/assembler.py:93` | `OrchestrationService.list_all_findings()` used in `BranchAssembler` |

**Next step (deferred):** Assess whether these callers can be redirected to `NormalizedFindingRepository` (Conductor pipeline) or dropped (legacy compat only). Redirect is V2-prep scope.

### `apps/scanner_orchestration/target_resolution/ssrf_guard.py`

**Reason retained:** 1 active external caller.

| Caller | What it calls |
|--------|--------------|
| `apps/validation/api/discovery.py:84` | `validate_target(target)` — SSRF guard on deprecated SSE scan-stream endpoint |

**Note:** The endpoint is marked "backward compatibility only; will be removed in a future release." When that endpoint is removed, `ssrf_guard.py` can be deleted with it.

---

## Verification

- **External caller grep:** All 12 target module paths grepped against codebase. Zero external importers confirmed for all deleted modules.
- **`__init__.py` cleanup:** `target_resolution` and `normalization` `__init__.py` updated; dead re-exports removed.
- **Test baseline:** 396 pass, 0 regressions introduced. Pre-existing failures unchanged (pydantic/fastapi not installed outside Docker).
- **Ruff:** Pre-existing E501 in `finding_repo.py:159` unchanged. No new errors.

---

## Classification cross-reference

C1 retained items (`services/orchestration_service.py`, `target_resolution/ssrf_guard.py`) were
classified here as **AMBIGUOUS-RETAINED** — callers confirmed, but not yet traced to a live
operator-facing route.

PR VESTIGE-2 (decisions-log-c2.md) introduced a finer distinction:

**ACTIVE-LEGACY** — code that is old and non-Conductor but has confirmed live callers traced
all the way to an operator-visible endpoint. The C2 targets (validation/tasks/, validation/adapters/,
investigation_workspace/adaptive/, cve_matcher.py, nvd_sync.py) are ACTIVE-LEGACY, not VESTIGE.

The C1 retained items may be ACTIVE-LEGACY as well once their call chains are fully traced.
`orchestration_service.py` is called from `feed/builder.py` and `branch/assembler.py` — both
part of the live investigation workspace. Likely ACTIVE-LEGACY; update if confirmed.
