# V1 Investigation Execution Architecture Audit

**Date:** 2026-05-24  
**Scope:** Read-only. No code changes.  
**Purpose:** Ground truth on the current execution architecture before planning a structured phased-execution refactor.

---

## Executive Summary

V1 shipped phase **classification** (finding tagging + pane routing) but did **not** ship sequential phased execution. The underlying execution model is the Phase 41–44 concurrent bootstrap: all five probes start simultaneously via `asyncio.gather`, and their findings arrive at roughly the same wall-clock time. The Recon / Enumeration phase tabs are a rendering overlay applied to these concurrent results — they do not reflect when probes ran relative to each other.

The "Bootstrap" concept is the **active execution model**, not vestige. The sidebar Bootstrap item, the stage transcript, and the in-memory `BootstrapRun` object are the ground truth for what ran and when. Phase tags describe the nature of the findings; they do not control sequencing.

---

## Section 1 — Current Execution Flow (End-to-End)

### 1.1 Trigger Chain

Probe execution is auto-triggered when the workspace is viewed and has no findings yet. There are three entry points, all sharing the same `_view_is_empty` guard.

**Entry point 1** — `GET /investigations/{id}/branches/topology.json`  
`routes.py:361`:
```python
if _view_is_empty(view):
    await _ensure_bootstrap_running(investigation_id, target)
```

**Entry point 2** — `GET /investigations/{id}/workspace-data.json`  
`routes.py:395`:
```python
if _view_is_empty(view):
    await _ensure_bootstrap_running(investigation_id, target)
```

**Entry point 3** — `GET /investigations/{id}` (HTML page render)  
`apps/validation/api/investigations.py:726–752`:  
The HTML render route assembles the workspace data to pre-populate the server-rendered `ws-initial-data` script tag. It calls `_build_workspace_data` with the bootstrap run (if any), but does **not** call `_ensure_bootstrap_running`. Execution is never auto-triggered from the page render — only from the JSON polling endpoints.

**`_view_is_empty` definition** (`routes.py:1062–1066`):
```python
def _view_is_empty(view) -> bool:
    for branch in view.branches:
        if branch.root.children:
            return False
    return True
```
Returns `True` when no branch has any discoveries below its surface root. This is `False` on any subsequent poll once at least one finding has been persisted to the DB — even if bootstrap is still running. The condition is checked on **every** request, not just the first.

**`_ensure_bootstrap_running` idempotency** (`bootstrap/runtime.py:129–131`):
```python
existing = _RUNS.get(investigation_id)
if existing is not None:
    return existing
```
`kick_off` is idempotent. Multiple concurrent requests calling `_ensure_bootstrap_running` on the same investigation all rejoin the same run. Bootstrap fires exactly once per process lifetime per investigation.

**First poll vs subsequent polls:**  
- **First poll** (empty view): `_view_is_empty` is `True` → `_ensure_bootstrap_running` is called → `kick_off` starts the concurrent runner → `asyncio.create_task(_runner(...))` returns immediately → re-assembles the (still mostly empty) view → returns workspace data with `is_bootstrap_running: true`.  
- **Subsequent polls**: `_view_is_empty` is `False` (findings now in DB) → `_ensure_bootstrap_running` is skipped → topology assembled from persisted findings → returns updated workspace data.  
- **Process restart**: `_RUNS` is wiped. Next poll hits `_view_is_empty = False` (findings exist in DB) so bootstrap does **not** re-trigger. Stage transcript is permanently gone; findings survive.

---

### 1.2 Probe Registry

**Definition location:** `bootstrap/runtime.py:202–203`

```python
probe_fns = (run_passive_probe, run_sqli_recon_probe, run_cmdi_recon_probe,
             run_auth_recon_probe, run_api_recon_probe)
```

All five probes are defined in `apps/investigation_workspace/probe/`. Their display labels are mapped at `runtime.py:173–179`:

| Probe function | Display label | Module |
|---|---|---|
| `run_passive_probe` | "Headers & Transport" | `probe/passive.py` |
| `run_sqli_recon_probe` | "SQL Injection" | `probe/sqli_recon.py` |
| `run_cmdi_recon_probe` | "Command Injection" | `probe/cmdi_recon.py` |
| `run_auth_recon_probe` | "Login Forms" | `probe/auth_recon.py` |
| `run_api_recon_probe` | "API Security" | `probe/api_recon.py` |

**Function signatures — all probes accept only `target: str`:**

```python
# passive.py:45
async def run_passive_probe(target: str) -> AsyncIterator[StageEvent | FindingEvent]:

# sqli_recon.py:88
async def run_sqli_recon_probe(target: str) -> AsyncIterator[StageEvent | FindingEvent]:

# cmdi_recon.py:127
async def run_cmdi_recon_probe(target: str) -> AsyncIterator[StageEvent | FindingEvent]:

# auth_recon.py:201
async def run_auth_recon_probe(target: str) -> AsyncIterator[StageEvent | FindingEvent]:

# api_recon.py:137
async def run_api_recon_probe(target: str) -> AsyncIterator[StageEvent | FindingEvent]:
```

No probe accepts findings, a DB session, or the output of another probe. Each takes a raw URL string and operates independently.

**Emission counts per probe:**

| Probe | Stages emitted | FindingEvents emitted | Notes |
|---|---|---|---|
| `run_passive_probe` | Always 6 | 1–6 | Always emits `http_service_detected`; up to 5 `missing_*_header` |
| `run_sqli_recon_probe` | Always 2 | 0 or 1 | Quiet on negative (no finding if no login endpoints found) |
| `run_cmdi_recon_probe` | Always 2 | 0 or 1 | Quiet on negative |
| `run_auth_recon_probe` | Always 2 | 0 or 1 | Quiet on negative |
| `run_api_recon_probe` | Always 2 | 0 or 1 | Quiet on negative |

Total stages per bootstrap run: 14 (6 + 2 + 2 + 2 + 2). This is the origin of the "14 stages" in the sidebar description.

---

### 1.3 Execution Mechanics

**Invocation** (`runtime.py:259–261`):
```python
await asyncio.gather(*(_run_one_probe(fn) for fn in probe_fns))
run.completed_at = time.time()
```

All five probes start simultaneously as coroutines. `asyncio.gather` suspends until all five complete. There is no sequencing gate; no probe waits for another.

**Per-probe event consumption** (`_run_one_probe`, `runtime.py:205–257`):

The inner loop processes events from each probe's async generator:

- **StageEvent** (`runtime.py:214–219`):
  1. `_make_stage_from_event(evt, probe_name)` → `StageState`
  2. `run.stages.append(stage)` — appended to the **shared** stage list (interleaved with other probes)
  3. `await asyncio.sleep(STAGE_DELAY_S)` — yields control for 1.3 seconds
  4. `stage.completed_at = time.time()` — marks stage complete

- **FindingEvent** (`runtime.py:221–241`):
  1. `persist_finding(evt)` → async DB insert (via callback)
  2. On success: `run.discoveries.append(DiscoveryState(spec=evt, finding_id=fid, ...))`
  3. Spawned attribution: translates `evt.after_stage_index` (0-based within probe) to global list position via `probe_stage_start` offset recorded at probe entry (`runtime.py:211`)

**Stage interleaving note:** Because all probes run concurrently and each `asyncio.sleep(1.3)` yields, stages from different probes are interleaved in `run.stages` in arrival order. The `probe_name` field on each `StageState` is the only way to reconstruct per-probe timelines from the flat list.

**Finding persistence** (`_persist` callback, `routes.py:1081–1145`):

The callback is defined inline in `_ensure_bootstrap_running`. For each `FindingEvent`:
1. Creates one `ScanExecution` record per investigation (lazy, with `scanner_type="passive_probe"`, `profile="bootstrap_probe"`) — shared by all five probes' findings.
2. Creates one `NormalizedFinding` per event:
   - `source_scanner = "passive_probe"` (same for all bootstrap findings, regardless of which probe emitted them)
   - `tags = ["passive_probe", "bootstrap", f"phase:{evt.phase}"]`
   - `raw_data = {**(evt.evidence or {}), "_phase": evt.phase}`
3. Calls `InvestigationService.record_finding_detected(...)` for bookkeeping

**Critical detail:** All five probes' findings are written under a single `ScanExecution` record with `scanner_type="passive_probe"`. There is no per-probe execution record and no per-phase execution record in the DB.

---

### 1.4 Run Lifecycle

**`BootstrapRun` data structure** (`runtime.py:81–88`):
```python
@dataclass
class BootstrapRun:
    run_id:           str                  # 12-char hex UUID
    investigation_id: str
    target:           str                  # canonical URL probed
    started_at:       float                # Unix timestamp
    completed_at:     float | None = None  # None while running
    stages:           list[StageState]     # all stages from all probes, interleaved
    discoveries:      list[DiscoveryState] # all persisted findings
```

**Lifecycle states:**

| State | Condition | `is_active()` | `is_visible()` |
|---|---|---|---|
| Not started | `_RUNS.get(inv_id) is None` | False | False |
| Running | `completed_at is None` | True | True |
| Completed | `completed_at is not None` | False | True |
| Process restart | `_RUNS` wiped | False | False |

`is_active` (`runtime.py:102–105`): `run.completed_at is None`  
`is_visible` (`runtime.py:108–110`): `_RUNS.get(investigation_id) is not None` — **True forever** post-completion within the same process lifetime (Phase 42: no GC).

**"Bootstrap is running" signal — two sources:**

1. **Frontend JSON field** (`routes.py:741`): `"is_bootstrap_running": boot_run is not None and boot_run.completed_at is None` — computed from in-memory `BootstrapRun.completed_at`.
2. **Topology meta** (`topology_v2.py:195`): `"has_active_bootstrap": bootstrap_is_active(view.investigation_id)` — same logic, different field name, used by the topology JSON endpoint.

These are consistent. There is no DB flag for bootstrap state; it is entirely in-memory.

**Frontend polling lifecycle** (`workspace.js:445`):
```javascript
var live = data.is_bootstrap_running || data.has_active_execution;
if (live) { _pollTimer = setTimeout(_poll, 1100); } else { _pollTimer = null; }
```
Polling continues at 1.1s intervals while either bootstrap or a probe execution is active. Both must be False for polling to stop.

---

## Section 2 — Phase Metadata Layer

### 2.1 Where Phase Tags Are Applied (Probe Side)

Phase is a hardcoded literal on each `FindingEvent` emission. The `FindingEvent.phase` field is typed `Phase = Literal["recon", "enumeration", "exploitation"]` (`events.py:15`).

| Probe | Finding type | Phase value | File:line |
|---|---|---|---|
| `run_passive_probe` | `http_service_detected` | `"recon"` | `passive.py:189` |
| `run_passive_probe` | `missing_csp_header` | `"recon"` | `passive.py:218` |
| `run_passive_probe` | `missing_hsts_header` | `"recon"` | `passive.py:218` |
| `run_passive_probe` | `missing_x_frame_options` | `"recon"` | `passive.py:218` |
| `run_passive_probe` | `missing_x_content_type_options` | `"recon"` | `passive.py:218` |
| `run_passive_probe` | `missing_referrer_policy` | `"recon"` | `passive.py:218` |
| `run_sqli_recon_probe` | `sqli` | `"enumeration"` | `sqli_recon.py:158` |
| `run_cmdi_recon_probe` | `command_injection` | `"enumeration"` | `cmdi_recon.py:201` |
| `run_auth_recon_probe` | `login_form_detected` | `"enumeration"` | `auth_recon.py:266` |
| `run_api_recon_probe` | `api_exposure` | `"enumeration"` | `api_recon.py:230` |

No probe emits `phase = "exploitation"` — the exploitation phase is operator-triggered only.

**`StageEvent` and `ResultEvent` carry no phase field.** `StageEvent` (`events.py:19–29`) has no `phase` attribute. `ResultEvent` (`events.py:51+`) has no `phase` attribute. Phase tagging is applied exclusively to `FindingEvent`.

---

### 2.2 Where Phase Tags Are Persisted

**`_persist` callback** (`routes.py:1132`):
```python
raw_data = {**(evt.evidence or {}), "_phase": evt.phase},
```
The phase tag is merged into `raw_data` alongside the probe's evidence dict. It is stored as the key `"_phase"` (underscore prefix marks it as internal metadata).

**Also in `tags` list** (`routes.py:1131`):
```python
tags = ["passive_probe", "bootstrap", f"phase:{evt.phase}"],
```
The `tags` column receives a `"phase:recon"` or `"phase:enumeration"` string. This is a duplicate channel — the tag array and `raw_data["_phase"]` carry the same value.

---

### 2.3 Where Phase Tags Are Consumed

**Primary consumer** — `workspace_data_json` route (`routes.py:403–430`):
```python
for f in findings:
    raw = f.raw_data or {}
    if isinstance(raw, dict):
        p = raw.get("_phase")
        if p:
            phase_map[f.finding_id] = p
```
Builds `phase_map: dict[str, str]` (finding_id → phase). Missing `_phase` produces no map entry.

**Phase bucketing** in `_build_workspace_data` (`routes.py:724`):
```python
phase_key = _phase_map.get(fid, "recon")
```
Falls back to `"recon"` for any finding without a `_phase` entry. This is the only default.

**The `tags` field** carrying `"phase:recon"` / `"phase:enumeration"` is **not consumed anywhere** in `routes.py`, `topology_v2.py`, the assembler, or the frontend. It is written but never read.

**No other code reads `raw_data["_phase"]` or `tags["phase:*"]`** outside of `workspace_data_json` and `_build_workspace_data`. The topology builder (`topology_v2.py`), assembler (`assembler.py`), and all template partials are phase-unaware.

---

### 2.4 Gaps in Phase Tagging

**Untagged FindingEvents:** None — every current `FindingEvent` emission in the five bootstrap probes has an explicit `phase=` argument. The default `phase: Phase = "recon"` on `FindingEvent` (`events.py:48`) means that future probes which forget to set phase will silently land in Recon.

**StageEvents carry no phase:** `StageEvent` has no `phase` field. Stage cards in the Bootstrap sidebar transcript are not phase-attributed. There is no way to say "this stage belongs to the Enumeration phase" without adding a field.

**Old DB rows without `_phase`:** Any `NormalizedFinding` inserted before the `_phase` key was added to `_persist` (before the FIX 4 work in this session) will have no `_phase` in `raw_data`. These fall back to `"recon"` via the `_phase_map.get(fid, "recon")` default. Whether this is correct depends on which probe produced the finding; enumeration findings in old rows would silently misclassify as Recon.

**Exploitation-phase findings:** No probe currently emits `phase="exploitation"`. The `phases["exploitation"]` bucket in `_build_workspace_data` (`routes.py:713`) always starts empty and can only be populated if a future probe explicitly sets `phase="exploitation"`.

---

## Section 3 — Bootstrap Concept Footprint

### 3.1 Backend

**Category builder** (`routes.py:617–660`): The Bootstrap sidebar category is built whenever `boot_run is not None`. The Bootstrap entry is **always first** in the `categories` list, before any real finding categories. The `slug: "bootstrap"` distinguishes it from real categories.

**Bootstrap meta fields in `serialize_topology`** (`topology_v2.py:194–196`):
```python
"has_active_bootstrap":   bootstrap_is_active(view.investigation_id),
"bootstrap_visible":      bootstrap_is_visible(view.investigation_id),
```
`bootstrap_visible` returns `True` permanently post-completion within the same process (Phase 42 no-GC). `has_active_bootstrap` returns `True` only while running.

**Bootstrap overlay in topology** (`topology_v2.py:342–384`): `_overlay_bootstrap_run` adds `execution_stage` nodes with `kind: "bootstrap_stage"` and `subtitle: "investigation bootstrap"` to the node list. These are orphan nodes (no incoming edges) that Dagre places in a left column. `_bootstrap_running_stage_id` (`topology_v2.py:379–384`) returns the id of the currently-running stage to drive the "suggested next" camera focus.

**`default_tab` initialization in HTML route** (`investigations.py:710`):
```python
workspace_data: dict = {"categories": [], "default_tab": "bootstrap", ...}
```
The fallback workspace data before `_build_workspace_data` runs defaults to `"bootstrap"` as the active tab.

**`ScanExecution` with `scanner_type="passive_probe"`** (`routes.py:1111`): A single `ScanExecution` record is created per investigation to parent all bootstrap findings. It is identified by `scanner_type="passive_probe"` and `profile="bootstrap_probe"`. No code outside `_persist` and the storage layer queries or filters by this value — it is an audit trail record, not a functional discriminator.

**No other routes reference bootstrap state** — the context panel route, the execution routes, and the action-execution routes are all phase-agnostic.

---

### 3.2 Frontend

**`workspace.js` — bootstrap-aware lines:**

| Line | Reference | Purpose |
|---|---|---|
| `95` | `"No findings yet — bootstrap running"` | Empty-state message in aggregation card panes |
| `130` | `.filter(c => c.slug !== 'bootstrap')` | Strips Bootstrap from exploit-cat-tab rendering |
| `445` | `data.is_bootstrap_running \|\| data.has_active_execution` | Live-state check for poll continuation |
| `454` | `if (data.is_bootstrap_running \|\| data.has_active_execution)` | Polling gate in `_startPolling` |

No JS variable or CSS class is named `bootstrap*`. The Bootstrap category is handled only via the `slug !== 'bootstrap'` filter; all other category rendering logic is generic.

**`context_panel_runtime.html`** (`frontend/templates/partials/context_panel_runtime.html:1`): Renders the side panel for a clicked bootstrap stage node. Shows `title`, `subtitle` ("investigation bootstrap"), `status`, and the `actions / tools / detected / confidence / spawned` fields from `StageState`. This partial is also reused for execution stage nodes (non-bootstrap); it is generic over `subtitle`.

No other template references bootstrap by name.

---

### 3.3 Database

**No DB columns or tables are named `bootstrap*`.** The concept lives entirely in:
- `NormalizedFinding.tags` (JSON array containing `"bootstrap"` string)
- `NormalizedFinding.raw_data` (JSON object containing `"_phase"` key)
- `ScanExecution.scanner_type` value `"passive_probe"` and `profile` value `"bootstrap_probe"`
- In-memory `_RUNS: dict[str, BootstrapRun]` in `bootstrap/runtime.py`

**No migration files exist.** Schema is defined inline in `CREATE TABLE IF NOT EXISTS` statements. Changes are additive `ALTER TABLE` statements. There are no Alembic or SQL migration files in the repository.

**Existing DB records:** All bootstrap findings can be identified by `source_scanner = 'passive_probe'` or by the `"bootstrap"` string in `tags`. No schema-level constraint ties these findings to the bootstrap concept — they are ordinary `NormalizedFinding` records.

---

### 3.4 Removing Bootstrap

If the Bootstrap concept were removed entirely, the following would break or need replacement:

| Component | What breaks | What needs replacement |
|---|---|---|
| `bootstrap/runtime.py` | All execution | New phased runner(s) |
| `routes.py:617–660` | Bootstrap sidebar category disappears | Per-phase progress summary |
| `routes.py:741` | `is_bootstrap_running` field always False | Per-phase `is_running` flags |
| `topology_v2.py:156–196` | Bootstrap stage nodes vanish from topology | Phase-aware stage nodes |
| `topology_v2.py:342–384` | `_overlay_bootstrap_run` dead | Phase-overlay equivalents |
| `_ensure_bootstrap_running` (`routes.py:1069`) | Probe trigger mechanism gone | Phase-aware trigger |
| `workspace.js:130` | Filter line becomes no-op (safe to remove) | No replacement needed |
| `workspace.js:95` | Empty-state message still accurate | No change needed |
| `context_panel_runtime.html` | Subtitle "investigation bootstrap" → stale | Update subtitle per phase |
| `investigations.py:710` | `default_tab: "bootstrap"` fallback stale | Update to `"recon"` |
| `_persist` callback | `scanner_type="passive_probe"` tag | Replace with per-phase scanner_type |

The `is_bootstrap_running` field drives frontend polling. If removed without replacement, polling would stop after first poll on every page load (no active signal). A per-phase progress field must replace it for the polling lifecycle to remain correct.

---

## Section 4 — Probe Input/Output Contracts

### 4.1 `run_passive_probe` — Recon

**Current input:** `target: str` (URL)  
**Current behavior:** Single GET to target root. No authentication. No crawling.

**Findings emitted:**
1. `http_service_detected` — always. Evidence: `{status_code, content_type, server, x_powered_by, body_bytes}`. The `server` and `x_powered_by` fields contain the actual fingerprint strings if present.
2. `missing_csp_header` / `missing_hsts_header` / `missing_x_frame_options` / `missing_x_content_type_options` / `missing_referrer_policy` — conditional on absence. Evidence: `{header, all_headers, status_code, probe_method}`.

**What downstream probes could consume from these findings if sequential:**
- `server` field in `http_service_detected` evidence → server fingerprint (e.g., `"nginx/1.18"`, `"Apache/2.4"`, `"Jetty"`) could narrow login-path candidates in `auth_recon` and API-endpoint candidates in `api_recon`
- `content_type` on root response → JSON content-type on root is a strong API signal already detected by `api_recon` independently; could shortcut `api_recon`'s own root check
- `all_headers` dict → reveals any custom headers that could hint at framework (e.g., `X-Powered-By: Express` → `/api` prefix typical)
- `body_bytes` → size hint (very large bodies suggest rendered pages, small bodies suggest API endpoints)

**Input contract change required for sequential:** None — `passive_probe` is the first phase and needs no inputs. Its probe signature is already correct as the Recon entrypoint.

---

### 4.2 `run_auth_recon_probe` — Enumeration

**Current input:** `target: str`  
**Current behavior:** Walks hardcoded `LOGIN_FORM_PATHS` (`auth_recon.py:65–74`): `/login`, `/login.php`, `/admin`, `/admin/login`, `/signin`, `/auth`, `/user/login`, `/wp-login.php`. Fetches each, parses for `<form>` with password field.

**Findings emitted:**
- `login_form_detected` — if any form found. Evidence includes per-form `{path, form_action, username_field, password_field, csrf_field, submit_fields}`.

**What it could consume from `passive_probe` findings if sequential:**
- `server` fingerprint → Java stacks (Jetty, Tomcat) rarely use `/wp-login.php` or `/login.php`; Spring apps commonly use `/login` or `/auth/login`. Could eliminate irrelevant paths, reducing outbound requests.
- `x_powered_by` header → `Express` suggests Node.js app; login is more likely at `/auth` or `/api/auth`.
- `all_headers` → `Set-Cookie` header on root can reveal session framework (JSESSIONID → Java, PHPSESSID → PHP) narrowing path candidates.

**Input contract change required:** Probe would need a new optional parameter: `passive_findings: list[FindingData] | None = None`. When provided, the probe could filter `LOGIN_FORM_PATHS` based on fingerprint clues. Backward-compatible if defaulted to None (current behavior when None).

---

### 4.3 `run_api_recon_probe` — Enumeration

**Current input:** `target: str`  
**Current behavior:** Probes root + `_CANDIDATE_PATHS` (`api_recon.py:29–35`): `/api`, `/api/docs`, `/openapi.json`, `/swagger.json`, `/v1`. Detection uses content-type, body markers, and HTML table structure.

**Findings emitted:**
- `api_exposure` — if any signal detected. Evidence includes `{signals, hit_paths}`.

**What it could consume from `passive_probe` findings if sequential:**
- `server` field → "Express" suggests `/api` prefix; "Django" suggests `/api/` or REST framework paths; Spring Boot suggests `/actuator` + `/api/v1`
- `content_type` on root → if root is already `application/json`, the probe's own root check would be redundant; this signal already exists in `passive_probe` findings
- `x_powered_by` → "Express" or "Next.js" confirms Node.js; could add Node-specific API paths
- `all_headers` → `X-Powered-By: PHP/8.x` eliminates Swagger/OpenAPI patterns unlikely in vanilla PHP

**Input contract change required:** New optional parameter: `passive_findings: list[FindingData] | None = None`. Framework hints could extend or filter `_CANDIDATE_PATHS`.

---

### 4.4 `run_sqli_recon_probe` — Enumeration

**Current input:** `target: str`  
**Current behavior:** Walks hardcoded `LOGIN_ENDPOINT_PATHS` (`sqli_recon.py:33–40`): `/rest/user/login`, `/api/login`, `/login`, `/signin`, `/auth`, `/auth/login`. Tests each with POST; identifies endpoints that accept login-shaped requests.

**Key relationship to `auth_recon`:** These probes overlap significantly. `sqli_recon` probes `/login`, `/signin`, `/auth`, `/auth/login` — the same paths as `auth_recon` plus two API-style variants. Both run simultaneously and make overlapping requests to the target. If sequential, `sqli_recon` could consume `auth_recon` findings (which carry confirmed login form endpoints with full form metadata) instead of re-probing from a fixed path list.

**What it could consume from `auth_recon` findings if sequential:**
- `login_form_detected` finding with `detected_forms[].path` → confirmed login endpoint with form structure. `sqli_recon` could target only confirmed endpoints instead of speculative path list, eliminating dead requests.
- `detected_forms[].form_action` → actual POST target (may differ from page URL), which is what `sqli_recon` needs for payload testing.

**Input contract change required:** New optional parameter: `auth_findings: list[FindingData] | None = None`. When provided, uses `detected_forms[].path` entries instead of `LOGIN_ENDPOINT_PATHS`. This would also require `auth_recon` to complete before `sqli_recon` starts — requiring sequencing within the Enumeration phase, not just between Recon and Enumeration.

---

### 4.5 `run_cmdi_recon_probe` — Enumeration

**Current input:** `target: str`  
**Current behavior:** Walks hardcoded `COMMON_CMDI_PATHS` (`cmdi_recon.py:34–44`): `/vulnerabilities/exec/`, `/commandi.php`, `/ping.php`, `/exec.php`, `/admin/cmd`, `/tools/ping`, `/diagnostic/ping`, `/index.php?page=dns-lookup.php`. Fetches each; parses forms for input parameter names.

**Findings emitted:**
- `command_injection` — if any DVWA-style endpoint found. Evidence includes `{detected_paths, public_paths, auth_required_paths, form_parameter_names, observations}`.

**What it could consume from `passive_probe` findings if sequential:**
- `body_bytes` / page HTML → if passive probe had crawled (it doesn't currently), form parameter names could be discovered without repeating the GET. Passive probe does NOT currently return body content beyond `body_bytes`, so no direct input is available today.
- `server` fingerprint → DVWA runs on Apache/PHP; `Nginx` without PHP hints these paths won't exist. Could short-circuit entirely on non-PHP targets.

**What it could consume from `auth_recon` findings if sequential:**
- `auth_recon` also detects and parses HTML forms at login paths. The form_parameter_names it extracts overlap with what `cmdi_recon` extracts at different paths. These probes do not currently share form data.
- If `auth_recon` found `/admin` accessible and form-bearing, `cmdi_recon` could target that endpoint specifically.

**Input contract change required:** New optional parameter: `passive_findings: list[FindingData] | None = None`. Server fingerprint could be used to skip DVWA-specific paths on incompatible targets.

---

## Section 5 — Concurrent-Bootstrap Assumptions Baked In

### 5.1 UI Rendering Assumptions

**Bootstrap as a single unified category:** `_build_workspace_data` (`routes.py:617–660`) builds one Bootstrap category entry from the combined `boot_run.stages` list. This list is inherently interleaved across all probes. There is no per-phase equivalent; the Bootstrap category is a monolith.

**Empty-state message** (`workspace.js:95`):
```javascript
'No findings yet — bootstrap running'
```
This message assumes there is one bootstrap phase and it is either running or not. A multi-phase model would need per-phase empty states ("Recon running…", "Enumeration starting…").

**`default_tab`** (`investigations.py:710`): Falls back to `"bootstrap"` as the active sidebar tab before workspace data is loaded. This is correct when Bootstrap is the execution model but would need to change to `"recon"` in a phase-separated model.

**Sidebar category ordering** (`routes.py:618`): The Bootstrap category is prepended before all real finding categories. Its presence at position 0 makes it the `default_tab` for new investigations. The category list has no phase-level grouping; Bootstrap sits alongside SQL Injection and API Security as peers.

---

### 5.2 Stage Timeline Assumptions

The Bootstrap stage transcript (`boot_run.stages`) is a single flat list of `StageState` objects appended as each stage arrives across all five concurrent probes. The grouping by `probe_name` (`routes.py:622–640`) provides the parallel-column view, but the underlying list has no phase separation.

The `after_stage_index` on `FindingEvent` is 0-based **within a probe's own stage sequence**, not within any phase or the global list. This translation is done at `runtime.py:244–246` using a per-probe `probe_stage_start` offset recorded when the probe starts. This mechanism assumes a single flat stage list; partitioning by phase would require re-architecting how stage indices are resolved.

The `probe_name` on `StageState` identifies the probe, not the phase. There is no "which phase did this stage belong to" field. A phase-partitioned transcript would require a `StageState.phase` field.

---

### 5.3 Polling and Lifecycle Assumptions

**Single `is_bootstrap_running` flag** (`routes.py:741`):
```python
"is_bootstrap_running": boot_run is not None and boot_run.completed_at is None
```
This is a binary: bootstrap is either running or not. There is no `is_recon_running` / `is_enumeration_running` distinction. The frontend polling gate (`workspace.js:445`) treats this as one lifecycle event: "bootstrap finishes → polling may stop."

**No per-phase progress signal exists** in the current architecture. To support a UI that shows "Recon complete → Enumeration starting," the JSON payload would need to expose per-phase state, and the frontend would need a matching state machine.

**`has_active_execution`** (`execution/runtime.py:236–238`): Tracks whether any **operator-triggered** probe execution is still running:
```python
def has_active_execution(investigation_id: str) -> bool:
    return any(r.completed_at is None for r in active_runs(investigation_id))
```
This is separate from bootstrap. In a phased model, Enumeration-phase bootstrap-like execution would need its own lifecycle signal distinct from both `is_bootstrap_running` and `has_active_execution`.

---

## Section 6 — Risk Analysis for the Restructure

### 6.1 Breaking Changes

**Probe signatures:** All five probes currently accept only `target: str`. Giving Enumeration probes access to Recon findings requires adding parameters. Existing callers (the `_runner` in `bootstrap/runtime.py`) pass only the target string; the `_run_one_probe` wrapper would need updating. Since all probes share the same invocation path, the signature change must be backward-compatible or all probes must be updated simultaneously.

**`_runner` in `bootstrap/runtime.py`:** The core concurrency mechanism (`asyncio.gather` over all five probes at once) must be replaced or supplemented. The current runner has no concept of phases. A phased runner needs two sequential `gather` calls at minimum: one for Recon probes, one for Enumeration probes.

**`_ensure_bootstrap_running` / `kick_off`:** The trigger function and `kick_off` both refer to a single `BootstrapRun` per investigation. A phased model would need either multiple run types or a restructured run object that tracks phase state separately.

**`is_bootstrap_running` field:** All frontend polling depends on this binary flag. Any restructure must preserve a working equivalent or update the frontend simultaneously. Breaking this field breaks the polling lifecycle.

**`_build_workspace_data` bootstrap pane:** The Bootstrap sidebar category is built from `boot_run.stages` directly. If bootstrap is split into phases, this pane either needs to be replaced with phase-aware panes or the Bootstrap concept removed entirely.

**`_overlay_bootstrap_run` in `topology_v2.py`:** Bootstrap stage nodes in the topology are built from the single `BootstrapRun.stages` list. A phased model would need per-phase equivalents or a restructured overlay.

**No DB schema changes required** for phase tags. `raw_data["_phase"]` and `tags` already carry the value. The only DB-level change that would be needed is if per-phase `ScanExecution` records become desirable (currently all bootstrap findings share one `scanner_type="passive_probe"` record).

---

### 6.2 Backward Compatibility

**Existing investigations with phase tags:** Already-persisted findings with `raw_data["_phase"]` values would continue to render in the correct Recon/Enumeration panes unchanged. The `_build_workspace_data` consumption logic is read-only and additive.

**Existing investigations without `_phase`:** Findings from investigations run before FIX 4 (no `_phase` in `raw_data`) fall back to `"recon"` via the `_phase_map.get(fid, "recon")` default. Enumeration-type findings in old rows (e.g., a `sqli` finding without `_phase`) would silently appear in the Recon pane instead of Enumeration. This is pre-existing behavior; the restructure does not worsen it.

**Process-restart behavior:** Unchanged. `_RUNS` is wiped on restart; persisted findings survive; bootstrap does not re-trigger.

**Bootstrap sidebar for old investigations:** An investigation probed before a restructure would have `boot_run = None` (process restart wipes runs). The Bootstrap sidebar category would not appear. This is already the case for any investigation from a previous process lifetime — the Bootstrap sidebar only shows up if the current process holds an in-memory `BootstrapRun` for that investigation.

---

### 6.3 Migration Considerations

**No DB migrations needed** for the phase metadata layer. Phase tags are already being written to `raw_data["_phase"]` and `tags` for all new findings. Existing findings without `_phase` fall back to Recon, which is a tolerable approximation for historical data.

**State management note:** If Enumeration-phase execution is tracked via a new in-memory structure (analogous to `_RUNS` for bootstrap), process restarts will lose that state. The same forensic-memory concern applies as with the current `BootstrapRun` Phase 42 decision.

**No configuration files need updating.** Phase values are code constants.

---

## Section 7 — Restructure Options

### Option A — Minimal: Artificial Phase Boundaries, Concurrent Execution Preserved

**What it is:** Keep `asyncio.gather` running all 5 probes concurrently. Add a synthetic "Recon complete" signal after `run_passive_probe` finishes, even though the other probes are still running in parallel.

**Implementation scope:**
- `_run_one_probe` wrapper detects when `passive_probe` coroutine completes; emits a `PhaseCompleteEvent("recon")` into a shared channel
- Frontend reads a new `recon_complete: bool` field in the JSON payload and updates the Recon tab to show "complete" badge
- `BootstrapRun` gains a `recon_completed_at: float | None` field
- `_build_workspace_data` adds `recon_complete` to the JSON payload
- Probe signatures unchanged; no input dependencies added

**What it delivers:**
- Operator sees "Recon → complete" before Enumeration shows activity (because passive probe finishes faster than the 4 enumeration probes)
- Phase tabs show temporal ordering naturally (Recon findings appear first in the Recon pane while Enumeration still loading)
- No real sequential methodology — Enumeration probes still start at t=0, not after Recon

**What it does NOT deliver:**
- Enumeration probes do not receive Recon findings as input
- No real probe dependency chain; the phase signal is cosmetic
- Enumeration probe results may appear before Recon is visually "complete" on slow targets

**Risks:**
- If `passive_probe` is slower than an Enumeration probe (network conditions), the signal is misleading — Enumeration findings appear before "Recon complete" signal
- Adds complexity (new event type, new signal path) for a cosmetic result

---

### Option B — Full Refactor: Sequential Phases with Real Input Dependencies

**What it is:** Split bootstrap into two sequential `asyncio.gather` calls. Recon phase runs first (passive_probe alone or with equivalent probes). Enumeration phase runs after Recon completes and receives Recon findings as input.

**Implementation scope:**
- `_runner` becomes two sequential phases: `await gather(passive_probe)` then `await gather(sqli_recon, cmdi_recon, auth_recon, api_recon, ...)` with Recon findings passed as arguments
- All four Enumeration probe signatures gain `recon_findings: list[FindingData] | None = None` parameter
- Probes use `recon_findings` to narrow path candidates when available (fall back to hardcoded lists when None for backward compatibility)
- `BootstrapRun` is replaced or extended with per-phase state: `recon_run` + `enumeration_run`, each with their own `started_at` / `completed_at`
- `is_bootstrap_running` becomes `is_recon_running` + `is_enumeration_running` (or a phase-aware `current_phase` field)
- `_build_workspace_data` builds per-phase progress indicators instead of a single Bootstrap sidebar item
- Frontend polling logic updated to handle per-phase state transitions
- `_overlay_bootstrap_run` replaced with two per-phase overlay functions (or removed if Bootstrap sidebar is eliminated)

**What it delivers:**
- Real sequential pentest methodology: Enumeration probes start only after Recon completes
- Enumeration probes can use Recon server fingerprint to narrow login/API path candidates
- `sqli_recon` can target the exact login endpoints confirmed by `auth_recon` (if `auth_recon` runs first within Enumeration)
- Operator sees real temporal separation between Recon and Enumeration in the timeline
- Bootstrap concept can be retired if per-phase sidebar items replace it

**What it does NOT deliver (immediately):**
- Enumeration-internal sequencing (e.g., `auth_recon` before `sqli_recon`) requires a third sequential step or a further split within the Enumeration phase
- Probe input improvement quality depends on `passive_probe` returning richer server fingerprint data — currently it returns raw `Server:` and `X-Powered-By:` header strings, which may not always be useful

**Risks:**
- Total bootstrap wall-clock time increases. Currently ~5–10s (all 5 concurrent). Sequential model: passive_probe (~3s) + Enumeration gather (~5–10s) = ~8–13s.
- More complex `_runner`; two `gather` calls means two error-handling paths
- Frontend changes are significant: per-phase `is_running` flags, per-phase empty states, polling gate update
- All four Enumeration probe signatures change (breaking if called directly in tests or scripts)
- `ScanExecution` record structure: currently one record for all bootstrap findings; a phased model may want separate execution records per phase for better audit trail, requiring additional DB writes

---

### Option C — Hybrid: Sequential Phases, Probe Inputs Optional

**What it is:** Run Recon first, then Enumeration sequentially, but keep Enumeration probe signatures backward-compatible by making `recon_findings` optional. Implement one high-value input dependency (server fingerprint → path narrowing) while leaving others for later.

**Implementation scope:**
- Same as Option B for the runner split: two sequential gather calls
- Only `run_auth_recon_probe` gains mandatory input: `login_paths: list[str] | None = None`. When provided, replaces `LOGIN_FORM_PATHS` with discovered paths. `run_sqli_recon_probe` consumes `auth_recon` output (within Enumeration) via a post-auth-recon hook
- Other Enumeration probes (`api_recon`, `cmdi_recon`) keep `target: str` only, run from hardcoded paths as now
- `BootstrapRun` gains `recon_completed_at` but retains a single `stages` list — no per-phase split of the stage transcript
- Per-phase progress signal added (`recon_complete: bool`) without restructuring the Bootstrap sidebar item
- Bootstrap sidebar item is preserved but re-labeled "Discovery" to reflect its actual scope

**What it delivers:**
- Real sequential execution: Enumeration starts after Recon
- One concrete input dependency: `auth_recon` login path discovery feeds into `sqli_recon` targeting (the highest-value dependency, since `sqli_recon`'s false-negative rate is highest on non-standard login paths)
- Minimal probe signature changes: only `auth_recon` and `sqli_recon` change
- No UI overhaul required: Bootstrap sidebar becomes "Discovery" with Recon-complete badge; existing polling lifecycle preserved with `recon_complete` augmentation

**What it does NOT deliver:**
- Server fingerprint narrowing for other probes
- Per-phase sidebar panes (Bootstrap/Discovery pane remains monolithic)
- Full audit trail separation between Recon and Enumeration findings (both still under one `ScanExecution` record)

**Risks:**
- The single-input-dependency scope may not justify the runner refactor complexity if the team intends full Option B later — Option C could become a dead-end intermediate state
- The preserved Bootstrap sidebar concept continues to be architecturally inconsistent with the phase tabs
- Timeline wall-clock increase: same as Option B (~3s serialization overhead from Recon phase)

---

## Appendix: File Reference Index

| File | Role in bootstrap execution |
|---|---|
| `apps/investigation_workspace/bootstrap/runtime.py` | In-memory runner, `BootstrapRun`, `kick_off`, `_runner` |
| `apps/investigation_workspace/api/routes.py` | Trigger chain, `_ensure_bootstrap_running`, `_persist`, `_build_workspace_data` |
| `apps/investigation_workspace/probe/events.py` | `FindingEvent`, `StageEvent`, `Phase` type |
| `apps/investigation_workspace/probe/passive.py` | Recon probe (passive HTTP, header check) |
| `apps/investigation_workspace/probe/sqli_recon.py` | Enumeration probe (login endpoint discovery) |
| `apps/investigation_workspace/probe/cmdi_recon.py` | Enumeration probe (CMDi endpoint discovery) |
| `apps/investigation_workspace/probe/auth_recon.py` | Enumeration probe (login form detection) |
| `apps/investigation_workspace/probe/api_recon.py` | Enumeration probe (API surface detection) |
| `apps/investigation_workspace/branch/topology_v2.py` | Bootstrap overlay, meta flags |
| `apps/investigation_workspace/branch/assembler.py` | DB finding assembly (phase-agnostic) |
| `apps/scanner_orchestration/storage/finding_repo.py` | `NormalizedFinding` persistence/retrieval |
| `apps/validation/api/investigations.py` | HTML page render + workspace_data pre-population |
| `frontend/static/js/workspace.js` | Polling loop, bootstrap-awareness at 4 lines |
| `frontend/templates/partials/context_panel_runtime.html` | Bootstrap stage click panel |
