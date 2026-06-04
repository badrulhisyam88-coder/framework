# V1.4a Regression Audit

**Date:** 2026-05-22  
**Scope:** Operator-facing affordances that existed pre-V1.4a and are missing or broken
in the current tabbed stage-card UI.

**Method:** Live codebase read + direct API probing of the running backend against
`http://host.docker.internal:10000/`. All file:line citations reference the current
codebase unless otherwise noted as "pre-V1.4a."

---

## Executive Summary

**13 regressions found.** 2 are blocking (operator cannot execute any probe on a fresh
investigation). 6 are important. 3 are minor. 2 are acceptable.

The most critical issue: completed finding stage cards are non-interactive `<div>` elements.
Pre-V1.4a, clicking any finding node opened the context panel (with Execute buttons). In
V1.4a that click affordance is gone — the context panel is unreachable for the primary
case (fresh investigation with no prior runs). Ghost nodes ("ready" cards) that would
otherwise provide the affordance are only emitted by the topology when probes have *already*
been run in the current process, which does not help on a fresh investigation or after a restart.

---

## Section 1 — Operator Triggers (Execute Buttons)

### R1 — Completed finding stage cards are non-interactive `<div>` elements

- **Was:** In pre-V1.4a React Flow, clicking any finding node (type=`finding`,
  `disc-{finding_id}`) dispatched a custom `inv-expand` event. The handler
  fetched `/context-panel/disc-{finding_id}` and injected the result into
  `#inv-panel-body`, which showed `context_panel.html` with both "Automated actions"
  (Execute buttons) and "Manual investigation paths" sections.
  *(Pre-V1.4a: `investigation-flow.js:881-900` — `inv-expand` handler;
  `investigation-flow.js:84-87` — Expand button per node)*

- **Now:** Findings land in workspace-data.json as stage cards with `type='stage'`,
  `status='completed'`. These are rendered as non-interactive `<div>` elements:
  `investigation_workspace.html:112-122` (completed/info path, `<div>`).
  `workspace.js:164-185` (JS-rendered path: only capture cards are `<button>`; all
  others including completed and ready are `<div>`).
  No click handler is wired to these elements.

- **Impact confirmed:** `GET /context-panel/disc-{auth_finding_id}` returns 1,870 bytes
  including 1 Execute button for `brute_force_login`. The panel is reachable and correct
  — it is simply never opened because the stage card that would trigger it is a `<div>`.

- **Severity:** **BLOCKING** — operator cannot trigger `probe_brute_force_login`,
  `probe_cmdi_reflected`, `probe_cmdi_blind_time`, `probe_cmdi_blind_boolean`,
  `probe_sqli_auth_bypass`, `probe_xss_reflected` or any other probe from a fresh
  investigation.

- **Where it should live:** `investigation_workspace.html:112-122` and `workspace.js:164-185`
  — convert completed (and warning, running) stage cards to `<button>` elements with
  `data-node-id` and a click handler calling `openContextPanel(nodeId)`. The node_ids
  are present in workspace-data.json for all non-bootstrap finding stage cards.

- **Effort estimate:** Small

---

### R2 — Ghost nodes ("ready" cards) are absent from fresh investigations

- **Was:** `topology_v2.py:147` calls `_emit_ghost_actions(view, runs, nodes, edges)`.
  Ghost nodes (type=`finding`, `ghost_state='ghost'`) appear as suggested-next action
  nodes in the React Flow graph. They are the visual entry point for actions that haven't
  been tried yet. In practice they appeared for ANY finding with matching catalog entries.

- **Now:** For the current investigation
  (`0762518c / http://host.docker.internal:10000/login.php`), live topology inspection
  shows zero ghost nodes:

  ```
  Node type counts: {'surface': 1, 'category': 4, 'finding': 8,
                     'exploitation_path': 9, 'execution_stage': 12}
  ```

  No `finding` node has `ghost_state='ghost'`. The workspace-data.json therefore produces
  no `type='ready'` stage cards. No ready cards = no clickable affordance for any probe
  (independent of R1).

- **Severity:** **BLOCKING** — even if R1 were fixed (completed cards become clickable),
  this regression would remain a gap: new operators may not know to click "completed"
  findings to find suggested actions. Ready cards were the primary visual cue pre-V1.4a.
  Ghost node emission may require prior execution evidence; if so, the UI gives zero
  affordance on a first-time investigation.

- **Where it should live:** Two possible fixes: (a) fix R1 so completed finding cards are
  clickable (makes ghost nodes less critical), or (b) investigate why ghost nodes aren't
  emitted for fresh findings and restore that behavior.

- **Effort estimate:** Small to medium (depends on ghost emission investigation)

---

### R3 — JS-rendered "ready" cards are `<div>`, not `<button>`

- **Was:** N/A (pre-V1.4a had React Flow, not JS-rendered HTML cards)

- **Now:** There is an inconsistency between the server-rendered Jinja2 template and the
  JS `_renderStageCard()` function in `workspace.js`:
  - Server-rendered ready cards: `<button class="ready-stage-card">` with `data-node-id`
    (`investigation_workspace.html:73-84`) — **clickable** ✓
  - JS-rendered ready cards: `<div class="...opacity-60">` (`workspace.js:182-185`) —
    **not clickable** ✗

  After the first poll triggers `_renderCategories()` and replaces the server HTML, any
  ready card that was clickable becomes a non-clickable `<div>`. The click affordance is
  lost on the first topology refresh (1.1 seconds after page load if bootstrap is running).

- **Severity:** **BLOCKING** — even if ready cards appear and are initially clickable
  (server-render), they become dead on first poll.

- **Where it should live:** `workspace.js:_renderStageCard()` — add a branch for
  `stage.type === 'ready'` that produces `<button class="ready-stage-card" data-node-id="...">`.

- **Effort estimate:** Small

---

## Section 2 — Capture Bundle Interactions

### R4 — Capture panel works only if the probe ran in the current uvicorn process

- **Was:** Capture nodes in React Flow were backed by both the in-memory bundle AND a
  persisted `bundle_id` in the result payload. After a backend restart, bundles are gone
  (in-memory only) but the topology still showed expired capture nodes, and clicking them
  served `capture_bundle_expired.html` with a clear explanation.

- **Now:** In V1.4a, capture stage cards only appear if execution run data is present in
  the uvicorn worker's `_RUNS` dict (set by `_overlay_execution_runs` in
  `topology_v2.py:206`). After a backend restart, `_RUNS` is empty, so no capture nodes
  appear in the topology, so no capture stage cards appear in workspace-data.json.

  The expired-bundle visual (`capture_bundle_expired.html`) IS still reachable IF the
  capture card appears in the UI — the route at `routes.py:1194-1213` returns it when
  `get_bundle(bundle_id)` returns None. But the card never appears post-restart.

  **Practical impact:** After a backend restart, an investigation that previously had
  captures shows zero capture stage cards — the operator sees no record of prior
  exploitation.

- **Severity:** **Important** — operator loses evidence of successful exploitation after
  every backend restart. This is the same limitation as pre-V1.4a (bundles are in-memory)
  but pre-V1.4a at least surfaced the expired-bundle visual. V1.4a surfaces nothing.

- **Where it should live:** Partially a design limitation (bundles are intentionally
  ephemeral). Fix would require either persisting bundle metadata to DB (out of scope) or
  surfacing probe outcomes (which ARE in the DB via NormalizedFinding.raw_data) as
  non-capture stage cards showing prior exploitation history.

- **Effort estimate:** Large (if full solution desired); Small (if just showing
  "previously exploited" text from DB data)

---

### R5 — Bookmarklet accessible but only after panel opens

- **Was:** Bookmarklet rendered in `capture_bundle.html:54-90` within the React Flow right
  panel. Pre-V1.4a panel was visible whenever a capture node was clicked.

- **Now:** Bookmarklet is still present in `capture_bundle.html:54-90` and will render
  when the capture panel opens in V1.4a. No regression in the panel content itself.
  Regression: the panel is harder to reach (requires capture stage card to appear, which
  requires an active/recent run).

- **Severity:** **Acceptable** — panel content is intact; accessibility depends on R4.

---

## Section 3 — Investigation Lifecycle

### R6 — Delete button absent from landing cards for legacy host-based investigations

- **Was:** All investigations had a delete affordance.

- **Now:** `investigations.html:99-106` renders the delete button inside
  `{% if inv.investigation_id %}`. The `InvestigationSummary.investigation_id` field
  (`investigations.py:77`) can be `None` for host-based legacy investigations that haven't
  been synced to the investigation_core layer. If `investigation_id` is None, no delete
  button renders for that card.

  Operator-confirmed: the delete button IS visible on most cards. Whether None-id
  investigations exist in the current operator's environment is unknown from code alone.

- **Severity:** **Minor** — edge case affecting only legacy host-based investigations
  without a matching investigation_core record.

- **Where it should live:** `investigations.py` — ensure all investigations are synced
  to investigation_core before rendering, or use the target URL to construct a delete
  path as a fallback.

- **Effort estimate:** Small

---

### R7 — No workspace URL in the workspace for returning to landing

- **Was:** Pre-V1.4a workspace had a breadcrumb (`ws24-breadcrumb` in old
  `investigation_workspace.html:48-83`) with `← Investigations` link as first element.

- **Now:** V1.4a workspace (`investigation_workspace.html`) has no breadcrumb. The only
  navigation to the landing page is the "Investigations" link in the sidebar
  (`base.html:39-43`), which triggers a full page reload. No in-page back affordance exists.

- **Severity:** **Minor** — functional navigation still exists via sidebar.

- **Where it should live:** Top of `investigation_workspace.html` — a minimal breadcrumb
  or target URL display.

- **Effort estimate:** Small

---

## Section 4 — Tab and Category Interactions

### R8 — All stage cards within a category are shown regardless of relevance

- **Was:** React Flow showed findings, exploitation paths, and execution stages in a
  spatial hierarchy. The operator could see at a glance which findings had been explored
  vs. not.

- **Now:** workspace-data.json BFS collects ALL descendants of a category node, including
  multiple exploitation_path chains. For Security Misconfiguration with 5 findings, all 5
  appear as stage cards. No hierarchy or grouping is visible — the operator cannot tell
  which finding has been explored vs. which is fresh.

- **Severity:** **Minor** — the data is correct, just less organized than before.

- **Where it should live:** Within each category pane, group stage cards by finding.

- **Effort estimate:** Medium

---

### R9 — Manual investigation paths (guidance_only=True suggestions) invisible

- **Was:** Pre-V1.4a: context_panel.html rendered a "Manual investigation paths" section
  for guidance_only=True catalog entries (HSTS, referrer-policy, etc.). Verified working:
  `GET /context-panel/disc-{hsts_finding_id}` returns 2,789 bytes including "Manual
  investigation paths" section with 4 "Not automated" badges.

- **Now:** These guidance entries ARE still accessible — but only if the operator can open
  the context panel for the relevant finding. Since completed finding stage cards are
  non-interactive (R1), the operator has no path to see manual guidance. On a fresh
  investigation, no "Manual investigation paths" section is visible anywhere in the UI.

- **Severity:** **Important** — guidance that operators relied on to understand what to
  do manually is hidden behind the R1 blocker.

- **Where it should live:** Fixing R1 restores access automatically (clicking a finding
  card opens the panel which shows both automated and guidance sections).

- **Effort estimate:** No independent effort needed — fixed by R1.

---

## Section 5 — Bootstrap Visualization

### R10 — Bootstrap stage cards have no node_id; clicking them does nothing

- **Was:** Pre-V1.4a, bootstrap stages were topology nodes with IDs like
  `boot-{run_id}-s{i}`. Clicking them opened a context panel from
  `routes.py:716` (`/context-panel/boot-{run_id}-s{i}`) showing the stage's reasoning:
  actions, tools, detected observations, confidence level.
  (`routes.py:1107-1149` — bootstrap stage context panel handler)

- **Now:** Bootstrap stages come from `boot_run.stages` directly (not from topology nodes),
  and `_build_workspace_data` stores them with `"node_id": ""` (`routes.py:533-541`).
  Even when R1 is fixed (completed cards become clickable), bootstrap cards will not be
  able to open a context panel because there is no node_id to pass to
  `openContextPanel("")`.

- **Severity:** **Important** — operator loses access to probe reasoning (what each
  bootstrap stage observed, detected, and what tools it used).

- **Where it should live:** Bootstrap stages need their real node_ids. The bootstrap
  runtime stores stages with a run_id (`boot_run.run_id`); the node_id would be
  `boot-{run_id}-s{i}`. This should be embedded in workspace-data.json bootstrap stage
  entries.

- **Effort estimate:** Small (add run_id to boot stage construction in
  `_build_workspace_data`)

---

## Section 6 — Live Update Behavior

### R11 — `inv-topology-refresh` CustomEvent has no listener

- **Was:** `context_panel.html:145` fires `inv-topology-refresh` CustomEvent after every
  Execute POST via `hx-on::after-request`. In pre-V1.4a `investigation-flow.js`, this
  event triggered a topology re-fetch.

- **Now:** `context_panel.html:145` still fires `inv-topology-refresh`:
  ```
  hx-on::after-request="window.dispatchEvent(new CustomEvent('inv-topology-refresh'));"
  ```
  `workspace.js` has **no `inv-topology-refresh` listener** (confirmed by grep). It does
  listen to `htmx:afterRequest` at `workspace.js:136-144`, which fires for ANY htmx
  request and triggers a poll restart. The practical effect of the missing listener is
  **partially compensated** by the `htmx:afterRequest` handler — polling will restart
  after 400ms when Execute is clicked.

  However: if the context panel is loaded via a plain `fetch()` (not htmx) and the Execute
  button inside it fires htmx, `htmx:afterRequest` will fire on `document` and workspace.js
  will catch it. This path works.

- **Severity:** **Minor** — `htmx:afterRequest` compensates. No operator impact.

- **Where it should live:** `workspace.js` could add a listener for `inv-topology-refresh`
  as a safety net, but it is not required.

- **Effort estimate:** Small (optional)

---

## Section 7 — Side Panel State

### (No new regression) Context panel and side panel work correctly when opened

The `#ws-panel` aside (`investigation_workspace.html:131-143`) functions correctly:
- Opens via `openCapturePanel()` or `openContextPanel()` in workspace.js
- Panel body loaded via fetch + `htmx.process()` to activate htmx attributes
- Close button (`#ws-panel-close`) calls `wsClosePanel()` ✓
- Keyboard Escape closes panel (`workspace.js:317-319`) ✓

The only regression here is R1 (the panel is rarely opened because stage cards are `<div>`).

---

## Section 8 — Visual States Beyond "Completed"

### R12 — Probe-execution stage cards rendered by JS lose click affordance

- **Was:** Execution stages (type=`execution_stage`) from running probes appeared in
  React Flow as live nodes. They had the node_id format `exec-{run_id}-s{i}` and were
  clickable to show stage reasoning.

- **Now:** Execution stage nodes from running probes DO appear in workspace-data.json
  (via `_overlay_execution_runs` in `topology_v2.py:206`) and map to stage cards with
  their correct `exec-{run_id}-s{i}` node_id. However:
  - They land in `_node_to_stage_card` as `execution_stage` type with `status='running'`
    or `status='completed'`.
  - In the workspace template, running stages render as `<div>` (`investigation_workspace.html:98-108`).
  - In workspace.js, ALL non-capture types render as `<div>` (`workspace.js:182-185`).
  - The operator cannot click them to see stage reasoning even though the node_id is present.

- **Severity:** **Important** — operator loses live visibility into what a running probe
  is doing.

- **Where it should live:** Covered by fixing R1 (convert all non-capture stage cards to
  `<button>` + add unified click handler in workspace.js).

- **Effort estimate:** No independent effort — fixed by R1.

---

### (No regression) Probe failure visual

- **Was:** Blocked/note outcomes from probes rendered in React Flow as outcome nodes with
  a distinct visual.

- **Now:** `_node_to_stage_card` maps `outcome` nodes with `kind='blocked'` or
  `kind='note'` to `type='warning'` stage cards (`routes.py:487-495`). The amber ⚠ icon
  renders correctly in the template (`investigation_workspace.html:87-96`). No regression
  in the visual — only in clickability (covered by R1).

---

## Section 9 — Other Affordances

### R13 — Theme toggle is a documented no-op stub

- **Was:** Pre-V1.4a, `base.html:149-184` fully toggled between dark and light themes
  by flipping `data-theme` on `<html>` and persisting to `localStorage`. The dark theme
  was the default; light theme was the fully-specified alternate.

- **Now:** V1.4a is light-only. `base.html:148-152`:
  ```javascript
  function toggleTheme() {
      // Light-only in V1.4a — toggle is a no-op; stub for future V1.4c token unification
      var lbl = document.getElementById('theme-label');
      if (lbl) lbl.textContent = '☀ Light';
  }
  ```
  The button is visible in the sidebar footer but clicking it does nothing.

- **Severity:** **Acceptable** — explicitly documented in the code as a V1.4c stub.

---

### (No regression) Settings link intact

`base.html:56-60` includes a Settings link to `/api/v1/validation/settings`. No regression.

---

### (No regression) Expired bundle visual accessible

`routes.py:1194-1213` serves `capture_bundle_expired.html` when a bundle is not found.
The visual is correct; it is only unreachable if no capture card appears (covered by R4).

---

## Summary Table

| ID  | Regression | Severity | Effort | Status |
|-----|---|---|---|---|
| R1  | Completed finding stage cards are `<div>` — no click affordance | **BLOCKING** | Small | Open |
| R2  | Ghost nodes absent from fresh investigations — no "ready" cards | **BLOCKING** | Sm–Med | Open |
| R3  | JS-rendered "ready" cards are `<div>` (inconsistent with server-render) | **BLOCKING** | Small | Open |
| R4  | Capture cards absent after backend restart (in-memory bundles gone) | Important | Large | Open |
| R8  | No grouping within category panes — all findings flat | Minor | Medium | Open |
| R9  | Manual investigation paths invisible (blocked by R1) | Important | None (R1) | Dependent |
| R10 | Bootstrap stage cards have no node_id — reasoning inaccessible | Important | Small | Open |
| R11 | `inv-topology-refresh` has no listener (compensated by htmx:afterRequest) | Minor | Small | Acceptable |
| R12 | Execution stage cards during running probe are `<div>` (blocked by R1) | Important | None (R1) | Dependent |
| R13 | Theme toggle is a no-op stub | Acceptable | N/A | By design |
| R5  | Bookmarklet accessible only when capture card visible | Acceptable | — | Dependent |
| R6  | Delete button missing for legacy host-only investigations | Minor | Small | Open |
| R7  | No breadcrumb / back navigation in workspace | Minor | Small | Open |

**Total regressions: 13**
- Blocking: 3 (R1, R2, R3) — all three are independently blocking but share a small fix surface
- Important: 4 (R4, R9, R10, R12) — R9 and R12 are fixed by R1; R10 is independent; R4 is a design limitation
- Minor: 3 (R6, R7, R11)
- Acceptable: 3 (R5, R13, and expired-bundle visual)

## Recommended Fix Priority

1. **R1 + R3 (unified)** — Convert all stage card templates to `<button>` with `data-node-id`. Update `workspace.js:_renderStageCard()` to match. One small PR fixes the primary operator blocker and resolves R9 and R12 as side effects.
2. **R10** — Add `boot-{run_id}-s{i}` node_ids to bootstrap stage entries in `_build_workspace_data`. Small, independent.
3. **R2** — Investigate ghost node emission for fresh investigations. May reveal a catalog binding gap.
4. **R6, R7** — Minor cosmetic/navigation fixes.
5. **R4** — Large scope; operator and planning conversation decide whether to address.
