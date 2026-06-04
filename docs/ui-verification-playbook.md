# UI Verification Playbook

Derived from live Playwright observation + code inspection (Phase C-2 diagnosis).
All wiring is verified real, not assumed. Do not change this doc without re-running
the Playwright steps to confirm citations still hold.

---

## Section A — This app's click-to-render wiring (REAL, cited)

### Tech stack

- **Mindmap**: React Flow rendered by `exploitation-mindmap.js`, mounted at
  `#exploit-tree-root` (`investigation_workspace.html:84`)
- **Panel**: `#ws-panel-body` (`investigation_workspace.html:101`) — populated either
  via inline JS (`innerHTML`) from the mindmap, or via `fetch` → `innerHTML` from
  `workspace.js:383`
- **Route**: FastAPI → Jinja2 templates. Panel content is HTML, NOT JSON. Processed
  by `htmx.process()` after insertion (`workspace.js:384`) so htmx attributes in the
  returned HTML are live.

### The six-link chain — FULL TAXONOMY

#### Chain 1: Exploitation mindmap → `mindAction` node (WORKING)

```
TRIGGER   → Click on React Flow node (type='mindAction') in #exploit-tree-root
EVENT     → React synthetic onClick → _onNodeClick(evt, node)
              exploitation-mindmap.js:569-575
CONDITION → if (t === 'mindAction') at line 572 — MATCHES
HANDLER   → _panelForAction(d, d._branch) → _setPanel(title, html)
              exploitation-mindmap.js:457-465
RESPONSE  → ws-panel-body.innerHTML = html (inline JS, NO HTTP request)
DOM TARGET → #ws-panel-body
```

Confirmed by Playwright: panel updates, zero HTTP requests fired for this path.
The `exploitation-data.json` polling visible in network is background, independent.

#### Chain 2: Exploitation mindmap → `mindFinding` node (BROKEN — root cause A)

```
TRIGGER   → Click on React Flow node (type='mindFinding') in #exploit-tree-root
EVENT     → React synthetic onClick → _onNodeClick(evt, node)
              exploitation-mindmap.js:569-575
CONDITION → if (t === 'mindAction') → FALSE
            if (t === 'mindProgress') → FALSE
            if (t === 'mindResult') → FALSE
            [NO branch for mindFinding]
HANDLER   → MISSING — intended: window.openContextPanel(d.finding_id)
              pattern exists in exploit-tree.js:120-124 (legacy, not loaded)
              FindingNode component (exploitation-mindmap.js:166-181) has NO onClick prop
RESPONSE  → none — function exits silently
DOM TARGET → #ws-panel-body — never reached
```

Confirmed by Playwright: zero HTTP requests, panel unchanged on click.
**Fix needed**: add `if (t === 'mindFinding') { window.openContextPanel(d.finding_id); }`
to `_onNodeClick` in `exploitation-mindmap.js`.

#### Chain 5: Auto-preselect fallback (V3.1 Part C — NEW)

```
TRIGGER   → Engine result returns fail/exhausted (Zone 3 result_zone route)
EVENT     → Attempt tree updated; context_panel re-renders on next operator click
ROUTE     → GET /workspace/investigations/{id}/context-panel/{node_id}
              context_panel() — reads attempt_tree + ranked_lists from InvestigationState
CONDITION → untried = [o for o in selection_options if o.engine_id and not o.already_attempted]
              if untried: preselect = untried[0] (next ranked, first non-tried)
              if not untried: all_techniques_tried = True → "All ranked techniques tried" state
RESPONSE  → _selection_card.html with next untried option preselected,
              exhausted options showing "Tried" badge, C6 preserved (operator clicks Execute)
DOM TARGET → #ws-panel-body via openContextPanel() → fetch → innerHTML → htmx.process()
```

No model call in this path. Ranking settled by Part A (deterministic) + A2 (once at build).
Fallback walks the pre-ranked list at operator pace.

#### Chain 4: Layer 3 variant execution (Phase E — NEW)

```
TRIGGER   → Operator selects radio in "Extract further?" section + clicks Execute Next Step
EVENT     → htmx POST (hx-post on the Execute Next Step button in _result_zone.html)
              hx-include="#variant-form-{finding_id}" (collects variant_index radio)
ROUTE     → POST /workspace/investigations/{id}/execute-variant
              routes.py  async def execute_variant(...)
CONDITION → validates engine_id + finding_id; dispatches engine with variant payload
RESPONSE  → "running" div with hx-trigger="every 3s" polling /result-zone/{finding_id}
              → when branch terminal: _result_zone.html with new ParsedResult
DOM TARGET → #result-zone-{finding_id} via hx-target + hx-swap="outerHTML"
```

#### Chain 3: Workspace topology → `disc-*` node → context-panel (BROKEN — root cause B)

```
TRIGGER   → openContextPanel(nodeId) called with disc-{finding_id} node ID
EVENT     → fetch('/api/v1/validation/workspace/investigations/{id}/context-panel/{nodeId}')
              workspace.js:379-381
ROUTE     → GET /workspace/investigations/{id}/context-panel/{node_id}
              routes.py:1563  async def context_panel(...)
CONDITION → if focus.kind == NodeKind.DISCOVERY  routes.py:1765
            → selection_card_enabled = True  → include _selection_card.html
RESPONSE  → _selection_card.html:125 CRASHES with Jinja2 TemplateSyntaxError
              (Python inline ternary inside {%if%} — not valid Jinja2 syntax)
              Docker log: jinja2.exceptions.TemplateSyntaxError: expected token ')', got 'preselect'
DOM TARGET → #ws-panel-body via fetch → innerHTML → htmx.process()
              workspace.js:383-384
```

HTTP status: **500 Internal Server Error** for every disc-* node.
**Fix needed**: replace the invalid Jinja2 expression with a pre-computed
`execute_disabled` boolean passed from the route.

### NodeKind taxonomy

From `apps/investigation_workspace/branch/model.py:16-26`:

| NodeKind | value | Description |
|---|---|---|
| TARGET | "target" | Investigation target root |
| SURFACE | "surface" | Group of findings sharing endpoint/family |
| DISCOVERY | "discovery" | A single normalized finding (`disc-{fid}` node ID) |
| ACTION | "action" | A guided action / engine execution card |
| EVIDENCE | "evidence" | An evidence artifact |
| REMEDIATION | "remediation" | A defensive verification step |

Mindmap React Flow node types (exploitation-mindmap.js — SEPARATE from NodeKind):

| React Flow type | NodeKind equivalent | Click behavior |
|---|---|---|
| `mindFinding` | DISCOVERY (finding) | **BROKEN** — no handler in _onNodeClick |
| `mindAction` | ACTION (engine card) | **WORKING** — _panelForAction() |
| `mindProgress` | ACTION (running) | WORKING — _panelForProgress() |
| `mindResult` | ACTION (result) | WORKING — _panelForResult() |

### Common failure modes

These have each occurred in this codebase at least once:

1. **Missing click handler for a new node type** (root cause A above): A new React Flow
   node type is added to the graph builder but the matching `if (t === '...')` branch
   is not added to `_onNodeClick`. The node renders and is selectable but clicking it
   silently exits. No error, no request — invisible failure.

2. **Jinja2-invalid Python syntax in template** (root cause B above): An expression valid
   in Python (e.g., inline ternary `x if cond else y`) is placed inside a Jinja2
   `{% if %}` or `{% set %}` block. Jinja2 does not support this syntax. The route
   returns HTTP 500 for every render. Error is only visible in Docker logs, not browser.
   Template tests that render with mock data catch this; source-inspection tests (grep)
   do not.

3. **NodeKind gate mismatch**: The route condition checks `NodeKind.DISCOVERY` but the
   topology assembler emits a different kind for some nodes. The panel renders an empty
   state for those nodes silently.

4. **openContextPanel not wired**: `window.openContextPanel` (workspace.js:393) is the
   bridge between the mindmap and the context-panel route. If a new JS file creates
   nodes without calling this function on click (or calls it before workspace.js has
   defined it), the panel never loads. Check load order.

5. **Connectivity misdiagnosis**: WSL2 → Docker networking sometimes puts the backend
   at a different port or host than expected. A "panel not updating" symptom can be a
   connection failure (0 HTTP requests) rather than a render bug. Always confirm with
   Step 0 (connectivity proof) before debugging the chain.

6. **Panel body updated but container stays hidden**: A new node-click handler (e.g.
   mindFinding) calls `openContextPanel()` which correctly fetches content into
   `#ws-panel-body` but `openContextPanel` has an early-return guard (`if (!_invId)`)
   that may prevent the `panel.classList.remove('hidden')` call. The symptom is:
   body content is set, panel is hidden, zero CSS changes on the container.
   Fix: explicitly call `panel.classList.remove('hidden')` in the new handler branch
   BEFORE delegating to `openContextPanel`, mirroring `_setPanel()` (line 471).
   This makes visibility unconditional and independent of the fetch path.
   The Playwright visibility assertion (check computed `display` and `visibility`
   on `#ws-panel`, not just `#ws-panel-body`) catches this — body content passes
   but the container visibility check fails.

7. **Suspected timer guard causing first-click failure — no such timer exists**:
   When "first click does nothing, second click works" is reported, the hypothesis
   is a legacy `setTimeout` / `_armed` / `_initialized` flag gating the click handler.
   In this codebase, `_onNodeClick` has NO readiness flag at its top. Timers present
   (5000ms arm reset, 1100ms/3000ms/4000ms branch polling) are all unrelated to
   click routing. The real root cause of "first click invisible" was the panel
   visibility dependency on `openContextPanel`'s `_invId` guard — fixed by
   mirroring `_setPanel()` visibility inline (pattern 6 above).
   Always search before assuming a timer exists: `grep -n "setTimeout\|_armed\|_ready\|_initialized"`.
   If the code is clean, the Playwright immediate-click gate (`wait_for_selector` then
   click with no extra sleep) is the correct regression test — it passes when fixed.

---

## Section B — The build protocol (every UI change follows this)

Before writing a single line of code for any UI change, state the complete
click-to-render chain — all six links. A missing link IS the work.

**Template for the pre-coding chain statement:**

```
TRIGGER   → [what the operator physically does]
EVENT     → [which JS function fires and in which file:line]
ROUTE     → [HTTP method + path + function name + file:line]
CONDITION → [which branch/gate inside the route decides what renders; file:line]
RESPONSE  → [which template/partial is returned; what it must contain]
DOM TARGET → [which element receives it; by what mechanism — innerHTML / htmx swap]
```

**Rules:**
- State the trigger, not just the destination. "The route returns the right HTML" is
  not enough — confirm the trigger fires a request at all before touching the route.
- A link marked MISSING is a task item, not an assumption. If the click handler
  doesn't exist, that is the work — not the template.
- Do not assume htmx wiring from the route side alone. Check the template for
  `hx-target`, `hx-swap`, or — in this app — check whether the JS uses `fetch`
  and `innerHTML` instead.
- In this app, the exploitation mindmap uses inline JS panels for action/progress/
  result nodes (no HTTP) and uses `window.openContextPanel()` → `fetch` → context-panel
  route for finding nodes. These are different paths; do not confuse them.

---

## Section C — The Playwright verification protocol (definition of done for UI)

UI work is done ONLY when all of the following pass against the running stack.
A skipped Playwright step is not done.

### Step 0 — CONNECTIVITY PROOF FIRST

Navigate to the page. Assert one trivially-true element (page title, a nav link,
any static text that is always present). If this fails, it is a **connectivity
problem** — wrong port, WSL2↔Docker networking, wrong URL, missing auth cookie —
NOT a UI bug. Resolve connectivity before touching the feature.

**Record and keep:**
- The confirmed base URL (e.g. `http://localhost:8000`)
- The confirmed investigation workspace URL pattern:
  `/api/v1/validation/investigations/workspace?target={url-encoded-target}`
- The confirmed exploitation partial URL (NOT used standalone; see note below):
  `/api/v1/validation/workspace/investigations/{id}/branches/flow/partial`
  returns "Graph view removed in V1.4a" — the real mindmap is in the full workspace page

**WSL2 note — Playwright setup**: Playwright headless Chromium in WSL2 requires
`--no-sandbox` and an `LD_LIBRARY_PATH` pointing to extracted system libraries.
The Playwright-bundled Chromium shell (`chromium_headless_shell-*`) needs
`libnspr4.so`, `libnss3.so`, `libnssutil3.so`, and `libasound.so.2` which are
absent from this system. No `sudo` is available; extract them from `.deb` packages:

```bash
mkdir -p /tmp/libnspr4
cd /tmp/libnspr4
apt-get download libnspr4 libnss3 libasound2t64
for deb in *.deb; do dpkg-deb -x "$deb" extracted/; done
```

Then launch Playwright with:

```python
import os
os.environ["LD_LIBRARY_PATH"] = (
    "/tmp/libnspr4/extracted/usr/lib/x86_64-linux-gnu:"
    + os.environ.get("LD_LIBRARY_PATH", "")
)
# ... in playwright launch:
browser = await pw.chromium.launch(
    headless=True,
    args=["--no-sandbox", "--disable-dev-shm-usage"],
    executable_path=(
        "/home/unctad/.cache/ms-playwright/chromium_headless_shell-1223/"
        "chrome-headless-shell-linux64/chrome-headless-shell"
    ),
)
```

Or set via shell before running the script:
```bash
LD_LIBRARY_PATH=/tmp/libnspr4/extracted/usr/lib/x86_64-linux-gnu \
python3 tests/e2e/verify_selection_card.py
```

The extracted path `/tmp/libnspr4/extracted/` does NOT survive reboots.
If the Playwright script fails with `libnspr4.so: cannot open shared object file`,
re-run the `apt-get download` + `dpkg-deb` steps above.

The Chromium executable path includes the version number (`chromium_headless_shell-1223`).
If `playwright install chromium` installs a different version, update accordingly:
`ls ~/.cache/ms-playwright/` to find the current path.

```python
# Step 0 — connectivity proof template
await page.goto(WORKSPACE_URL, wait_until="networkidle", timeout=30000)
title = await page.title()
assert title, f"No page title — connectivity failure at {WORKSPACE_URL}"
print(f"[PASS] Step 0 connectivity: {WORKSPACE_URL!r} → {title!r}")
```

### Step 1 — INSTRUMENT

Attach event listeners before any interaction. Keep them for the entire run.
These are the evidence that localizes a broken chain link in one pass:
- Zero HTTP requests after click → the trigger did not fire (frontend gap)
- HTTP request fired but 500 → the route or template crashed (backend/template gap)
- HTTP request fired, 200, but panel unchanged → DOM target mismatch or JS gap

```python
requests_log, responses_log, console_msgs = [], [], []
page.on("request",  lambda r: requests_log.append((r.method, r.url)))
page.on("response", lambda r: responses_log.append((r.status, r.url)))
page.on("console",  lambda m: console_msgs.append(f"[{m.type}] {m.text[:300]}"))
```

### Step 2 — SCRIPT THE REAL OPERATOR ACTION

Perform the actual click on the actual element. Do NOT call the route directly —
that bypasses the trigger and skips the evidence. Wait explicitly for the expected
element, then assert presence AND content.

```python
# Example: finding node click → selection card appears
await page.goto(WORKSPACE_URL, wait_until="networkidle")
# Switch to Exploitation tab (real operator action)
await page.get_by_text("Exploitation", exact=True).first.click()
await asyncio.sleep(2)
# Click the real finding node (real operator action)
finding_node = page.locator(".react-flow__node-mindFinding").first
await finding_node.click()
await asyncio.sleep(3)
# Assert panel updated (not empty, contains expected content)
panel = page.locator("#ws-panel-body")
content = await panel.inner_html()
assert "select technique" in content.lower() or "Execute" in content, \
    f"Selection card not rendered. Panel: {content[:200]!r}"
```

Save the Playwright script to the repo as `tests/e2e/verify_{feature_name}.py`
so it can be re-run without re-derivation.

### Step 3 — ON FAILURE

1. Screenshot: `await page.screenshot(path="/tmp/fail_{feature}.png")`
2. Dump request log: which requests fired, which did not
3. Dump console log: JS errors, warnings, htmx errors
4. Localize the broken chain link:
   - 0 requests → trigger not wired (JS, no-HTTP path)
   - request fired → 5xx → route or template crash (check Docker logs for traceback)
   - request fired → 200 → panel not updating → DOM target wrong or htmx not processed
5. Fix the broken link; do NOT fix downstream links before confirming the upstream link works
6. Re-run the Playwright script in-session until it passes

### Step 4 — MOCK SUITE

```bash
python3 -m pytest --ignore=tests/test_infrastructure.py --tb=no -q
```

Zero regressions. Required but NOT sufficient for UI work. The mock suite cannot
see the click-to-render seam.

### Definition of done for UI

A UI task is complete when:
- [ ] Step 0 connectivity proof passed (URL + port recorded)
- [ ] Step 1 instrumentation attached
- [ ] Step 2 script passes: real operator action asserted, result in DOM
- [ ] Script saved to `tests/e2e/` for future re-runs
- [ ] Step 3 not needed (or was needed, fixed, re-run passed)
- [ ] Step 4 mock suite green, zero regressions
