# V2.3 Closeout — Operator-Driven Live Verification Checklist

**Purpose:** Verify the three-level mindmap UI, right-side panel rendering,
and branch state polling against a real lab target. Confirms surfaces that
Playwright milestone scenarios cannot reach (workspace React Flow rendering,
real DB artifact data, live state transitions).

**When to run:** After all V2.3 Playwright milestone scenarios pass (7/10
static pass, 3/10 documented-skip in bare WSL2 — expected).

**Target:** `192.168.200.202` or a PortSwigger lab with at least one login
form + API surface. MetasploitRecipeEngine deferred (requires `msfrpcd`).

**New surfaces in V2.3 (vs V2.2 checklist):**
- Three-level mindmap (`exploitation-mindmap.js` replaces `exploit-tree.js`)
- Right-side panel populated from cached branch data (no server fetch)
- `/exploitation-data.json` endpoint live (BranchReader first consumer)
- Branch state persists and reconstructs after restart

---

## Prerequisites

### Dagre vendor file

`dagre.min.js` must be placed at `frontend/static/vendor/dagre.min.js` before
the first page load. The template no longer loads dagre from a CDN.

Obtain the file from the npmjs.com registry (dagre 0.8.5):

```
https://cdn.jsdelivr.net/npm/dagre@0.8.5/dist/dagre.min.js
```

Download manually, copy to `frontend/static/vendor/dagre.min.js` inside the
container (or mount it via docker-compose). If the file is absent, the mindmap
renders as a 4-column grid (no hierarchical layout).

---

## Pre-flight

### Step 0 — Healthy target and clean start

```
curl -s -o /dev/null -w "%{http_code}" http://<TARGET>/
```

**Pass:** HTTP 200 or 3xx redirect.
**Fail:** Connection refused, timeout, or 5xx.

Also confirm:
- `frontend/static/vendor/dagre.min.js` is present (see Prerequisites above)
- No stale investigation from a previous session still active in `/admin/conductor`.
  Cancel or delete it before starting.

Do not proceed until Step 0 passes.

---

## Phase progression

### Step 1 — Start investigation and reach Exploitation phase

Start an investigation from the workspace UI.

**Observe:**
- [ ] Investigation appears in `/admin/conductor` table within 5s
- [ ] State transitions: `RECON_RUNNING` → `ENUM_RUNNING` → `EXPLOIT_RUNNING`
- [ ] All three transitions happen without manual intervention
- [ ] Mark Done button visible in conductor table when state = `EXPLOIT_RUNNING`

---

## Mindmap rendering (new in V2.3)

### Step 2 — Exploitation tab loads three-level mindmap (Layer 1 only — before execution)

Navigate to the workspace Exploitation tab.

**Note:** Layer 2 (progress) and Layer 3 (artifact/exhaustion) nodes do **not** appear until
an engine is armed and executed in Step 3. This step verifies the mindmap container and
Layer 1 action nodes only. Three-layer rendering is verified in Step 3.

**Observe:**
- [ ] Exploitation pane renders (not blank, not "Loading…")
- [ ] No JavaScript console errors mentioning `exploitation-mindmap.js`
- [ ] `exploit-tree.js` NOT loaded in network panel (replaced by `exploitation-mindmap.js`)
- [ ] React Flow graph is visible in `#exploit-tree-root` container
- [ ] At least one Layer 1 (action) node visible for each finding type

**Layer 1 node checks:**
- [ ] Each action node shows technique class label (operator-friendly, not `engine_id`)
- [ ] "Arm exploit →" button visible on arm-enabled action nodes (state = no branch yet)
- [ ] "Execute →" button visible on non-critical nodes (state = no branch yet)

---

## Branch state rendering (new in V2.3)

### Step 3 — Arm and Execute one engine; observe state transitions

Pick one engine (recommendation: SqliAuthBypassEngine for Layer 3 artifact or
CredentialBruteEngine for captured session).

**Important — V2 engines only for state persistence:** Only V2 exploitation engines
(CredentialBruteEngine, SqliAuthBypassEngine, CmdiReflectedEngine, XssReflectedEngine,
etc.) write branch state to `exploitation_branches`. V1 legacy probes
(api_browser_recon, api_method_enum, api_endpoint_enum, api_authed_recon,
api_full_discovery, purchase_flow) write only to the in-memory `_RUNS` dict and
**do not appear in the mindmap or persist across restarts**. Steps 3–7 require
execution via V2 engine action nodes.

**Steps:**
- [ ] Click "Arm exploit →" on the target action node
- [ ] Within 5 seconds, "Execute →" (or "Confirm (5s)" for critical kinds) appears
- [ ] Click Execute (or Confirm)

**Observe Layer 1 during execution:**
- [ ] Branch state badge appears: "Starting…" then "⏳ Running…"
- [ ] Arm/Execute buttons disappear once branch is created

**Observe Layer 2 (Running — should appear within one poll cycle, ~1.1s):**
- [ ] A child "⏳ In progress" node appears under the action node
- [ ] Last stage log entry and stage count shown in the progress node

**Observe Layer 3 (Terminal — appears after engine completes):**
- [ ] "⏳ In progress" child node disappears (no duplicate node rendering)
- [ ] Layer 3 result node appears under the action node

For succeeded branch:
- [ ] Result node shows "✓ Artifact" with artifact_type label
- [ ] Layer 1 badge changes to "✓ Done"

For exhausted branch:
- [ ] Result node shows "⊘ Exhausted" with detection_method label
- [ ] Layer 1 badge changes to "No finding"

---

## Right-side panel (new in V2.3)

### Step 4 — Panel opens on node click with correct content

Click each of the following node types in the mindmap. Verify panel content.

**Layer 1 node click (any action node):**
- [ ] Right-side panel opens (slides in from right)
- [ ] Panel header text shows "Branch State" (not "Capture Bundle")
- [ ] Panel body shows: engine description, current state badge, technique class
- [ ] If branch exists: branch_id visible in panel
- [ ] If no branch yet: Arm button visible in panel (or guidance-only note)

**Layer 2 node click (Running progress node):**
- [ ] Panel opens
- [ ] Panel header text shows "Stage Log"
- [ ] Stage log entries visible with state + timestamp per entry
- [ ] All stage log entries shown in timeline order

**Layer 3 node click — Succeeded (Artifact):**
- [ ] Panel header text shows "Result"
- [ ] artifact_type rendered (e.g., `bookmarklet_href`, `captured_session`)
- [ ] For SqliAuthBypassEngine: bookmarklet link rendered as a clickable `<a>` tag
- [ ] For CredentialBruteEngine: username and session cookies rendered
- [ ] branch_id visible at bottom of panel

**Layer 3 node click — Exhausted:**
- [ ] Panel header text shows "Result"
- [ ] `detection_method` value rendered
- [ ] `negative_evidence` dict rendered (if present)
- [ ] Count of payloads tried shown

**Closing the panel:**
- [ ] × button closes the panel
- [ ] Escape key closes the panel
- [ ] Opening a different node swaps panel content correctly

---

## Panel data source verification (Pattern 19 invariant)

### Step 5 — Panel renders from cached data, not live fetch

With browser DevTools Network tab open:

- [ ] After the mindmap is loaded and polling is running, note that only
  `exploitation-data.json` is being polled repeatedly
- [ ] Click L1, L2, L3 nodes rapidly
- [ ] Verify that clicking a node does NOT trigger a new network request
  (panel content comes from cached `_branchMap`, not a server fetch)
- [ ] Specifically: no request to `context-panel` endpoint on node click
  (that endpoint is the legacy capture-bundle panel, not used here)

---

## Engine-specific verifications (at least 2)

### Engine A — SqliAuthBypassEngine

**Trigger finding:** `sqli` (from sqli_recon during enumeration)

**Pass criteria:**
- [ ] Layer 3 succeeded: bookmarklet artifact renders as clickable link
- [ ] Bookmarklet starts with `javascript:` — valid href content
- [ ] Layer 3 exhausted: ExhaustionRecord with `technique_class=injection.sql`
- [ ] session cookies/JWT captured via `store_auth()` — confirm in admin
  conductor panel → Session Auth section

### Engine B — CredentialBruteEngine

**Trigger finding:** `login_form_detected`

**Pass criteria:**
- [ ] Engine runs (visible in admin execution panel as running)
- [ ] Layer 3 succeeded: `artifact_type=captured_session`, username visible in panel
- [ ] Layer 3 exhausted: ExhaustionRecord, `payloads_tried` count > 0
- [ ] No false exhaustion from stale CSRF token (Pattern 15 — verify by checking
  stage_log in panel: each credential attempt should follow a CSRF-refresh stage)

### Engine C — DefaultCredsEngine

**Trigger finding:** `api_exposure`, `api_idor`, or `api_bola`

**Pass criteria:**
- [ ] On success: captured session written via `store_auth()` (check admin conductor)
- [ ] Layer 3 artifact shows username + login_path
- [ ] Downstream AccessControlEngine can use the session (check if it runs after)

---

## Phase completion

### Step 6 — Mark exploitation done

- [ ] Click **Mark Done** in admin conductor table, OR
  `POST /admin/exploitation/complete {"investigation_id": "<id>"}`
- [ ] Mark Done button disappears from conductor table
- [ ] Exploitation tab in workspace shows completed state (no new Arm buttons)

---

## Restart persistence check (new in V2.3)

### Step 7 — Branch state reconstructs after restart

If accessible: restart the application (or reload the workspace page in a new tab).

**Pass criteria (V2 engines only — see Step 3 note):**
- [ ] Mindmap renders all previous branches correctly (state persisted in
  `exploitation_branches` table — no blank mindmap after restart)
- [ ] Layer 3 artifact/exhaustion visible for terminal branches
- [ ] Panel content correct after reload

**Note:** V1 legacy probe results are in-memory only and will not reconstruct after
restart. This is a known limitation deferred to V2.4 (probe retirement sprint).

---

## Re-run verification (regression guard from V2.1)

### Step 8 — New investigation against same target

Start a new investigation against the same target.

**Pass criteria:**
- [ ] Second investigation runs independently through all phases
- [ ] No bleed from first investigation's branch state
- [ ] Mindmap renders fresh (no orphan nodes from previous branches)

---

## MetasploitRecipeEngine (deferred)

MetasploitRecipeEngine requires `msfrpcd` running separately. Verify independently:

- [ ] nmap finds at least one open service
- [ ] `service_detected` finding in workspace
- [ ] MSF unavailable → ExhaustionRecord `detection_method=msf_unavailable`
- [ ] Unknown service → ExhaustionRecord `detection_method=unknown_service`

---

## Report format

```
STEP 0: PASS / FAIL
STEP 1: PASS / FAIL — [Recon→Enum→Exploit transition time: X sec total]
STEP 2: PASS / FAIL — [L1 node count: X, any JS errors: Y/N]
STEP 3: PASS / FAIL — [engine used: A/B/C, state transitions observed: Y/N]
STEP 4: PASS / FAIL — [layers panel-tested: 1/2/3, headers correct: Y/N]
STEP 5: PASS / FAIL — [no context-panel requests on node click: Y/N]
ENGINES VERIFIED: A, B (at minimum two)
STEP 6: PASS / FAIL
STEP 7: PASS / FAIL (or SKIP if restart not accessible)
STEP 8: PASS / FAIL
NOTES: [unexpected behavior, deferred items, environment issues]
```

V2.3 closes when:
- All Steps 0–6 pass
- At least 2 engines verified with Layer 3 artifact OR exhaustion confirmed
- Panel content correct across all three layers
- No context-panel requests on node click (Pattern 19 confirmed live)
