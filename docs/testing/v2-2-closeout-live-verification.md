# V2.2 Closeout — Operator-Driven Live Verification Checklist

**Purpose:** This checklist covers the surfaces that Playwright milestone scenarios
cannot reach (workspace exploitation UI, Arm→Execute flow, engine output artifacts)
and the surfaces where live interaction against a real lab target is required to
confirm correct behavior.

**When to run:** After all Playwright milestone scenarios pass. Report results back
so V2.2 can close and V2.3 can begin.

**Target:** `192.168.200.202` or a PortSwigger lab that exposes at least one login
form + API surface. MetasploitRecipeEngine verification deferred (requires `msfrpcd`
running separately — see §8).

---

## Pre-flight

### Step 0 — Healthy target confirmation

```
curl -s -o /dev/null -w "%{http_code}" http://<TARGET>/
```

**Pass:** HTTP 200 (or redirect 3xx to a working page).
**Fail:** Connection refused, timeout, or 5xx.

Do not proceed until Step 0 passes.

---

## Phase progression

### Step 1 — Start investigation

Start an investigation against the confirmed lab target from the workspace UI.

**Observe:**
- [ ] Investigation appears in `/admin/conductor` table within 5s
- [ ] State column shows `RECON_RUNNING`

### Step 2 — Recon phase completes

Wait for passive probe engines to complete (passive_probe, nmap, nuclei, ZAP if gated on).

**Observe:**
- [ ] Admin conductor table transitions from `RECON_RUNNING` → `ENUM_RUNNING`
- [ ] Findings appear in the workspace findings panel
- [ ] State column does NOT auto-advance to `EXPLOIT_RUNNING` (admin drives that next)

### Step 3 — Enumeration phase completes

Wait for enumeration engines (auth_recon, api_recon, sqli_recon if triggered) to complete.

**Observe:**
- [ ] Admin conductor table shows `EXPLOIT_RUNNING`
- [ ] Mark Done button is visible in the Action column
- [ ] Exploitation tab is accessible in the workspace UI

### Step 4 — Exploitation tab loads

Navigate to the Exploitation tab in the workspace.

**Observe:**
- [ ] Category sidebar renders with at least one category
- [ ] Category chip counts match the number of engine cards visible in the graph
- [ ] No JavaScript console errors related to exploit-tree.js

---

## Engine verification (at least 3 of the following)

Complete at least 3 of the 8 engine verifications below. Choose engines whose
trigger findings appeared during Steps 1–3.

### Engine A — SqliAuthBypassEngine (technique: SQLi login bypass)

**Trigger finding:** `sqli` (produced by sqli_recon engine during enumeration)

**Steps:**
- [ ] Arm the engine via per-action approval button in the workspace
- [ ] Execute the engine
- [ ] Observe Layer 2 node transitions: running → (success or exhaustion)

**Pass criteria:**
- [ ] If a SQLi bypass is found: Layer 3 node appears with `finding_type=sqli_auth_bypass`
- [ ] Bookmarklet artifact renders at Layer 3 with valid JavaScript content
  (`javascript:void(...)` or `javascript:(function...)`)
- [ ] Severity = critical for successful token capture, high for redirect/cookie
- [ ] If no SQLi found: ExhaustionRecord node appears at Layer 3

### Engine B — CredentialBruteEngine (technique: form login brute-force)

**Trigger finding:** `login_form_detected` (produced by passive_probe or auth_recon)

**Steps:**
- [ ] Arm the engine via per-action approval button
- [ ] Execute the engine

**Pass criteria:**
- [ ] Engine runs credential pairs (visible via admin execution panel — engine appears in running list)
- [ ] On success: Layer 3 node with `finding_type=credential_brute_success`, severity=high
- [ ] On exhaustion: ExhaustionRecord node at Layer 3
- [ ] No false exhaustion from stale CSRF tokens (Pattern 15 invariant — each credential
  pair should have a preceding GET to refresh the token)

### Engine C — CmdiReflectedEngine (technique: reflected command injection)

**Trigger finding:** `command_injection` (produced by passive_probe CSP check)

**Pass criteria:**
- [ ] Engine executes 7 separator templates
- [ ] On detection: Layer 3 node with `finding_type=cmdi_reflected`, severity=critical
- [ ] On exhaustion: ExhaustionRecord with `detection_method=no_reflection`

### Engine D — CmdiBlindTimeEngine (technique: time-based blind command injection)

**Trigger finding:** `command_injection`

**Pass criteria:**
- [ ] 2-sample confirmation visible in engine run (two slow requests per confirmed injection)
- [ ] On detection: Layer 3 node, severity=critical
- [ ] On exhaustion: ExhaustionRecord

### Engine E — CmdiBlindBooleanEngine (technique: boolean-based blind command injection)

**Trigger finding:** `command_injection`

**Pass criteria:**
- [ ] Strategy A (reflecting target: echo differential) OR Strategy B (timing differential)
- [ ] On detection: Layer 3 node, severity=critical

### Engine F — XssReflectedEngine (technique: XSS via missing CSP)

**Trigger finding:** `missing_csp_header`

**Pass criteria:**
- [ ] Engine tests XSS payloads and checks reflection
- [ ] On detection: Layer 3 node with `finding_type=xss_reflected`, severity=high
- [ ] No probe_csp_xss_reflected ghost node fires in parallel (Pattern 12 retirement invariant)

### Engine G — DefaultCredsEngine (technique: API default credentials)

**Trigger finding:** `api_exposure`, `api_idor`, or `api_bola`

**Pass criteria:**
- [ ] Engine queries normalized_findings for the three finding types at startup
- [ ] On success: Layer 3 node with `finding_type=default_creds_success`, severity=high
- [ ] `store_auth()` called — downstream AccessControlEngine picks up credentials
  (confirm by checking session auth section of admin conductor panel)

### Engine H — AccessControlEngine (technique: IDOR/BOLA via authenticated GET)

**Trigger finding:** `api_exposure`, `api_idor`, or `api_bola`

**Pass criteria:**
- [ ] Engine discovers API spec and extracts user-scoped endpoints
- [ ] On IDOR detection: Layer 3 node with `finding_type=access_control_idor`, severity=high
- [ ] On no spec found: ExhaustionRecord with `detection_method=no_spec`
- [ ] On empty target_users: info note emitted (not an exhaustion record)

---

## Operator drives exploitation phase completion

### Step 5 — Mark exploitation done

After at least 3 engines have been exercised:

**Steps:**
- [ ] Click **Mark Done** button in admin conductor table, OR
- [ ] `POST /admin/exploitation/complete` with `{"investigation_id": "<id>"}`

**Pass criteria:**
- [ ] Mark Done button disappears from conductor table
- [ ] Admin table state column shows `EXPLOIT_COMPLETE` or `COMPLETED`
- [ ] Workspace UI exploitation tab becomes read-only (no new Arm buttons)

---

## Re-run verification (regression guard)

### Step 6 — Delete investigation and re-run against same target

Delete the investigation via the workspace UI, then start a new one against the same target.

**Pass criteria:**
- [ ] Second investigation runs through all phases independently
- [ ] No stale state from the first investigation bleeds into the second
- [ ] Phase progression: RECON_RUNNING → ENUM_RUNNING → EXPLOIT_RUNNING (clean)

This step guards against the regression uncovered during V2.1 Step 3 fix-2 verification.

---

## MetasploitRecipeEngine deferred verification

MetasploitRecipeEngine requires `msfrpcd` running and a target with detected services
(`service_detected` finding type from nmap engine). Verify separately once the MSF
environment is ready:

- [ ] nmap finds at least one open service on the target
- [ ] `service_detected` finding type appears in workspace findings
- [ ] MetasploitRecipeEngine appears in admin execution panel when that finding is present
- [ ] MSF unavailable → ExhaustionRecord with `detection_method=msf_unavailable`
  (test by stopping msfrpcd before running)
- [ ] Unknown service_name → ExhaustionRecord with `detection_method=unknown_service`
  (Pattern 17 invariant)

---

## Report format

After completing the checklist, report back:

```
STEP 0: PASS / FAIL
STEP 1: PASS / FAIL
STEP 2: PASS / FAIL — [phase transition time: X seconds]
STEP 3: PASS / FAIL — [phase transition time: X seconds]
STEP 4: PASS / FAIL — [categories visible: X, chips: Y]
ENGINES VERIFIED: A, B, C (or whichever 3+ were exercised)
STEP 5: PASS / FAIL
STEP 6: PASS / FAIL
NOTES: [any unexpected behavior, deferred items, environment issues]
```

V2.2 closes when:
- All Steps 0–6 are PASS
- At least 3 engines verified
- Playwright milestone scenarios pass (separate report)
