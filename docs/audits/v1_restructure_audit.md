# V1 Restructure Audit

Date: 2026-05-23
Scope: read-only audit of `ai-assist-tool` against the proposed V1 design
(Sidebar → Investigations → Recon / Enumeration / Exploitation tabs,
categories as sub-tabs under Exploitation only, React-Flow LR mind tree
for Exploitation, lucide-react icons on sub-tabs).

Source-of-truth references appear as `file:line`.

---

## SECTION 1 — PROBE PHASE CLASSIFICATION

This section enumerates **every** probe in the codebase — both the raw
async generators under `apps/investigation_workspace/probe/*.py` and the
wrapper async generators in
`apps/investigation_workspace/suggestions/probes.py`. Total probes
catalogued: **23** (19 distinct probe entities; 4 internal helpers that
are imported and re-yielded from wrappers also appear).

Legend:
- *Network behavior*: P=passive (read-only headers/body), AD=active
  discovery (touches endpoints without payloads), AE=active exploit
  (sends payloads / mutations / credentials).
- *Current trigger*: BOOT=auto on investigation start (bootstrap
  `_runner`), OP=operator clicks Execute, NEST=invoked transitively
  from another probe.
- *Proposed phase* matches the V1 design: **Recon**, **Enumeration**,
  **Exploitation**.

| # | Probe | File:Line | Emits | Network behavior | Current trigger | Proposed phase | FP risk | Aggregation candidate |
|---|-------|-----------|-------|------------------|-----------------|----------------|---------|----------------------|
| 1 | `run_passive_probe` | `apps/investigation_workspace/probe/passive.py:45` | StageEvent×6, FindingEvent (HTTP service + 5 missing-header types) | P – single GET | BOOT (`bootstrap/runtime.py:202`) | **Recon** | low (only emits when header truly absent) | YES – aggregate all `missing_*_header` into one "Security headers" card |
| 2 | `run_auth_recon_probe` | `apps/investigation_workspace/probe/auth_recon.py:201` | StageEvent×2, FindingEvent `login_form_detected` (aggregated) | AD – GET 8 login paths | BOOT (`bootstrap/runtime.py:203`) | **Enumeration** | low (HTML parse with password input required) | already aggregated (one finding regardless of count) |
| 3 | `run_api_recon_probe` | `apps/investigation_workspace/probe/api_recon.py:137` | StageEvent×2, FindingEvent `api_exposure` | AD – GET root + 5 candidate API paths, parses body markers | BOOT (`bootstrap/runtime.py:203`) | **Enumeration** | medium (weak-hit promotion logic at `api_recon.py:187-193`) | already aggregated |
| 4 | `run_sqli_recon_probe` | `apps/investigation_workspace/probe/sqli_recon.py:88` | StageEvent×2, FindingEvent `sqli` | AD – POST empty JSON body to 6 login paths | BOOT (`bootstrap/runtime.py:202`) | **Enumeration** | medium (POST {} is touched payload; 200/JSON heuristic) | already aggregated |
| 5 | `run_cmdi_recon_probe` | `apps/investigation_workspace/probe/cmdi_recon.py:127` | StageEvent×2, FindingEvent `command_injection` | AD – GET 9 well-known cmdi paths, HTML form parse | BOOT (`bootstrap/runtime.py:202`) | **Enumeration** | low (requires `<form>` + filter) | already aggregated |
| 6 | `run_authed_recon` | `apps/investigation_workspace/probe/api_authed_recon.py:132` | StageEvent×2, ResultEvent (structured payload) | AD – GET 9 auth pages with session cookies; BS4 extract /api/* paths + IDs | NEST (called from wrappers 13 & 16) | **Enumeration** | low | n/a (helper) |
| 7 | `run_endpoint_enum` | `apps/investigation_workspace/probe/api_endpoint_enum.py:116` | StageEvent×2, ResultEvent | AD – up to several hundred GETs via SecLists wordlist, sem=10 | NEST (called from wrappers 14 & 16) | **Enumeration** | medium-high (large surface, may trigger WAFs) | n/a (helper) |
| 8 | `run_method_enum` | `apps/investigation_workspace/probe/api_method_enum.py:368` | StageEvent×2, ResultEvent + `next_actions[]` cards | AD/AE – sends OPTIONS + GET/POST/PUT/PATCH/DELETE/HEAD per endpoint; *empty body* for 400/422 shape inference | NEST (called from wrapper 15 & 16) | **Exploitation** (POST/PUT/PATCH/DELETE classify as **AE** even with empty body) | high (non-GET methods are mutation territory even at HEAD-empty) | n/a (helper) |
| 9 | `run_browser_recon` | `apps/investigation_workspace/probe/api_browser_recon.py:67` | StageEvent×N, ResultEvent | AD – headless Chromium (Playwright), 8 nav pages + 10 link follow each | NEST (called from wrapper 17) | **Enumeration** (active; ~30–60s) | low (browser-driven, real navigation) | n/a (helper) |
| 10 | `authenticate_dvwa` | `apps/investigation_workspace/probe/lab_auth.py:35` | dict (not events) — called by cmdi probes for auth state | AE – POSTs admin/password and `security=low` to any target | NEST (read inside cmdi exploit probes; gate removed per CLAUDE.md accepted risk) | **Exploitation** | high — sends credentials to any target | n/a (helper) |
| 11 | `run_purchase_flow` | `apps/investigation_workspace/probe/purchase_flow.py:167` | StageEvent×N, ResultEvent | AE – PATCH price, POST cart, POST checkout with multiple CSRF strategies | NEST (called from wrapper 18) | **Exploitation** | critical (real state mutation, real "purchase") | n/a (helper) |
| 12 | `probe_robots_check` | `apps/investigation_workspace/suggestions/probes.py:53` | StageEvent×2, ResultEvent×4 (robots/sitemap detail) | P – GET /robots.txt + /sitemap.xml | OP | **Recon** | low | could fold into Recon "External-resources" aggregate |
| 13 | `probe_csp_check_meta` | `apps/investigation_workspace/suggestions/probes.py:186` | StageEvent + ResultEvent | P – GET root, regex meta tag | OP | **Recon** | low | YES — aggregate under "CSP gap" composite (with #14) |
| 14 | `probe_csp_inspect_origins` | `apps/investigation_workspace/suggestions/probes.py:259` | StageEvent×2, ResultEvent | P – GET root, walk script/img origins | OP | **Recon** | low | YES — aggregate under "CSP gap" composite |
| 15 | `probe_xss_reflected` | `apps/investigation_workspace/suggestions/probes.py:493` | StageEvent×N, ResultEvent w/ structured `payload` | AE – injects payload markers into reflective query params | OP | **Exploitation** | high (real payload reflection test) | n/a |
| 16 | `probe_sqli_auth_bypass` | `apps/investigation_workspace/suggestions/probes.py:1133` | StageEvent×N, ResultEvent + capture bundle | AE – POSTs tautology payloads to discovered login endpoints | OP | **Exploitation** | critical — fires SQLi auth-bypass against login form | n/a |
| 17 | `probe_cmdi_reflected` | `apps/investigation_workspace/suggestions/probes.py:1941` | StageEvent×N, ResultEvent + capture bundle | AE – injects `;whoami;id` marker payloads | OP | **Exploitation** | critical | n/a |
| 18 | `probe_cmdi_blind_time` | `apps/investigation_workspace/suggestions/probes.py:2318` | StageEvent×N, ResultEvent + capture bundle | AE – sleep-based timing exploitation | OP | **Exploitation** | critical | n/a |
| 19 | `probe_cmdi_blind_boolean` | `apps/investigation_workspace/suggestions/probes.py:2575` | StageEvent×N, ResultEvent + capture bundle | AE – boolean differential exploitation | OP | **Exploitation** | critical | n/a |
| 20 | `probe_brute_force_login` | `apps/investigation_workspace/suggestions/probes.py:2921` | StageEvent×N, ResultEvent + capture bundle | AE – iterates SecLists default-passwords.csv against detected login form | OP | **Exploitation** | critical (lockout risk explicit in reasoning at `catalog.py:145-150`) | n/a |
| 21 | `probe_api_exploit` | `apps/investigation_workspace/suggestions/probes.py:3554` | StageEvent×N, ResultEvent + capture bundle + dynamic next_actions | AE – auth + IDOR + cross-user GET + dynamic mutate cards | OP | **Exploitation** | critical | n/a |
| 22 | `probe_api_idor_mutate` | `apps/investigation_workspace/suggestions/probes.py:4110` | StageEvent×N, ResultEvent | AE – fires one operator-approved non-GET request | OP (dynamic `api_idor_mutate_*` action_kind) | **Exploitation** | critical (mutating) | n/a |
| 23 | `probe_api_authed_recon` | `apps/investigation_workspace/suggestions/probes.py:4758` | wrapper → re-yields #6 | AD (after creds posted at `probes.py:4784`) | OP | **Enumeration** (with operator gate; sends creds) | medium — sends default creds | n/a |
| 24 | `probe_api_endpoint_enum` | `apps/investigation_workspace/suggestions/probes.py:4807` | wrapper → re-yields #7 | AD + creds | OP | **Enumeration** | medium-high | n/a |
| 25 | `probe_api_method_enum` | `apps/investigation_workspace/suggestions/probes.py:4850` | wrapper → re-yields #8 | AD/AE + creds | OP | **Exploitation** (per #8 rationale) | high | n/a |
| 26 | `probe_api_full_discovery` | `apps/investigation_workspace/suggestions/probes.py:4934` | orchestrates #6 → #7 ∥ #8 | AE — sends creds, then runs wordlist + method enum in parallel | OP | **Exploitation** (sends default creds *then* mutates) | high | n/a |
| 27 | `probe_api_browser_recon` | `apps/investigation_workspace/suggestions/probes.py:5028` | wrapper → re-yields #9 with auth | AD/AE — credentials + headless browser | OP | **Enumeration** (still active discovery, but auth) | medium | n/a |
| 28 | `probe_api_method_execute` | `apps/investigation_workspace/suggestions/probes.py:5080` | StageEvent×N, ResultEvent | AE – one operator-approved mutation per click | OP (dynamic `api_method_*` action_kinds, decoded at `api_method_enum.py:97`) | **Exploitation** | critical | n/a |
| 29 | `probe_purchase_flow` | `apps/investigation_workspace/suggestions/probes.py:5244` | wrapper → re-yields #11 | AE | OP | **Exploitation** | critical | n/a |

### Probes that need detailed phase discussion

**`run_sqli_recon_probe` (sqli_recon.py:88)** — Currently fires at
bootstrap. It is sharper than `passive`: it sends **HTTP POST with an
empty JSON body** to 6 login paths (`sqli_recon.py:64-66`). Even though
no payload is injected, the body is non-empty (the JSON literal `{}`)
and the act of touching `/login` etc. shows up in WAF logs as POSTs from
the operator. In V1 it must move to **Enumeration** so it is gated on
the operator hitting the Enumeration tab (still automatic — the V1
design auto-runs Enumeration probes when the operator opens the
investigation, so the practical behavior is unchanged, but the
phase-attribution becomes explicit).

**`run_cmdi_recon_probe` (cmdi_recon.py:127)** — Pure GET requests with
strict 200+HTML+`<form>` filtering. Lowest active-discovery FP risk of
the active probes. **Enumeration**.

**`run_api_recon_probe` (api_recon.py:137)** — The weak-hit promotion
logic at `api_recon.py:187-193` (a 4xx-JSON-boundary path is only
promoted to a hit when the root also carries an API signal) means this
probe has medium FP risk and can fire `api_exposure` on sites that just
happen to return `application/json` with errors. Recommend keeping in
**Enumeration** with the existing guard; aggregation is already in
place (single FindingEvent).

**`run_auth_recon_probe` (auth_recon.py:201)** — Pure presence
detection. Safe for **Enumeration**. Note that its sibling helpers
`discover_login_form` and `attempt_default_creds_login` (`auth_recon.py:272`
and `auth_recon.py:291`) actively POST credentials and are invoked from
several Exploitation-phase wrappers — those usages should remain
under Exploitation, not Enumeration.

**`run_method_enum` (api_method_enum.py:368)** — Despite the `_probe_body_shape`
helper claiming "READ-SAFE: an empty {} body is rejected by the server's
validation layer before any state mutation can occur" (`api_method_enum.py:218-220`),
the probe still fires `POST/PUT/PATCH/DELETE` against any endpoint and
emits action cards that, when executed, do mutate. The recon claim is
only true for the *body-shape probe* (`_probe_body_shape`) on
400/422 responses, NOT for `_probe_endpoint`, which fires all verbs
unconditionally. This is **Exploitation** phase work even before the
operator clicks any action card.

**`authenticate_dvwa` (lab_auth.py:35)** — Per CLAUDE.md "Accepted
Risks" (2026-05-22), this function POSTs `admin/password` and
`security=low` to **any** target the operator points the tool at. Used
exclusively by the cmdi exploit probes. The phase mapping is
**Exploitation** — the gate that should sit in front of this is the
operator's explicit click of a cmdi exploit action, not the host gate
that was removed.

**`probe_api_method_execute` (probes.py:5080)** — Only mutating probe in
the method-enum flow per its own docstring. Reads `ACTION_ID_CTX` for
the decoded (method, path) tuple. The V1 exploitation-tree node for
each method-enum action card terminates in this probe. **Exploitation**.

---

## SECTION 2 — AGGREGATION CANDIDATES

Below: groupings the V1 design should collapse into a single summary
card with an "expand to see members" interaction.

### Group: Security Headers Gap (Recon)

- **Current**: `run_passive_probe` (`probe/passive.py:191-232`) loops
  over `SECURITY_HEADERS` (lines 26-42) and emits ONE FindingEvent per
  missing header — up to 5 (`missing_csp_header`,
  `missing_hsts_header`, `missing_x_frame_options`,
  `missing_x_content_type_options`, `missing_referrer_policy`).
- **Proposed summary card text**:
  "Security headers — N of 5 baseline headers absent"
- **Drill-down detail**: list each header with its severity chip, the
  short `description` from the `SECURITY_HEADERS` table, and the
  evidence `header` + `all_headers` snapshot the probe already attached
  to each FindingEvent at `passive.py:211-216`.

### Group: HTTP Service + Fingerprint (Recon)

- **Current**: `passive.py:171-189` emits a `http_service_detected`
  finding with status_code + content_type + server + x_powered_by +
  body_bytes evidence. Right next to it the probe yields a
  "Fingerprinting target" stage (`passive.py:144-152`) that already
  contains the Server / X-Powered-By extraction.
- **Proposed summary card**: "HTTP service — HTTP {status} · {server}"
- **Drill-down**: the existing evidence dict already has every field
  needed (no new probe work required).

### Group: CSP Gap composite (Recon)

- **Current**: three siblings in catalog: `csp_xss_reflected`
  (probe-backed, Exploitation), `csp_inspect_origins` (probe-backed,
  Recon), `csp_check_meta` (probe-backed, Recon). The CSP-meta probe
  (`probes.py:186`) and origin-inspector (`probes.py:259`) both make a
  single GET of the root. Currently they re-fetch even though the
  passive probe already has the headers.
- **Proposed summary card**: under Recon → "CSP analysis" with two
  sub-items (meta tag, origin inventory). The Exploitation member
  (`csp_xss_reflected`) lives on the Exploitation tab.

### Group: API surface (Enumeration)

- **Current**: `api_recon.py` emits a single `api_exposure` finding
  with `signals[]` and `hit_paths[]` evidence — already pre-aggregated
  (line 215-230).
- **Proposed summary card**: "API surface — {N} signals across {M}
  paths" with drill-down listing each `path: reason` pair from
  `signals`.

### Group: Default-creds enumeration cluster (Exploitation)

- **Current**: every API-family wrapper (probes.py:4758, 4807, 4850,
  4934, 5028) starts with `attempt_default_creds_login` against the
  same `load_default_credentials()` set. The operator sees five
  separate Execute buttons that all do the same auth step before
  doing different work.
- **Proposed summary card**: under Exploitation → API Security: one
  shared "Authenticate with default credentials" step that runs once
  and feeds session cookies into the child Execute buttons.

### Group: cmdi variants (Exploitation)

- **Current**: three probes (`probe_cmdi_reflected`,
  `probe_cmdi_blind_time`, `probe_cmdi_blind_boolean`) all on
  `command_injection` finding, registered as separate
  `SuggestionSpec`s (`catalog.py:186-205`).
- **Proposed summary card**: under Exploitation → Command Injection
  one node "Test command injection" with three child nodes for the
  three variants. The mind-tree visualization makes this natural.

---

## SECTION 3 — WORKFLOW GAP ANALYSIS

### 3a — Current auto-run probes (bootstrap)

`apps/investigation_workspace/bootstrap/runtime.py:202-203` registers
exactly five probes that fire concurrently via `asyncio.gather` when an
investigation has no discoveries yet
(`api/routes.py:362`, `api/routes.py:748`):

| Probe | bootstrap binding |
|-------|---|
| `run_passive_probe` | `bootstrap/runtime.py:202` |
| `run_sqli_recon_probe` | `bootstrap/runtime.py:202` |
| `run_cmdi_recon_probe` | `bootstrap/runtime.py:202` |
| `run_auth_recon_probe` | `bootstrap/runtime.py:203` |
| `run_api_recon_probe` | `bootstrap/runtime.py:203` |

Trigger entry point: `_ensure_bootstrap_running` at `api/routes.py:748-830`,
called from `branch_topology_json` (`api/routes.py:362`) and
`workspace_data_json` (`api/routes.py:396`). The actual probe-stream
consumer is `_runner` at `bootstrap/runtime.py:182-272`.

### 3b — Probes that must move to operator-triggered (V1 Exploitation phase)

The five bootstrap probes are all phase-Recon or phase-Enumeration in
the V1 design. The probes that fire **only** on operator click today
(via `execute_suggestion` route at `api/routes.py:1099-1211`) are
already operator-gated. The V1 design treats Recon + Enumeration as
"auto-run when investigation opens" and only Exploitation as
"require explicit click", so the V1 gate location is the same place
the current execute_suggestion already lives.

**Already operator-gated (correct for V1 Exploitation tab):**

| action_kind | catalog file:line | probe | reason |
|---|---|---|---|
| `csp_xss_reflected` | `catalog.py:43-48` | `probe_xss_reflected` | real payload reflection |
| `brute_force_login` | `catalog.py:141-151` | `probe_brute_force_login` | credential iteration |
| `sqli_auth_bypass` | `catalog.py:130-137` | `probe_sqli_auth_bypass` | SQL payloads |
| `cmdi_reflected/blind_time/blind_boolean` | `catalog.py:186-205` | three cmdi probes | OS command exec |
| `api_exploit` | `catalog.py:156-164` | `probe_api_exploit` | IDOR + auth |
| `purchase_flow` | `catalog.py:165-173` | `probe_purchase_flow` | real state mutation |
| `api_idor_mutate_*` (dynamic) | sentinel `catalog.py:302-310` | `probe_api_idor_mutate` | one mutation per click |
| `api_method_*` (dynamic) | sentinel `catalog.py:286-294` | `probe_api_method_execute` | one mutation per click |

**Currently operator-gated but classified by V1 as Enumeration (no
behavior change needed, just phase label):**

| action_kind | catalog file:line | probe |
|---|---|---|
| `svc_robots_check` | `catalog.py:120-126` | `probe_robots_check` |
| `csp_inspect_origins` | `catalog.py:49-54` | `probe_csp_inspect_origins` |
| `csp_check_meta` | `catalog.py:55-60` | `probe_csp_check_meta` |
| `api_authed_recon` | `catalog.py:219-224` | `probe_api_authed_recon` |
| `api_endpoint_enum` | `catalog.py:225-232` | `probe_api_endpoint_enum` |
| `api_browser_recon` | `catalog.py:242-251` | `probe_api_browser_recon` |

These all currently auth with default creds inside the wrapper (e.g.
`probes.py:4784` for authed_recon). For V1 Enumeration they should
**not** auto-fire creds; the auth step belongs under Exploitation. See
3d.

### 3c — Ordering dependencies

```
Recon
└── run_passive_probe                          (no deps; sole input is target URL)
└── probe_robots_check                         (no deps)
└── probe_csp_check_meta                       (no deps; could reuse passive body)
└── probe_csp_inspect_origins                  (no deps; could reuse passive body)

Enumeration
└── run_auth_recon_probe                       (no deps)
└── run_sqli_recon_probe                       (no deps)
└── run_cmdi_recon_probe                       (no deps)
└── run_api_recon_probe                        (no deps)

Exploitation
├── probe_brute_force_login                    needs FindingEvent.login_form_detected.evidence
│                                              (form_action / username_field / password_field / csrf_field)
│                                              passed via FINDING_EVIDENCE_CTX
│                                              (read at probes.py:2944)
├── probe_sqli_auth_bypass                     needs detected_login_endpoints from sqli_recon
│                                              (read via FINDING_EVIDENCE_CTX at probes.py:1153-1155)
├── probe_cmdi_reflected / blind_time / blind_boolean
│                                              need detected_paths / public_paths /
│                                              auth_required_paths / form_parameter_names
│                                              from cmdi_recon (read via FINDING_EVIDENCE_CTX at probes.py:1648-1654)
├── probe_api_exploit                          needs api_exposure finding (any hit_path / signal)
│                                              + default credentials wordlist
├── probe_api_idor_mutate                      needs preceding probe_api_exploit run
│                                              (anchored under exec-{run}-r0; api/routes.py:1146-1149)
├── probe_api_method_execute                   needs preceding probe_api_method_enum result
│                                              (ACTION_ID_CTX carries the encoded path/method;
│                                              decoded at api_method_enum.py:97)
├── probe_api_full_discovery                   internally orchestrates:
│      Phase 1: run_authed_recon  (probes.py:4994)
│      Phase 2: run_endpoint_enum ∥ run_method_enum
│              (probes.py:5012-5022, merged via _merge_probe_streams)
└── probe_purchase_flow                        needs captured_requests (browser recon evidence)
                                                + product_id (operator input)
                                                (read at probes.py:5274-5275)
```

### 3d — Phase-spanning probes that need splitting

**`probe_api_authed_recon` / `probe_api_endpoint_enum` /
`probe_api_browser_recon` (probes.py:4758, 4807, 5028)** — Wrap a clean
recon helper (`run_authed_recon`, `run_endpoint_enum`,
`run_browser_recon`) by **first calling `attempt_default_creds_login`**
(`probes.py:4784, 4833, 5057`). The credential-posting half belongs in
Exploitation; the recon halves belong in Enumeration. For V1, split
each into two probes:

- *Enumeration half*: invoke the underlying `run_*` directly using an
  **operator-provided** cookie jar (empty if anonymous). No
  `attempt_default_creds_login` call.
- *Exploitation half*: a single "Authenticate (default credentials)"
  card that runs `attempt_default_creds_login` and stores the cookies
  in a per-investigation auth state, which subsequent
  Enumeration/Exploitation cards consume.

**`probe_api_full_discovery` (probes.py:4934)** — does both: auth +
authed scrape + wordlist enum + method enum. In V1 the same flow is
expressed as a *chain* on the Exploitation mind-tree: Auth → Authed
recon → (Wordlist ∥ Method enum) → mutate cards.

**`run_method_enum` (api_method_enum.py:368)** — emits Enumeration
data (method matrix) but also emits Exploitation `next_actions[]` that
will fire mutations on click. Already split internally: the body-shape
probe at `api_method_enum.py:210` is read-safe; the resulting cards
fire through `probe_api_method_execute`. No code change needed; phase
attribution is what changes.

---

## SECTION 4 — LEGACY CODE AUDIT

### 4a — Unreferenced templates

The active sidebar (`frontend/templates/base.html:23-75`) only exposes
two nav targets: **Investigations** and **Settings**. All other
top-level pages from the older `apps/validation/` era still have
intact routes and templates but are no longer reachable from the
sidebar.

| Template | File | Originally for | Why legacy | Recommendation |
|---|---|---|---|---|
| `dashboard.html` | `frontend/templates/dashboard.html` | Original landing dashboard | Replaced by `investigations.html` (V1.4a) — still rendered from `apps/validation/api/history.py:239` but not linked from sidebar | Delete after confirming history flow is cut |
| `discovery.html` | `frontend/templates/discovery.html` | apps/validation network scanner | Pre-investigation-workspace; no sidebar link | Delete (along with `apps/validation/api/discovery.py`) |
| `queue.html` | `frontend/templates/queue.html` | apps/validation queue page | No sidebar link | Delete |
| `findings.html` | `frontend/templates/findings.html` | apps/validation findings list | No sidebar link | Delete |
| `finding_detail.html` | `frontend/templates/finding_detail.html` | apps/validation finding view | No sidebar link | Delete |
| `assets.html` | `frontend/templates/assets.html` | apps/validation asset inventory | No sidebar link | Delete |
| `changes.html` | `frontend/templates/changes.html` | apps/validation change tracking | No sidebar link | Delete |
| `history.html` | `frontend/templates/history.html` | apps/validation scan history | No sidebar link | Delete |
| `metasploit.html` | `frontend/templates/metasploit.html` | apps/validation MSF integration | No sidebar link | Delete |
| `known_issues.html` | `frontend/templates/known_issues.html` | apps/validation suppression UI | No sidebar link | Delete |
| `custom_report.html` | `frontend/templates/custom_report.html` | apps/validation stateless CVE report | No sidebar link | Delete |
| `custom_report_pdf.html` | `frontend/templates/custom_report_pdf.html` | Custom report PDF rendering | Coupled to deletable custom_report flow | Delete |
| `report_pdf.html` | `frontend/templates/report_pdf.html` | apps/validation PDF reports | Standalone PDF used by `services/report_generator.py:34` — not in V1 surface | Delete unless PDF export is required for V1 |
| `partials/asset_details.html` | partial | assets page | dead | Delete |
| `partials/asset_row.html` | partial | assets page | dead | Delete |
| `partials/dc_group_card.html` | partial | assets page (DC grouping) | dead | Delete |
| `partials/host_services.html` | partial | discovery / workspace | dead (only used by removed discovery flow) | Delete |
| `partials/queue_row.html` | partial | queue page | dead | Delete |
| `partials/scan_result.html` | partial | discovery scan SSE | dead | Delete |
| `partials/scan_timeline_fragment.html` | partial | scanner_orchestration timeline | only used by orchestration route which is itself behind the legacy flow | Delete |
| `partials/run_timeline_fragment.html` | partial | scanner_orchestration | dead | Delete |
| `partials/scan_orchestration_panel.html` | partial | scanner_orchestration | only used by `apps/scanner_orchestration/api/routes.py:297` | Delete with that route |
| `partials/target_diagnostics_panel.html` | partial | scanner_orchestration | included by `scan_orchestration_panel.html`; dead transitively | Delete |
| `partials/msf_guide.html` | partial | metasploit page | dead | Delete |
| `partials/msf_module_info.html` | partial | metasploit page | dead | Delete |
| `partials/msf_run_output.html` | partial | metasploit page | dead | Delete |
| `partials/msf_search_results.html` | partial | metasploit page | dead | Delete |
| `partials/investigation_maturity_banner.html` | partial | older investigation banner | not rendered anywhere (grep returns 0 references) | **Confirmed unreferenced — delete** |
| `partials/investigation_timeline_panel.html` | partial | investigation_core timeline view | only used by `investigation_core/api/routes.py:212`; not surfaced in V1 sidebar | Delete with that route |
| `partials/investigation_comparison_panel.html` | partial | cross-investigation comparison | only used by `investigation_workspace/api/routes.py:2301`; not in V1 | Delete with that route |
| `partials/learning_path_panel.html` | partial | learning paths | used by `investigation_core/api/routes.py:236`; not in V1 surface | Delete or hide behind dev-mode |
| `partials/skill_progression_panel.html` | partial | skill graph | used by `investigation_core/api/skill_routes.py:177`; not in V1 surface | Delete or hide |
| `partials/guided_action_panel.html` | partial | older guided action card | used by `investigation_core/api/guided_action_routes.py:180`; replaced by `context_panel.html` for V1 | Delete |
| `partials/posture_snapshot_chip.html` | partial | defensive posture | used by `investigation_workspace/api/routes.py:2207`; not in V1 | Delete with route |
| `partials/posture_snapshots_panel.html` | partial | defensive posture panel | used at `investigation_workspace/api/routes.py:2227`; not in V1 | Delete with route |
| `partials/posture_comparison_panel.html` | partial | posture before/after | used at `investigation_workspace/api/routes.py:2258`; not in V1 | Delete with route |
| `partials/campaign_dashboard.html` | partial | campaign management | used at `investigation_core/api/campaign_routes.py:226`; not in V1 | Delete with routes |
| `partials/campaigns_list.html` | partial | campaign list | used by `campaign_routes.py:287`; not in V1 | Delete |
| `partials/campaign_timeline.html` | partial | campaign timeline | used by `campaign_routes.py:250`; not in V1 | Delete |
| `partials/branch_flow.html` | partial | Phase 37 React Flow mount shell | superseded by V1.4a `investigation_workspace.html` (Preact + Dagre); still rendered by `branch_flow_partial` route at `investigation_workspace/api/routes.py:131-264` which is no longer called from the V1 sidebar | Delete with `/branches/flow/partial` route |
| `partials/evidence_capture_form.html` | partial | inline evidence capture | used by `investigation_workspace/api/routes.py:2029` — V1 evidence flow keeps this; **alive** | KEEP |
| `partials/evidence_capture_success.html` | partial | inline evidence capture success | used at `investigation_workspace/api/routes.py:2145`; **alive** | KEEP |
| `partials/evidence_panel.html` | partial | evidence list | used by `investigation_core/api/evidence_routes.py:101`; **alive** | KEEP |
| `partials/context_panel.html` | partial | Phase 37 unified context panel | rendered at `investigation_workspace/api/routes.py:1050`; **alive in V1** | KEEP |
| `partials/context_panel_runtime.html` | partial | runtime stage/result panel | rendered at `investigation_workspace/api/routes.py:1336, 1612, 1639`; **alive in V1** | KEEP |
| `partials/structured_evidence.html` | partial | Phase 54 structured evidence | rendered at `investigation_workspace/api/routes.py:1705`; **alive in V1** | KEEP |
| `partials/capture_bundle.html` | partial | Phase 58 capture bundle view | rendered at `investigation_workspace/api/routes.py:1383`; **alive in V1** | KEEP |
| `partials/capture_bundle_expired.html` | partial | Phase 57d expired-bundle state | rendered at `investigation_workspace/api/routes.py:1360`; **alive in V1** | KEEP |

### 4b — Unreferenced routes

Routes wired by `apps/validation/api/__init__.py:22-36`. Every router
that backs a deletable template above carries deletable routes.

| Route | File:Line | Originally for | Why legacy | Recommendation |
|---|---|---|---|---|
| `GET /discovery*` | `apps/validation/api/discovery.py` (whole file) | Network scanner SSE | Pre-investigation-workspace | Delete |
| `GET /queue*` | `apps/validation/api/queue.py` (whole file) | Validation queue page | Not linked | Delete |
| `GET /assets*` | `apps/validation/api/assets.py` (whole file) | Asset inventory | Not linked | Delete |
| `GET /changes*` | `apps/validation/api/changes.py` | Scan-diff change tracker | Not linked | Delete |
| `GET /findings*` | `apps/validation/api/findings.py` | Old findings tab | Not linked | Delete |
| `GET /finding/{id}` | `apps/validation/api/findings.py:165, 262` | Finding detail | Not linked | Delete |
| `GET /history*` | `apps/validation/api/history.py` | Scan history | Not linked | Delete |
| `GET /known-issues*` | `apps/validation/api/known_issues.py` | Suppression list | Not linked | Delete |
| `GET /metasploit*` | `apps/validation/api/metasploit.py` | MSF integration | Not linked | Delete |
| `GET /custom-report*` + `POST /custom-report/pdf` | `apps/validation/api/custom_report.py` | Stateless CVE report | Not linked | Delete |
| `GET /reports*` | `apps/validation/api/reports.py` | PDF reports | Not linked unless PDF export retained | Delete |
| `GET /scanner/run/{group}/timeline` and orchestration HTML routes | `apps/scanner_orchestration/api/routes.py:297, 425, 495, 534` | Scanner timeline UI | Not in V1 sidebar | Delete the HTML-render routes; keep the JSON ones if used by V1 |
| `GET /investigations/{id}/branches/flow/partial` | `apps/investigation_workspace/api/routes.py:131` | Phase 37 React Flow shell | Replaced by V1.4a tabbed Preact UI; **dead** | Delete this route + `branch_flow.html` |
| `POST /investigations/{id}/branch-action/{id}/capture-snapshot` | `investigation_workspace/api/routes.py:1862` | Posture snapshot trigger from old branch view | No V1 caller (old `branch_flow.html`) | Delete with branch_flow route |
| `POST /investigations/{id}/branch-action/{id}/mark-regression` | `investigation_workspace/api/routes.py:1903` | Regression flag from old branch view | No V1 caller | Delete |
| `POST /investigations/{id}/branch-action/{id}/complete` | `investigation_workspace/api/routes.py:1835` | Old branch "Mark complete" button | No V1 caller | Delete |
| Posture endpoints (snapshots panel, snapshot chip, compare-partial) | `investigation_workspace/api/routes.py:2207, 2227, 2258` | Defensive posture UI | Not in V1 surface | Delete |
| Cross-investigation comparison `/comparison/partial` | `investigation_workspace/api/routes.py:2301` | Cross-target diff | Not in V1 surface | Delete |
| Campaign routes | `apps/investigation_core/api/campaign_routes.py:226, 250, 287` | Campaign management | Not in V1 | Delete |
| Investigation timeline + learning-path routes | `apps/investigation_core/api/routes.py:211, 235` | Older investigation-detail panels | Not in V1 | Delete |
| Skill progression route | `apps/investigation_core/api/skill_routes.py:176` | Skill panel | Not in V1 | Delete |
| Guided-action panel route | `apps/investigation_core/api/guided_action_routes.py:179, 215` | Older guided action card | Superseded by `context_panel.html` | Delete |

### 4c — Unreferenced JavaScript

Total JS files in `frontend/static/js/`: 3.

| JS file | Originally for | Why legacy | Recommendation |
|---|---|---|---|
| `frontend/static/js/htmx.min.js` | HTMX library bundled locally | Still loaded by `base.html:10`; only consumer left in V1 is the capture-panel HX-Trigger and Execute POST refresh (see `workspace.js:597`) | KEEP — htmx is the partial-swap mechanism in V1 |
| `frontend/static/js/workspace.js` | V1.4a Preact + Dagre stage-card workspace | Active in V1; this is the main UI module (789 LOC) | KEEP |
| `frontend/static/js/cross-context-routing.js` | Cross-link to AI_Cyber_Lab (`/findings?source=ai-assist`) | CLAUDE.md "What this tool is NOT integrated with" explicitly states this tool is NOT integrated with AI_Cyber_Lab. The functions `openCyberLabLearning`, `openCyberLabFinding`, `openCyberLabWorkspace` are unreferenced from any template after the V1 restructure. | **Delete — confirmed dead per CLAUDE.md direction** |

### 4d — Dead CSS classes (sample)

`frontend/static/css/main.css` is 1,277 lines and 258 class selectors.
The V1 templates (`base.html`, `investigation_workspace.html`,
`investigations.html`) use Tailwind utility classes inline; **none of
the bespoke `.card`, `.stat-card`, `.qstatus`, `.qstatus-*`,
`.btn-primary`, `.btn-secondary`, `.form-input`, `.form-select`,
`.empty-state`, `.spinner`, `.table-wrap` classes documented in
CLAUDE.md** appear in the active V1 templates. Spot-check:

- `.sidebar`, `.sidebar-header`, `.logo` (`main.css:89-103`) — base.html
  V1 uses Tailwind `nav.w-64` instead. Dead.
- `.layout` (`main.css:84`) — replaced by `.flex min-h-screen` in
  base.html. Dead.
- The CSS variables block at `main.css:4-71` (`--bg-base`, `--accent`,
  `--critical`, `--mono`) is consumed by the dead-legacy partials
  (e.g. `discovery.html`, `findings.html`) and the diagnostic block at
  `api/routes.py:297-328`. Once the legacy templates are deleted, the
  variables are only used by the diagnostic block — fold them into an
  inline style there and delete the global block.
- `.stage-card`, `.capture-stage-card`, `.ready-stage-card`,
  `.stage-card-btn` — referenced by `workspace.js:140-143`. **Active in
  V1.** Search results: these class names do appear in `main.css`
  somewhere; verify before deleting.

Recommendation: keep CSS variables + stage-card classes; delete all
sidebar, layout, table, status-pill, queue-row, form-input variants.
Estimated reduction: 60–70% of `main.css`.

### 4e — Registered probes never triggered

Every `SuggestionSpec` with `probe_runner != None` has at least one
binding (verified by reading `catalog.py:42-273` against
`bindings.py:22-66`). However:

| SuggestionSpec | Catalog file:line | probe_runner | Why dormant in practice |
|---|---|---|---|
| `hsts_http_downgrade` | `catalog.py:67-77` | None (guidance_only) | Phase 59b classed it as guidance-only — never executable. Will appear in V1 Recon "Manual investigation paths" subsection. KEEP as info card. |
| `hsts_redirect_chain` | `catalog.py:78-87` | None (guidance_only) | Same as above. |
| `referrer_check_outbound` | `catalog.py:93-104` | None (guidance_only) | Same. |
| `svc_fingerprint_deep` | `catalog.py:109-119` | None (guidance_only) | Same. |
| `api_idor_execute` sentinel | `catalog.py:315-320` | `probe_api_exploit` | Only resolvable via `find_spec` sentinel (`catalog.py:331-332`); intentionally not surfaced as a ghost. Surfaces inside the structured-evidence panel only. Behavior is correct; V1 should keep. |
| `api_method` sentinel | `catalog.py:286-294` | `probe_api_method_execute` | Same pattern — sentinel only for dynamic `api_method_*` action_kinds. Correct. |
| `api_idor_mutate` sentinel | `catalog.py:302-310` | `probe_api_idor_mutate` | Same pattern. Correct. |
| `purchase_flow` | `catalog.py:165-173` | `probe_purchase_flow` | Bound to `api_exposure / api_idor / api_bola` finding types. Only fires if those findings have been emitted. Operational, **not** dormant. |

No truly orphaned `SuggestionSpec`s found. No `probe_runner` registered
without a corresponding `bindings.py` entry. **`catalog.py` is clean.**

### 4f — Legacy app paths (validation/, exporters/)

`apps/validation/` (the original network-validation app) and
`exporters/` (the markdown vault exporter) are explicit CLAUDE.md
direction targets for deletion *for the operational surface*. The
parts still in use:

- `apps/validation/database.py` — `get_db()` is the shared SQLite
  context manager used by **every** investigation_workspace and
  investigation_core route. Cannot delete; rename/relocate optional.
- `apps/validation/config.py` — used by `investigations.py:614`
  (`get_default_workers`). Cannot delete without re-homing.
- `apps/validation/models/__init__.py` — Pydantic domain models still
  referenced indirectly by repositories. Investigate.

Definitely deletable from `apps/validation/`:

| Path | Why |
|---|---|
| `apps/validation/api/discovery.py` | Pre-IW scanner page |
| `apps/validation/api/queue.py` | Pre-IW queue |
| `apps/validation/api/findings.py` | Old findings tab |
| `apps/validation/api/assets.py` | Asset inventory |
| `apps/validation/api/changes.py` | Change tracker |
| `apps/validation/api/history.py` | Scan history |
| `apps/validation/api/known_issues.py` | Suppression UI |
| `apps/validation/api/metasploit.py` | MSF integration |
| `apps/validation/api/custom_report.py` | CVE custom report |
| `apps/validation/api/reports.py` | PDF reports |
| `apps/validation/api/settings_router.py` | NVD-sync settings UI (Settings page in V1 is just a stub link) |
| `apps/validation/services/{metasploit,msf_recipes,msf_wordlists}.py` | MSF backend |
| `apps/validation/services/{scanner,executor,recon,custom_report_scanner,change_detector,backend_detect,deep_lift,report_generator}.py` | Scanner pipeline |
| `apps/validation/engines/{cve_matcher,fingerprint_normalizer,nvd_sync}.py` | CVE matching engine |
| `apps/validation/plugins/*.py` (10 files) | Per-CVE validation plugins |
| `apps/validation/adapters/{nmap,recon_ng}.py` | nmap/recon-ng scanners |
| `apps/validation/tasks/expiry_worker.py` | Capture-bundle expiry (already partially superseded by `capture_bundle_expired.html`) |
| `apps/validation/services/{correlator,cve_registry,suppression}.py` | Findings correlation + suppression |

`exporters/` (whole directory, 11 files at `/exporters/*.py`) — the
README references at `/home/unctad/projects/INTEROPERABILITY_*` and
`FINDING_ENRICHMENT_FLOW.md` are explicitly named in CLAUDE.md
("That direction is NOT being pursued. Those docs remain as historical
reference; this tool's direction is the one stated in this CLAUDE.md").
**Delete the entire `/exporters/` directory.**

### 4g — Dead helpers

Within `apps/investigation_workspace/suggestions/probes.py` (5,332
lines):

- The TODO at `probes.py:12-25` mentions Phase 54-probe-migration
  (`probe_robots_check` / `probe_csp_check_meta` /
  `probe_csp_inspect_origins` still emit legacy `evidence: dict`
  without `payload`). These are not dead — they're un-migrated, and
  V1 should either migrate them or accept the "legacy evidence" chip
  shown in the side panel.

- `_format_evidence_lines` at `apps/investigation_workspace/api/routes.py:1733`
  is the legacy-payload renderer feeding `context_panel_runtime.html`.
  Once the three un-migrated probes above are migrated, this helper
  becomes dead and the legacy-evidence chip path
  (`api/routes.py:1316-1330`) can be deleted.

- `_compute_next_hint` at `api/routes.py:1769-1818` is consumed by the
  old branch_flow card view (`branch_flow.html`). After deleting the
  branch_flow route + template, this function has no callers.

- `_render_flow_diagnostic` at `api/routes.py:287-331` exists only to
  produce a graceful failure for `branch_flow.html`. Dead after that
  route is removed.

- `_make_stage_from_event` at `bootstrap/runtime.py:160` and probe
  ordering helpers — alive. KEEP.

- The diagnostic infer-helpers `infer_artifact_type` and
  `_derive_title_from_content` at `api/routes.py:45-101` — alive via
  the inline evidence capture form route. KEEP.

---

## SECTION 5 — CONCRETE CODE PATTERNS

### 5a — lucide-react icons in Jinja template context

Lucide ships SVG path data as a public dataset (per-icon JSON at
`https://unpkg.com/lucide-static@latest/icons/<name>.svg`). For a
no-npm Jinja stack, vendor the four icons inline as a macro file:

`frontend/templates/partials/_lucide.html` (new file — proposed):

```jinja
{# Lucide icon macro library (vendored from lucide-static; SVGs are
   straight from upstream and trimmed of XML preamble + classes). #}

{%- macro lock(cls='w-4 h-4', stroke='currentColor') -%}
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"
     viewBox="0 0 24 24" fill="none" stroke="{{ stroke }}"
     stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
     class="{{ cls }}">
  <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
  <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
</svg>
{%- endmacro -%}

{%- macro database_zap(cls='w-4 h-4', stroke='currentColor') -%}
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"
     viewBox="0 0 24 24" fill="none" stroke="{{ stroke }}"
     stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
     class="{{ cls }}">
  <ellipse cx="12" cy="5" rx="9" ry="3"/>
  <path d="M3 5V19A9 3 0 0 0 15 21.84"/>
  <path d="M21 5V8"/>
  <path d="M21 12L18 17H22L19 22"/>
  <path d="M3 12A9 3 0 0 0 14.59 14.87"/>
</svg>
{%- endmacro -%}

{%- macro terminal(cls='w-4 h-4', stroke='currentColor') -%}
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"
     viewBox="0 0 24 24" fill="none" stroke="{{ stroke }}"
     stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
     class="{{ cls }}">
  <polyline points="4 17 10 11 4 5"/>
  <line x1="12" y1="19" x2="20" y2="19"/>
</svg>
{%- endmacro -%}

{%- macro globe(cls='w-4 h-4', stroke='currentColor') -%}
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"
     viewBox="0 0 24 24" fill="none" stroke="{{ stroke }}"
     stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
     class="{{ cls }}">
  <circle cx="12" cy="12" r="10"/>
  <line x1="2" y1="12" x2="22" y2="12"/>
  <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10
           15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
</svg>
{%- endmacro -%}

{%- macro radar(cls='w-4 h-4', stroke='currentColor') -%}
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"
     viewBox="0 0 24 24" fill="none" stroke="{{ stroke }}"
     stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
     class="{{ cls }}">
  <path d="M19.07 4.93A10 10 0 0 0 6.99 3.34"/>
  <path d="M4 6h.01"/>
  <path d="M2.29 9.62A10 10 0 1 0 21.31 8.35"/>
  <path d="M16.24 7.76A6 6 0 1 0 17.7 13.5"/>
  <path d="M12 18h.01"/>
  <path d="M17.99 11.66A6 6 0 0 1 15.77 16.67"/>
  <circle cx="12" cy="12" r="2"/>
  <path d="M12 12L17 7"/>
</svg>
{%- endmacro -%}

{%- macro search(cls='w-4 h-4', stroke='currentColor') -%}
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"
     viewBox="0 0 24 24" fill="none" stroke="{{ stroke }}"
     stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
     class="{{ cls }}">
  <circle cx="11" cy="11" r="8"/>
  <line x1="21" y1="21" x2="16.65" y2="16.65"/>
</svg>
{%- endmacro -%}

{%- macro zap(cls='w-4 h-4', stroke='currentColor') -%}
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"
     viewBox="0 0 24 24" fill="none" stroke="{{ stroke }}"
     stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
     class="{{ cls }}">
  <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
</svg>
{%- endmacro -%}
```

Then in `investigation_workspace.html` (or its V1 replacement), the
phase tab strip and Exploitation sub-tabs would look like:

```jinja
{% from "partials/_lucide.html" import lock, database_zap, terminal,
                                       globe, radar, search, zap %}

<nav class="flex border-b border-[#d0d7de] mb-4" role="tablist">
  <button type="button"
          role="tab"
          aria-selected="{{ 'true' if active_phase=='recon' else 'false' }}"
          data-phase="recon"
          class="phase-tab flex items-center gap-2 px-4 py-2 text-sm
                 {% if active_phase=='recon' %}border-b-2 border-[#0969da] text-[#0969da] font-semibold
                 {% else %}text-[#656d76] hover:text-[#1f2328]{% endif %}">
    {{ radar(cls='w-4 h-4') }} Recon
  </button>
  <button type="button"
          role="tab"
          aria-selected="{{ 'true' if active_phase=='enumeration' else 'false' }}"
          data-phase="enumeration"
          class="phase-tab flex items-center gap-2 px-4 py-2 text-sm
                 {% if active_phase=='enumeration' %}border-b-2 border-[#0969da] text-[#0969da] font-semibold
                 {% else %}text-[#656d76] hover:text-[#1f2328]{% endif %}">
    {{ search(cls='w-4 h-4') }} Enumeration
  </button>
  <button type="button"
          role="tab"
          aria-selected="{{ 'true' if active_phase=='exploitation' else 'false' }}"
          data-phase="exploitation"
          class="phase-tab flex items-center gap-2 px-4 py-2 text-sm
                 {% if active_phase=='exploitation' %}border-b-2 border-[#0969da] text-[#0969da] font-semibold
                 {% else %}text-[#656d76] hover:text-[#1f2328]{% endif %}">
    {{ zap(cls='w-4 h-4') }} Exploitation
  </button>
</nav>

{# Category sub-tabs — visible only when Exploitation is the active phase. #}
{% if active_phase == 'exploitation' %}
<div class="flex gap-1 mb-4" role="tablist" aria-label="Exploitation category">
  {% for cat in exploitation_categories %}
  {% set icon = {
       'authentication':     'lock',
       'sql_injection':      'database_zap',
       'command_injection':  'terminal',
       'api_security':       'globe'
     }[cat.category_id] if cat.category_id in
       ['authentication','sql_injection','command_injection','api_security']
       else None %}
  <button type="button"
          role="tab"
          data-category="{{ cat.category_id }}"
          aria-selected="{{ 'true' if cat.category_id == active_category else 'false' }}"
          class="cat-tab flex items-center gap-1.5 px-3 py-1.5 text-xs rounded
                 {% if cat.category_id == active_category %}bg-[#0969da] text-white
                 {% else %}bg-[#f3f4f6] text-[#1f2328] hover:bg-[#e3e8ee]{% endif %}">
    {%- if icon == 'lock'         %}{{ lock(cls='w-3.5 h-3.5')         }}{% endif -%}
    {%- if icon == 'database_zap' %}{{ database_zap(cls='w-3.5 h-3.5') }}{% endif -%}
    {%- if icon == 'terminal'     %}{{ terminal(cls='w-3.5 h-3.5')     }}{% endif -%}
    {%- if icon == 'globe'        %}{{ globe(cls='w-3.5 h-3.5')        }}{% endif -%}
    <span>{{ cat.label }}</span>
  </button>
  {% endfor %}
</div>
{% endif %}
```

Why this approach over `lucide-react`: lucide-react ships an npm
React package; this codebase has no npm pipeline, no React import
chain, and uses Preact-via-CDN for workspace.js. Inlining the same SVG
geometry that lucide-react would render avoids the toolchain delta and
matches the existing static-template stack.

### 5b — React Flow mind tree for Exploitation tab

V1 keeps Preact UMD-via-CDN (see `investigation_workspace.html:70-73`).
React Flow v11 ships as both `reactflow` (NPM) and a UMD bundle on
unpkg. The cleanest path: add the React Flow UMD + React UMD via CDN
(no build step), mount React Flow inside the Exploitation phase pane,
and let the rest of the workspace stay Preact.

Add to `investigation_workspace.html` `{% block extra_js %}`:

```html
{# Mind tree (Exploitation only) — React + React Flow v11 UMD. #}
<script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script crossorigin src="https://unpkg.com/reactflow@11.11.4/dist/umd/index.js"></script>
<link href="https://unpkg.com/reactflow@11.11.4/dist/style.css" rel="stylesheet">
<script src="/static/js/exploit-tree.js"></script>
```

Then `frontend/static/js/exploit-tree.js` (new file — proposed):

```javascript
/**
 * Exploitation phase mind tree — React Flow LR layout.
 *
 * Data shape consumed (from /workspace-data.json):
 *   exploit_tree: {
 *     nodes: [
 *       {
 *         id: 'finding-<fid>',
 *         type: 'action',
 *         data: {
 *           kind: 'finding' | 'action' | 'capture' | 'outcome',
 *           label: string,
 *           sub_label?: string,
 *           action_kind?: string,
 *           finding_id?: string,
 *           bundle_id?: string,
 *           executed?: boolean,
 *           execute_url?: string,
 *           guidance_only?: boolean,
 *         }
 *       }, ...
 *     ],
 *     edges: [
 *       { id: 'e-<src>-<tgt>', source: 'finding-<fid>', target: 'action-<ak>' }
 *     ],
 *   }
 */
(function () {
  'use strict';
  if (!window.React || !window.ReactDOM || !window.ReactFlow) return;

  var React        = window.React;
  var ReactDOM     = window.ReactDOM;
  var ReactFlow    = window.ReactFlow.default;
  var Background   = window.ReactFlow.Background;
  var Controls     = window.ReactFlow.Controls;
  var MarkerType   = window.ReactFlow.MarkerType;
  var useNodesState = window.ReactFlow.useNodesState;
  var useEdgesState = window.ReactFlow.useEdgesState;

  var NODE_W = 240, NODE_H = 96;
  var RANK_GAP = 60, SIB_GAP = 16;

  // Dagre-driven layout (already loaded for workspace.js)
  function _layout(nodes, edges) {
    var g = new dagre.graphlib.Graph().setDefaultEdgeLabel(function () { return {}; });
    g.setGraph({ rankdir: 'LR', ranksep: RANK_GAP, nodesep: SIB_GAP, marginx: 24, marginy: 24 });
    nodes.forEach(function (n) { g.setNode(n.id, { width: NODE_W, height: NODE_H }); });
    edges.forEach(function (e) { g.setEdge(e.source, e.target); });
    dagre.layout(g);
    return nodes.map(function (n) {
      var d = g.node(n.id);
      return Object.assign({}, n, {
        position: { x: d.x - NODE_W / 2, y: d.y - NODE_H / 2 },
        sourcePosition: 'right',
        targetPosition: 'left',
      });
    });
  }

  // Custom node for an exploit action card with Execute button.
  function ActionCardNode(props) {
    var d = props.data;
    var border = d.kind === 'capture' ? '#1a7f37'
               : d.executed             ? '#0969da'
               : d.guidance_only        ? '#bf8700'
                                        : '#d0d7de';
    var bg     = d.kind === 'capture' ? '#dafbe1'
               : d.guidance_only        ? '#fff8c5'
                                        : '#ffffff';
    function onExec(e) {
      e.stopPropagation();
      if (!d.execute_url) return;
      fetch(d.execute_url, { method: 'POST',
                              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                              body: '' })
        .then(function () { window.dispatchEvent(new CustomEvent('inv-topology-refresh')); });
    }
    return React.createElement('div', {
      style: {
        width: NODE_W + 'px',
        minHeight: NODE_H + 'px',
        background: bg,
        border: '1px solid ' + border,
        borderRadius: '6px',
        padding: '10px 12px',
        display: 'flex', flexDirection: 'column', gap: '6px',
        boxShadow: '0 1px 2px rgba(0,0,0,.06)',
      },
    },
      React.createElement('div', { style: { fontSize: '13px', fontWeight: 600, color: '#1f2328' } },
        d.label),
      d.sub_label
        ? React.createElement('div', { style: { fontSize: '11px', color: '#656d76' } }, d.sub_label)
        : null,
      d.kind === 'action' && !d.guidance_only
        ? React.createElement('button', {
            type: 'button',
            disabled: !!d.executed,
            onClick: onExec,
            style: {
              alignSelf: 'flex-start',
              background: d.executed ? '#dafbe1' : '#0969da',
              color: d.executed ? '#1a7f37' : '#fff',
              border: 'none', borderRadius: '4px',
              padding: '3px 10px', fontSize: '11px', fontWeight: 600,
              cursor: d.executed ? 'default' : 'pointer',
            },
          }, d.executed ? '✓ Executed' : 'Execute →')
        : null
    );
  }

  var nodeTypes = { actionCard: ActionCardNode };

  function ExploitTree(props) {
    var laidOut = React.useMemo(function () { return _layout(props.nodes, props.edges); },
                                 [props.nodes, props.edges]);
    var ns = useNodesState(laidOut);
    var es = useEdgesState(props.edges.map(function (e) {
      return Object.assign({}, e, {
        type: 'smoothstep',
        markerEnd: { type: MarkerType.ArrowClosed, color: '#d0d7de' },
        style: { stroke: '#d0d7de', strokeWidth: 1.5 },
      });
    }));

    return React.createElement(ReactFlow, {
      nodes: ns[0], edges: es[0],
      nodeTypes: nodeTypes,
      proOptions: { hideAttribution: true },
      fitView: true,
      fitViewOptions: { padding: 0.2 },
      minZoom: 0.4, maxZoom: 1.6,
      nodesDraggable: false, nodesConnectable: false, elementsSelectable: true,
    },
      React.createElement(Background, { gap: 16, color: '#e3e8ee' }),
      React.createElement(Controls, { showInteractive: false })
    );
  }

  window.mountExploitTree = function (containerId, data) {
    var el = document.getElementById(containerId);
    if (!el || !data) return;
    var nodes = data.nodes.map(function (n) {
      return Object.assign({}, n, { type: 'actionCard' });
    });
    ReactDOM.createRoot(el).render(
      React.createElement(ExploitTree, { nodes: nodes, edges: data.edges })
    );
  };
})();
```

Markup for the Exploitation pane:

```html
<div id="exploit-tree-root"
     style="width: 100%; height: 70vh; border: 1px solid #d0d7de; border-radius: 6px;"></div>
<script>
  // Called from workspace.js after the JSON poll lands.
  // data shape: see exploit-tree.js comment.
  window.addEventListener('inv-topology-refresh', function () {
    fetch('/api/v1/validation/workspace/investigations/' + INV_ID
          + '/workspace-data.json')
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (window.mountExploitTree && d.exploit_tree) {
          window.mountExploitTree('exploit-tree-root', d.exploit_tree);
        }
      });
  });
</script>
```

Backend side, the new `exploit_tree` field is built in
`_build_workspace_data` at `apps/investigation_workspace/api/routes.py:405`,
walking the same finding → category → exploit-path → action chain that
already exists in `topology_v2.py`, but emitting React-Flow shaped
nodes+edges instead of the flat-card structure.

### 5c — Phase tagging schema

Add a `phase` field to `FindingEvent` (and pass through to the
persisted finding). The bootstrap orchestration routes findings to
their tab based on the phase value.

Change `apps/investigation_workspace/probe/events.py:30`:

```python
from dataclasses import dataclass, field
from typing import Literal

Phase = Literal["recon", "enumeration", "exploitation"]


@dataclass(frozen=True)
class FindingEvent:
    """A real finding the probe discovered. Persists as NormalizedFinding."""
    after_stage_index: int
    finding_type:      str
    title:             str
    severity:          str
    description:       str
    endpoint:          str | None = None
    port:              int | None = None
    evidence:          dict       = field(default_factory=dict)
    # V1 — phase label routes the finding to the correct tab.
    phase:             Phase      = "recon"
```

Probe-side examples:

```python
# Recon — apps/investigation_workspace/probe/passive.py
yield FindingEvent(
    after_stage_index = 2,
    finding_type      = "http_service_detected",
    title             = f"HTTP {resp.status_code} service responding",
    severity          = "info",
    description       = "...",
    endpoint          = parsed.path or "/",
    evidence          = {"status_code": resp.status_code, ...},
    phase             = "recon",
)

# Enumeration — apps/investigation_workspace/probe/auth_recon.py
yield FindingEvent(
    after_stage_index = 1,
    finding_type      = "login_form_detected",
    title             = "Login form detected",
    severity          = "info",
    description       = "...",
    endpoint          = primary["path"],
    evidence          = {"detected_forms": found, ...},
    phase             = "enumeration",
)

# Exploitation — emitted from a kick-off probe's ResultEvent chain
# would not normally produce a FindingEvent; if it does (e.g., a fresh
# IDOR cross-user finding emerged), tag it explicitly:
yield FindingEvent(
    after_stage_index = 5,
    finding_type      = "api_idor",
    title             = "Cross-user GET succeeded",
    severity          = "critical",
    description       = "...",
    endpoint          = "/api/user/carlos",
    evidence          = {"target_user": "carlos", "status": 200, ...},
    phase             = "exploitation",
)
```

Bootstrap orchestration side — extend the persist callback at
`api/routes.py:760-824`:

```python
async def _persist(evt: FindingEvent) -> str | None:
    """Insert one probe-observed finding into the DB, tagged with phase."""
    # ... existing scan-execution setup ...

    finding = NormalizedFinding(
        scan_id          = scan.scan_id,
        investigation_id = investigation_id,
        source_scanner   = "passive_probe",
        finding_type     = evt.finding_type,
        severity         = evt.severity,
        title            = evt.title,
        description      = evt.description,
        target           = target,
        port             = evt.port,
        endpoint         = evt.endpoint,
        # V1 — every persisted finding carries its phase tag so the
        # workspace-data builder can route it to Recon / Enumeration /
        # Exploitation without re-deriving from finding_type.
        tags             = ["passive_probe", "bootstrap", f"phase:{evt.phase}"],
        raw_data         = {**(evt.evidence or {}), "_phase": evt.phase},
    )
    await NormalizedFindingRepository(db).insert(finding)
    # ...
```

Workspace-data builder side — extend `_build_workspace_data` to bucket
by phase:

```python
def _build_workspace_data(topology, boot_run, investigation_id, target):
    # ... existing node/edge collection ...

    # New V1 structure: top-level keys for each phase.
    phases: dict[str, dict] = {
        "recon":        {"summary_cards": [], "stage_columns": []},
        "enumeration":  {"summary_cards": [], "stage_columns": []},
        "exploitation": {"categories": [], "tree": {"nodes": [], "edges": []}},
    }

    # Bootstrap stages always land in recon/enumeration columns by probe_name.
    if boot_run is not None:
        for stage in boot_run.stages:
            pname = stage.probe_name  # "Headers & Transport", "API Security", ...
            phase = "recon" if pname == "Headers & Transport" else "enumeration"
            phases[phase]["stage_columns"].append({
                "probe_name": pname,
                "label":      stage.label,
                "status":     "completed" if stage.completed_at else "running",
            })

    # Findings — read raw_data["_phase"] to decide where they render.
    for n in nodes:
        if n.get("type") != "finding":
            continue
        raw = n.get("data", {}).get("raw_data", {})
        phase = raw.get("_phase", "recon")
        # ... aggregate into phases[phase] ...

    return {
        "investigation_id": investigation_id,
        "target":           target,
        "phases":           phases,
        # legacy fields preserved for backward-compat during migration
        "categories":       categories,
        "default_tab":      default_tab,
    }
```

### 5d — Operator gate at Exploitation

The V1 design says Recon and Enumeration auto-run; Exploitation
requires explicit click. The current code already enforces this for
the suggestion execute route (`api/routes.py:1099-1211`). The hardening
needed is:

1. **Bootstrap must not include Exploitation probes.** Today's bootstrap
   wires only Recon + Enumeration probes (verified at
   `bootstrap/runtime.py:202-203`). No change required.

2. **The execute route must reject any probe whose phase is not
   Exploitation, unless the operator explicitly confirms.** Today this
   is enforced indirectly: only `SuggestionSpec`s with `probe_runner`
   reach the route, and Exploitation probes are the only ones expected
   to be clicked. Add an explicit check.

Route-level guard at `api/routes.py:1099` (proposed extension):

```python
@router.post(
    "/investigations/{investigation_id}/finding/{finding_id}/suggest/{action_kind}/execute",
    response_class=HTMLResponse,
)
async def execute_suggestion(
    investigation_id: str,
    finding_id:       str,
    action_kind:      str,
    request:          Request,
    exploit_path_id:  str = "",
    parent_run_id:    str = "",
    confirm:          str = "",   # V1 — must equal action_kind for AE probes
):
    from apps.investigation_workspace.execution.runtime import (
        kick_off as exec_kick_off,
    )
    from apps.investigation_workspace.suggestions.catalog import find_spec

    spec = find_spec(action_kind)
    if spec is None:
        raise HTTPException(404, f"Unknown action_kind: {action_kind}")
    if spec.probe_runner is None:
        raise HTTPException(
            400,
            f"Action '{action_kind}' is guidance-only — no probe is registered.",
        )

    # V1 — Exploitation gate. Every Exploitation-phase action requires
    # an explicit ?confirm=<action_kind> query param so a stray GET-then-POST
    # (htmx replay, browser back/forward) cannot fire AE traffic.
    EXPLOITATION_ACTIONS = {
        "sqli_auth_bypass", "brute_force_login",
        "cmdi_reflected", "cmdi_blind_time", "cmdi_blind_boolean",
        "api_exploit", "purchase_flow", "csp_xss_reflected",
        "api_full_discovery",   # sends creds
    }
    is_dynamic_ae = action_kind.startswith(("api_idor_mutate_", "api_method_"))
    needs_confirm = action_kind in EXPLOITATION_ACTIONS or is_dynamic_ae
    if needs_confirm and confirm != action_kind:
        raise HTTPException(
            status_code = 409,
            detail      = (
                f"Action '{action_kind}' is operator-gated. "
                f"POST with ?confirm={action_kind} to fire."
            ),
        )

    # ...rest unchanged...
```

Frontend confirmation pattern — the Execute button in the React Flow
custom node (Section 5b) becomes a two-click sequence:

```javascript
function ActionCardNode(props) {
  var d = props.data;
  var armed = React.useState(false);     // [armed, setArmed]
  var setArmed = armed[1]; armed = armed[0];

  function onExec(e) {
    e.stopPropagation();
    if (!d.execute_url) return;

    var url = d.execute_url;
    var isAE = (d.phase === 'exploitation');   // server-emitted hint

    if (isAE && !armed) {
      setArmed(true);
      // Auto-disarm after 5s so a forgotten armed button doesn't
      // turn into a single-click landmine.
      setTimeout(function () { setArmed(false); }, 5000);
      return;
    }

    var finalUrl = isAE ? url + (url.indexOf('?') >= 0 ? '&' : '?')
                          + 'confirm=' + encodeURIComponent(d.action_kind)
                        : url;
    fetch(finalUrl, { method: 'POST',
                      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                      body: '' })
      .then(function () {
        setArmed(false);
        window.dispatchEvent(new CustomEvent('inv-topology-refresh'));
      });
  }

  var label = d.executed ? '✓ Executed'
            : armed       ? 'Click again to confirm'
            : d.phase === 'exploitation' ? 'Arm exploit →'
                                          : 'Execute →';
  // ... rest of node template ...
}
```

The "Arm exploit" → "Click again to confirm" pattern (with a 5-second
auto-disarm) matches the Capture-bundle bookmarklet treatment that
already shows up amber-accented (`capture_bundle.html`) and the
"Manual investigation paths" amber-accented section
(`catalog.py:64-119`). Visual + interaction consistency, route-level
enforcement.

---

## APPENDIX — file inventory consulted

Probes / probe wrappers:
- `apps/investigation_workspace/probe/passive.py` (262 LOC)
- `apps/investigation_workspace/probe/auth_recon.py` (438 LOC)
- `apps/investigation_workspace/probe/api_recon.py` (231 LOC)
- `apps/investigation_workspace/probe/sqli_recon.py` (159 LOC)
- `apps/investigation_workspace/probe/cmdi_recon.py` (216 LOC)
- `apps/investigation_workspace/probe/api_browser_recon.py` (318 LOC)
- `apps/investigation_workspace/probe/api_endpoint_enum.py` (308 LOC)
- `apps/investigation_workspace/probe/api_method_enum.py` (587 LOC)
- `apps/investigation_workspace/probe/api_authed_recon.py` (295 LOC)
- `apps/investigation_workspace/probe/purchase_flow.py` (485 LOC)
- `apps/investigation_workspace/probe/lab_auth.py` (142 LOC)
- `apps/investigation_workspace/probe/events.py` (99 LOC)
- `apps/investigation_workspace/probe/normalize.py`
- `apps/investigation_workspace/suggestions/probes.py` (5,332 LOC)
- `apps/investigation_workspace/suggestions/catalog.py` (337 LOC)

Bootstrap, runtime, routes:
- `apps/investigation_workspace/bootstrap/runtime.py` (273 LOC)
- `apps/investigation_workspace/execution/runtime.py` (581 LOC, key
  sections — context vars at lines 84-105, kick_off at 241-328)
- `apps/investigation_workspace/api/routes.py` (2,365 LOC)
- `apps/investigation_workspace/exploitation_paths/bindings.py` (87 LOC)
- `apps/investigation_workspace/categories/catalog.py` (148 LOC)
- `apps/validation/api/investigations.py` (~1k LOC, route at 522)

Frontend:
- `frontend/templates/base.html` (160 LOC)
- `frontend/templates/investigation_workspace.html` (74 LOC)
- `frontend/templates/investigations.html` (152 LOC)
- 14 top-level templates + 35 partials enumerated in 4a
- `frontend/static/js/workspace.js` (789 LOC)
- `frontend/static/js/cross-context-routing.js` (67 LOC)
- `frontend/static/js/htmx.min.js`
- `frontend/static/css/main.css` (1,277 LOC, 258 class selectors)
