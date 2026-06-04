# API Security — Stage Card Audit

**Date:** 2026-05-23
**Scope:** Every StageEvent / ResultEvent / FindingEvent emitted by the API
Security probe family. Read-only — no code changes.

**Classification key:**

| Tag | Meaning |
|-----|---------|
| **KEEP** | Carries real operator signal (finding, exploit result, quality indicator). Must remain a visible graph node. |
| **COLLAPSE** | Process narration only. Could be hidden inside a parent summary card without losing operator value. |
| **DROP** | No operator value; pure internal state. Safe to remove the yield entirely. |

---

## 1. `probe_api_exploit` (`probes.py` ~line 3556)

The primary IDOR/BOLA probe. Runs in four sequential phases.

### Phase 1 — Discover API documentation

| # | Event type | Label (truncated) | Classification | Reason |
|---|-----------|-------------------|----------------|--------|
| 1 | StageEvent | "Discovering API documentation" | **COLLAPSE** | Lists the doc paths being probed. Outcome is fully captured by the next card; narration adds no signal. |
| 2 | ResultEvent | "No API documentation found" (kind=blocked) | **KEEP** | Terminal failure. Operator needs to know docs are absent and which paths were tried. Probe halts here. |
| 3 | StageEvent | "API documentation discovered at `{doc_path}`" | **KEEP** | Real signal: which URL held the spec and what format (`openapi`/`swagger`/`html_table`). |

### Phase 2 — Parse spec

| # | Event type | Label (truncated) | Classification | Reason |
|---|-----------|-------------------|----------------|--------|
| 4 | StageEvent | "Parsed `{N}` endpoints from API spec" | **KEEP** | Real signal: total endpoint count and the list of user-scoped endpoints that will be probed in Phase 4. |
| 5 | StageEvent | "Deferred `{N}` mutating endpoint(s) — operator approval required" | **KEEP** | Real signal (conditional). Surfaces DELETE/PATCH/POST/PUT endpoints that need explicit operator action. Only emitted when mutating endpoints exist. |

### Phase 3 — Authenticate

| # | Event type | Label (truncated) | Classification | Reason |
|---|-----------|-------------------|----------------|--------|
| 6 | StageEvent | "Trying `{N}` credential pair(s) — HTML form login then JSON API fallback" | **COLLAPSE** | Process narration. Auth outcome (success or failure) is already captured in cards 7 and 8. |
| 7 | ResultEvent | "Default credentials failed — operator credentials required" (kind=note) | **KEEP** | Auth blocker. Probe halts here. Operator must see why and what was tried. |
| 8 | StageEvent | "Authenticated as `{username}` — probing `{N}` GET endpoint(s) for IDOR" | **KEEP** | Real signal: which identity will probe the endpoints, and how many GET endpoints are queued. |

### Phase 4 — IDOR detection loop

| # | Event type | Label (truncated) | Classification | Reason |
|---|-----------|-------------------|----------------|--------|
| 9 | StageEvent | "IDOR confirmed at `{method}` `{exploit_path}`" | **KEEP** | Primary exploit finding label. Emitted only on a confirmed 2xx cross-user access. |
| 10 | ResultEvent | "IDOR confirmed — `{method}` `{exploit_path}` accessible as `{username}`" (kind=detected) | **KEEP** | Full structured evidence node: request, response, analysis, next_actions (mutating cards with pre-filled target user). |
| 11 | ResultEvent | "No IDOR detected on GET endpoints" (kind=blocked) | **KEEP** | Negative outcome. Records which endpoints and users were checked; surfaces mutating action cards if any deferred endpoints exist. |

---

## 2. `run_auth_recon_probe` (`auth_recon.py` ~line 201)

Bootstrap recon probe. Detects HTML login forms; emits a FindingEvent that
triggers the `login_form_detected` suggestion branch.

| # | Event type | Label (truncated) | Classification | Reason |
|---|-----------|-------------------|----------------|--------|
| 1 | StageEvent | "Scanning for login forms" | **COLLAPSE** | Lists the paths probed. No new information beyond what the FindingEvent carries. |
| 2 | StageEvent | "Cataloguing login forms" | **KEEP** | Real signal: lists detected username/password/CSRF field names so the operator can verify the parser correctly identified the form structure. |
| 3 | FindingEvent | "Login form detected" | **KEEP** | Bootstrap finding. Triggers the `login_form_detected` suggestion branch; carries full form metadata for downstream probes. |

*No FindingEvent is emitted on negative result — the probe is silent when no form is found (correct pattern).*

---

## 3. `probe_api_authed_recon` (standalone wrapper, `probes.py` ~4758) + `run_authed_recon` (`api_authed_recon.py`)

Standalone probe C. Authenticates, then scrapes authenticated pages for hidden
`/api/*` paths and resource IDs.

### Wrapper stages (emitted by `probe_api_authed_recon`)

| # | Event type | Label (truncated) | Classification | Reason |
|---|-----------|-------------------|----------------|--------|
| 1 | StageEvent | "Authenticating for authed-page recon" | **COLLAPSE** | Repeated auth-attempt pattern. Outcome is captured in card 2 or 3. |
| 2 | StageEvent | "Authentication succeeded" | **KEEP** | Real signal: which user was authenticated; session cookie keys visible. |
| 3 | StageEvent | "Authentication failed — continuing with unauthenticated scrape" | **KEEP** | Quality signal. Operator knows result quality is degraded (public pages only). |

### Stages from `run_authed_recon`

| # | Event type | Label (truncated) | Classification | Reason |
|---|-----------|-------------------|----------------|--------|
| 4 | StageEvent | "BeautifulSoup4 not installed — authenticated recon limited to raw-regex..." | **KEEP** | Tooling-degradation alert. Operator must know coverage is reduced. Only emitted when bs4 is absent. |
| 5 | StageEvent | "Scraping authenticated pages for API paths and resource IDs" | **COLLAPSE** | Process narration. Lists URLs being fetched; outcome captured in card 6. |
| 6 | StageEvent | "Authenticated page scraping complete" | **KEEP** | Real signal: pages scraped count, unique `/api/*` path count, ID counts. |
| 7 | ResultEvent | "Authenticated recon complete" (kind=detected\|note) | **KEEP** | Evidence node: `discovered_paths`, `discovered_ids`, `pages_scraped`. Fed into probe A and B. |

---

## 4. `probe_api_endpoint_enum` (standalone wrapper, `probes.py` ~4807) + `run_endpoint_enum` (`api_endpoint_enum.py`)

Standalone probe A. Wordlist + candidate-path enumeration with ID substitution.

### Wrapper stages

| # | Event type | Label (truncated) | Classification | Reason |
|---|-----------|-------------------|----------------|--------|
| 1 | StageEvent | "Authenticating for endpoint enumeration" | **COLLAPSE** | Repeated auth-attempt pattern. No auth outcome cards follow (silent on failure). |

### Stages from `run_endpoint_enum`

| # | Event type | Label (truncated) | Classification | Reason |
|---|-----------|-------------------|----------------|--------|
| 2 | StageEvent | "Enumerating API endpoints via wordlist" | **COLLAPSE** | Process narration. Total path count + base URL; outcome captured in card 3. |
| 3 | StageEvent | "Endpoint enumeration complete" | **KEEP** | Real signal: 2xx/401-403/405 counts with sample paths in `detected` field. |
| 4 | ResultEvent | "Endpoint enumeration: `{N}` endpoint(s) found" (kind=detected\|note) | **KEEP** | Primary evidence: `accessible`, `auth_required`, `wrong_method` lists, `allow_headers`. Carries a `next_actions` card for method enum when endpoints exist. |

---

## 5. `probe_api_method_enum` (standalone wrapper, `probes.py` ~4850) + `run_method_enum` (`api_method_enum.py`)

Standalone probe B. Tests all HTTP verbs against discovered endpoints.

### Wrapper stages

| # | Event type | Label (truncated) | Classification | Reason |
|---|-----------|-------------------|----------------|--------|
| 1 | StageEvent | "Authenticating for HTTP method enumeration" | **COLLAPSE** | Repeated auth-attempt pattern. No auth outcome cards follow. |

### Stages from `run_method_enum`

| # | Event type | Label (truncated) | Classification | Reason |
|---|-----------|-------------------|----------------|--------|
| 2 | StageEvent | "No endpoints supplied for method enumeration" | **KEEP** | Real signal: probe cannot proceed; tells operator to run endpoint enum first or supply paths. |
| 3 | ResultEvent | "Method enumeration skipped — no endpoints" (kind=note) | **KEEP** | Records the no-input outcome. Needed for audit trail when probe fires with no evidence context. |
| 4 | StageEvent | "Probing HTTP methods on discovered endpoints" | **COLLAPSE** | Process narration. Endpoint and verb count; outcome captured in card 5. |
| 5 | StageEvent | "HTTP method enumeration complete" | **KEEP** | Real signal: unusual method/endpoint pairs in `detected` field. |
| 6 | ResultEvent | "Method enumeration: `{N}` unusual combination(s)" (kind=detected\|note) | **KEEP** | Primary evidence: full method matrix, unusual pairs list, per-endpoint action cards with optional `body` input field. |

---

## 6. `probe_api_full_discovery` (`probes.py` ~4923)

Orchestrator: runs C → (A ∥ B). Emits a superset of the above cards.

### Orchestrator-specific stages

| # | Event type | Label (truncated) | Classification | Reason |
|---|-----------|-------------------|----------------|--------|
| 1 | StageEvent | "Authenticating for API discovery" | **COLLAPSE** | Same repeated auth-attempt pattern. |
| 2 | StageEvent | "Authentication succeeded — starting full discovery" | **KEEP** | Real signal: confirms which user authenticated before the full orchestrated run. |
| 3 | StageEvent | "Authentication failed — discovery will use empty session" | **KEEP** | Quality signal: all sub-probe results will be unauthenticated. |
| 4 | StageEvent | "Phase 1 — scraping authenticated pages for API paths" | **COLLAPSE** | Transition label. Could merge with `run_authed_recon`'s own start stage (card C.5 above). |
| 5 | StageEvent | "Phase 2 — running endpoint enum (A) and method enum (B) in parallel" | **KEEP** | Real signal: seed counts from Phase 1 visible; marks the parallel execution boundary. |

*Cards 6–14 are the standard outputs from `run_authed_recon`, `run_endpoint_enum`, and `run_method_enum` as enumerated in sections 3–5 above.*

**Known issue (not a stage-card issue):** `probe_api_full_discovery` calls
`extract_recon_data` (which runs the full HTTP scrape internally) and then
immediately calls `run_authed_recon` again, doubling the authenticated page
requests. The duplicate scrape does not produce duplicate graph nodes (same
events, same content), but it wastes 2× HTTP requests and 2× processing time.

---

## Summary — COLLAPSE candidates

These are the stage cards that could be eliminated or nested inside a parent
summary without any operator information loss. They represent process narration
that duplicates what adjacent KEEP cards already report.

| Probe | Label | Suggested treatment |
|-------|-------|---------------------|
| `probe_api_exploit` | "Discovering API documentation" | Collapse into Phase 1 result card |
| `probe_api_exploit` | "Trying `{N}` credential pair(s)..." | Collapse into "Authenticated as..." or failure result |
| `run_auth_recon_probe` | "Scanning for login forms" | Collapse into "Cataloguing login forms" |
| `probe_api_authed_recon` wrapper | "Authenticating for authed-page recon" | Collapse (repeated pattern × 4 probes) |
| `probe_api_endpoint_enum` wrapper | "Authenticating for endpoint enumeration" | Collapse |
| `probe_api_method_enum` wrapper | "Authenticating for HTTP method enumeration" | Collapse |
| `probe_api_full_discovery` | "Authenticating for API discovery" | Collapse |
| `probe_api_full_discovery` | "Phase 1 — scraping authenticated pages..." | Merge with recon start card |
| `run_authed_recon` | "Scraping authenticated pages for API paths..." | Collapse into "...complete" card |
| `run_endpoint_enum` | "Enumerating API endpoints via wordlist" | Collapse into "...complete" card |
| `run_method_enum` | "Probing HTTP methods on discovered endpoints" | Collapse into "...complete" card |

**Impact if collapsed:** 11 cards removed. All signal is preserved. The graph
drops from ~22 cards (full discovery run) to ~11 cards per orchestrated run.

---

## No DROP candidates

Every remaining card carries unique signal: confirmation of which identity
authenticated, which spec format was detected, what paths were found, exploit
confirmation, or tool-degradation warnings. None are safe to remove entirely.
