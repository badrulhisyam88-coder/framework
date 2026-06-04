# Dormant Capabilities Inventory
**Date:** 2026-05-24
**Scope:** `/home/unctad/projects/ai-assist-tool`
**Methodology:** Static import tracing from `apps/investigation_workspace/bootstrap/runtime.py`, full repo walk at depth 2, cross-reference of all discovered artifacts against the live import graph.

---

## Active System Boundary

### Live import graph (bootstrap/runtime.py → transitive closure)

The active runtime is defined by what `apps/investigation_workspace/bootstrap/runtime.py` imports on startup:

| Module | Role |
|---|---|
| `apps.investigation_workspace.bootstrap.runtime` | Entry point |
| `apps.investigation_workspace.probe.api_recon` | API structure recon probe |
| `apps.investigation_workspace.probe.auth_recon` | Auth header / mechanism recon probe |
| `apps.investigation_workspace.probe.cmdi_recon` | Command injection recon probe |
| `apps.investigation_workspace.probe.cors_recon` | CORS misconfiguration probe |
| `apps.investigation_workspace.probe.events` | Event dataclasses (FindingEvent, StageEvent) |
| `apps.investigation_workspace.probe.finding_id` | Deterministic finding ID generator |
| `apps.investigation_workspace.probe.fingerprint_recon` | Service/technology fingerprinting probe |
| `apps.investigation_workspace.probe.normalize` | URL/target normalization helpers |
| `apps.investigation_workspace.probe.passive` | Passive HTTP metadata collection probe |
| `apps.investigation_workspace.probe.sqli_recon` | SQLi recon probe |
| `apps.investigation_workspace.probe.wellknown_recon` | /.well-known path discovery probe |

**Total live modules at bootstrap time:** 12 (within `apps.investigation_workspace` only)

**Top-level folders spanned by the live import graph:** 1 (`apps/investigation_workspace/probe/`)

### What else is wired via the FastAPI router chain

The following modules are **not** imported at bootstrap but are registered as HTTP route handlers (therefore reachable via API calls at runtime). They are in-scope for the active system but conditionally executed:

- `apps/investigation_workspace/` — workspace router (investigation execution, branch assembly, suggestions engine)
- `apps/investigation_core/` — investigation lifecycle, evidence, campaigns, skills, progression, guided actions
- `apps/scanner_orchestration/` — nmap/nuclei/ZAP adapters, scan profiles, normalization pipeline
- `apps/validation/` — scanner service, correlator, executor, Metasploit integration, CVE sync, queue worker

These are all mounted in `core/api/app.py` → `apps/validation/api/__init__.py` → `validation_router`.

---

## Dormant Capabilities — Recon-Class

### DC-R-01: Subdomain Enumeration Adapter (`apps/validation/adapters/recon_ng.py`)

- **File:** `apps/validation/adapters/recon_ng.py` (60+ lines)
- **What it is:** Subdomain enumerator using crt.sh (Certificate Transparency) and hackertarget.com DNS host search. Resolves discovered hostnames to IPs. Despite the filename, no recon-ng binary is required — it hits the same free data sources over plain HTTP.
- **Status:** FULLY DORMANT
- **Evidence:** No import of `recon_ng` exists anywhere outside its own file. The external API clients (Shodan, Censys, BinaryEdge, HIBP) mentioned in the docstring as future additions are not present.
- **What it could do if wired:** Enumerate subdomains of a target domain before the probe pipeline starts, expanding the attack surface automatically. Would feed discovered hostnames into the passive/fingerprint probes.
- **Effort to wire:** Small — expose `SubdomainEnumerator.run(domain)` via a new discovery route or call it from `run_passive_probe` as a pre-probe step.
- **Overlap with active system:** Passive probe (`probe/passive.py`) operates on a single URL target. This adapter would precede it, generating additional targets from a domain root.

---

### DC-R-02: API Authenticated Page Scraper (`apps/investigation_workspace/probe/api_authed_recon.py`)

- **File:** `apps/investigation_workspace/probe/api_authed_recon.py`
- **What it is:** BeautifulSoup-based HTML scraper. Fetches common authenticated pages (`/`, `/catalog`, `/my-account`, `/products`, `/admin`, etc.) using caller-supplied session cookies. Extracts `href/src/action/data-url` attributes, `fetch()`/`axios()`/XHR URLs from script tags, and `/api/*` path substrings. Emits discovered paths and numeric/UUID resource IDs.
- **Status:** REFERENCED BUT NOT EXECUTED — `probe_api_authed_recon` is defined in `suggestions/probes.py` and registered in `suggestions/catalog.py`, but the catalog entry requires `operator_auth_state` to be present in hints, and the probe is triggered only on `api_structure_recon` findings with auth evidence attached.
- **What it could do if wired:** Phase 1 of a full API discovery chain. Operator supplies session cookies; the probe harvests hidden API paths, feeds them into `api_endpoint_enum`, and identifies resource IDs for BFLA/IDOR testing.
- **Effort to wire:** None — fully wired in `suggestions/probes.py:4854` and `catalog.py:230`. Activation requires: (a) a `api_structure_recon` finding with auth evidence, (b) operator providing session cookies via hint input. Optional `bs4` dependency gracefully absent.
- **Overlap with active system:** Downstream complement to `api_recon` (DC-E-01). Output feeds `api_endpoint_enum` (DC-E-02) and `api_method_enum` (DC-E-03).

---

### DC-R-03: NVD Feed Sync (`apps/validation/engines/nvd_sync.py`)

- **File:** `apps/validation/engines/nvd_sync.py` (320 lines)
- **What it is:** Pulls CVE data from the NVD 2.0 REST API (`services.nvd.nist.gov`) into local SQLite. Paginated with rate limiting (6s between requests without API key; key configurable via `TOOL_NVD_API_KEY`). Can do full sync or incremental since last run date.
- **Status:** REFERENCED BUT NOT EXECUTED — the settings page exposes a manual trigger; the engine is wired into the validation database and `CVERepository`. However, `data/validation.db` exists and is 438 KB, suggesting data is present from previous syncs.
- **What it could do if wired:** Keep the local CVE database current. Required for the CVE matcher (DC-R-04) to produce useful results. Already manually triggerable from the Settings page.
- **Effort to wire:** None — already triggerable. Automated weekly scheduling would be a small addition.
- **Overlap with active system:** Required infrastructure for `cve_matcher.py` which feeds the `correlator.py` in `apps/validation/services/`.

---

### DC-R-04: CVE Matcher (`apps/validation/engines/cve_matcher.py`)

- **File:** `apps/validation/engines/cve_matcher.py` (209 lines)
- **What it is:** Bridges nmap-discovered services to CVEs. Takes a normalized service (vendor/product/version from `fingerprint_normalizer.py`) and queries local SQLite for matching CVEs. Handles exact version, version range (versionStartIncluding/versionEndExcluding), and wildcard matching.
- **Status:** REFERENCED BUT NOT EXECUTED — used by `apps/validation/services/correlator.py` which is part of the post-nmap pipeline. Wired in the correlator but only fires when nmap scan results are processed.
- **What it could do if wired:** Automatically surface CVEs applicable to discovered service versions after an nmap scan, populating the validation queue.
- **Effort to wire:** None — already wired in the correlator pipeline. Only fires when an nmap scan completes and services are stored.
- **Overlap with active system:** Part of the validation module's correlator pipeline. Active when nmap is running.

---

## Dormant Capabilities — Enumeration-Class

### DC-E-01: API Endpoint Enumerator via Wordlist (`apps/investigation_workspace/probe/api_endpoint_enum.py`)

- **File:** `apps/investigation_workspace/probe/api_endpoint_enum.py`
- **What it is:** Wordlist-driven endpoint discovery. Loads the 269-entry vendored SecLists wordlist (`probe/wordlists/api-endpoints.txt`). Accepts high-priority candidates from prior recon and a list of discovered resource IDs to substitute into `{id}` placeholders. Classifies responses: 2xx (accessible), 401/403 (auth-gated), 405 (wrong method, fires OPTIONS), 5xx (server error), 404 (absent). Concurrency: `asyncio.Semaphore(10)`.
- **Status:** REFERENCED BUT NOT EXECUTED — `probe_api_endpoint_enum` is defined in `suggestions/probes.py:4891` and registered in `catalog.py:236`. Requires an existing `api_structure_recon` finding and is conditioned on non-empty discovered paths or spec hints.
- **What it could do if wired:** Discover API endpoints not surfaced by passive inspection or spec parsing. The `{id}` substitution enables IDOR/BFLA surface mapping.
- **Effort to wire:** None — catalog entry exists. Trigger condition met when an `api_structure_recon` finding is present.
- **Overlap with active system:** Follows `api_recon` and `api_authed_recon`. Output feeds `api_method_enum` (DC-E-02) and provides input for BFLA/IDOR investigations.

### DC-E-02: Vendored API Endpoint Wordlist (`apps/investigation_workspace/probe/wordlists/api-endpoints.txt`)

- **File:** `apps/investigation_workspace/probe/wordlists/api-endpoints.txt` (269 entries)
- **What it is:** Curated list of common REST API endpoint paths (`/api/users`, `/api/admin`, `/api/v1/...`, etc.) used by `api_endpoint_enum.py`.
- **Status:** FULLY DORMANT (wordlist only executes when DC-E-01 runs)
- **What it could do if wired:** Feeds endpoint enumeration.
- **Effort to wire:** None — used automatically by DC-E-01.
- **Overlap with active system:** None until `api_endpoint_enum` fires.

### DC-E-03: HTTP Method Enumerator (`apps/investigation_workspace/probe/api_method_enum.py`)

- **File:** `apps/investigation_workspace/probe/api_method_enum.py` (667 lines)
- **What it is:** Per-endpoint HTTP verb matrix. For each endpoint: (1) sends OPTIONS and parses `Allow` header, (2) sends GET/POST/PUT/PATCH/DELETE/HEAD in parallel via `asyncio.Semaphore(8)`, (3) flags non-GET methods returning 2xx/3xx on resource-like paths, (4) sends empty JSON body probes on 400/422 to extract field-validation hints and infer schema. Emits `next_actions` for each endpoint+method combination where the server accepts or would accept an authenticated request.
- **Status:** REFERENCED BUT NOT EXECUTED — `probe_api_method_enum` is in `suggestions/probes.py:4921` and `catalog.py:244`. Also spawned dynamically from `api_endpoint_enum` output (`api_method_enum` action_kinds encoded in ResultEvent next_actions).
- **What it could do if wired:** Map the full writable surface of an API. The body-schema extraction from 400/422 errors is particularly valuable: it reveals field names without requiring a spec.
- **Effort to wire:** None — already in catalog and triggered dynamically from `api_endpoint_enum`.
- **Overlap with active system:** Part of the API recon chain. The 667-line size reflects the body-schema inference logic (base64-encoded action kinds carrying endpoint+method state).

### DC-E-04: Default Password Credential List (`apps/investigation_workspace/probe/wordlists/default-passwords.csv`)

- **File:** `apps/investigation_workspace/probe/wordlists/default-passwords.csv` (2,876 entries)
- **What it is:** Large credential list of default vendor username/password pairs across router manufacturers, IoT devices, NAS systems, network appliances, etc.
- **Status:** FULLY DORMANT — no Python file in the active system imports or references this CSV. The SSH validation plugin uses a separate 12-entry YAML list (`config/credentials/ssh_defaults.yaml`), not this file.
- **What it could do if wired:** Feed a multi-protocol credential stuffing probe (SSH, Telnet, HTTP Basic Auth) against discovered services.
- **Effort to wire:** Medium — a new probe module would need to load this file and iterate over relevant entries for each discovered service type.
- **Overlap with active system:** The SSH validation plugin (`apps/validation/plugins/ssh.py`) does credential testing but uses only the 12-entry YAML. This list would extend coverage to non-SSH services and obscure vendors.

### DC-E-05: SSH Default Credentials (`config/credentials/ssh_defaults.yaml`)

- **File:** `config/credentials/ssh_defaults.yaml` (29 lines, 12 credential pairs)
- **What it is:** YAML list of default SSH credentials (admin/admin, root/root, pi/raspberry, etc.). Referenced by `config/validation_profiles/ssh.yaml` and consumed by `apps/validation/plugins/ssh.py`.
- **Status:** REFERENCED BUT NOT EXECUTED — the SSH plugin is wired in the validation pipeline but only fires when an SSH service is discovered by nmap and queued by the correlator.
- **What it could do if wired:** Validate weak/default SSH credentials on discovered hosts. Already fully wired — activation requires an nmap scan that discovers port 22/SSH.
- **Effort to wire:** None.
- **Overlap with active system:** Validation plugin infrastructure, not investigation_workspace probes.

---

## Dormant Capabilities — Exploitation-Class

### DC-X-01: Metasploit RPC Integration (`apps/validation/services/metasploit.py`, `apps/validation/api/metasploit.py`, `apps/validation/services/msf_recipes.py`, `apps/validation/services/msf_wordlists.py`)

- **Files:**
  - `apps/validation/services/metasploit.py` (360 lines) — async wrapper around `pymetasploit3`, lazy reconnect
  - `apps/validation/api/metasploit.py` (230 lines) — FastAPI routes: status, module search, module info, run, run detail, delete
  - `apps/validation/services/msf_recipes.py` (547 lines) — curated module catalog with pre-filled options
  - `apps/validation/services/msf_wordlists.py` (124 lines) — catalog of wordlists inside the Metasploit container
- **What it is:** Full Metasploit RPC UI. Allows the operator to search the module library, inspect module options, run modules with pre-filled or custom options, and view results. The docker-compose.yml includes a `metasploit` service (`metasploitframework/metasploit-framework:latest`) running `msfrpcd`. Explicitly designed so no automatic code path invokes it — every execution is an explicit operator action from the Metasploit tab.
- **Status:** LIVE — routes are registered in `validation_router` and operator-accessible. `msf_recipes.py` and `msf_wordlists.py` serve static data to the Metasploit tab UI. The `metasploit` Docker service is a separate container that must be started independently; `pymetasploit3` is imported with try/except fallback. V2 design audit (2026-05-26) confirmed operator-driven execution is functional. _(Formerly classified "REFERENCED BUT NOT EXECUTED" in this inventory; corrected to LIVE.)_
- **What it does:** Full Metasploit module execution from the web UI. The `msf_recipes.py` catalog pre-populates options for common exploitation modules across 9 service classes. `msf_wordlists.py` catalogs 40+ credential wordlists inside the Metasploit container.
- **Effort to activate container:** Small — start the `metasploit` Docker service (already defined in `docker-compose.yml`). Ensure `pymetasploit3` is installed in the backend image.
- **Overlap with active system:** Completely isolated from the probe pipeline by design. No investigation_workspace or scanner_orchestration code references it.

### DC-X-02: Purchase Flow / BFLA Price Manipulation Probe (`apps/investigation_workspace/probe/purchase_flow.py`)

- **File:** `apps/investigation_workspace/probe/purchase_flow.py`
- **What it is:** Full e-commerce exploit chain probe. Steps: (1) detect price endpoint from captured evidence, (2) PATCH price to 0 (tries 5 JSON body shapes), (3) verify price changed via GET, (4) add item to cart (tries multiple form/JSON patterns), (5) extract CSRF token from HTML/cookies, (6) submit checkout, (7) detect order success via redirect URL or body keywords. Includes explicit BFLA (Broken Function Level Authorization) price manipulation.
- **Status:** REFERENCED BUT NOT EXECUTED — `probe_purchase_flow` registered in `suggestions/probes.py:5305` and `catalog.py:162`. Triggered only when a `bfla_price_manipulation` or similar finding is present in the investigation, combined with a captured price endpoint URL.
- **What it could do if wired:** Execute an end-to-end BFLA exploit: zero out a product price and complete a fraudulent purchase. The probe is fully automated.
- **Effort to wire:** None — catalog entry exists. Trigger requires a `bfla_price_manipulation` finding with a price endpoint URL in evidence.
- **Overlap with active system:** Downstream exploitation step following BFLA recon. Operates on `api_recon` and browser-recon discoveries.

### DC-X-03: Chromium / Playwright Browser Probe (`apps/investigation_workspace/probe/api_browser_recon.py`)

- **File:** `apps/investigation_workspace/probe/api_browser_recon.py`
- **What it is:** Headless Chromium probe via Playwright. Navigates to the target URL with an intercepting network proxy, captures XHR/fetch API calls and their request/response bodies, extracts resource IDs from navigation URLs, and maps the JS-driven API surface. Gracefully degrades: if Playwright is not installed, emits a `playwright_unavailable` finding with install instructions.
- **Status:** REFERENCED BUT NOT EXECUTED — `probe_api_browser_recon` registered in `suggestions/probes.py:5101` and `catalog.py:253`. Playwright is not in `pyproject.toml`; the Docker image does not include Chromium.
- **What it could do if wired:** Capture the full SPA/JS API surface including dynamically constructed URLs, Bearer tokens visible in Authorization headers, and resource IDs embedded in navigation paths.
- **Effort to wire:** Medium — add `playwright` to `pyproject.toml`, rebuild Docker image with `playwright install chromium` (significant image size increase). The probe code itself is ready.
- **Overlap with active system:** Complements `api_recon` for SPAs. Output feeds `api_authed_recon` and `api_method_enum`.

### DC-X-04: Validation Plugin Stack — SMB, Telnet, WordPress, Drupal, Apache, Nginx (`apps/validation/plugins/`)

- **Files:**
  - `smb.py` — null session share enumeration via impacket or pure TCP SMB2 NEGOTIATE probe
  - `telnet.py` — Telnet banner grab + cleartext credential capture
  - `wordpress.py` — 5-check probe: SQLi exposure, version disclosure, user enumeration via author redirect, XML-RPC availability, wp-config exposure
  - `drupal.py` — 6-check probe: Drupalgeddon2 (CVE-2018-7600), version disclosure, settings file exposure, admin enumeration, xmlrpc, Drupageddon SQLi (CVE-2014-3704)
  - `apache.py` — server header disclosure, sensitive path exposure, HTTP method check (TRACE/TRACK), directory listing
  - `nginx.py` — server header disclosure, default welcome page, misconfig paths (/.git/HEAD, /.env, /nginx_status), security headers
- **What they are:** Service-specific validation plugins that fire when the correlator matches a service type to a plugin name. Each plugin performs single-attempt, non-destructive checks and returns an `Evidence` record.
- **Status:** REFERENCED BUT NOT EXECUTED — plugins are registered in `config/validation_profiles/*.yaml` and loaded by the `executor.py` service. They only fire when (a) nmap discovers a matching service, (b) the correlator queues a validation, (c) the executor runs the queue item.
- **What they could do if wired:** Full service validation for WordPress/Drupal CMS installations and common network services. The Drupalgeddon2 probe is a non-destructive reachability check for a critical RCE. The WordPress user enumeration via author redirect directly feeds further exploitation. Telnet credential capture sends real credentials to a Telnet service.
- **Effort to wire:** None — fully wired in the executor pipeline. Activation requires nmap to discover relevant services and the correlator to queue them.
- **Overlap with active system:** Validation module pipeline, parallel to but isolated from investigation_workspace probes.

### DC-X-05: Files Archive — Legacy Nmap/SMB/SSH/SQLi/Telnet Implementations (`files/`)

- **Files:** `files/nmap.py`, `files/smb.py` (partial), `files/ssh.py` (partial), `files/sqli.py`, `files/telnet.py`, `files/scanner.py`, `files/executor.py`, `files/correlator.py`, and ~30 other files including HTML templates, `cve_matcher.py`, `nvd_sync.py`, `fingerprint_normalizer.py`
- **What it is:** A complete prior generation of the validation application. `files/copy_to_project.sh` exists, indicating this directory is a factory-generated scaffold that was copied into the project structure. The code is NOT imported anywhere in the live application — zero `from files.` imports exist. The `files/nmap.py` contains a direct `nmap` shell invocation (superseded by `apps/validation/adapters/nmap.py`).
- **Status:** FULLY DORMANT — dead code, not imported, not referenced.
- **What it could do if wired:** Nothing useful — superseded by the production implementations in `apps/validation/`. The scaffold appears to be a source artifact that was refactored into the apps/ structure.
- **Effort to wire:** Large — these are prototype/scaffold files that would require significant reconciliation with the current architecture before use.
- **Overlap with active system:** Duplicates functionality in `apps/validation/`. `files/nmap.py` duplicates `apps/validation/adapters/nmap.py`. `files/cve_matcher.py` duplicates `apps/validation/engines/cve_matcher.py`. All other `files/` modules have production equivalents in `apps/validation/`.

---

## Dormant Capabilities — Reporting-Class

### DC-P-01: Knowledge Vault Exporter (`exporters/`)

- **Files:** `exporters/exporter_service.py`, `exporters/finding_exporter.py`, `exporters/discovery_exporter.py`, `exporters/remediation_exporter.py`, `exporters/attack_observation_exporter.py`, `exporters/markdown_renderer.py`, `exporters/frontmatter_builder.py`, `exporters/link_builder.py`, `exporters/export_validator.py`, `exporters/config.py`
- **What it is:** Markdown export pipeline that writes investigation findings, discovery summaries, attack observations, and remediation guides to the `data/knowledge-vault/` directory as Obsidian-compatible markdown files with YAML frontmatter and wiki-link backlinks.
- **Status:** REFERENCED BUT NOT EXECUTED — `investigation_core/exports/` references this pipeline via its own export service; `scripts/e2e_validation.py` and `scripts/e2e_export_test.py` test it. The `data/knowledge-vault/` directory exists with `investigations/` and `campaigns/` subdirs. However, no live HTTP route in the active application calls `ExporterService` directly.
- **What it could do if wired:** Publish investigation findings to a searchable knowledge vault with bidirectional links between findings, remediations, and concepts. The `data/knowledge-vault/` directory is already structured and used by the interoperability pipeline noted in the memory index.
- **Effort to wire:** Small — `ExporterService` is fully functional and tested by scripts. Wiring it to a live investigation event (e.g., on finding confirmation or investigation close) would be a single service call.
- **Overlap with active system:** `investigation_core/exports/services/export_service.py` wraps this. The interoperability pipeline (memory: `project_interoperability.md`) depends on it for cross-tool export.

### DC-P-02: Investigation Core Export Routes (`apps/investigation_core/api/export_routes.py`)

- **File:** `apps/investigation_core/api/export_routes.py`
- **What it is:** FastAPI routes for triggering knowledge-vault exports from the investigation_core API.
- **Status:** REFERENCED BUT NOT EXECUTED — registered in `apps/investigation_core/api/__init__.py` which is mounted into `validation_router`. Routes exist but may depend on the exporters pipeline being fully operational.
- **What it could do if wired:** Expose `/api/v1/validation/investigation-core/exports/...` endpoints for on-demand vault exports.
- **Effort to wire:** Small — routes are registered; functionality depends on DC-P-01 being operational.
- **Overlap with active system:** Complement to the investigation_core API surface.

---

## Dormant Capabilities — Infrastructure-Class

### DC-I-01: Scanner Orchestration — Nmap Adapter (`apps/scanner_orchestration/adapters/nmap_adapter.py`)

- **File:** `apps/scanner_orchestration/adapters/nmap_adapter.py`
- **What it is:** Second-generation nmap adapter (distinct from `apps/validation/adapters/nmap.py`). Uses a temp-file XML output approach (vs. the validation adapter's stdout XML parsing). Integrated with `scan_profiles.py` profile system: `quick_recon` (nmap -sV -T4 -F), `standard_recon` (nmap -sV -O -T3), `full_discovery` (nmap + ZAP + nuclei), `cve_validation` (nuclei only), `nuclei_discovery` (nuclei only).
- **Status:** REFERENCED BUT NOT EXECUTED — imported in `scanner_orchestration/adapters/__init__.py` and `services/orchestration_service.py`. The `/api/v1/validation/scans/` endpoint routes are registered. The nmap binary is not guaranteed to be present in the Docker image (requires `cap_add: NET_RAW/NET_ADMIN` which docker-compose does grant).
- **What it could do if wired:** Automated port/service scanning via the `/api/v1/validation/scans/` REST endpoint with profile selection. Results feed the normalization pipeline → CVE enricher → finding storage.
- **Effort to wire:** Small — run a scan via `POST /api/v1/validation/scans/` with a target and profile_id. Requires nmap binary in the Docker image (`apt-get install nmap` in Dockerfile, or `cap_add` already present for SYN scans).
- **Overlap with active system:** Parallel to `apps/validation/adapters/nmap.py`. The validation adapter is used by `apps/validation/services/scanner.py` (the legacy UI flow); this adapter is used by `scanner_orchestration` (the newer orchestrated scan flow).

### DC-I-02: Scanner Orchestration — Nuclei Adapter (`apps/scanner_orchestration/adapters/nuclei_adapter.py`)

- **File:** `apps/scanner_orchestration/adapters/nuclei_adapter.py`
- **What it is:** Nuclei CLI adapter with governed template profiles. `nuclei_profiles.py` defines allowlist-based template profiles: `web_learning` (info/low severity, `exposures/` + `technologies/`), `cve_validation` (CVEs listed in the project's CVE list), `discovery_only` (non-intrusive discovery templates). Gracefully skips if nuclei is not on PATH.
- **Status:** REFERENCED BUT NOT EXECUTED — imported and registered identically to the nmap adapter. Nuclei is not in the Docker image by default.
- **What it could do if wired:** Template-based web vulnerability detection. The `web_learning` profile is deliberately limited to low-risk templates, avoiding active exploitation.
- **Effort to wire:** Medium — requires nuclei binary in the Docker image (separate install step; nuclei is not apt-packaged, requires Go or binary download). Profile governance is already implemented.
- **Overlap with active system:** No overlap. No other component does template-based web scanning.

### DC-I-03: Scanner Orchestration — OWASP ZAP Adapter (`apps/scanner_orchestration/adapters/zap_adapter.py`)

- **File:** `apps/scanner_orchestration/adapters/zap_adapter.py` (284 lines)
- **What it is:** REST API client for OWASP ZAP. Implements availability status check (reachable/starting/degraded/unavailable), spider scan, active scan, result retrieval, and status polling with SSE-compatible streaming. The docker-compose.yml includes the ZAP service (`ghcr.io/zaproxy/zaproxy:stable`) configured with API key disabled and accepting all origins. The internal Docker service is named `zap` and accessible from the backend at `http://zap:8080`.
- **Status:** REFERENCED BUT NOT EXECUTED — imported in `scanner_orchestration/adapters/__init__.py` and `services/orchestration_service.py`. The ZAP Docker service is defined and would start with `docker-compose up`. Port 8090 on the host is commented out (internal-only access).
- **What it could do if wired:** Full DAST scanning via ZAP's spider + active scanner. Spider discovers pages; active scanner probes for common vulnerabilities. Results are normalized and stored as findings.
- **Effort to wire:** Small — ZAP service is already in docker-compose; start it alongside the backend. ZAP takes ~60-90s to initialize (healthcheck already accounts for this with 18 retries × 10s).
- **Overlap with active system:** No overlap. ZAP covers web application attack surface; nmap covers network services; nuclei covers template patterns.

### DC-I-04: SSRF Guard (`apps/scanner_orchestration/target_resolution/ssrf_guard.py`)

- **File:** `apps/scanner_orchestration/target_resolution/ssrf_guard.py`
- **What it is:** Validates scan targets to prevent SSRF: blocks RFC 1918 private ranges, loopback, link-local, and reserved ranges unless a lab-mode flag is set. Part of the `target_resolution` subsystem.
- **Status:** REFERENCED BUT NOT EXECUTED — called from `resolver.py` which is used by `orchestration_service.py`. Only fires when a scan is initiated via the scanner_orchestration API.
- **What it could do if wired:** Mandatory safety check for scan target validation. Already wired — fires automatically when scanner_orchestration is used.
- **Effort to wire:** None.
- **Overlap with active system:** The investigation_workspace probes do their own target validation in `probe/normalize.py`.

### DC-I-05: Docker Target Resolver (`apps/scanner_orchestration/target_resolution/docker.py`)

- **File:** `apps/scanner_orchestration/target_resolution/docker.py`
- **What it is:** Resolves Docker service names to container IPs for scanning containers in the same Docker network (e.g., resolving `dvwa` to its Docker bridge IP for nmap scanning).
- **Status:** REFERENCED BUT NOT EXECUTED — part of the `target_resolution` subsystem.
- **What it could do if wired:** Allow scanning lab containers (DVWA, Metasploitable, etc.) by service name rather than hardcoded IP.
- **Effort to wire:** None — fires automatically when scanner_orchestration resolves a Docker hostname target.
- **Overlap with active system:** Complements `host.docker.internal` resolution used in the investigation_workspace probes.

### DC-I-06: Scan Monitor / Timeline (`apps/scanner_orchestration/monitoring/scan_monitor.py`, `apps/scanner_orchestration/timeline/scan_events.py`)

- **Files:**
  - `monitoring/scan_monitor.py` — polls active scan executions and emits SSE progress events
  - `timeline/scan_events.py` — records scan lifecycle events to the investigation_core timeline
- **Status:** REFERENCED BUT NOT EXECUTED — wired into the orchestration service. Only fires when scans run.
- **What it could do if wired:** Real-time scan progress in the UI via SSE. Timeline events create an auditable record of scan activity.
- **Effort to wire:** None.
- **Overlap with active system:** The investigation_workspace uses its own `StageEvent`/`FindingEvent` streaming; this is the scanner_orchestration equivalent.

### DC-I-07: Investigation Core — Campaigns (`apps/investigation_core/campaigns/`)

- **Files:** Models, services, storage, exports for `Campaign`, `CampaignMembership`, `CampaignObjective`, `CampaignSnapshot`
- **What it is:** Groups multiple investigations under a named campaign with shared objectives and snapshot synthesis exports.
- **Status:** REFERENCED BUT NOT EXECUTED — routes registered in `investigation_core_router` (via `api/campaign_routes.py`). The `data/knowledge-vault/campaigns/` directory exists. However `data/investigation_core.db` is 0 bytes (empty), indicating no campaigns have been created.
- **What it could do if wired:** Aggregate findings across multiple targets into a campaign narrative, generate synthesis reports for the knowledge vault.
- **Effort to wire:** Small — the campaign API is registered. Needs the investigation_core DB to be initialized (separate from `validation.db` — `data/investigation_core.db` is currently empty).
- **Overlap with active system:** `investigation_core` evidence, guided_actions, and progression systems use their own DB. The campaigns system is an overlay.

### DC-I-08: Investigation Core — Skills & Progression (`apps/investigation_core/skills/`, `apps/investigation_core/progression/`, `apps/investigation_core/learning/`)

- **Files:**
  - `skills/` — SkillGraph, skill taxonomy (auth, SQLi, XSS, hardening skills), skill recommender
  - `progression/` — mastery tracker, unlock engine, mastery validator, progression trigger
  - `learning/` — learning path registry, 6 defined paths (auth/SQLi/XSS beginner+intermediate, web hardening, auth beginner)
- **What it is:** A gamification layer that tracks operator skill mastery across finding types, unlocks advanced probes based on demonstrated proficiency, and recommends learning paths.
- **Status:** REFERENCED BUT NOT EXECUTED — `adaptive/guidance.py` in the workspace imports `category_for_finding_type` and memory models; `branch/corridors.py` imports `CLUSTERS`. The progression and unlock engine itself (`progression_trigger.py`, `unlock_engine.py`) is not called by any live code path.
- **What it could do if wired:** Gate advanced probes behind mastery thresholds. When an operator demonstrates understanding of SQLi basics (confirming findings, reviewing evidence), the system could unlock intermediate-level probes automatically.
- **Effort to wire:** Medium — the progression API routes are registered but the trigger integration points in the investigation workflow are not connected. The `adaptive/guidance.py` already imports memory models.
- **Overlap with active system:** The suggestion catalog (`suggestions/catalog.py`) conditions some actions on `operator_tier` hints; the progression system would supply those tier values.

---

## Dormant Capabilities — Unclassified

### DC-U-01: Lab Authentication Helper (`apps/investigation_workspace/probe/lab_auth.py`)

- **File:** `apps/investigation_workspace/probe/lab_auth.py`
- **What it is:** DVWA-specific authentication helper. Authenticates with default DVWA credentials (`admin/password`), runs first-time database setup if needed (GET `/setup.php?setupSecurity=true`), and sets security level to Low. Returns session state dict. Originally host-restricted to `host.docker.internal:10001`; Phase 60 removed that restriction — it now attempts against any target, failing harmlessly on non-DVWA hosts.
- **Status:** REFERENCED AND EXECUTES on every CMDi/brute-force probe run. Originally host-restricted to `host.docker.internal:10001`; Phase 60 removed that restriction — it now attempts DVWA authentication against any target, failing harmlessly (ok=False) on non-DVWA hosts. _(Formerly classified "REFERENCED BUT NOT EXECUTED"; Phase 60 gate removal means it fires on all targets.)_
- **What it does:** Provides a DVWA-authenticated session for CMDi and brute-force probe pipelines. Hardcodes `admin/password` credentials and DVWA-specific paths (`/login.php`, `/setup.php`, `/security.php`). On non-DVWA targets it produces `ok=False` and the calling probe falls back to its next auth strategy.
- **V2 note:** The host gate removal means this helper adds HTTP round-trips against every target. V2 should replace it with operator-supplied auth state from `_API_AUTH_STORE` rather than a DVWA-specific fallback.
- **Overlap with active system:** Called by `suggestions/probes.py` cmdi and auth recon probe families.

### DC-U-02: Fingerprint Normalizer + Service Map (`apps/validation/engines/fingerprint_normalizer.py`, `config/fingerprints/service_map.yaml`)

- **Files:**
  - `apps/validation/engines/fingerprint_normalizer.py` (125 lines)
  - `config/fingerprints/service_map.yaml` (111 lines, 20 vendor/product patterns)
- **What it is:** Translates nmap-parsed service banners into normalized vendor/product/version tuples (e.g., `nginx/1.18.0` → `{vendor: "nginx", product: "nginx", version: "1.18.0"}`). Required upstream of `cve_matcher.py`.
- **Status:** REFERENCED BUT NOT EXECUTED — called from the correlator pipeline (`apps/validation/services/correlator.py`). Only fires when nmap results are processed.
- **What it could do if wired:** Bridge nmap service discovery to CVE lookup. Already fully wired — fires automatically in the correlator pipeline after a nmap scan.
- **Effort to wire:** None.
- **Overlap with active system:** Required by DC-R-04 (CVE Matcher).

### DC-U-03: Validation Profile YAMLs (`config/validation_profiles/`)

- **Files:** `ssh.yaml`, `wordpress.yaml`, `drupal.yaml`, `cve_pocs.yaml`
- **What it is:** Declarative configuration mapping service types to validation plugin names and check lists. `cve_pocs.yaml` maps CVE IDs to plugin names and severity levels (CVE-2018-7600 Drupalgeddon2, CVE-2014-3704 Drupageddon SQLi, plus Apache Struts S2-045 and OpenSSH CVEs).
- **Status:** REFERENCED BUT NOT EXECUTED — `apps/validation/config.py` references these profiles; the correlator uses them to route services to plugins.
- **What it could do if wired:** Drive the full validation plugin dispatch. Already wired — fires when the correlator matches a discovered service.
- **Effort to wire:** None.
- **Overlap with active system:** Required configuration for the validation plugin stack (DC-X-04).

### DC-U-04: Observation + Script Audit Scripts (`scripts/`)

- **Files (utility/dev-only):** `scripts/audit_knowledge_vault.py`, `scripts/backfill_evidence_refs.py`, `scripts/e2e_export_test.py`, `scripts/e2e_validation.py`, `scripts/validate_investigation.py`, `scripts/verify_phase*.py` (8 files), `scripts/verify_v1_2_brute_force.py`
- **What it is:** Development and verification harnesses. Phase-numbered verify scripts are one-time regression tests. `validate_investigation.py` runs a full investigation lifecycle against a live platform. `e2e_validation.py` tests the export pipeline. `audit_knowledge_vault.py` checks vault quality. None are production code.
- **Status:** FULLY DORMANT — not imported anywhere, not auto-executed. Dev tooling only.
- **What it could do if wired:** Regression testing and continuous validation of the pipeline. `validate_investigation.py` is the closest to a production health check.
- **Effort to wire:** Large — would require a live target environment to be useful; intended as manual dev tools.
- **Overlap with active system:** Tests the same pipeline that runs in production, but from outside the HTTP layer.

### DC-U-05: Scan History and Queue Expiry Worker (`apps/validation/tasks/expiry_worker.py`)

- **File:** `apps/validation/tasks/expiry_worker.py`
- **What it is:** Background hourly asyncio task. Purges queue items with 3+ rejections (operator noise filter). Archives completed/rejected items past retention windows (configurable per validation type). Exports to a history table before deletion.
- **Status:** REFERENCED BUT NOT EXECUTED in isolation — **this IS running**. It is started via `start_expiry_worker()` in the FastAPI lifespan (`core/api/app.py`). However, since nmap scans have not run (no services in the queue), it has nothing to process.
- **What it could do if wired:** Already wired. Functions as designed when the queue is populated by scanner activity.
- **Effort to wire:** None.
- **Overlap with active system:** Part of the live application startup.

---

## Per-Capability Triage Summary

| ID | Capability | Class | Status | Effort to Wire | Priority Signal |
|---|---|---|---|---|---|
| DC-R-01 | Subdomain enumeration (`recon_ng.py`) | Recon | FULLY DORMANT | Small | Expands attack surface for any domain target |
| DC-R-02 | API auth page scraper (`api_authed_recon.py`) | Recon | REFERENCED BUT NOT EXECUTED | None | Requires operator auth state; zero code work |
| DC-R-03 | NVD feed sync (`nvd_sync.py`) | Recon | REFERENCED BUT NOT EXECUTED | None | Already manually triggerable from Settings |
| DC-R-04 | CVE matcher (`cve_matcher.py`) | Recon | REFERENCED BUT NOT EXECUTED | None | Fires automatically after nmap scan |
| DC-E-01 | API endpoint wordlist enum (`api_endpoint_enum.py`) | Enumeration | REFERENCED BUT NOT EXECUTED | None | Catalog entry exists; fires on api_structure_recon finding |
| DC-E-02 | API endpoint wordlist (`api-endpoints.txt`, 269 lines) | Enumeration | FULLY DORMANT | None | Used by DC-E-01 |
| DC-E-03 | HTTP method enumerator (`api_method_enum.py`, 667 lines) | Enumeration | REFERENCED BUT NOT EXECUTED | None | Triggered dynamically by DC-E-01 output |
| DC-E-04 | Default password list (`default-passwords.csv`, 2876 entries) | Enumeration | FULLY DORMANT | Medium | No consumer exists; needs new probe module |
| DC-E-05 | SSH credentials (`ssh_defaults.yaml`, 12 pairs) | Enumeration | REFERENCED BUT NOT EXECUTED | None | Fires when SSH service discovered by nmap |
| DC-X-01 | Metasploit RPC integration (4 files, ~1260 lines) | Exploitation | LIVE (routes + UI active; container started separately) | — | Operator-driven; container must be running |
| DC-X-02 | Purchase flow / BFLA probe (`purchase_flow.py`) | Exploitation | REFERENCED BUT NOT EXECUTED | None | Fires on bfla_price_manipulation finding |
| DC-X-03 | Chromium browser probe (`api_browser_recon.py`) | Exploitation | REFERENCED BUT NOT EXECUTED | Medium | Needs playwright + Chromium in Docker image |
| DC-X-04 | Validation plugin stack (SMB, Telnet, WP, Drupal, Apache, Nginx) | Exploitation | REFERENCED BUT NOT EXECUTED | None | Fires when nmap discovers relevant services |
| DC-X-05 | Legacy scaffold archive (`files/`, ~30 files) | Exploitation | FULLY DORMANT | Large | Dead code; superseded by apps/ implementations |
| DC-P-01 | Knowledge vault exporter (`exporters/`, 10 files) | Reporting | REFERENCED BUT NOT EXECUTED | Small | Already tested by scripts; data/knowledge-vault/ exists |
| DC-P-02 | Investigation core export routes | Reporting | REFERENCED BUT NOT EXECUTED | Small | Depends on DC-P-01 |
| DC-I-01 | Scanner orchestration nmap adapter | Infrastructure | REFERENCED BUT NOT EXECUTED | Small | Needs nmap binary; docker-compose already grants NET_RAW/NET_ADMIN |
| DC-I-02 | Nuclei adapter + profiles | Infrastructure | REFERENCED BUT NOT EXECUTED | Medium | Needs nuclei binary installed in image |
| DC-I-03 | OWASP ZAP adapter + Docker service | Infrastructure | REFERENCED BUT NOT EXECUTED | Small | ZAP already in docker-compose; just needs starting |
| DC-I-04 | SSRF guard | Infrastructure | REFERENCED BUT NOT EXECUTED | None | Fires automatically with scanner_orchestration |
| DC-I-05 | Docker target resolver | Infrastructure | REFERENCED BUT NOT EXECUTED | None | Fires automatically for Docker hostname targets |
| DC-I-06 | Scan monitor + timeline events | Infrastructure | REFERENCED BUT NOT EXECUTED | None | Fires automatically when scans run |
| DC-I-07 | Campaigns system (`investigation_core/campaigns/`) | Infrastructure | REFERENCED BUT NOT EXECUTED | Small | API registered; DB needs initialization |
| DC-I-08 | Skills / progression / learning paths | Infrastructure | REFERENCED BUT NOT EXECUTED | Medium | Trigger integration points not yet connected |
| DC-U-01 | Lab auth helper (`lab_auth.py`) | Unclassified | EXECUTES ON ALL TARGETS (Phase 60 gate removed) | — | DVWA-specific; fires harmlessly on non-DVWA targets; V2 should replace with operator auth state |
| DC-U-02 | Fingerprint normalizer + service map | Unclassified | REFERENCED BUT NOT EXECUTED | None | Fires in correlator pipeline after nmap |
| DC-U-03 | Validation profile YAMLs | Unclassified | REFERENCED BUT NOT EXECUTED | None | Configuration for DC-X-04 plugin dispatch |
| DC-U-04 | Dev/verify scripts (`scripts/`, 14 files) | Unclassified | FULLY DORMANT | Large | Dev tooling, not production code |
| DC-U-05 | Scan history expiry worker | Unclassified | RUNNING | — | Already live; nothing to process yet |

### Summary counts

| Status | Count |
|---|---|
| FULLY DORMANT | 5 |
| REFERENCED BUT NOT EXECUTED | 21 |
| LIVE / RUNNING (active) | 3 |

_Counts updated 2026-05-26: DC-X-01 (Metasploit) reclassified LIVE; DC-U-01 (lab_auth.py) reclassified as executing on all targets (Phase 60 gate removal)._

### Highest-leverage zero-effort activations

The following capabilities require zero code changes — they become active the moment an appropriate precondition is met:

1. **DC-I-03 (ZAP)** — start the `zap` Docker service
2. **DC-I-01 (nmap scanner_orchestration)** — install nmap in the Docker image, make one API call
3. **DC-R-03 (NVD sync)** — click the Settings page sync button
4. **DC-R-04 + DC-U-02 + DC-E-05 (CVE matcher chain)** — follow from DC-I-01
5. **DC-X-04 (validation plugin stack)** — follow from DC-I-01 (correlator fires plugins after nmap discovers services)
6. **DC-R-02, DC-E-01, DC-E-03, DC-X-02 (API probe chain)** — require investigation_workspace findings to exist (already firing in the live system)
