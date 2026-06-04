# .md Inventory Audit

**Date:** 2026-05-25  
**Scope:** All .md files in ai-assist-tool repository  
**Method:** Static content audit + metadata analysis (line count, file size, modification date)  

---

## File list

| Path | Lines | Size (bytes) | Modified | Purpose |
|---|---|---|---|---|
| CLAUDE.md | 661 | 51397 | 2026-05-25 | Top-level project context, locked architectural decisions, V1.7 complete feature delivery sequence, gate registry, live parity verification gate, hard-learned lessons from V1.6-V1.7 work |
| README.md | 14 | 220 | 2026-05-13 | Minimal stub: project name, stack summary, docker usage instructions |
| AI_CONTEXT.md | 52 | 1492 | 2026-05-13 | Factory-era context document: project inheritance from AI-Factory-Base, stack summary, protected infrastructure rules, module extension rules |
| ai-context/ACTIVE_DECISIONS.md | 9 | 303 | 2026-05-11 | Bullet-point decisions log: monorepo approved, FastAPI/React locked, Docker Compose standardized, SDK-only access enforced |
| ai-context/CURRENT_STATE.md | 39 | 993 | 2026-05-25 | Implementation status snapshot (foundation phase): what is implemented (settings, logging, health endpoints, Docker), what is in progress (apps/ structure), what is pending (module registry, deployment, queue/AI/notification SDKs) |
| ai-context/FACTORY_RULES.md | 30 | 768 | 2026-05-11 | Factory inheritance constraints: protected areas (core/, deployment/, observability/, tooling/), forbidden patterns (rewrites, duplicate logic), required patterns (SDK interfaces, modularity), engineering principles |
| ai-context/MODULE_PATTERNS.md | 16 | 287 | 2026-05-11 | Module directory structure template and rules: /apps/module-name with api/, services/, repositories/, models/, tasks/, tests/ subdirectories; modules must not access core internals |
| ai-context/REPOSITORY_STRUCTURE.md | 9 | 328 | 2026-05-25 | High-level directory map: core, sdk, apps, tooling, deployment, observability, frontend, ai-context |
| ai-context/SDK_REFERENCE.md | 47 | 578 | 2026-05-12 | Interface documentation: implemented (Logger, Config), planned but not yet implemented (Queue, AI, Notifications, Scheduler) |
| ai-context/VERSION.md | 23 | 406 | 2026-05-11 | Factory core version v0.1, foundation phase, pre-stabilization, target is reusable infrastructure primitives |
| data/wordlists/README.md | 25 | 919 | 2026-05-24 | Wordlist registry documentation: credentials/, paths/, payloads/ structure, adding wordlists via REGISTERED_WORDLISTS dict in apps/conductor/wordlists.py, source attribution |
| docs/architecture/orchestration.md | 912 | 39514 | 2026-05-24 | Definitive contract for three-level orchestration system (Conductor Level 3, five orchestrators Level 2, engines Level 1): design principles, three-level overview, Conductor specification, orchestrator specifications, phase definitions, engine interface, findings flow, chain orchestration, gate/capability filtering, reinvocation workflow |
| docs/audits/api_stage_card_audit.md | 188 | 12549 | 2026-05-23 | Classification audit of probe_api_exploit event outputs: which cards KEEP (operator signal), COLLAPSE (internal narration), DROP (no value); stages, phases, condition combinations analyzed across discovery → parse → auth → IDOR detection |
| docs/audits/dormant-capabilities-inventory.md | 405 | 44047 | 2026-05-24 | Extensive catalog of wired-but-not-executed and parked code: recon-class (subdomain enum via recon_ng, api_authed_recon, NVD sync, CVE matcher), enumeration-class (api endpoint enum, api method enum, browser recon, etc.), exploitation-class (IDOR mutate, XSS, SQLi, CMDi, brute force, purchase flow), detailed per-dormant-capability analysis of file location, what it does, effort to wire, overlap assessment |
| docs/audits/operator_input_audit.md | 156 | 8148 | 2026-05-23 | Read-only audit of operator input flow: action card system — how do operator-supplied runtime parameters reach a probe; template → route → ContextVar → probe substitution pipeline; currently only probe_api_idor_mutate uses it (has_input=True cards with target_user parameter) |
| docs/audits/v1.6-recon-enum-audit.md | 913 | 43670 | 2026-05-24 | Classification and inventory of 14+ recon/enumeration probes: per-probe file location, phase assignment, HTTP behavior, findings emitted, evidence shapes, next_actions, severity distribution; covers run_passive_probe through run_api_endpoint_enum |
| docs/audits/v1.6-recon-output-inventory.md | 1227 | 48063 | 2026-05-25 | Design input for V1.7 enumeration: per-engine output inventory (passive_probe through ZAP), evidence field shapes from live DB data, re-invocation capability assessment, recon-evidence-driven parameter refinement opportunities; sampled from 192.168.200.202 investigations |
| docs/audits/v1_4a_regression_audit.md | 438 | 20876 | 2026-05-22 | Live regression audit: 13 regressions found in V1.4a UI vs pre-V1.4a baseline; 2 blocking (no execute affordance on findings), 6 important, 3 minor, 2 acceptable; root cause analysis of stage card rendering (div vs button) and context panel access loss |
| docs/audits/v1_execution_architecture_audit.md | 654 | 43398 | 2026-05-24 | Ground truth analysis of current execution model: V1 shipped phase classification (tagging + rendering) but NOT sequential phased execution; actual execution model is concurrent bootstrap (Phase 41-44, all five probes via asyncio.gather); Bootstrap concept is active, not vestige; detailed trigger chain and _view_is_empty guard analysis |
| docs/audits/v1_restructure_audit.md | 1235 | 68611 | 2026-05-23 | Comprehensive probe phase classification audit: 29 probes cataloged (19 distinct + 4 helpers that re-yield), each with file:line, network behavior (P/AD/AE), trigger (BOOT/OP/NEST), proposed phase, false positive risk, aggregation candidacy; detailed discussion of phase assignment rationale for each probe |
| docs/audits/v1_ui_audit.md | 478 | 27921 | 2026-05-23 | V1 UI compliance verification against PR1-PR4 requirements: phase classification delivered, UI restructure delivered (phase tabs, lucide macros, React Flow root, vendor assets), workspace template structure verified live against PortSwigger lab target |
| tests/conductor/_patterns/README.md | 87 | 4417 | 2026-05-25 | Seam bug pattern catalog documenting 7 critical architectural bugs from V1.6-V1.7: Two-Parallel-ID-Systems, Attribution Loss at Seam, Silently-Disabling Default, Adapter Shape Mismatch, Dangling Reference, Resource-Class-Blind Policy, Wrong DB Target; explains why seam tests exist, pattern/test mappings, lesson learned from each |
| .claude/rules/common/agents.md | 51 | 1626 | 2026-05-13 | Agent orchestration guide: available agents (planner, architect, code-reviewer, security-reviewer, etc.), when to use each, parallel task execution, multi-perspective analysis guidance |
| .claude/rules/common/code-review.md | 124 | 3502 | 2026-05-13 | Code review standards: mandatory review triggers, pre-review requirements, review checklist (readability, function size, nesting, error handling, secrets, tests, coverage), security review triggers, severity levels, agent usage, review workflow |
| .claude/rules/common/coding-style.md | 90 | 2537 | 2026-05-13 | Coding style discipline: immutability as CRITICAL, KISS/DRY/YAGNI principles, file organization (small files preferred), error handling, input validation, naming conventions (camelCase/PascalCase/UPPER_SNAKE_CASE), code smells to avoid |
| .claude/rules/common/development-workflow.md | 44 | 2252 | 2026-05-13 | Feature implementation workflow: research & reuse first (GitHub search → lib docs → Exa), plan first (planner agent), TDD approach, code review, commit & push, pre-review checks |
| .claude/rules/common/git-workflow.md | 24 | 622 | 2026-05-13 | Git workflow: commit message format (type: description + optional body), pull request workflow (analyze full history, git diff base...HEAD, comprehensive summary, test plan) |
| .claude/rules/common/hooks.md | 30 | 768 | 2026-05-13 | Hooks system: PreToolUse/PostToolUse/Stop hook types, auto-accept permissions caution, TodoWrite best practices |
| .claude/rules/common/patterns.md | 31 | 1022 | 2026-05-13 | Common patterns: skeleton projects evaluation, design patterns (Repository, API response format) |
| .claude/rules/common/performance.md | 55 | 1599 | 2026-05-13 | Performance optimization: model selection (Haiku 3x cost savings, Sonnet best coding, Opus deepest reasoning), context window management, extended thinking + plan mode, build troubleshooting |
| .claude/rules/common/security.md | 29 | 862 | 2026-05-13 | Security guidelines: mandatory checks before commit (no hardcoded secrets, input validation, SQL injection/XSS/CSRF prevention, auth verification, rate limiting, error message redaction), secret management, security response protocol |
| .claude/rules/common/testing.md | 57 | 1400 | 2026-05-13 | Testing requirements: 80% minimum coverage, test types (unit/integration/E2E), TDD workflow (RED/GREEN/IMPROVE), test failure troubleshooting, AAA pattern, descriptive test naming |
| .claude/rules/python/coding-style.md | 42 | 711 | 2026-05-13 | Python coding style: PEP 8 + type annotations, immutable data structures (dataclass frozen, NamedTuple), black/isort/ruff for formatting/linting |
| .claude/rules/python/fastapi.md | 58 | 1736 | 2026-05-13 | FastAPI rules: structure (create_app, thin routers, separate schemas), async/await discipline, dependency injection, schema security (no passwords/tokens), CORS/JWT/rate-limiting, testing patterns (dependency override, clear overrides after tests) |
| .claude/rules/python/hooks.md | 19 | 424 | 2026-05-13 | Python hooks: PostToolUse hooks for black/ruff/mypy/pyright, warnings about print() statements |
| .claude/rules/python/patterns.md | 39 | 823 | 2026-05-13 | Python patterns: Protocol/duck typing, dataclasses as DTOs, context managers & generators |
| .claude/rules/python/security.md | 30 | 524 | 2026-05-13 | Python security: secret management (os.environ with dotenv), bandit for static analysis |
| .claude/rules/python/testing.md | 38 | 581 | 2026-05-13 | Python testing: pytest framework, coverage measurement, test organization with pytest.mark (unit/integration) |

---

## Per-file detail

### CLAUDE.md
- **Purpose:** Top-level project documentation covering locked architectural decisions, delivery sequence, and hard-learned lessons.
- **Topics:** Reference scenario (telnet+HTTP+login chain), three-level orchestration (Conductor, five orchestrators, engines), feature gates, V1.6-V1.7 PRs delivery history, live parity verification, 19 hard-learned lessons, gate registry, factory scaffold cleanup deferral, documentation discipline.
- **References dead/dropped code:** YES — explicitly documents dropped features: CVE matcher chain (dormant, not wired), deferred work (ZAP active scan, AJAX spider, catalog mapping, tag-based filtering). Explains WHY each is dropped/deferred.
- **Cross-references:** Links to `docs/audits/dormant-capabilities-inventory.md` for dormant stack. References `apps/conductor/rules/` for Python-based rule functions. No specific file links but extensive cross-references within its own sections.
- **Overlap detected:** Substantial overlap with `docs/architecture/orchestration.md` (both cover three-level architecture, orchestrator responsibilities, design principles). CLAUDE.md is more delivery-focused; orchestration.md is more specification-focused.

### README.md
- **Purpose:** Minimal project stub providing basic orientation.
- **Topics:** Project name, stack summary (FastAPI, Python 3.12, React), Docker Compose startup, health endpoints.
- **References dead/dropped code:** NO.
- **Cross-references:** None.
- **Overlap detected:** Minimal content; completely subsumed by AI_CONTEXT.md and CLAUDE.md for anything more than the absolute basics.

### AI_CONTEXT.md
- **Purpose:** Factory-era context document establishing project inheritance and infrastructure rules.
- **Topics:** Project name, AI-Factory-Base inheritance, base version v0.4, stack summary, active ports, Docker usage, validation commands, protected infrastructure rules (core, sdk, apps), module extension rules (no direct core access).
- **References dead/dropped code:** NO — purely about factory inheritance structure.
- **Cross-references:** None explicit; references factory inheritance concept from AI-Factory-Base.
- **Overlap detected:** Complete overlap with ai-context/FACTORY_RULES.md (both describe protected areas and inheritance), with ai-context/MODULE_PATTERNS.md (both describe /apps/module structure), with ai-context/REPOSITORY_STRUCTURE.md (both enumerate directories). AI_CONTEXT.md is the narrative intro; the ai-context/ subdirectory files are the detailed reference specs.

### ai-context/ACTIVE_DECISIONS.md
- **Purpose:** Snapshot log of architectural decisions locked in place.
- **Topics:** Monorepo approved, FastAPI locked, React locked, Docker Compose standardized, SDK-only access enforced, modular monolith approved, API-first architecture enforced.
- **References dead/dropped code:** NO.
- **Cross-references:** None.
- **Overlap detected:** Implicit overlap with FACTORY_RULES.md and AI_CONTEXT.md; decision log is the summary of what those files prescribe.

### ai-context/CURRENT_STATE.md
- **Purpose:** Implementation status tracker from factory foundation phase perspective.
- **Topics:** Implemented systems (repository structure, settings, logging, health endpoints, Docker, SDK interfaces, factory provisioner, tests, linting), in-progress (apps/ structure), pending (module registry, deployment, queue/AI SDKs), protected core version (v0.1), validated systems.
- **References dead/dropped code:** NO — status document only.
- **Cross-references:** None explicit.
- **Overlap detected:** Status information is orthogonal to other files; no direct overlap, but assumes foundation described in AI_CONTEXT.md.

### ai-context/FACTORY_RULES.md
- **Purpose:** Codify factory inheritance constraints and required patterns.
- **Topics:** Protected areas (core, deployment, observability, tooling), forbidden patterns (rewrites, speculative abstractions, stack replacement, duplicate logic, hidden coupling), required patterns (SDK interfaces, modularity, business logic in apps/), engineering principles (infrastructure-first, observability-first, determinism), critical rules (no abstractions without use cases, prefer simple deterministic).
- **References dead/dropped code:** NO — prescriptive rules only.
- **Cross-references:** None.
- **Overlap detected:** Overlaps extensively with AI_CONTEXT.md (both cover protected areas and module extension); overlaps with MODULE_PATTERNS.md (both require modularity and SDK-only access). FACTORY_RULES.md is the more rigorous policy; others are application examples.

### ai-context/MODULE_PATTERNS.md
- **Purpose:** Standardize the directory layout and dependency rules for any module under /apps/.
- **Topics:** Directory template (/apps/module-name with api, services, repositories, models, tasks, tests), rules (business logic in services, API routes in api, repositories for DB, tasks for background, modules must not access core internals).
- **References dead/dropped code:** NO.
- **Cross-references:** Implicit reference to FACTORY_RULES.md (enforces factory rules).
- **Overlap detected:** Overlaps with AI_CONTEXT.md Module Extension Rules section. MODULE_PATTERNS.md is the detailed template; AI_CONTEXT.md is the summary.

### ai-context/REPOSITORY_STRUCTURE.md
- **Purpose:** High-level directory map of the repository.
- **Topics:** core (protected infrastructure), sdk (stable interfaces), apps (business modules), tooling (generators/utilities), deployment (docker/nginx), observability (monitoring/logging), frontend (shared systems), ai-context (operational docs).
- **References dead/dropped code:** NO.
- **Cross-references:** None.
- **Overlap detected:** Same directory list appears in AI_CONTEXT.md. REPOSITORY_STRUCTURE.md is more concise; AI_CONTEXT.md provides narrative context.

### ai-context/SDK_REFERENCE.md
- **Purpose:** Document current and planned SDK interface contracts.
- **Topics:** Implemented (Logger with .info/.error, Config with .get), planned but not implemented (Queue.publish, AIProvider.generate, Notification.send, Scheduler.register) — these will raise AttributeError if called.
- **References dead/dropped code:** NO — deferred, not dropped.
- **Cross-references:** None.
- **Overlap detected:** None; purely interface reference.

### ai-context/VERSION.md
- **Purpose:** Track factory core version and architectural phase.
- **Topics:** Version v0.1, status (foundation phase), pre-stabilization, goal (reusable infrastructure), validated systems (none yet), compatible clients (React web, future React Native).
- **References dead/dropped code:** NO.
- **Cross-references:** None.
- **Overlap detected:** None; metadata-only.

### data/wordlists/README.md
- **Purpose:** Explain wordlist registry system and how to add new wordlists.
- **Topics:** Directory structure (credentials/, paths/, payloads/), adding wordlists via REGISTERED_WORDLISTS dict, consuming via apps.conductor.wordlists.load_entries(), source attribution.
- **References dead/dropped code:** NO.
- **Cross-references:** References apps/conductor/wordlists.py indirectly.
- **Overlap detected:** None; specialized to one feature.

### docs/architecture/orchestration.md
- **Purpose:** Definitive contract for the three-level orchestration system; all PRs from PR A onward implement this design exactly.
- **Topics:** Design principles (operator drives car, engines stateless, single ingress, architecture-first, three levels no more, session inheritance non-negotiable, no lab-specific code, documentation-first), three-level overview (Conductor L3, five orchestrators L2, engines L1), detailed specifications for Conductor, Phase Orchestrator, Execution Orchestrator, Findings Orchestrator, Chain Orchestrator, Session Orchestrator, Engine ABC, findings flow, next_actions chain semantics, gate/capability filtering, reinvocation mechanics, session state management, audit log discipline.
- **References dead/dropped code:** NO — prescriptive design only.
- **Cross-references:** Implicitly references apps/conductor/ module tree.
- **Overlap detected:** Substantial overlap with CLAUDE.md (both cover three-level architecture, design principles, orchestrator responsibilities). orchestration.md is the detailed technical spec; CLAUDE.md is the executive summary and delivery log.

### docs/audits/api_stage_card_audit.md
- **Purpose:** Classify event outputs from the API security probe family (probe_api_exploit) as KEEP/COLLAPSE/DROP.
- **Topics:** probe_api_exploit phases (discover API docs → parse spec → authenticate → IDOR detection), per-event classification with justification, operator signal assessment.
- **References dead/dropped code:** NO — audit of active code.
- **Cross-references:** References probes.py line 3556 (probe_api_exploit location).
- **Overlap detected:** None; specialized audit of one probe.

### docs/audits/dormant-capabilities-inventory.md
- **Purpose:** Comprehensive catalog of wired but not executed dormant capabilities, grouped by class (Recon, Enumeration, Exploitation).
- **Topics:** Active system boundary definition (bootstrap/runtime.py imports), dormant recon-class (subdomain enum via recon_ng, api_authed_recon, NVD sync, CVE matcher), dormant enumeration-class (api endpoint enum, api method enum, browser recon), dormant exploitation-class (IDOR mutate, XSS, SQLi, CMDi probes, brute force, purchase flow, etc.). For each dormant capability: file location, what it does, current status (fully dormant vs referenced but not executed), what it would do if wired, effort to wire, overlap with active system.
- **References dead/dropped code:** YES — extensively documents dormant code. Explicitly notes what is parked but not wired (CVE matcher, dormant exports/, knowledge vault code).
- **Cross-references:** References apps/investigation_core/exports/, apps/validation/, apps/scanner_orchestration/, apps/investigation_workspace/ extensively.
- **Overlap detected:** Complements CLAUDE.md's hard-learned lessons section. Overlaps with the dormant-code discussion in CLAUDE.md (CVE matcher is explicitly dropped; knowledge vault is parked for V2.7).

### docs/audits/operator_input_audit.md
- **Purpose:** Verify that operator-supplied runtime parameters can reach a probe via the action card system.
- **Topics:** Input pipeline (template → route Form parameter → ContextVar → probe substitution), currently only probe_api_idor_mutate implements has_input=True, other probes operate on pre-determined parameters.
- **References dead/dropped code:** NO — audit of current system.
- **Cross-references:** References suggestions/probes.py, catalog.py, routes.py.
- **Overlap detected:** None; specialized audit.

### docs/audits/v1.6-recon-enum-audit.md
- **Purpose:** Classify and inventory recon and enumeration probes (per V1.6 design).
- **Topics:** Phase classification (recon: run_passive_probe; enumeration: run_sqli_recon_probe, run_cmdi_recon_probe, run_auth_recon_probe, run_api_recon_probe), per-probe details (file, phase, HTTP behavior, findings types, evidence shapes, next_actions, confidence distribution).
- **References dead/dropped code:** NO — audit of active probes.
- **Cross-references:** References bootstrap/runtime.py, apps/investigation_workspace/probe/*.py files extensively.
- **Overlap detected:** Overlaps with v1_restructure_audit.md (both catalog probes with phase assignments); differs in scope (v1.6-recon-enum focuses on recon+enum phases only, v1_restructure covers all 29 probes).

### docs/audits/v1.6-recon-output-inventory.md
- **Purpose:** Design input for V1.7 enumeration phase; determines which engines support re-invocation cleanly, what refined parameters they accept, what evidence gaps exist.
- **Topics:** Per-engine output inventory (passive_probe through ZAP), current output shapes from live DB data (192.168.200.202 investigations), re-invocation capability assessment (clean vs requires modification), recon-evidence-driven parameter refinement opportunities.
- **References dead/dropped code:** NO — analysis of current V1.6 engine outputs.
- **Cross-references:** References apps/conductor/engines/, normalized_findings table, data/validation.db.
- **Overlap detected:** Complements v1.6-recon-enum-audit.md (that audit enumerates probes; this audit analyzes output inventory of wrapped engines).

### docs/audits/v1_4a_regression_audit.md
- **Purpose:** Identify regressions in V1.4a UI compared to pre-V1.4a baseline.
- **Topics:** 13 regressions found (2 blocking, 6 important, 3 minor, 2 acceptable), root causes (stage card rendering as div vs button, context panel access loss, payload execution blocking, etc.), live regression verification against running backend.
- **References dead/dropped code:** NO — audit of regression, not dead code.
- **Cross-references:** References investigation-flow.js, investigation_workspace.html, workspace.js.
- **Overlap detected:** None; regression-specific audit.

### docs/audits/v1_execution_architecture_audit.md
- **Purpose:** Document ground truth of current execution model before planning phased-execution refactor.
- **Topics:** V1 shipped phase classification (tagging + pane routing) but NOT sequential execution; actual model is concurrent bootstrap (Phase 41-44, asyncio.gather); Bootstrap is the active execution model, not vestige; trigger chain (_view_is_empty guard), three entry points (topology.json, workspace-data.json, HTML page render).
- **References dead/dropped code:** NO — analysis of current architecture.
- **Cross-references:** References bootstrap/runtime.py, routes.py, _view_is_empty guard.
- **Overlap detected:** Complements v1_restructure_audit.md (that audit classifies probes; this audit explains when they execute).

### docs/audits/v1_restructure_audit.md
- **Purpose:** Comprehensive probe phase classification audit covering all probes in the codebase (29 total: 19 distinct + 4 re-yielded helpers).
- **Topics:** Probe classification matrix (file:line, network behavior P/AD/AE, current trigger BOOT/OP/NEST, proposed phase, FP risk, aggregation candidacy), detailed phase discussion for each, probe rationale for recon vs enumeration vs exploitation assignment.
- **References dead/dropped code:** NO — audit of existing probes.
- **Cross-references:** References apps/investigation_workspace/probe/*.py, suggestions/probes.py, catalog.py extensively with line numbers.
- **Overlap detected:** Overlaps with v1.6-recon-enum-audit.md (both classify probes); v1_restructure_audit is more comprehensive (all 29 vs recon+enum subset). Also overlaps with v1_execution_architecture_audit.md (both discuss phases).

### docs/audits/v1_ui_audit.md
- **Purpose:** Verify V1 UI compliance with PR1-PR4 requirements.
- **Topics:** Phase classification delivery (FindingEvent.phase field, per-probe phase tagging), UI restructure delivery (phase tabs, lucide macros, React Flow root, vendor assets), live observation against PortSwigger lab.
- **References dead/dropped code:** NO — compliance audit.
- **Cross-references:** References base.html, _lucide.html, investigation_workspace.html, workspace.js, vendor assets.
- **Overlap detected:** Overlaps with v1_restructure_audit.md (both discuss phase classification); v1_ui_audit validates rendering, v1_restructure validates probe classification.

### tests/conductor/_patterns/README.md
- **Purpose:** Document the seam bug pattern catalog; serve as living catalog of architectural bugs and enforcement device.
- **Topics:** Why seam tests exist (mock tests miss cross-layer mismatches), 7 documented patterns with test files (Two-Parallel-ID-Systems, Attribution Loss, Silently-Disabling Default, Adapter Shape Mismatch, Dangling Reference, Resource-Class-Blind Policy, Wrong DB Target), lesson learned from each, pattern/test file mappings, guidance for adding new patterns as V2+ introduces new seams.
- **References dead/dropped code:** NO — catalog of past bugs to prevent regression.
- **Cross-references:** References CLAUDE.md extensively (hard-learned lessons section matches the patterns documented here).
- **Overlap detected:** Complements CLAUDE.md (both document V1.6-V1.7 bugs); tests/conductor/_patterns/ is the enforcement layer with test files; CLAUDE.md hard-learned section is the narrative explanation.

### .claude/rules/common/agents.md
- **Purpose:** Guide on available agents, when to use each, multi-perspective analysis.
- **Topics:** Agent list (planner, architect, code-reviewer, security-reviewer, tdd-guide, build-error-resolver, e2e-runner, refactor-cleaner, doc-updater, etc.), immediate agent usage (when to invoke without user prompt), parallel task execution, multi-perspective analysis.
- **References dead/dropped code:** NO — operational guidance only.
- **Cross-references:** None.
- **Overlap detected:** Complements code-review.md, development-workflow.md, and common/patterns.md (all delegate to agents).

### .claude/rules/common/code-review.md
- **Purpose:** Define when and how to conduct code reviews.
- **Topics:** Mandatory review triggers (after writing, before commit, security-sensitive, architectural, before merge), pre-review requirements, review checklist (readability, function size, nesting, error handling, secrets, tests, coverage ≥80%), security review triggers, severity levels (CRITICAL/HIGH/MEDIUM/LOW), agent usage, review workflow, common issues (security, code quality, performance), approval criteria.
- **References dead/dropped code:** NO — process guidance.
- **Cross-references:** References testing.md, security.md, git-workflow.md, agents.md.
- **Overlap detected:** Overlaps with common/security.md (both cover security checklist), common/testing.md (both require 80% coverage), common/coding-style.md (both reference code quality concerns).

### .claude/rules/common/coding-style.md
- **Purpose:** Establish coding style discipline and code quality standards.
- **Topics:** Immutability as CRITICAL, KISS/DRY/YAGNI principles, file organization (small files preferred, 200-400 lines typical, 800 max), error handling, input validation, naming conventions (camelCase, PascalCase, UPPER_SNAKE_CASE), code smells (deep nesting, magic numbers, long functions), code quality checklist.
- **References dead/dropped code:** NO — prescriptive guidance.
- **Cross-references:** None.
- **Overlap detected:** Overlaps with code-review.md (both cover function size, nesting, error handling, naming); coding-style.md is prescriptive, code-review.md is the enforcement checklist.

### .claude/rules/common/development-workflow.md
- **Purpose:** Describe the full feature development pipeline before git operations.
- **Topics:** Research & reuse first (GitHub search → lib docs → Exa), plan first (planner agent), TDD approach (tdd-guide agent), code review (code-reviewer agent), commit & push (following git-workflow.md), pre-review checks.
- **References dead/dropped code:** NO — workflow process.
- **Cross-references:** References git-workflow.md extensively.
- **Overlap detected:** Overlaps with git-workflow.md (both describe commit); development-workflow.md is the overall pipeline, git-workflow.md is the git-specific part.

### .claude/rules/common/git-workflow.md
- **Purpose:** Standardize git commit message format and pull request workflow.
- **Topics:** Commit message format (type: description + optional body), PR workflow (analyze full history, git diff base...HEAD, comprehensive summary, test plan).
- **References dead/dropped code:** NO — git operation standards.
- **Cross-references:** References development-workflow.md.
- **Overlap detected:** Minimal; git-workflow.md is specialized to git operations.

### .claude/rules/common/hooks.md
- **Purpose:** Document hooks system (PreToolUse, PostToolUse, Stop) and auto-accept permissions usage.
- **Topics:** Hook types, auto-accept permissions caution, TodoWrite best practices.
- **References dead/dropped code:** NO — operational system guidance.
- **Cross-references:** None.
- **Overlap detected:** None; specialized to hooks mechanism.

### .claude/rules/common/patterns.md
- **Purpose:** Describe common design patterns and skeleton project evaluation.
- **Topics:** Skeleton projects evaluation (search existing, use parallel agents to evaluate, clone as foundation), design patterns (Repository pattern, API response format).
- **References dead/dropped code:** NO.
- **Cross-references:** References python/patterns.md implicitly.
- **Overlap detected:** Overlaps with python/patterns.md (both discuss patterns); common/ is language-agnostic, python/ is Python-specific.

### .claude/rules/common/performance.md
- **Purpose:** Guide model selection, context window management, and build troubleshooting.
- **Topics:** Model selection (Haiku for lightweight agents, Sonnet for main work, Opus for deep reasoning), context window management (avoid last 20% for large refactors), extended thinking + plan mode, build troubleshooting (build-error-resolver agent).
- **References dead/dropped code:** NO — operational guidance.
- **Cross-references:** None.
- **Overlap detected:** None; specialized to performance optimization.

### .claude/rules/common/security.md
- **Purpose:** Mandatory security checks and protocols before commit.
- **Topics:** Mandatory checklist (no hardcoded secrets, input validation, SQL injection/XSS/CSRF prevention, auth verification, rate limiting, error message redaction), secret management (env vars, secret manager), security response protocol (stop, use security-reviewer agent, fix CRITICAL, rotate exposed secrets).
- **References dead/dropped code:** NO — security policy.
- **Cross-references:** References security-reviewer agent, python/security.md.
- **Overlap detected:** Overlaps with code-review.md (both mention security checklist); common/security is the mandatory policy, code-review is where it's enforced.

### .claude/rules/common/testing.md
- **Purpose:** Define testing requirements and TDD discipline.
- **Topics:** 80% minimum coverage, test types (unit, integration, E2E), TDD workflow (RED/GREEN/IMPROVE), test failure troubleshooting (tdd-guide agent), AAA pattern, descriptive test naming.
- **References dead/dropped code:** NO — testing discipline.
- **Cross-references:** References tdd-guide agent, python/testing.md.
- **Overlap detected:** Overlaps with code-review.md (both require 80% coverage); testing.md is the detailed discipline, code-review.md enforces it.

### .claude/rules/python/coding-style.md
- **Purpose:** Python-specific coding style extending common/coding-style.md.
- **Topics:** PEP 8 + type annotations, immutable data structures (dataclass frozen, NamedTuple), black/isort/ruff for formatting/linting.
- **References dead/dropped code:** NO.
- **Cross-references:** References common/coding-style.md, python-patterns skill.
- **Overlap detected:** Extends common/coding-style.md; no duplication within the Python-specific file.

### .claude/rules/python/fastapi.md
- **Purpose:** FastAPI-specific rules extending Python coding standards.
- **Topics:** Structure (create_app, thin routers, separate schemas), async/await discipline (use async for I/O, use async clients), dependency injection (Depends), schema security (no passwords/tokens), CORS/JWT/rate-limiting security, testing (dependency override, clear overrides).
- **References dead/dropped code:** NO.
- **Cross-references:** References fastapi-patterns skill.
- **Overlap detected:** Complements python/coding-style.md; no duplication.

### .claude/rules/python/hooks.md
- **Purpose:** Python-specific hooks extending common/hooks.md.
- **Topics:** PostToolUse hooks (black/ruff, mypy/pyright), warnings (print statements).
- **References dead/dropped code:** NO.
- **Cross-references:** References common/hooks.md.
- **Overlap detected:** Minimal; Python-specific configuration.

### .claude/rules/python/patterns.md
- **Purpose:** Python-specific patterns extending common/patterns.md.
- **Topics:** Protocol/duck typing, dataclasses as DTOs, context managers & generators.
- **References dead/dropped code:** NO.
- **Cross-references:** References common/patterns.md, python-patterns skill.
- **Overlap detected:** Extends common/patterns.md; no duplication.

### .claude/rules/python/security.md
- **Purpose:** Python-specific security extending common/security.md.
- **Topics:** Secret management (os.environ, dotenv), bandit for static analysis.
- **References dead/dropped code:** NO.
- **Cross-references:** References common/security.md, django-security skill (conditional).
- **Overlap detected:** Extends common/security.md; no duplication.

### .claude/rules/python/testing.md
- **Purpose:** Python testing guidance extending common/testing.md.
- **Topics:** pytest framework, coverage measurement, test organization (pytest.mark: unit, integration).
- **References dead/dropped code:** NO.
- **Cross-references:** References common/testing.md, python-testing skill.
- **Overlap detected:** Extends common/testing.md; no duplication.

---

## Redundancy clusters

### Cluster 1: Architecture & Orchestration Foundation

**Files:** CLAUDE.md, docs/architecture/orchestration.md, AI_CONTEXT.md, ai-context/FACTORY_RULES.md, ai-context/MODULE_PATTERNS.md

**Description:** All five files describe the three-level orchestration system and factory inheritance structure. They overlap heavily in coverage of design principles, orchestrator responsibilities, and module constraints.

**Most canonical:** `docs/architecture/orchestration.md` — This is the explicit "definitive contract" (stated on line 7 of the file itself). It is the most detailed, most technical, and serves as the reference that all PR work implements.

**Redundant:** CLAUDE.md covers orchestration at a higher level as delivery summary. AI_CONTEXT.md is factory-era context that is superseded by current deployment. FACTORY_RULES.md and MODULE_PATTERNS.md codify constraints that orchestration.md assumes.

**Consolidation recommendation:** Keep orchestration.md as the single source of truth. Reduce CLAUDE.md to delivery summary + hard-learned lessons (remove orchestration system description, link to orchestration.md instead). Archive or consolidate AI_CONTEXT.md, FACTORY_RULES.md, MODULE_PATTERNS.md into a single "Factory Inheritance & Rules" document if they are actively consulted; otherwise retire them as they predate the current V1.7 system.

---

### Cluster 2: Audit Reports (V1 Architecture Verification)

**Files:** docs/audits/v1.6-recon-enum-audit.md, docs/audits/v1.6-recon-output-inventory.md, docs/audits/v1_restructure_audit.md, docs/audits/v1_4a_regression_audit.md, docs/audits/v1_execution_architecture_audit.md

**Description:** All five audit files analyze V1.x architecture from different angles: probe classification, output shapes, regressions, execution model.

**Most canonical:** `docs/audits/v1_restructure_audit.md` — Covers all 29 probes with the most comprehensive classification matrix (file:line, network behavior, phase, FP risk, aggregation). It is a complete inventory.

**Redundant:** v1.6-recon-enum-audit is a subset (recon+enum only). v1.6-recon-output-inventory duplicates probe inventory but focuses on output shapes and re-invocation capability (useful complement, not pure duplication). v1_execution_architecture is orthogonal (execution timing, not probe classification). v1_4a_regression is regression-specific.

**Consolidation recommendation:** Keep v1_restructure_audit as the canonical probe inventory. Keep v1.6-recon-output-inventory (orthogonal focus on output design). Cross-reference from both into execution_architecture and 4a_regression (they are analysis documents, not inventories). Retire v1.6-recon-enum-audit as it is fully contained in v1_restructure.

---

### Cluster 3: Code Review / Quality Standards

**Files:** .claude/rules/common/code-review.md, .claude/rules/common/coding-style.md, .claude/rules/common/testing.md

**Description:** All three overlap on coverage of code quality checklist, function size limits, test coverage %, error handling.

**Most canonical:** `code-review.md` — Consolidates the checklist and process.

**Redundant:** coding-style.md repeats checklist items (function size, nesting limits, error handling). testing.md repeats coverage % requirement.

**Consolidation recommendation:** Keep code-review.md as the integration point. Reduce coding-style.md to style-only (naming, immutability, DRY/KISS). Have code-review.md link to coding-style.md and testing.md for detailed rules, not duplicate them.

---

### Cluster 4: Development Workflow Process

**Files:** .claude/rules/common/development-workflow.md, .claude/rules/common/git-workflow.md

**Description:** development-workflow covers the full pipeline (research → plan → TDD → code review → commit); git-workflow covers the git-specific part (commit format, PR workflow).

**Most canonical:** `development-workflow.md` — Higher-level process. git-workflow is a proper subset.

**Redundant:** Minor—git-workflow.md properly focuses on git mechanics; development-workflow.md references it.

**Consolidation recommendation:** Keep both. They are clearly scoped: development-workflow is the process, git-workflow is the git-tool specifics. No consolidation needed.

---

### Cluster 5: Language-Agnostic vs Python-Specific Rules

**Files:** .claude/rules/common/*.md (15 files) vs .claude/rules/python/*.md (6 files)

**Description:** The python/ subdirectory extends common/ with Python-specific implementation for each concern (coding-style, fastapi, hooks, patterns, security, testing).

**Most canonical:** Both together — python/ explicitly extends common/ via "extends [common/foo.md]" comments at the top. No consolidation needed; this is the correct structure.

**Redundant:** None—proper inheritance hierarchy.

**Consolidation recommendation:** None. This structure is correct: common/ is language-agnostic, python/ specializes. If the project adds other languages, add .claude/rules/rust/, .claude/rules/javascript/, etc. following the same pattern.

---

### Cluster 6: Dormant Code Documentation

**Files:** CLAUDE.md (hard-learned lessons section), docs/audits/dormant-capabilities-inventory.md, tests/conductor/_patterns/README.md

**Description:** All three document bugs, dropped features, and deferred work.

**Most canonical:** `docs/audits/dormant-capabilities-inventory.md` — Comprehensive catalog of every dormant capability, organized by class (Recon/Enumeration/Exploitation), with detailed analysis of each.

**Redundant:** CLAUDE.md hard-learned lessons section covers 19 lessons (many of which resulted in seam bugs now documented in tests/conductor/_patterns/). CLAUDE.md also documents explicitly dropped features (CVE matcher, etc.). tests/conductor/_patterns/README.md documents the same bugs from a testing/enforcement angle.

**Consolidation recommendation:** Keep dormant-capabilities-inventory.md as the live capability catalog. Keep tests/conductor/_patterns/README.md as the enforcement layer (documents the bugs + test files that prevent regression). Reduce CLAUDE.md hard-learned section to link to these two documents rather than repeating the bugs.

---

## Contradictions found

**Contradiction 1: V1 Execution Model — Classification vs Reality**

- **Files:** v1_restructure_audit.md, v1_execution_architecture_audit.md
- **Claim A (v1_restructure_audit):** "Currently fires at bootstrap" for run_passive_probe, run_sqli_recon_probe, etc. The audit assigns phases (Recon, Enumeration) and discusses *proposed* phase reassignment.
- **Claim B (v1_execution_architecture_audit):** "V1 shipped phase **classification** (finding tagging + pane routing) but did **not** ship sequential phased execution. [...] The Recon / Enumeration phase tabs are a rendering overlay applied to these concurrent results — they do not reflect when probes ran relative to each other."
- **Resolution:** Both are correct but describe different layers. Claim A is about probe tagging (the phase field on FindingEvent). Claim B is about execution sequencing (all probes run concurrently via asyncio.gather). The "phase" is a property of the finding, not a control on probe execution. The contradiction is apparent, not real—they're describing different concerns (classification vs execution timing). Clarify in both files that phase tagging and phase execution are orthogonal.

**Contradiction 2: Enumeration Start Trigger**

- **Files:** v1_restructure_audit.md (~line 74), CLAUDE.md (PR B description at line 284)
- **Claim A (v1_restructure_audit):** "In V1 it must move to **Enumeration** so it is gated on the operator hitting the Enumeration tab (still automatic — the V1 design auto-runs Enumeration probes when the operator opens the investigation, so the practical behavior is unchanged, but the phase-attribution becomes explicit)."
- **Claim B (CLAUDE.md PR B):** "CONDUCTOR_PARALLEL_TRACK=true routes passive_probe via Conductor while wellknown/fingerprint/cors stay on existing path; default OFF."
- **Resolution:** v1_restructure is a *proposed* redesign document (written before V1.7 was implemented). CLAUDE.md describes the current *actual* state (V1.7 complete, probes run on Conductor). No contradiction—one is a proposal, the other is implementation status. Mark v1_restructure as historical/proposal document to avoid confusion.

---

## Dead code references

### CLAUDE.md

**Explicit drops documented (lines 355-362):**
- CVE matcher chain — dormant infrastructure (cves table, cve_watchlist, nvd_sync code, validation/engines/cve_matcher.py) stays in DB and codebase, parked, not wired, recoverable. Reason: reference/annotation work vs action work; medium-ROI.

**Deferral (lines 364-374):**
- ZAP active scan — exploitation-phase work; belongs in V2
- AJAX spider in ZAP — defer until regular spider proves insufficient
- Catalog mapping — defer until exploitation categories are defined
- Tag-based filtering in nuclei — defer until severity filtering proves insufficient

**Factory scaffold cleanup deferred (lines 528-535):**
- core/ and sdk/ directories cannot be removed yet; sdk/ imported throughout apps/ via "from sdk import Logger"; core/ is application entrypoint. Cleanup requires replacing all sdk.Logger usages with stdlib logging first.

---

### docs/audits/dormant-capabilities-inventory.md

**Extensive catalog of dormant code:**
- DC-R-01 through DC-R-04: Recon-class dormant (subdomain enum, api_authed_recon, NVD sync, CVE matcher)
- DC-E-01 through DC-E-06: Enumeration-class dormant (endpoint enum, method enum, browser recon, etc.)
- DC-X-01 through DC-X-11: Exploitation-class dormant (IDOR mutate, XSS, SQLi, CMDi, brute force, purchase flow, etc.)

Each entry notes status (FULLY DORMANT vs REFERENCED BUT NOT EXECUTED), effort to wire, overlap with active system.

---

### tests/conductor/_patterns/README.md

**Bug patterns documented (lines 21-75):**
- Pattern 1: Two-Parallel-ID-Systems (PR B→L fix)
- Pattern 2: Attribution Loss at Seam (PR D-fix-2 fix)
- Pattern 3: Silently-Disabling Default (PR D-fix-2 + PR K fixes)
- Pattern 4: Adapter Shape Mismatch (PR E-fix nuclei, PR F ZAP fixes)
- Pattern 5: Dangling Reference (PR G nmap cve_lookup removal)
- Pattern 6: Resource-Class-Blind Policy (PR G watchdog threshold fix)
- Pattern 7: Wrong DB Target (PR K FilterOrchestrator DB fix)

Each pattern includes: bug example, fix explanation, lesson learned, corresponding test file.

---

## Summary

This audit reveals a well-documented codebase with clear layering between:
1. **Factory era context** (ai-context/ — now superseded by V1.7 but still referenced for inheritance rules)
2. **Current architecture spec** (docs/architecture/orchestration.md — the definitive contract)
3. **Delivery history** (CLAUDE.md — current status and hard-learned lessons)
4. **Audit trails** (docs/audits/ — snapshots of previous analysis for reference)
5. **Enforcement patterns** (tests/conductor/_patterns/ — regression prevention)
6. **Development discipline** (.claude/rules/ — mandatory standards for all work)

**Primary redundancy:** The factory-era files (ai-context/, AI_CONTEXT.md, README.md) overlap with CLAUDE.md and should be consolidated or archived. The current source of truth is CLAUDE.md + docs/architecture/orchestration.md + the audit trail.

**Primary dead code:** Explicitly documented in CLAUDE.md (CVE matcher dropped, ZAP active scan deferred, factory scaffold cleanup deferred) and comprehensively cataloged in dormant-capabilities-inventory.md.

**No critical contradictions:** The two apparent contradictions are actually describing orthogonal concerns (phase tagging vs execution timing) or document different time states (proposal vs implementation).

