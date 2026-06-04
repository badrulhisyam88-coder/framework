# Bug Ledger

Tracks vault dedup runs and removal decisions. Appended by POST /admin/vault-dedup.

## Pre-existing test errors — 17 async fixture errors (since PR-A)

Root cause: `pytest-asyncio 1.3.0` + `asyncio_mode = "strict"` in pyproject.toml.
Strict mode requires `@pytest.mark.asyncio` on async test functions and
`@pytest_asyncio.fixture` on async fixtures. These tests use undecorated
`async def` functions and `@pytest.fixture`. Written for auto mode; require
Docker environment (aiosqlite) regardless.

Affected files (17 tests):
- tests/admin_ui/test_admin_ui_renders.py (7 tests) — async `admin_setup` fixture
- tests/admin_ui/test_settings_panel.py (5 tests) — async `settings_setup` or similar
- tests/conductor/test_end_to_end_mock_flow.py (5 tests) — async `conductor_bundle` fixture

Status: pre-existing since session start (PR-A). Not introduced by B-2.
Fix: add `@pytest.mark.asyncio` + `@pytest_asyncio.fixture` in a dedicated
async-fixture cleanup PR, or switch to `asyncio_mode = "auto"` globally.
Deferred — Docker tests cannot pass on host regardless.

---

## Phase B/C Gate — 2026-05-30

### CLEARED

- **_fft().category_id systemic bug (all 8 engines)** — Fixed PR-C. `"category"` field in
  all 8 V2 exploitation engine emissions changed from `_fft(x).category_id` (wrong category
  string) to the verbatim finding_type string. `normalized_findings.finding_type` now stores
  the correct value for all engines.

- **_APPROVED_ENGINES drift risk** — Fixed PR-C Scope 3. Maintenance comment added to
  `apps/conductor/qwen/action_schema.py` fallback list; comment states it must stay in sync
  with `engine_registry.engines_for_phase("exploitation")`.

- **AI chat raw JSON rendering** — Fixed PR-C Scope 2. `parse_structured_output` now returns
  `parsed.get("response") or response_text` (graceful fallback to raw text) instead of `""`.
  Operator sees human-readable advice in the chat panel instead of a JSON blob.

- **Lowercase duplicate ChromaDB entries** — Removed Phase B-2/B-3 preflight. 11 stale
  lowercase concept IDs (`concept-access-control` etc.) deleted from the vault index.
  Canonical uppercase CONCEPT-* IDs now always rank first. New admin endpoint
  `POST /admin/vault/delete-ids` added to support targeted ID removal.

- **CONCEPT-CMDI-REFLECTED weak content** — Fixed Phase B-3 preflight. Engine signature
  line added to body; concept now ranks #1 for reflected command injection queries after
  the lowercase duplicate was removed and the file re-embedded.

- **concept-default-creds.md missing input trigger** — Fixed Phase B/C gate (Scope 1).
  `default_creds_attempt` added to `finding_types` in frontmatter. Vault retrieval for
  `default_creds_attempt` queries now returns CONCEPT-DEFAULT-CREDS at rank 1.

### DEFERRED → Phase C/D gate

- **chromadb posthog telemetry · capture() signature mismatch** — Non-blocking; vault is
  fully functional. Cosmetic warning in logs only. Deferred to Phase C/D gate.

- **pytest-asyncio strict mode · 17 pre-existing errors** — async fixture + strict mode
  incompatibility (`asyncio_mode = "strict"` in pyproject.toml, but async fixtures use
  `@pytest.fixture` not `@pytest_asyncio.fixture`). Host-only issue; Docker tests
  unaffected. Fix: add `@pytest_asyncio.fixture` decorators or switch to
  `asyncio_mode = "auto"` globally. Deferred → Phase C/D gate.

- **dedup_vault_entries() O(n²) pairwise cosine** — Acceptable at current vault size
  (~90 entries). Deferred → revisit if vault exceeds ~300 entries post Phase C.

---

## Phase C/D Gate — 2026-05-31

### CLEARED

- **Jinja2 inline ternary in _selection_card.html:125** — Fixed Bundle 1. Replaced
  `(selection_options[preselect].engine_id is none if preselect is not none else true)`
  with pre-computed `execute_disabled` boolean passed from the route.

- **mindFinding click handler missing in _onNodeClick** — Fixed Bundle 1. Added
  `if (t === 'mindFinding')` branch to `_onNodeClick` in exploitation-mindmap.js.
  Calls `window.openContextPanel('disc-' + fid.replace(/_/g, '-'))`.

- **Panel container hidden on first click (_invId race)** — Fixed Bundle 1. Added
  explicit `panel.classList.remove('hidden')` in the mindFinding branch before
  delegating to `openContextPanel`, matching `_setPanel()` exactly. No legacy arm
  timer found in code search.

- **concept-js-spider.md "Triggers on: login_form_detected"** — Fixed Bundle 1
  preflight. Replaced with `**Mode**: automatic post-authentication · **Precondition**:
  credential_brute must succeed and capture a session first`. Vault rebuild confirmed
  js_spider no longer ranks #1 for login_form_detected.

### DEFERRED → Phase D/E gate

- **chromadb posthog telemetry** — cosmetic, vault functional. Deferred.

- **pytest-asyncio strict mode (17 errors)** — host-only, Docker tests unaffected.
  Fix: switch `asyncio_mode = "auto"` or add `@pytest_asyncio.fixture` decorators.
  Deferred.

- **dedup_vault_entries() O(n²)** — acceptable at ~90 entries. Monitor. Deferred.

- **openContextPanel() _invId race** — mitigated by explicit panel visibility fix.
  Check other callers (bundle-* nodes, etc.) at D/E gate.

- **mindFinding → disc-* ID construction brittle** — `fid.replace(/_/g, '-')` assumes
  finding_id uses underscores throughout. Non-blocking; monitor if IDs change.

- **_APPROVED_ENGINES drift risk in action_schema.py** — maintenance comment added;
  fallback list must stay in sync with registry. Deferred.

---

## Phase D/E Gate — 2026-05-31

### CLEARED

- **embeddable_text() EXEC-TEMPLATE stripping** — Verified no ranking degradation.
  All 4 templated concept files rank #1 after template addition and rebuild.

- **technique_selector.py removed** — Model no longer on hot path confirmed.
  Zero Ollama /api/chat calls during context-panel rendering (Scenario C PASS).
  Model invoked only post-execution or when vault similarity < SIM_FLOOR.

- **model_advisor.py system prompt additions** — access_control + js_spider
  scoped correctly. Bakeoff failure modes addressed in advisor prompt.

- **SIM_FLOOR gate applied in context_panel route** — routes.py: if
  selection_options[0].similarity >= SIM_FLOOR → preselect=0, no model call.
  Else → preselect=None, model advisor invoked asynchronously.

### DEFERRED → Phase E/done gate

- **chromadb posthog telemetry** — cosmetic, vault functional. Deferred.

- **pytest-asyncio strict mode (17 errors)** — host-only, Docker unaffected.
  Deferred.

- **dedup_vault_entries() O(n²)** — fine at current vault size. Deferred.

- **openContextPanel() _invId race** — mitigated. Check other callers at done gate.

- **mindFinding → disc-* ID construction brittle** — monitor. Deferred.

- **Scenario C Playwright clicks same node twice** — strengthen test in Phase E
  to use 3 distinct finding nodes.
