# Stage 2 Code Audit — Summary

**Date:** 2026-05-25
**Scope:** Three parallel read-only audits. No code or .md changes outside `/docs/audits/`.
**Constituent reports:**
- `v1.7-output-inventory.md` — engines, rules, DB coverage
- `legacy-classification.md` — active vs dormant vs vestige vs ambiguous
- `seams-verification.md` — 11 seams vs code vs test coverage

---

## Headline numbers

| Metric | Count |
|---|---|
| Active engines | 15 |
| Rules in REGISTERED_RULES | 19 (6 drop + 7 validate + 6 incomplete) |
| Reinvocation rules | 8 |
| Finding types with zero rules (always pending) | 10 (+ 1 partial: command_injection) |
| DB findings classified in only known run | 3 of 16 (2 validated, 1 incomplete) |
| Seams verified correct | 10 of 11 (1 not implemented: audit log) |
| Seams with dedicated pattern test | 7 of 11 |
| Seams missing pattern test | 4 (RuleResult, Wordlist, OutputChannel, EventBus) |
| Undocumented seams found in code | 5 |
| Confirmed VESTIGE lines | ~12 858 |
| AMBIGUOUS lines (pending operator decision) | ~14 000 |
| DORMANT_V2 lines (protected, do not delete) | ~3 163 |

---

## Critical findings

### 1. Ten passive_probe finding types are permanently pending — no rules exist

`http_service_detected`, `verbose_banner_disclosed`, `missing_csp_header`, `missing_hsts_header`, `missing_x_frame_options`, `missing_x_content_type_options`, `missing_referrer_policy`, `missing_permissions_policy`, `waf_cdn_detected`, `http_methods_advertised` — all emitted by `passive_probe` — have zero drop, validate, or incomplete rules. They will never exit pending status regardless of evidence. In the only DB investigation, 6 of 16 findings are of these types.

**Operator decision needed:** Are these finding types in-scope for V1.7 filtering, or are they intentionally left unfiltered as raw recon output? If they should be surfaced or suppressed, a rule set PR is required before live verification is meaningful for these types.

### 2. Nuclei info/low is an uncontrolled noise source

7 of 16 DB findings are nuclei `vulnerability_assessed` at `info` severity (`wildcard-dns-detect`, `secrets-patterns-pii`). No rule exists to drop, validate, or classify them. With `nuclei_severity_info` and `nuclei_severity_low` gates ON by default, every investigation accumulates permanently-pending nuclei info findings. These are low-ROI templates for a pentest workbench.

**Recommended fix (small PR):** Add a drop rule for nuclei `vulnerability_assessed` findings where severity is `info` or `low` AND probe_id is `nuclei` AND evidence `tags` include known noise tags (e.g. `global-matchers`, `dns`). Or: flip `nuclei_severity_info` gate default to OFF.

### 3. `command_injection` has no validate rule — sqli/cmdi asymmetry

`ValidateSqliEndpointsFound` exists for `sqli`; no equivalent `ValidateCmdiEndpointsFound` exists for `command_injection`. If cmdi_recon finds injectable paths where `auth_required` is False, the finding stays pending. The `IncompleteCmdiAuthRequired` rule only fires for the auth-gated case.

**Recommended fix:** Add `ValidateCmdiEndpointsFound` (cmdi + non-empty detected_paths + auth_required=False → validated), parallel to the sqli validate rule.

### 4. Web-server drop rules are blind on empty `Server` header

`detect_server()` in `drop_rules.py` reads `evidence.server` from `http_service_detected`. PortSwigger labs return an empty `Server` header. All four web-plugin drop rules (wordpress, drupal, apache, nginx) silently fail to fire. Plugins dispatched against a non-matching server are NOT dropped — they produce spurious findings.

**Mitigating factor:** These plugins are gate-OFF by default. Only affects investigations where operator has enabled plugin gates against targets that don't expose the Server header.

### 5. Four seams have no dedicated pattern test

| Seam | Risk |
|---|---|
| Seam 6 — RuleResult protocol (`is_evidence_gap` not first-match-wins) | **HIGH** — no test protects the chain-continues behavior. A future rule refactor could make `evidence_gap` first-match-wins and silently drop all gap-blocked findings. |
| Seam 7 — Wordlist registry | MEDIUM — no test verifies engines can't open wordlist files directly |
| Seam 8 — OutputChannel (engine → FindingsOrchestrator) | MEDIUM — no test verifies engines emit via channel, not direct DB write |
| Seam 10 — EventBus subscription/cancellation | LOW — covered indirectly by integration tests |

**Recommended:** Add `test_seam_rule_chain_evidence_gap.py` for Seam 6 before any rule authoring in V2.

### 6. Five undocumented seams found in code

See `seams-verification.md` §Undocumented seams for full detail.

| ID | Seam | Priority |
|---|---|---|
| US-1 | FindingsOrchestrator fallback ID uses different inputs than `generate_finding_id()` | LOW (only fires on broken engines) |
| US-2 | ContextVar evidence bridge: `_CURRENT_EVIDENCE_CTX` in routes.py passes evidence across async boundary | MEDIUM — add before V2.5 chain dispatch |
| US-3 | Disc/node ID convention in branch topology | LOW (AMBIGUOUS code) |
| US-4 | `normalized_findings` table collision: same table written by `_persist()` (routes.py) and FilterOrchestrator callbacks (conductor.py) | LOW (routes.py writes new rows; FilterOrchestrator only UPDATEs existing rows) |
| US-5 | `sdk.Logger` vestigial facade: thin wrapper over stdlib logging | LOW (cosmetic; migration pending) |

### 7. `service_detected` with version="unknown" would be falsely validated

`ValidateServiceDetectedWithVersion` checks `if not version` — the string `"unknown"` is truthy. Nmap emits `"unknown"` as its fallback when product and version are both empty. Such findings would be validated with reason "service identified: {svc} unknown on port {port}". Operator may want an incomplete rule (or explicit drop) for version="unknown".

---

## V1.7 live verification status

The three finding types critical to the reference scenario (api_exposure, sqli, login_form_detected) classified correctly in the only DB investigation:

- `api_exposure` → validated: "api_exposure: 1 path(s) return 200 with no auth gate observed"
- `sqli` → validated: "sqli: 1 accessible login endpoint(s) found, no auth required"
- `login_form_detected` → incomplete: "login form has CSRF protection" (gap: csrf_token_needed)

**All 16 findings carry deterministic `fnd_xxx` IDs.** PR L fix confirmed effective. DB write path (conductor.py → validation.db) is functioning.

**V1.7 is correctly filtering for the reference scenario's core chain.** The 13 pending findings are a combination of: (a) permanently-pending types with no rules (passive_probe security headers), and (b) nuclei info findings with no classify path.

---

## Legacy code

### DORMANT_V2 — do not delete

| Module | Lines | V2.x stage | Bit-rot risk |
|---|---|---|---|
| `apps/investigation_core/exports/vault/` | ~300 | V2.7 RAG | Medium |
| `exporters/` (repo root) | 2 220 | V2.7 markdown export | **High** — predates all V1.7 schema additions; needs audit before activation |
| Metasploit cluster (3 service files + API) | ~760 | V2 exploitation | Medium |
| `apps/investigation_workspace/exploitation_paths/` | 552 | V2 design | **High** — taxonomy predates V2 architecture decisions |

**Highest pre-activation risk:** `exporters/` — 2 220 lines that predate `validation_status`, `enumeration_gaps`, `hit_paths: list[dict]`, `detected_login_endpoints: list[dict]`. Needs evidence-schema compatibility pass before V2.7 activation.

### VESTIGE — confirmed deletion candidates

Safe to delete without operator confirmation (zero Conductor-pipeline callers):

| Cluster | Lines | Suggested PR |
|---|---|---|
| `apps/scanner_orchestration/` non-active subdirs (services, monitoring, profiles, timeline, execution/run.py, target_resolution minus models.py, normalization/pipeline.py + cve_enricher.py) | 2 059 | **PR VESTIGE-1** — highest-confidence, no ambiguity |
| `apps/investigation_core/` confirmed vestiges (progression, lifecycle, taxonomy, models, campaigns, memory, learning) | 4 130 | PR VESTIGE-3 |
| `apps/validation/engines/` (operator must confirm CVE code deletion acceptable) | 654 | PR VESTIGE-2 (requires operator sign-off per CLAUDE.md "parked, recoverable") |
| `apps/validation/tasks/` + `apps/validation/adapters/` + `apps/investment_workspace/adaptive/` | 1 165 | PR VESTIGE-2 (no confirmation needed) |
| `apps/validation/services/` (minus metasploit/msf_*) | 3 073 | PR VESTIGE-4 (clear validation/api routes first) |

**Estimated total VESTIGE:** ~12 858 lines.

### AMBIGUOUS — operator review required

~14 000 lines across 7 clusters. Key questions:

| Cluster | Lines | Question |
|---|---|---|
| `apps/investigation_workspace/branch/` | 2 375 | Is React Flow topology canvas still rendered in operator UI? |
| `apps/investigation_workspace/suggestions/` | 5 762 | Is `execute_suggestion` route still used? (NOT V2.1 Qwen — deterministic catalog) |
| `apps/investigation_workspace/feed/` | 1 398 | Is chronological feed panel still in operator UI? |
| `apps/scanner_orchestration/api/` | 744 | Does frontend call `/api/v1/validation/scanner/` endpoints? |
| `apps/validation/api/` (minus metasploit.py) | ~3 484 | Which panels beyond `discovery.py` are actively used? |
| `apps/investigation_core/` defensive/evidence/guided_actions | ~2 461 | Are these workflows still operational? |
| `apps/validation/repositories/` | 1 192 | Fate follows validation/api resolution |

---

## Recommended next steps

**Before V2 (small PRs, address coverage gaps):**

1. **Rule PR A:** Add `ValidateCmdiEndpointsFound` (cmdi, accessible paths, no auth → validated). Closes the sqli/cmdi asymmetry.
2. **Rule PR B:** Decide on passive_probe security-header finding types (add drop rules OR add validate/incomplete rules OR document as intentionally unfiltered). Currently 10 finding types are silent pending.
3. **Rule PR C:** Add drop rule or flip gate for nuclei info/low noise (`wildcard-dns-detect`, `global-matchers` tagged templates). 7 DB findings permanently pending from this gap.
4. **Seam test:** Add `test_seam_rule_chain_evidence_gap.py` for Seam 6 (RuleResult evidence_gap is not first-match-wins). Highest-risk unseeded seam.

**Before V2 vestige cleanup:**

5. **AMBIGUOUS resolution:** Operator reviews 7 AMBIGUOUS clusters and assigns ACTIVE/DORMANT_V2/VESTIGE. Gates vestige cleanup PRs 3–4.
6. **PR VESTIGE-1:** Delete `apps/scanner_orchestration/` non-active subdirs (2 059 lines, no operator decision needed).
7. **Operator sign-off:** Confirm CVE code (`apps/validation/engines/`) is acceptable to delete (CLAUDE.md marks it "parked, recoverable").

**Before V2.7 (RAG activation):**

8. **exporters/ pre-activation audit:** Evidence-schema compatibility pass. Finding shapes evolved through V1.7 (typed-list evidence, validation_status, enumeration_gaps).

---

*Stage 2 complete. Three reports in `/docs/audits/`. No code or architecture docs modified.*
