# .md Audit Summary

**Date:** 2026-05-25  
**Produced by:** 3-subagent parallel audit (inventory, glossary, architecture claims) + consolidation pass  
**Detailed reports:** inventory.md (487 lines), glossary-terms.md (639 lines), architecture-claims.md (517 lines)

---

## Headline numbers

| Metric | Count |
|---|---|
| Total .md files audited (excluding .venv, .pytest_cache) | 38 |
| Total lines across all 38 files | ~8,380 |
| Files mentioning dead/dropped architecture | 3 (CLAUDE.md, dormant-capabilities-inventory.md, _patterns/README.md) |
| Distinct domain terms documented in glossary | 25+ |
| Terms with current inconsistencies | 2 (probe/engine drift, phase_run naming) |
| Terms that were inconsistent but are now fixed | 8 (documented as historical bugs) |
| Architecture claims audited | 45 |
| Claims verified against code | 38 (84%) |
| Stale claims (code diverged from doc) | 3 |
| Legacy/dormant claims (intentionally not implemented) | 4 (all V2+ roadmap) |
| Contradictions between files | 1 (resolvable) |
| Undocumented components found in code | 8 |
| Redundancy clusters identified | 6 |

---

## Critical findings

1. **Factory-era files describe a different system and are still on disk.** `ai-context/` (7 files) and `AI_CONTEXT.md` describe AI-Factory-Base inheritance, SDK interfaces, and module patterns from before the Conductor rewrite. They are not stale in the "wrong" sense — they're accurate about the factory — but they describe a different era. Any Claude Code session that loads them alongside CLAUDE.md gets conflicting signals about what is protected, what is the entrypoint, and what the module rules are. These are the highest-priority restructure target.

2. **CLAUDE.md §Architecture has one stale sentence that encodes a real bug.** Line 84: "FilterOrchestrator (V1.7) — runs after recon phase." Code runs after enumeration (PR K fix). A future dev reading this sentence could move the invocation back to after recon and re-introduce the timing bug. This is not a wording issue — it's a regression risk embedded in the architecture summary.

3. **Three files describe system architecture without cross-referencing each other.** `CLAUDE.md` (delivery log + hard-learned lessons), `docs/architecture/orchestration.md` (the definitive spec), and `ai-context/FACTORY_RULES.md` + `AI_CONTEXT.md` (factory constraints) all answer "how does this system work?" with different answers and no pointers between them. A reader can't tell which is authoritative.

4. **Eight components exist in code with no architectural documentation.** StorageBridge, NormalizedFindingRepository, finding_id algorithm, Wordlist Registry, Event Bus subscription mechanism, Audit log structure, OutputChannel interface, RuleResult/rule-chaining semantics. Three of these (StorageBridge, finding_id, RuleResult) are seam-critical — they're exactly the class of component that historically produced silent cross-layer bugs. No doc = no seam test = no protection.

5. **`v1.6-recon-enum-audit.md` is fully subsumed by `v1_restructure_audit.md`.** The recon+enum probe inventory in the former is a strict subset of the 29-probe classification in the latter. Dead weight — retire candidate.

6. **`data/wordlists/README.md` is the only documentation for a component that engines depend on.** The Wordlist Registry is a production dependency (SSH engine, API engines) with a single README as its only spec. It's correct but not cross-referenced from orchestration.md or CLAUDE.md's architecture section.

7. **All V1.7 seam bugs are fixed and pattern-tested.** No open architectural issues. The pattern catalog at `tests/conductor/_patterns/` covers 7 bug patterns. The 8 undocumented components in Finding 4 are the next seam risk if V2 touches them without adding seam tests first.

8. **Live verification gate for V1.7 not yet confirmed since PR L.** Architecture-claims audit notes: "Live verification gate for V1.7 is not yet passed." The reference scenario (telnet + API + login chain) and operator UI badges (validated/incomplete/dropped) need real-world confirmation against 192.168.200.202 or PortSwigger lab.

---

## Redundancy map

```
factory era:
  ai-context/ACTIVE_DECISIONS.md  ──┐
  ai-context/CURRENT_STATE.md     ──┤
  ai-context/FACTORY_RULES.md     ──┼──→  AI_CONTEXT.md  ──→  CLAUDE.md (most current)
  ai-context/MODULE_PATTERNS.md   ──┤
  ai-context/REPOSITORY_STRUCTURE.md ─┤
  ai-context/SDK_REFERENCE.md     ──┤
  ai-context/VERSION.md           ──┘

architecture spec:
  AI_CONTEXT.md (factory rules summary)  ──→  docs/architecture/orchestration.md (canonical spec)

probe classification:
  docs/audits/v1.6-recon-enum-audit.md  ──→  docs/audits/v1_restructure_audit.md (superset)

code quality standards:
  .claude/rules/common/coding-style.md  ──┐
  .claude/rules/common/testing.md       ──┼──→  .claude/rules/common/code-review.md
  (style + testing reference each other in code-review checklist — healthy)

dormant/dead code documentation:
  docs/audits/dormant-capabilities-inventory.md  ──→  canonical capability catalog
  tests/conductor/_patterns/README.md             ──→  seam bug enforcement layer
  CLAUDE.md §Hard-learned lessons                 ──→  delivery narrative (keep — different angle)

NOTE: python/ rules extend common/ correctly. No redundancy in .claude/rules/ hierarchy.
```

---

## Dead content inventory

| File / Section | What it describes | Status |
|---|---|---|
| `ai-context/` (all 7 files) | AI-Factory-Base inheritance, SDK interfaces, factory module rules | Superseded by Conductor + V1.7; factory rules still referenced by core/ and sdk/ which remain load-bearing (can't delete yet) |
| `AI_CONTEXT.md` | Factory inheritance narrative, protected areas, Docker usage from factory era | Same era as ai-context/; predates current architecture |
| `docs/audits/v1.6-recon-enum-audit.md` | Probe inventory for recon+enum subset | Fully subsumed by v1_restructure_audit.md |
| CLAUDE.md §Architecture line 84 | "runs after recon phase" (FilterOrchestrator) | Stale one-liner — code runs after enumeration since PR K |
| dormant-capabilities-inventory.md DC-R-03/04 | NVD sync, CVE matcher | Explicitly dropped; code parked but not wired |
| dormant-capabilities-inventory.md DC-I-07/08 | Campaign system, skill progression, learning paths | Legacy learning platform era; code dormant but not deleted |

---

## Terminology issues

Top inconsistencies and gaps — sorted by impact on future development:

1. **`FilterOrchestrator` timing encoded in stale sentence.** CLAUDE.md line 84 says "recon phase"; code and PR K say "enumeration phase." Risk: regression re-introduction.

2. **`probe` vs `engine` terminology drift.** Pre-V1.6 code uses `probe`; V1.6+ orchestration uses `engine`. Both terms appear in CLAUDE.md. Low severity — context disambiguates — but creates friction in new PR prompts.

3. **`phase_run` vs `PhasedRun`.** CLAUDE.md line 284 uses "phase_run" to mean an action, but the dataclass is `PhasedRun`. Minor naming confusion; no functional impact.

4. **`StorageBridge` is named in CLAUDE.md but not defined.** No formal spec of what it owns vs. what the routes layer owns. This was the site of the two-parallel-ID-systems bug (PR L). Critical seam with no architectural documentation.

5. **`RuleResult` protocol undocumented outside docstrings.** V1.7 rule authoring depends on understanding the 4-tuple return, `evidence_gap` semantics, and first-match-wins chain. No formal spec; engineers writing new rules rely on reading existing rules.

6. **`finding_id` determinism guarantee undocumented.** Seam tests verify it but no document specifies the hash algorithm, inputs, stability guarantee. If anyone touches `generate_finding_id()`, they won't know what they'd be breaking.

7. **`validation_pipeline` / `executor` / `correlator` terms appear in dormant-capabilities-inventory.md** but are not part of the current Conductor architecture. Risk of confusion about whether these are active components.

8. **`max_chain_depth` (config key in dict) vs `max_chain_depth` (keyword argument).** Glossary audit found the AST keyword search fails for the dict-key form. Documented in seam test with regex fallback. Not a bug; just unusual and worth noting for anyone writing new config-injection tests.

9. **`has_input` on next_actions vs SuggestionSpec.** operator_input_audit.md identifies that catalog-registered probes can't declare `has_input` statically — only probe-emitted next_actions carry it. Known gap; not a contradiction, but underdocumented.

10. **Evidence shape transition (flat list → typed dict).** Old DB records use flat `list[str]`; new records use `list[dict{path, status_code, ...}]`. Backward-compat guards in aggregations.py mitigate this but the transition period is not formally documented.

---

## Recommended further investigation

Before deciding restructure shape, architect should consider:

1. **Are the factory-era files (`ai-context/`, `AI_CONTEXT.md`) actively loaded by Claude Code sessions?** If they're auto-loaded as context, they're actively interfering with prompt accuracy. If they're only read when explicitly referenced, they're latent noise. Check which files are referenced in `.claude/` config and CLAUDE.md `## Documentation discipline` section.

2. **Is `docs/architecture/orchestration.md` kept current?** It was last modified 2026-05-24 (one day before this audit). Quick check: does it reflect PR K's FilterOrchestrator timing fix and PR L's finding_id fix? If it predates these PRs' resolution, it may have the same stale-timing sentence as CLAUDE.md.

3. **What is the intended audience for each doc tier?** CLAUDE.md is clearly Claude Code context. orchestration.md is engineer spec. But who are the ai-context/ files for? If they're Claude Code context, they compete with CLAUDE.md. If they're human-only reference, they could be archived rather than restructured.

4. **V1.7 live verification.** Eight of the 38 files contain architecture claims about V1.7 behavior (filtered findings, status badges, enumeration gaps panel). All are based on code inspection, not live runs since PR L. Before using any of these files as the basis for V2 design, confirm V1.7 behavior live. See PR K LIVE RE-VERIFICATION GATE in CLAUDE.md.

5. **Rule authoring guide gap.** Eight undocumented components were identified, but `RuleResult` and rule-chaining semantics are the most pressing gap for the next PR cycle. V1.7 has 19 rules; V2 will add more. Engineers writing new rules currently have no spec beyond reading existing code.

---

*Audit complete. Four reports in `/docs/_audit_md/`. Operator reviews. No files were modified.*
