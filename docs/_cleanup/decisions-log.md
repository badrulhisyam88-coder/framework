# Cleanup Decisions Log

---

## Session: orchestration.md stale-content patch — 2026-05-25

**Scope:** Patch only what Stage 1A audit (docs/_audit_md/architecture-claims.md) flagged as stale in docs/architecture/orchestration.md.

---

### Item 1: FilterOrchestrator timing ("after recon" vs "after enumeration")

**What I looked for:** Any occurrence of "after recon", "recon phase complete", or "FilterOrchestrator" in orchestration.md.

**What I found:** orchestration.md contains NO mention of FilterOrchestrator at all. The stale "runs after recon phase" claim lives in CLAUDE.md §Architecture line 84, not in orchestration.md.

**Action:** No change to orchestration.md for this item. The stale sentence is in CLAUDE.md and is out of scope for this task (task is scoped to orchestration.md only).

---

### Item 2: finding_id round-trip contract (underdocumented)

**What I looked for:** Any reference to the round-trip ID contract — that evt.id from generate_finding_id() must be explicitly passed as finding_id=evt.id to NormalizedFinding in _persist (routes.py), and that the default_factory uuid4() fallback breaks FilterOrchestrator UPDATEs.

**What I found:** orchestration.md references finding_id.py at lines 283 and 666 for dedup semantics, but contains no mention of the _persist layer, NormalizedFinding constructor, or the consequence of the uuid4() fallback. The critical round-trip contract was absent.

**Action:** Added one explanatory sentence block after the Dedup paragraph in the "Findings flow" section (after line 668 in the original). The addition reads:

> Finding IDs (fnd_xxx format from `generate_finding_id`) must be explicitly passed to `NormalizedFinding` as `finding_id=evt.id` in `_persist` (routes.py); the `default_factory` fallback is `uuid4()`, which breaks FilterOrchestrator UPDATEs (all WHERE clauses match 0 rows).

**Approximate line number in original:** 666–668 (Dedup paragraph). New text appended immediately after.

---

### Item 3: Rule chain count (17 rules vs 19 rules vs actual)

**What I looked for:** Any specific rule count mentioned in orchestration.md (e.g. "17 rules", "19 rules").

**What I found:** orchestration.md contains no specific rule count at all. The counts "17 rules" and "19 rules" appear only in CLAUDE.md PR H and PR K status lines, not in orchestration.md.

**Actual rule count (verified):**
- validate_rules.py: 7 classes
- drop_rules.py: 6 classes
- incomplete_rules.py: 6 classes
- reinvocation_rules.py: 8 classes
- Total: 27 rule classes

**Action:** No change. No rule count exists in orchestration.md to patch.

---

### Item 4: Any other stale claims flagged by the audit in orchestration.md specifically

**What I looked for:** STALE CLAIM 2 (CVE matcher), STALE CLAIM 3 (port_open), STALE CLAIM 4 (has_input field), CONTRADICTION 2 (max chain depth).

**What I found:**
- STALE CLAIM 2 (CVE matcher wired) — audit flagged this as a CLAUDE.md implication, not in orchestration.md. orchestration.md mentions "CVE chain" in the PR D+ row of the Implementation sequencing table as planned future work — this is accurate historical sequencing, not a live claim.
- STALE CLAIM 3 (port_open from nmap) — orchestration.md does not mention port_open finding type. No patch needed.
- STALE CLAIM 4 (has_input field) — audit marked this "ACCURATE (not stale, but a known limitation)". No patch needed.
- CONTRADICTION 2 (max chain depth 0 vs 5 vs 3) — audit resolved this as two different depth metrics, both correct. orchestration.md correctly documents linear depth capped at 5 and cycle detection at 3. No patch needed.

**Action:** No additional changes.

---

## Summary

| Item | Found in orchestration.md | Action |
|---|---|---|
| FilterOrchestrator timing (after recon vs after enumeration) | Not present — stale claim is in CLAUDE.md line 84 | No change |
| finding_id round-trip contract | Absent — only dedup semantics documented | Added one sentence block after Dedup paragraph in Findings flow section |
| Rule count | Not mentioned in orchestration.md | No change |
| Other stale claims from audit | None apply to orchestration.md | No change |

---

## Session: CLAUDE.md rewrite + archive moves — 2026-05-25

**Scope:** Operation 4 (CLAUDE.md rewrite) and Operation 5 (9-file archive).

---

### CLAUDE.md rewrite decisions

**Decision 1: FilterOrchestrator timing sentence**
- Old CLAUDE.md §Architecture line 84: "runs after recon phase"
- New CLAUDE.md Locked decisions: "FilterOrchestrator runs after enumeration phase (NOT recon)"
- Why: Code was fixed in PR K; the architecture description had not been updated. New locked-decision form is unambiguous.

**Decision 2: Lessons — compress vs drop**
- Considered: dropping lessons tied to fixed bugs (they're now in seams.md)
- Decision: compress all 21 to one-line form; keep all. Reason: one-line lessons serve as memory triggers. Seams.md has the detail; the lesson list is the index.
- Alternatives rejected: dropping lessons entirely (loses the institutional memory trigger), keeping verbose form (violates line target).
- See: /files/_removed_lessons.md

**Decision 3: PR delivery history — keep compressed vs remove**
- Considered: removing PR history entirely (just keep "current status" as one line)
- Decision: keep as one-line-per-PR table. Reason: operator and future Claude sessions need to know what landed and in what order. The history is not available elsewhere in compressed form (backup has it verbose; git log doesn't exist).

**Decision 4: Reference scenario — removed from CLAUDE.md**
- Old: CLAUDE.md had a full reference scenario table (~50 lines with stage-by-stage breakdown)
- Decision: moved to /docs/architecture/system.md §Reference scenario
- Why: scenario is architectural context, not operational protocol. CLAUDE.md should be an operational guide.

**Decision 5: Architecture section — removed from CLAUDE.md**
- Old: CLAUDE.md §Architecture was ~80 lines describing three-level hierarchy, orchestrators, design principles
- Decision: replaced with pointer to canonical docs in §Always read first
- Why: duplicated orchestration.md. CLAUDE.md must not be an architecture textbook.

**Decision 6: Gate registry — removed from CLAUDE.md**
- Old: CLAUDE.md §Gate registry was a full table (~30 lines)
- Decision: table now in /docs/architecture/system.md §Gate registry
- Why: single source of truth; gate table doesn't need to be in the operational guide

**Decision 7: Design notes for distant work — removed from CLAUDE.md**
- Old: ~200 lines of design notes covering V2.7+ RAG, wordlist pattern, evidence shapes, etc.
- Decision: distilled into Locked decisions section (single-line items) + canonical docs
- Why: not operational protocol; specific design notes belong in architecture docs or seams doc

**Decision 8: Audit log documented as not implemented**
- seams.md Subagent D finding: audit log (`orchestration_audit.jsonl`) is described in orchestration.md but has zero writers in apps/conductor/. seams.md now documents this explicitly as "not yet implemented."
- No CLAUDE.md change needed for this item; it's captured in seams.md.

---

### Archive moves decisions

**Decision 9: ai-context/ (7 files) — archive**
- Why: all 7 files describe AI-Factory-Base inheritance era (pre-V1.6 Conductor rewrite). Their content is superseded by CLAUDE.md + canonical docs. Kept at /files/_orphaned_md/ai-context/ not deleted.

**Decision 10: AI_CONTEXT.md — archive**
- Why: same era as ai-context/; factory inheritance narrative with obsolete module patterns.

**Decision 11: docs/audits/v1.6-recon-enum-audit.md — archive**
- Why: Stage 1A audit confirmed fully subsumed by v1_restructure_audit.md (broader, more comprehensive). Archived at /files/_orphaned_md/docs/audits/.

**Files considered for archive but KEPT:**
- docs/audits/dormant-capabilities-inventory.md — kept; canonical capability catalog, actively referenced
- docs/audits/v1_restructure_audit.md — kept; canonical 29-probe classification
- docs/audits/v1_execution_architecture_audit.md — kept; orthogonal (execution timing vs probe classification)
- README.md — kept; minimal stub but correct as public-facing entry point
