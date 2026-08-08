# Governance

This document defines how architectural decisions are made, recorded, and kept synchronized
across every Application built on `framework_final`. It applies equally to every future
Application — nothing here is specific to any one project's business domain. See
`docs/ARCHITECTURE.md` for the Meta-Model itself and `docs/GLOSSARY.md` for terminology; this
document is about *process*, not primitives, and introduces no new architectural concept.

This document was added after a real gap surfaced while building an Application on this
platform: architectural changes were being implemented and tested, but the derived artifacts and
documentation describing them were left to be resynchronized "later" — an implicit, unenforced
expectation rather than a stated one. Nothing about the underlying mechanism was missing (the
Validator already checks for exactly this — see `generated_artifact_drift` below); what was
missing was the policy declaring that skipping this step means a change isn't finished.

## Architecture Lifecycle

Every architectural change moves through the same four stages, regardless of which Application
it happens in:

1. **Propose** — a change to a Contract, Event, Module boundary, Capability, or (rarely) the
   Meta-Model itself is proposed, with its reasoning.
2. **Decide** — the proposal is accepted, rejected, or superseded. A **permanent** decision (one
   that other code, documentation, or future decisions will depend on) is recorded — see
   Architecture Decision Workflow, below. A **routine** change (an ordinary in-Module edit that
   crosses no boundary) does not need this ceremony — see `docs/ARCHITECTURE.md`'s existing
   guidance on when Contract-level ceremony is and isn't warranted.
3. **Implement** — the code changes.
4. **Synchronize** — every derived artifact affected by the decision is regenerated, and every
   document that described the old state is updated.

A change is not complete until stage 4 finishes. Treating "the code works" and "the change is
done" as the same moment is the gap this document closes.

## Documentation Synchronization Policy

**When a permanent architectural decision changes, every affected artifact must be
resynchronized before the task is considered complete.** This applies uniformly to:

- Generated artifacts (dependency graphs, AI context bundles, reference documentation — anything
  produced by a Generator)
- Human-authored documentation that described the old state
- The architecture decision record itself (a new entry, or an existing entry marked Superseded)

A change that updates code but leaves any of these stale is incomplete, not finished with
follow-up work pending. This is deliberately a *policy*, not new enforcement code: the mechanism
that makes it checkable already exists (Validator check `generated_artifact_drift`, see
`registry/validator.py`), regenerating a stale artifact is already one Generator call, and the
record-keeping mechanism is the Architecture Decision Workflow below. Nothing here required a
framework code change — it required stating the expectation explicitly.

## Definition of Done for Architectural Work

A permanent architectural change is done when, and only when:

- [ ] The code change is implemented and tested.
- [ ] Registry (`registry.yaml` / `manifest.yaml`, and any Application-level conventions layered
      on top, as applicable) reflects the new state.
- [ ] The Validator passes with zero findings, including `generated_artifact_drift`.
- [ ] Every Generator output affected by the change has been regenerated and committed.
- [ ] Any human-authored documentation describing the old state has been updated.
- [ ] A permanent decision has a recorded entry — new, or an existing one marked Superseded (see
      Architecture Decision Workflow).

If any box is unchecked, the change is in progress, not finished — regardless of whether the code
itself works correctly.

## Registry as the Architectural Source of Truth

Unchanged from `docs/ARCHITECTURE.md` and `docs/GLOSSARY.md`: Registry is the declared,
human-approved source of truth for what exists. This document adds nothing to that definition —
it makes explicit that *staying* the source of truth is an ongoing obligation, not a one-time
property established at authoring time. A Registry that no longer matches observed reality
(caught by `module_boundary_conformance`) or no longer matches its own derived artifacts (caught
by `generated_artifact_drift`) has stopped being trustworthy, even though the checks that would
catch it already exist and already run.

## Generated Artifacts Lifecycle

Registry (declared) and Discovery Index (observed — this role has historically also been referred
to by one specific implementation's product name; see `docs/GLOSSARY.md`'s retired-terms table)
are Generator's two inputs. Generator produces every derived artifact from them — today, the
dependency graph, AI context bundles, and reference documentation; permission graphs, routing
tables, and other artifact types are named in the spec but not yet built (see
`docs/ARCHITECTURE.md`).

```
Registry (declared)         --\
                                >---  Generator  --->  Dependency Graph
Discovery Index (observed)  --/                 --->  AI Context Bundles
                                                 --->  Reference Documentation
```

Every output of this pipeline is **derived** and carries **zero authority** (see
`docs/GLOSSARY.md`'s source-of-truth taxonomy). If any output ever disagrees with Registry,
Registry wins, and the disagreement is drift to fix — never evidence to trust over Registry. This
was already true by design; this document makes it an explicit, checked part of *finishing* a
change, not just a background invariant nobody is responsible for maintaining.

## Architecture Decision Workflow

A **permanent** architectural decision — one that changes a Contract's shape, a Module's
boundary, a Capability's responsibility, or (rarely) the Meta-Model itself — gets a recorded
entry using the template at `docs/adr/TEMPLATE.md`. Copy it into your Application's own decision
log (a `docs/decisions/` directory is the suggested convention; `framework_final` does not
prescribe exactly where — that choice belongs to each Application) and fill it in completely.

An entry is never deleted. A decision that gets replaced earns a *new* entry, and the old one is
marked `Status: Superseded`, pointing at the new entry's ID — the same non-destructive pattern
Registry itself already uses for deprecating a Contract or Concept (a new version, never a silent
overwrite).

Routine, in-Module changes that cross no Contract/Capability/Meta-Model boundary do not need a
decision entry — recording every line of code as a "decision" would drown the permanent decisions
that actually matter. The test: would a different Module, Capability, or Application need to know
this decision happened? If yes, record it.

*(This template's shape — ID / Status / Decision / Context / Consequences / Supersedes — traces
to a pattern identified as genuinely reusable during this platform's own design research, in an
earlier template repository's `DECISIONS.md`. It's adopted here in full, generalized, and given
an enforceable home in the Architecture Lifecycle above, rather than left as an unused,
never-applied template.)*

## Validation Workflow

Architectural validation (`registry/validator.py`, run via `python -m
framework_final.registry.validator <roots>`) already checks Registry–Discovery Index consistency
and generated-artifact freshness as two of its ten checks. This document does not add a new
Validator check — it extends what "validation passing" is understood to mean for a *permanent*
change: a green Validator run confirms the code and Registry are internally consistent; the
Definition of Done above confirms the surrounding documentation and decision record are too. Both
are required for a permanent change to be complete; previously, only the first was checked
mechanically.
