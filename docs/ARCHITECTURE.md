# Architecture

This document is the condensed, canonical spec. See `docs/GLOSSARY.md` for term-by-term
definitions and `docs/AGENTS.md` for how an AI agent should use all of this in practice.

## What this is

`framework_final` is an AI-native, domain-agnostic application platform. **Project Tracker,
Hospital, ERP, CRM, Inventory, HR, Booking, Asset Management — none of these are the
platform. They are Applications built on top of it.** The platform must never change to
ship one of them; if it does, the platform's boundary was drawn wrong.

The one demonstration Application (`/examples`) is a tiny Task tracker — deliberately not
Project Tracker, and deliberately not the security-investigation domain this platform's
implementation lineage came from (see "Lineage" below). It exists only to prove the stack
works end to end; it is not part of the platform and carries no special status.

## The one-way dependency rule

```
Application -> Module -> Capability -> Platform
```

Nothing points upward. A Capability must never import a Module. A Module must never import
another Module. This is enforced mechanically, not just documented — see
`platform/dependency_rules.py` and `registry/validator.py` check #4. Two different things
are checked:

- The framework's own internal packages (`platform/`, `runtime/`, `registry/`, `discovery/`,
  `applications/`) — infrastructure, allowed to consult Registry and Discovery Index.
- Concrete example content under `/examples` — the stricter, more important check. A
  concrete Module or Capability must never import a sibling example directly; cross-boundary
  communication only ever happens through a Contract, resolved at runtime by
  `runtime/container.py`. This is the check that proves the rule holds for real business
  implementations, not just the framework's own plumbing.

Modules default to **Event-based** coupling with each other (subscribe, never know who's
listening). A synchronous Contract call between Modules is the deliberate exception, used
only when eventual consistency is genuinely unacceptable for that one interaction.

## Why Capability, Module, and Application are both a *type* and a *layer*

Platform defines the behavioral contract every Capability/Module must satisfy
(`platform/capability.py`'s `CapabilityBase`, `platform/module.py`'s `ModuleBase`) — this is
why those base classes live in `platform/` rather than in their own framework packages:
Runtime needs to reference them to orchestrate anything at all, and Platform is precisely
"the definitions of every Meta-Model primitive... and the mechanisms that make them
operable." There is no separate `capabilities/` or `modules/` package in this repo for that
reason — it would be empty, and an empty package with no responsibility is exactly the kind
of folder bloat this platform is designed to avoid.

The *layer* — where concrete implementations actually live — is realized in `/examples` for
this repo, and would be realized in a real deployment's own Application-specific location.
The type and the layer are two different questions ("what must a Module implement" vs.
"where do concrete Modules live"), and conflating them was an early design mistake this
build corrected once the dependency-rule checker itself caught the resulting import cycle.

## Registry, Runtime, Discovery Index, Platform — four responsibilities that never overlap

| Layer | Role | Analogy |
|---|---|---|
| Platform | Defines what a Module/Capability/Contract/etc. *are*, and the one-way dependency rule | The constitution |
| Registry | Declares what's *intended* to exist — Modules, Contracts, Events, ownership, versions | The census |
| Runtime | *Executes* the Registry's declarations — loads, wires, dispatches, enforces | The government enacting law |
| Discovery Index | *Observes* what actually exists in code right now — descriptive, disposable | The surveyor confirming what's really built |

Registry data is **distributed, not centralized**: each Module/Capability/Application owns
its own `registry.yaml` (or `manifest.yaml`), colocated with its code. `registry/store.py`
discovers and aggregates them via a known glob — never an unbounded repository scan. This is
what keeps "AI only reads the relevant folder" true in practice; a single giant registry
file would itself violate the platform's own goal.

## Why there is no "Architecture Compiler"

An earlier proposal considered a single monolithic "Architecture Compiler" component. That
name and shape were rejected: it would have combined validation, generation, and (if scope
crept, as these things do) code emission into one component — exactly the kind of
multi-responsibility layer this platform's own rules forbid everywhere else. Instead:

- **Validator** (`registry/validator.py`) checks every proposed Registry change for internal
  consistency *before* anything downstream happens. It never generates and never edits — it
  only reports Findings.
- **Generator** (`registry/generators/`) is a *family* of independent processes, one per
  derived artifact (dependency graph, AI context bundle, reference documentation — three are
  implemented; permission graphs, routing tables, and on-demand impact analysis are named in
  the spec but not built in this pass). Each reads only Registry + Discovery Index and
  produces one deterministic, disposable output. None depend on each other.

Neither is a new peer to Platform/Runtime/Registry/Discovery-Index. Both are tooling that
operates *on* Registry.

## The ten Validator checks

Ownership completeness · Referential integrity · Circular dependency detection · Dependency
direction conformance · Vocabulary conformance · Contract compatibility · Module boundary
conformance (declared footprint vs. Discovery Index's observed scan) · Generated-artifact
drift · Application composition validity · Policy coverage. Every check is fail-closed: an
ambiguous or missing declaration is a violation, not a silent pass. See `registry/validator.py`
for the implementation of each.

## Concept Model

Business/domain vocabulary belongs **only to Modules**, and is scoped **per Application**
(never global — "Customer," "Patient," and "Student" are different concepts even if they're
structurally similar, and forcing them into one universal term destroys domain clarity
without adding anything). Capabilities never own Concept Model entries: they are
domain-agnostic by definition and have no business vocabulary to canonicalize — this is
enforced by `registry/validator.py`'s vocabulary conformance check, not just documented.

A Concept has a permanent, namespace-qualified **id**, separate from its human-readable
**label** (the label may be relabeled freely; the id never changes). Exactly three
relationship types are allowed — `specializes`, `references`, `supersedes` — deliberately
not an open-ended ontology graph. See `registry/concept_model.py`.

## Lineage

Built from two sources, neither copied wholesale:

- **`framework-core`** (the security-investigation/pentest-training platform this repo's
  implementation lineage traces to): almost nothing was reusable as literal code — it's
  overwhelmingly domain-specific. What carried forward was *pattern*: the 3-level
  Conductor→Orchestrator→Engine discipline generalizes into `runtime/dispatcher.py`'s
  Command pipeline; the fail-closed security default generalizes into `Policy`'s
  default-deny; the regression-test-per-boundary discipline generalizes into this repo's own
  test suite; and the negative lesson of **seven independent ad-hoc registries** is exactly
  why this platform has one unified Registry mechanism instead.
- **`AI_Framework_Template_v4.1`**: contributed process, not folders — the sources-of-truth
  hierarchy and canonical-vocabulary discipline that became `docs/AGENTS.md` and the Concept
  Model, and Graphify's own stated charter ("descriptive, not prescriptive") which became
  Discovery Index's charter, renamed specifically to stop coupling the architecture to one
  tool's brand name.
