# AI Operating Manual

This is the entry point for any AI agent working in this repository. Read this before
reading anything else.

## Sources of truth, in priority order

1. **User instruction** — explicit direction always wins.
2. **`registry/` (Registry)** — the declared, human-approved source of truth for what
   Modules/Capabilities/Contracts/Events/Applications/Concepts exist.
3. **Discovery Index** (`discovery/index.py`, run against the relevant folder) — what
   actually exists in code, right now.
4. **Source code** itself, scoped to exactly the files Registry + Discovery Index point you to.
5. **`docs/ARCHITECTURE.md` and `docs/GLOSSARY.md`** — narrative context and canonical terms.

If two of these disagree, the higher one wins, and the disagreement itself is worth
flagging as drift (`registry/validator.py`, generated-artifact drift check) rather than
silently picking one.

## The workflow for any change

You should never need to scan this whole repository. Every step below is a lookup, not a
search:

1. **Locate.** Resolve the request to a canonical term via each Module's `concepts.yaml`
   (the Concept Model), then to the owning Module via `registry/store.py`'s aggregated
   Registry.
2. **Scope.** Pull that Module's Registry entry: owner, published/consumed Contracts,
   published/subscribed Events, required Capabilities, status.
3. **Impact.** Query `RegistryStore.consumers_of_contract(...)` /
   `consumers_of_event(...)` for anything this Module publishes — the blast radius, known
   *before* you touch anything.
4. **Fetch.** Use `registry/generators/ai_context.py` to get one bundle answering steps 1–3
   already, plus the exact file scope (`discovery/index.py`'s scan of that Module's own
   folder). Read only those files, plus the *public* Contract definitions of anything
   directly, declaratively consumed.
5. **Change.** Implement inside the Module's own folder. If the change touches a *published*
   Contract, that's a new Contract version (`major_version` bump) with a deprecation window
   for the old one — never a silent in-place edit.
6. **Validate.** Run `registry/validator.py` (`python -m framework_final.registry.validator
   <roots>`). All ten checks must pass. Also re-run the relevant tests in `/tests`.
7. **Register.** If you introduced a new Entity/Contract/Event/Capability dependency, update
   the owning `registry.yaml`/`concepts.yaml` explicitly. Small, purely in-Module changes
   don't need this ceremony — Registry ceremony is reserved for boundary crossings.

## What you must never do

- Never import a concrete Module or Capability from a sibling example/Application directly.
  Cross-boundary communication is a Contract, resolved by `runtime/container.py`, always.
- Never put business vocabulary in `platform/`. If you're tempted to, the thing you're
  building is a Module or a Capability, not a Platform change.
- Never let a Capability own a Concept Model entry. Capabilities are domain-agnostic by
  definition.
- Never hand-edit anything under a generated-output directory. Regenerate it instead — see
  `registry/generators/`.
- Never treat a generated artifact (dependency graph, AI context bundle, documentation) as
  authoritative over Registry. It has zero authority by design.

## Which files you should never need to open

- Another Module's private implementation files (only its `registry.yaml`-declared
  Contracts/Events are visible to you).
- A Capability's internals beyond its published Contract.
- `platform/` internals, unless the task explicitly is a Platform-level change (rare, and
  should clear a much higher bar than an ordinary Module change — see
  `docs/ARCHITECTURE.md`).
- Any other Application's Modules entirely, unless the task explicitly spans Applications.

## Adding a new Application

See the root `README.md`, "Building a new Application," for the concrete Hospital-instead-
of-Project-Tracker walkthrough. In short: nothing in `platform/`, `runtime/`, `registry/`,
or `discovery/` should ever need to change. You add a new Application by writing new
Modules (and, only when genuinely reusable across ≥2 Applications, a new Capability),
registering them, and composing them in a new `manifest.yaml`.
