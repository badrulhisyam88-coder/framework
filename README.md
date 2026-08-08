# framework_final

An AI-native, domain-agnostic application platform. Applications change — Project Tracker,
Hospital, ERP, CRM, Inventory, HR, Booking, Asset Management, or anything else. The platform
does not.

Full architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Terminology:
[`docs/GLOSSARY.md`](docs/GLOSSARY.md). AI operating instructions:
[`docs/AGENTS.md`](docs/AGENTS.md). How architectural decisions are made, recorded, and kept
synchronized: [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md).

## Layout

```
src/framework_final/
  platform/     Meta-Model primitives (Entity, Principal, Event, Policy, Contract,
                Workflow, Capability, Module, Application) + the one-way dependency rule
  runtime/      boot, DI container, Command/Query dispatch, event bus, workflow (Saga)
                engine, policy enforcement
  registry/     declared source of truth, Concept Model, Validator, Generator
  discovery/    descriptive, disposable structural index of what code actually contains
  applications/ Application manifest loading

examples/       the ONE demonstration: a tiny Task module + a logging Capability +
                an Application composing them. Not part of the platform.
docs/           ARCHITECTURE.md, GLOSSARY.md, AGENTS.md
tests/          full test suite over the core mechanics
```

`platform/`, `runtime/`, `registry/`, `discovery/`, `applications/` are the platform.
Everything else is an example of using it.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Validate the Registry

```bash
.venv/bin/python -m framework_final.registry.validator examples
```

## Run tests

```bash
.venv/bin/python -m pytest
```

## Building a new Application

Say you've built out Project Tracker for a year, and now want to build Hospital instead.
Nothing in `platform/`, `runtime/`, `registry/`, or `discovery/` should need to change. The
process:

1. **Write new Modules.** Each is a folder with its own `registry.yaml` (id, owner, status,
   Contracts, Events, Policies, required Capabilities) and `concepts.yaml` (its own
   canonical business vocabulary — `Patient`, `Admission`, `Bed`, scoped to this
   Application, never global). A Module subclasses `framework_final.platform.module.ModuleBase`.
2. **Reuse existing Capabilities where they fit.** A generic Capability (logging,
   notification, search, workflow execution) doesn't care whether it's running under
   Project Tracker or Hospital — it's bound in through a Contract either way. Only write a
   *new* Capability when something is genuinely reusable across two or more real
   Applications; otherwise it belongs inside the Module that needs it.
3. **Compose a new `manifest.yaml`** declaring which Modules and Capabilities the Hospital
   Application uses.
4. **Run the Validator** (`registry/validator.py`) against the new Modules before writing any
   more code — it will catch ownership gaps, broken references, vocabulary collisions, and
   dependency-direction violations before they become a debugging problem later.
5. **Retire Project Tracker's Modules** (if you're replacing, not adding) by marking their
   Registry status `deprecated` → `removed`. Because Modules never depend on each other
   directly — only through published Contracts and Events — removing one is safe by
   construction: `RegistryStore.consumers_of_contract(...)` tells you exactly who would be
   affected *before* you delete anything, mechanically, without reading the whole
   repository.

If, partway through, you find yourself wanting to change something in `platform/` to make
Hospital work — stop. That's a signal the Platform's boundary was drawn wrong somewhere, not
a normal cost of adding a new Application. See `docs/ARCHITECTURE.md`.

Step 4 (the Validator) isn't the last step for a *permanent* decision — see
[`docs/GOVERNANCE.md`](docs/GOVERNANCE.md) for the Documentation Synchronization Policy and
Definition of Done that make "done" mean every derived artifact and document is current too, not
just that the code works.

## Lineage

This platform was extracted from two source repositories, neither copied wholesale — see
`docs/ARCHITECTURE.md`, "Lineage," for what was kept from each and why.
