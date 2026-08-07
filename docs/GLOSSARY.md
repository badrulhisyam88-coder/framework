# Architecture Glossary

Single source of truth for terminology. Concise, precise, implementation-independent.
If a definition here ever conflicts with code behavior, this document is describing
intent — file it as drift (see `registry/validator.py`, check #8), don't just trust
whichever one you read first.

| Term | Definition | Layer |
|---|---|---|
| **Entity** | A thing with durable identity and state | Meta-Model |
| **Principal** | An identity that can be authenticated and authorized to invoke a Command | Meta-Model |
| **Event** | An immutable statement that something has already happened | Meta-Model |
| **Policy** | A rule governing whether a Principal may invoke a Command against an Entity | Meta-Model |
| **Contract** | A versioned, governed interface at a boundary; kind is Command (write) or Query (read) | Meta-Model |
| **Workflow** | The sanctioned mechanism for a process to span multiple Modules with retry/compensation semantics (Saga-grounded) | Meta-Model |
| **Capability** | A reusable, domain-agnostic, swappable service, invoked only via its Contract | Capability |
| **Module** | A bounded unit of domain logic; exactly one bounded context | Module |
| **Application** | A named composition of Modules and Capabilities for one business purpose | Application |
| **Platform** | The meta-model, the one-way dependency rule, and the seams that make them operable | Platform |
| **Registry** | The declared, human-approved source of truth for everything intended to exist | Registry |
| **Concept Model** | The canonical, scoped naming layer for business vocabulary | Registry |
| **Validator** | The gate that checks a Registry change's consistency before anything downstream proceeds | Registry |
| **Generator** | An independent process producing one derived, read-only artifact from Registry + Discovery Index | Registry |
| **Runtime** | The operating system that loads, wires, and executes what Registry declares | Runtime |
| **Discovery Index** | A descriptive, disposable, regenerable index of what actually exists in code | Discovery Index |

## Retired terms

Do not reuse these. If you encounter them in older material, translate as follows:

| Retired | Replaced by |
|---|---|
| Vocabulary | Meta-Model (universal types) / Concept Model (business terms) |
| Graphify | Discovery Index (role) — "Graphify" may still name a specific *implementation*, never the architecture concept |
| Actor | Principal |
| Action | Contract (Command kind) |
| View | Contract (Query kind) |
| Permission | Policy (its resolved decision output) |
| Identity | A property of Entity/Principal, not a standalone term |
| Relationship (as a primitive) | A property of Entity, or a join Entity |
| Context (as distinct from Module) | Module |
| Capability Concepts | Retired outright — Capabilities have Contracts, never Concepts (they are domain-agnostic by definition and have no business vocabulary to canonicalize) |
| "Architecture Compiler" | Validator + Generator |

## The nine Meta-Model primitives — why each exists, why nothing else made the cut

| # | Primitive | Why it exists |
|---|---|---|
| 1 | Entity | Every domain has durable, identified things — one primitive for "a thing with state," not per-domain variants |
| 2 | Principal | Every domain needs an identity concept Policy can evaluate, independent of who specifically is calling |
| 3 | Event | The only mechanism that lets Modules stay decoupled while still communicating what happened |
| 4 | Policy | One enforcement point for "is this allowed," not one invented per Module |
| 5 | Contract | The only sanctioned shape for a boundary crossing — read (Query) and write (Command) as one governed artifact |
| 6 | Workflow | The one sanctioned exception to "Modules never coordinate directly" — some processes span Modules and need retry/compensation semantics |
| 7 | Capability | Lets cross-cutting functionality be built once and reused across every Application |
| 8 | Module | Lets business logic for one domain be added or removed without touching anything else |
| 9 | Application | Lets the same Platform serve completely different businesses by composing different Modules |

Rejected candidates, and why: **Identity** (a property of Entity/Principal, not its own primitive) ·
**Action** (a Contract whose kind is Command) · **View** (a Contract whose kind is Query) ·
**Permission** (the resolved output of a Policy evaluation) · **Relationship** (a property of Entity,
or a join Entity if it needs its own lifecycle) · **Context** (forced 1:1 with Module by design rule) ·
**Platform** (not a primitive within its own Meta-Model — it's the substrate that hosts the Meta-Model,
not something a Module instantiates).

## Source-of-truth taxonomy

Every artifact belongs to exactly one category:

1. **Human-authored (intent)** — new Platform concepts, new Capability contracts, canonical vocabulary
   decisions, ADR/decision log entries. Highest authority.
2. **Declared (Registry)** — Module/Capability/Contract/Event/Policy/Concept entries. Authoritative for
   *intent*, cross-checked against Discovery Index to confirm it's real.
3. **Derived (Generated)** — dependency graphs, AI context bundles, documentation, impact-analysis
   reports, the Discovery Index itself. **Zero authority.** If it disagrees with Registry, Registry wins.
4. **Runtime-only (operational)** — live Principal sessions, in-flight Workflow instances, event-bus
   logs. No architectural authority; never persisted as Registry.
5. **Temporary (working state)** — an in-progress draft of a Registry change. Doesn't exist for anyone
   else until promoted.
