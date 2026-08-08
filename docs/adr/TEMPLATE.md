# Architecture Decision Record Template

Copy this file into your Application's own decision log for every **permanent** architectural
decision (see `docs/GOVERNANCE.md`, Architecture Decision Workflow, for what qualifies). Fill in
every field; leave nothing as a placeholder in a committed entry. Name the copied file with the
entry's own ID, e.g. `0001-short-slug.md`.

---

**ID:** `<application-scope>-<sequential-number>` (e.g. `myapp-0001`)

**Status:** Proposed | Accepted | Superseded

**Date:** YYYY-MM-DD

**Decision**

One or two sentences. State what was decided as a fact, not as a discussion.

**Context**

What prompted this. The constraint, requirement, or problem that made a decision necessary.

**Consequences**

What this decision commits future work to, and what it rules out. Be concrete about the
trade-off, not just the upside.

**Supersedes:** `<ID of a prior entry this replaces>` or `None`

**Superseded by:** `<ID of a later entry that replaced this one>` or `None` — filled in later,
never at authoring time.

---
