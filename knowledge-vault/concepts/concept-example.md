---
id: CONCEPT-EXAMPLE
title: Example Concept (replace with your domain title)
priority: 50
finding_types:
  - example_event          # replace: finding_type strings that trigger this concept
state_changes:
  - example_state_reached  # replace: fact labels added to agent_state.facts on success
artifacts_captured:
  credentials: []          # replace: artifacts stored in agent_state.artifacts buckets
unlocks:
  - concept: CONCEPT-EXAMPLE  # replace: concept_ids queued into agent_state.pending
    priority: 40
leaf_type: terminal          # "terminal" | "can_be_blocked" | "unknown"
keywords:
  - example                  # replace: keywords used by vault semantic search
---

# Example Concept

> **Framework reference** — Replace all content below with your domain knowledge.
> This file documents the frontmatter contract. Every field is required unless
> marked optional. See docs/productization/layer-contracts.md §5.2 for the
> GraphResolver contract that reads these files.

## What this technique does

Describe what the technique achieves in one paragraph. The planner uses this
description when surfacing concepts to the operator.

## When to use

Describe the conditions under which this technique applies. The GraphResolver
checks `finding_types` to select applicable concepts; this prose explains the
reasoning to the operator.

## Required preconditions

List any preconditions that must be satisfied before this technique can run.
If position-based (e.g. requires authentication), declare them in
`apps/conductor/planner.py::_CONCEPT_PRECONDITIONS`.

## Expected outcomes

Describe success and failure cases. On success, what artifacts are captured?
What state changes occur? What does `leaf_type: terminal` mean for this concept?

## Engine mapping

Map this concept to an engine in `apps/conductor/constants.py::CONCEPT_ENGINE_MAP`:

```python
CONCEPT_ENGINE_MAP = {
    "CONCEPT-EXAMPLE": "example_event",  # engine_id registered in engine_registry
}
```

## Frontmatter field reference

| Field | Type | Purpose |
|---|---|---|
| `id` | string | Canonical CONCEPT-* identifier. Used as primary key in CONCEPT_ENGINE_MAP. |
| `title` | string | Human-readable technique name shown in operator UI. |
| `priority` | int (0–100) | Planner ranking weight. Higher = selected earlier. |
| `finding_types` | list[str] | Finding types that trigger this concept via GraphResolver. |
| `state_changes` | list[str] | Fact labels added to agent_state.facts on execution success. |
| `artifacts_captured` | dict | Artifact buckets populated on success (credentials, sessions, tokens, files). |
| `unlocks` | list[{concept, priority}] | Concepts queued into pending after this one succeeds. |
| `leaf_type` | string | `terminal` = branch ends here. `can_be_blocked` = stem engines tried on exhaustion. |
| `keywords` | list[str] | Semantic search terms for vault embedding pipeline. |
