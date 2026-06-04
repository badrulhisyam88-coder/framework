"""Investigation bootstrap orchestration.

When the operator opens the workspace for an investigation that has no
findings yet, the topology is not empty. The bootstrap runtime drives a
real passive HTTP probe (apps/investigation_workspace/probe/) against
the target and translates its event stream into topology nodes:

    StageEvent  → reasoning node (actions / tools / detected / confidence)
    FindingEvent → real NormalizedFinding insert with probe evidence

Phase 40 introduced this with canned scripts. Phase 44 rewired it to a
real probe — findings now exist only when the probe actually observes
the corresponding condition in the live response.

Deterministic. No LLM. The probe is real but the event vocabulary and
ordering are pure functions of the response.
"""
