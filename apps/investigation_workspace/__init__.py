"""Investigation Workspace — cross-context aggregation layer.

This module owns workspace composition and HTMX partial routing.
It aggregates reads from bounded contexts:
  - apps/scanner_orchestration/ (orchestration, findings, runs)
  - apps/investigation_core/    (lifecycle, evidence, mastery)

It does NOT:
  - own persistence
  - contain business logic
  - modify bounded-context data

All writes still go through the owning bounded context's API.
"""
