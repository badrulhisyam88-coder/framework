"""Adaptive guidance — deterministic translation of memory into UI hints.

This package consumes InvestigationMemory snapshots and emits:
  - AdaptiveInsight entries surfaced as feed items / banners
  - Adaptive unlock-rule filtering (suppress beginner steps for advanced users)
  - Per-finding reinforcement chips

Everything here is pure-function over a memory snapshot. No DB access.
"""

from apps.investigation_workspace.adaptive.guidance import (
    adapt_unlock_hint,
    reinforcement_chips_for_finding,
)
from apps.investigation_workspace.adaptive.insights import (
    generate_insights,
)

__all__ = [
    "adapt_unlock_hint",
    "generate_insights",
    "reinforcement_chips_for_finding",
]
