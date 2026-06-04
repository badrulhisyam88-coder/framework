"""Investigation Branch Workspace — Phase 19.

Deterministic transformation of existing Phase 11–17 data (findings, actions,
evidence, milestones, themes, defensive snapshots) into a branch-oriented
graph view. NO new "intelligence" — only a re-shaping of data the user has
already produced.

The branch model represents investigation causality:

    target
      └── surface discovery
            └── finding (discovery node)
                  ├── guided action (validation node)
                  │     └── evidence (capture node)
                  │           └── milestone (objective node)
                  └── theme overlay (root cause)
                        └── remediation step

Each node carries an explicit `why` field so the operator can always ask
"why is this branch showing this state?".
"""
from __future__ import annotations

from apps.investigation_workspace.branch.model import (
    BranchNode,
    BranchState,
    CausalEdge,
    InvestigationBranch,
    NodeKind,
    StorylineEntry,
)

__all__ = [
    "BranchNode",
    "BranchState",
    "CausalEdge",
    "InvestigationBranch",
    "NodeKind",
    "StorylineEntry",
]
