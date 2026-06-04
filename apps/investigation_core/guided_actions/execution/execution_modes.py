"""Execution mode context — determines how guidance is presented to the user.

NO code is executed here. This module purely determines presentation mode
and returns the appropriate display context for the template.
"""

from __future__ import annotations

from dataclasses import dataclass

from apps.investigation_core.guided_actions.models.action import ExecutionMode, GuidedAction


@dataclass
class ExecutionContext:
    """Template context for how to render a guided action's execution steps."""
    mode: ExecutionMode
    show_examples: bool           # Whether to show copy-paste examples
    show_expected_results: bool   # Whether to show expected outcome per step
    show_evidence_prompts: bool   # Whether to prompt evidence capture per step
    show_simulation: bool         # Whether to show simulated output panel
    preamble: str                 # Short description shown before steps


_MODE_PREAMBLE: dict[ExecutionMode, str] = {
    ExecutionMode.MANUAL_ONLY: (
        "This action is for self-guided testing. Follow the steps below at your own pace "
        "using your preferred tools. Document what you find in the evidence panel."
    ),
    ExecutionMode.GUIDED_MANUAL: (
        "Follow the steps below. Each step includes an example command or payload "
        "you can copy. Capture evidence when prompted."
    ),
    ExecutionMode.SIMULATED: (
        "This is a simulated walkthrough. The examples show what output you would expect "
        "to see during a real test. Use this to understand the technique before performing "
        "it in a live environment."
    ),
}


def get_execution_context(action: GuidedAction) -> ExecutionContext:
    mode = action.execution_mode
    return ExecutionContext(
        mode=mode,
        show_examples=mode in (ExecutionMode.GUIDED_MANUAL, ExecutionMode.SIMULATED),
        show_expected_results=True,
        show_evidence_prompts=mode != ExecutionMode.SIMULATED,
        show_simulation=mode == ExecutionMode.SIMULATED,
        preamble=_MODE_PREAMBLE.get(mode, ""),
    )
