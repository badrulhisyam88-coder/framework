"""PolicyEnforcer: the seam every Command passes through before executing.

Fails closed: a missing rule, an evaluation error, or a malformed result are
all treated as deny, never as allow (see docs/ARCHITECTURE.md, Policy).
"""

from __future__ import annotations

from dataclasses import dataclass

from framework_final.platform.module import ModuleBase
from framework_final.platform.policy import PolicyResult
from framework_final.platform.principal import Principal


@dataclass
class PolicyEnforcer:
    def evaluate(
        self, module: ModuleBase, principal: Principal, command_name: str, entity: object = None
    ) -> PolicyResult:
        rule = module.policy_rules().get(command_name)
        if rule is None:
            return PolicyResult.deny(f"no Policy rule declared for command '{command_name}'")
        try:
            result = rule(principal, command_name, entity)
        except Exception as exc:  # fail closed on any evaluation error
            return PolicyResult.deny(f"Policy rule raised {exc!r}")
        if not isinstance(result, PolicyResult):
            return PolicyResult.deny("Policy rule returned a non-PolicyResult value")
        return result
