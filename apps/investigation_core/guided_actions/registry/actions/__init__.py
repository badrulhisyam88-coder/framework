from apps.investigation_core.guided_actions.registry.actions.auth_actions import AUTH_ACTIONS
from apps.investigation_core.guided_actions.registry.actions.defensive_actions import (
    DEFENSIVE_ACTIONS,
)
from apps.investigation_core.guided_actions.registry.actions.hardening_actions import (
    HARDENING_ACTIONS,
)
from apps.investigation_core.guided_actions.registry.actions.sqli_actions import SQLI_ACTIONS
from apps.investigation_core.guided_actions.registry.actions.xss_actions import XSS_ACTIONS

ALL_ACTIONS = [
    *SQLI_ACTIONS, *XSS_ACTIONS, *AUTH_ACTIONS, *HARDENING_ACTIONS,
    *DEFENSIVE_ACTIONS,
]

__all__ = [
    "ALL_ACTIONS", "AUTH_ACTIONS", "DEFENSIVE_ACTIONS",
    "HARDENING_ACTIONS", "SQLI_ACTIONS", "XSS_ACTIONS",
]
