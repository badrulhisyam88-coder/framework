"""Deterministic next-step unlock graph.

Maps progression events to the next investigation steps they unlock. Used by
the FeedBuilder to surface "Unlocked next:" hints after the user completes a
relevant action. No autonomous planning — just static rules.

Each key maps "trigger" → {next_actions, narrative}. A trigger is:
    action_completed:<action_id>

Phase 59a — milestone-keyed unlock rules and the `unlocks_for_milestone`
helper were removed alongside the milestone subsystem. The `next_milestones`
key on each rule was also removed since nothing emits MILESTONE_ACHIEVED
events anymore.
"""

from __future__ import annotations

UNLOCK_RULES: dict[str, dict[str, list[str] | str]] = {

    # ── SQL Injection progression ─────────────────────────────────────────
    "action_completed:sqli_injection_probe": {
        "next_actions":    ["sqli_boolean_confirmation", "sqli_auth_bypass"],
        "narrative":       "Injection point identified — confirm impact next.",
    },
    "action_completed:sqli_boolean_confirmation": {
        "next_actions":    ["sqli_version_extraction", "sqli_auth_bypass"],
        "narrative":       "Injection confirmed — move on to data extraction or auth bypass.",
    },
    "action_completed:sqli_auth_bypass": {
        "next_actions":    ["sqli_version_extraction"],
        "narrative":       "Authentication bypassed — explore the authenticated surface.",
    },
    "action_completed:sqli_version_extraction": {
        "next_actions":    [],
        "narrative":       "Database fingerprinted — document the extracted schema.",
    },

    # ── XSS progression ───────────────────────────────────────────────────
    "action_completed:xss_reflected_probe": {
        "next_actions":    ["xss_session_demonstration"],
        "narrative":       "Reflection confirmed — demonstrate session-context impact.",
    },
    "action_completed:xss_session_demonstration": {
        "next_actions":    [],
        "narrative":       "Same-origin script execution proven — document the impact chain.",
    },

    # ── Auth progression ──────────────────────────────────────────────────
    "action_completed:auth_default_credentials_probe": {
        "next_actions":    ["auth_session_inspection"],
        "narrative":       "Default credentials work — inspect the resulting session.",
    },
    "action_completed:auth_session_inspection": {
        "next_actions":    [],
        "narrative":       "Session inspected — record token handling weaknesses.",
    },

    # ── Hardening progression ─────────────────────────────────────────────
    "action_completed:security_headers_audit": {
        "next_actions":    ["info_disclosure_inspect"],
        "narrative":       "Header posture documented — sweep for information disclosure.",
    },
}


def unlocks_for_action_completed(action_id: str) -> dict[str, list[str] | str] | None:
    return UNLOCK_RULES.get(f"action_completed:{action_id}")
