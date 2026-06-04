"""Auth guided actions."""

from apps.investigation_core.guided_actions.models.action import (
    ExecutionMode,
    GuidedAction,
    GuidedActionStep,
    RiskLevel,
)

AUTH_ACTIONS = [
    GuidedAction(
        action_id="auth_default_cred_test",
        finding_type="auth_bypass",
        finding_types=[
            "auth_bypass",
            "weak_credentials",
            "default_credentials",
            "ssh_cred",
            "credential_exposure",
        ],
        title="Default Credential Test",
        explanation=(
            "Test the target service against a curated list of vendor default "
            "and commonly-reused credential pairs. Stop immediately on first success "
            "and document the exact pair found."
        ),
        why_this_matters=(
            "Default credentials are the most common reason networked services are "
            "compromised. A successful match gives an attacker immediate authenticated "
            "access with no further exploitation required."
        ),
        required_skills=[],
        expected_evidence=(
            "The credential pair that succeeded (username + password) and "
            "evidence of the authenticated session (screenshot of logged-in state "
            "or HTTP 200 response with session cookie)."
        ),
        approval_required=True,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.MEDIUM,
        related_learning_path="auth_beginner_01",
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction=(
                    "Identify the authentication mechanism: web form (POST), "
                    "HTTP Basic auth, SSH, FTP, or other protocol."
                ),
                expected_result="Authentication method and endpoint documented.",
            ),
            GuidedActionStep(
                step_number=2,
                instruction=(
                    "Test the following credential pairs in order. Stop at first success."
                ),
                example=(
                    "admin / admin\n"
                    "admin / password\n"
                    "admin / (empty)\n"
                    "root / root\n"
                    "root / (empty)\n"
                    "admin / 1234\n"
                    "guest / guest"
                ),
                expected_result="One pair succeeds (200/authenticated) or all fail.",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=3,
                instruction=(
                    "If a pair succeeded: capture a screenshot of the authenticated "
                    "state and log the exact credentials. Do not take any further "
                    "action with the session."
                ),
                expected_result="Evidence of successful authentication documented.",
                capture_evidence=True,
            ),
        ],
        preconditions=[
            "Authentication service accessible on the network.",
            "No account lockout policy that would block testing (check first).",
        ],
        outcome_indicators=[
            "HTTP 200 / redirect to authenticated page on web targets.",
            "SSH session established on SSH targets.",
            "FTP 230 Login successful on FTP targets.",
        ],
        remediation_context=(
            "Default credentials give immediate full access. "
            "Remediation: change all default credentials during initial setup. "
            "Enforce password complexity policy. Implement account lockout. "
            "Rotate credentials immediately if defaults found in production."
        ),
    ),
    GuidedAction(
        action_id="auth_session_analysis",
        finding_type="auth_bypass",
        finding_types=[
            "auth_bypass",
            "weak_credentials",
            "cleartext_transmission",
            "credential_exposure",
        ],
        title="Session Token Security Analysis",
        explanation=(
            "Inspect the session token issued after authentication: transport security "
            "(HTTPS/HTTP), cookie flags (Secure, HttpOnly, SameSite), token entropy, "
            "and whether tokens appear in URLs or server logs."
        ),
        why_this_matters=(
            "A strong password is worthless if the session token can be stolen in transit "
            "or via script. Session token weaknesses convert an authentication "
            "finding into a one-step attack for any user who logs in."
        ),
        required_skills=["Valid test credentials (any account)."],
        expected_evidence=(
            "Browser DevTools Network tab screenshot showing the Set-Cookie header "
            "with flags noted. Record: Secure present (yes/no), HttpOnly (yes/no), "
            "SameSite value, token length."
        ),
        approval_required=True,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.INFORMATIONAL,
        related_learning_path="auth_beginner_01",
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction=(
                    "Log in with any valid test account. Open Browser DevTools "
                    "(F12) → Network tab → find the login response."
                ),
                expected_result="Login response visible in DevTools Network tab.",
            ),
            GuidedActionStep(
                step_number=2,
                instruction=(
                    "In the response Headers, locate the Set-Cookie header. "
                    "Note all attributes."
                ),
                example="Set-Cookie: session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict",
                expected_result="Cookie flags recorded.",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=3,
                instruction=(
                    "Check the page URL — does the session token appear in the URL? "
                    "Check whether the connection is HTTP or HTTPS."
                ),
                expected_result=(
                    "Transport noted (HTTP/HTTPS). Token-in-URL finding noted if present."
                ),
                capture_evidence=True,
            ),
        ],
        preconditions=[
            "Access to the application login page.",
            "Any valid test account credentials.",
        ],
        outcome_indicators=[
            "Secure flag absent → token sent over HTTP = stolen in transit.",
            "HttpOnly absent → token accessible via document.cookie = XSS theft.",
            "Token in URL → logged in server access logs = log exposure.",
        ],
        remediation_context=(
            "Session weaknesses allow token theft without exploiting "
            "the auth mechanism itself. Remediation: enforce HTTPS via HSTS, "
            "set Secure and HttpOnly on all session cookies, use SameSite=Strict, "
            "never include session tokens in URLs."
        ),
    ),
]
