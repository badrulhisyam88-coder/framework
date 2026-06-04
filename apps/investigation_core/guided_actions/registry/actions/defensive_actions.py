"""Defensive verification actions — prove that mitigations are actually deployed.

Each action mirrors the offensive guided-action shape but flips the orientation:
verify the fix landed rather than demonstrate the vulnerability. They surface
under a separate "Defensive verification" header on finding entries.

NO autonomous patching. Each action lists manual verification steps; the user
executes them and captures evidence.
"""

from apps.investigation_core.guided_actions.models.action import (
    ExecutionMode,
    GuidedAction,
    GuidedActionStep,
    RiskLevel,
)

DEFENSIVE_ACTIONS = [

    GuidedAction(
        action_id="verify_csp_policy",
        finding_type="security_misconfiguration",
        finding_types=["security_misconfiguration", "information_disclosure"],
        title="Verify Content-Security-Policy is deployed",
        explanation=(
            "Confirm the target now sends a Content-Security-Policy response "
            "header that constrains script sources, frame ancestors, and inline "
            "script execution."
        ),
        why_this_matters=(
            "CSP is the strongest defence-in-depth control against reflected/"
            "stored XSS. Verification proves the deployment landed and the "
            "policy is restrictive enough to block real attacks."
        ),
        expected_evidence=(
            "HTTP response headers showing a non-trivial CSP header — "
            "default-src/script-src/frame-ancestors directives present."
        ),
        approval_required=False,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.INFORMATIONAL,
        is_defensive=True,
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction="Fetch the target's main HTML response with a normal request.",
                example="curl -sI https://target/ | grep -i content-security-policy",
                expected_result="A Content-Security-Policy header is returned.",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=2,
                instruction=(
                    "Inspect the policy. Confirm default-src is not '*' and "
                    "script-src does not include 'unsafe-inline' or 'unsafe-eval'."
                ),
                expected_result="Restrictive directives present.",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=3,
                instruction=(
                    "If previous XSS findings existed, retry the same payload "
                    "and confirm browser console reports a CSP violation."
                ),
                expected_result="Browser refuses to execute the previously-working payload.",
                capture_evidence=True,
            ),
        ],
        remediation_context=(
            "Once verified, document the CSP directives in the remediation note "
            "for the affected findings — this becomes the proof-of-fix."
        ),
    ),

    GuidedAction(
        action_id="verify_hsts_header",
        finding_type="http_only_site",
        finding_types=["http_only_site", "cleartext_transmission", "tls_weakness"],
        title="Verify Strict-Transport-Security is enforced",
        explanation=(
            "Confirm Strict-Transport-Security is sent over HTTPS with an "
            "appropriate max-age, that includeSubDomains is set where applicable, "
            "and that HTTP requests redirect to HTTPS."
        ),
        why_this_matters=(
            "HSTS prevents protocol downgrade attacks and tells browsers to "
            "refuse cleartext connections after the first visit."
        ),
        expected_evidence=(
            "HTTPS response with HSTS header (max-age ≥ 31536000) and HTTP "
            "request returning 301/308 to HTTPS."
        ),
        approval_required=False,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.INFORMATIONAL,
        is_defensive=True,
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction="Request the HTTPS endpoint and capture response headers.",
                example="curl -sI https://target/ | grep -i strict-transport-security",
                expected_result="HSTS header with max-age in seconds.",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=2,
                instruction="Request the HTTP endpoint and confirm 301/308 redirect to HTTPS.",
                example="curl -sI http://target/",
                expected_result="3xx redirect with Location: https://...",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=3,
                instruction=(
                    "Document the max-age value and whether includeSubDomains + "
                    "preload are present."
                ),
                expected_result="Notes covering all three directives.",
                capture_evidence=True,
            ),
        ],
    ),

    GuidedAction(
        action_id="verify_cookie_security_flags",
        finding_type="security_misconfiguration",
        finding_types=["security_misconfiguration", "credential_exposure"],
        title="Verify session cookie security flags",
        explanation=(
            "Confirm session-bearing cookies now carry Secure, HttpOnly, and "
            "SameSite attributes appropriate to the application."
        ),
        why_this_matters=(
            "Cookie flags directly limit the impact of XSS (HttpOnly), CSRF "
            "(SameSite), and network-position attacks (Secure). They are the "
            "minimum hygiene on every authenticated session."
        ),
        expected_evidence=(
            "Set-Cookie response header showing all three flags for the "
            "primary session cookie."
        ),
        approval_required=False,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.INFORMATIONAL,
        is_defensive=True,
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction="Log in to the target and capture the Set-Cookie header.",
                expected_result="Set-Cookie line(s) for session cookies.",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=2,
                instruction=(
                    "Confirm: Secure (HTTPS-only), HttpOnly (no JS access), "
                    "SameSite=Lax or Strict (CSRF defence)."
                ),
                expected_result="All three flags present and appropriate.",
                capture_evidence=True,
            ),
        ],
    ),

    GuidedAction(
        action_id="verify_parameterised_queries",
        finding_type="sqli",
        finding_types=["sqli", "sql_injection", "sqli_error_based", "sqli_blind", "auth_bypass"],
        title="Verify SQL injection is mitigated",
        explanation=(
            "Re-run the previously-working SQL injection payload and confirm "
            "it now fails closed. Inspect a sample of the application source/"
            "config to confirm parameterised queries are in use on the affected path."
        ),
        why_this_matters=(
            "A patch is only meaningful when the original payload no longer "
            "produces the original effect AND the underlying query construction "
            "has been replaced — not just filtered."
        ),
        expected_evidence=(
            "HTTP response showing the previously-working payload failing "
            "(no authentication bypass, no error leak), plus a code/config "
            "snippet showing parameterised query usage."
        ),
        approval_required=True,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.LOW,
        is_defensive=True,
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction=(
                    "Replay the exact payload that previously bypassed "
                    "authentication or extracted data."
                ),
                example="username: ' OR 1=1--   password: anything",
                expected_result="Login fails. No version/schema disclosure in response.",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=2,
                instruction=(
                    "If you have code access, confirm the query uses prepared "
                    "statements / ORM safe defaults instead of string interpolation."
                ),
                expected_result="Parameterised query in the affected source path.",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=3,
                instruction=(
                    "Document the remediation: which query was changed, "
                    "to what construction, and the test run that confirms the fix."
                ),
                expected_result="A clear remediation note linked to the original finding.",
                capture_evidence=True,
            ),
        ],
        remediation_context=(
            "Capture this verification as remediation-proof evidence — link it "
            "to the original SQLi finding so the lineage is preserved."
        ),
    ),

    GuidedAction(
        action_id="verify_tls_configuration",
        finding_type="tls_weakness",
        finding_types=["tls_weakness", "ssl_weak", "cleartext_transmission"],
        title="Verify TLS configuration is modernised",
        explanation=(
            "Confirm the target now accepts only TLS 1.2+ with modern cipher "
            "suites, and that legacy protocols (SSLv3, TLS 1.0, TLS 1.1) are "
            "rejected."
        ),
        why_this_matters=(
            "Legacy TLS exposes the application to BEAST, POODLE, SWEET32, "
            "and downgrade attacks. Verification gives the auditor and "
            "compliance reviewer a concrete artefact."
        ),
        expected_evidence=(
            "Output of testssl.sh or `nmap --script ssl-enum-ciphers` showing "
            "only TLS 1.2/1.3 with forward-secrecy cipher suites."
        ),
        approval_required=False,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.INFORMATIONAL,
        is_defensive=True,
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction="Probe the target's TLS configuration.",
                example="nmap --script ssl-enum-ciphers -p 443 target",
                expected_result="Cipher list contains only TLS 1.2/1.3 entries.",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=2,
                instruction=(
                    "Confirm legacy protocols are rejected: try forcing "
                    "TLS 1.0 / 1.1 and observe the handshake fails."
                ),
                example="openssl s_client -connect target:443 -tls1_1",
                expected_result="Handshake failure.",
                capture_evidence=True,
            ),
        ],
    ),

    GuidedAction(
        action_id="verify_error_page_genericness",
        finding_type="information_disclosure",
        finding_types=["information_disclosure", "sqli_error_based"],
        title="Verify error pages no longer leak details",
        explanation=(
            "Re-trigger conditions that previously produced verbose error "
            "messages (database errors, stack traces, framework banners) and "
            "confirm the application now returns a generic message."
        ),
        why_this_matters=(
            "Verbose errors reveal stack frames, library versions, and SQL "
            "structure. Production error handling should expose only a "
            "non-actionable identifier the user can quote to support."
        ),
        expected_evidence=(
            "HTTP response demonstrating a generic error (no stack frames, "
            "no SQL fragments) for the same condition that previously leaked."
        ),
        approval_required=False,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.INFORMATIONAL,
        is_defensive=True,
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction=(
                    "Re-issue the request that previously produced the "
                    "verbose error."
                ),
                expected_result=(
                    "Response no longer contains stack frames, SQL fragments, "
                    "or version banners."
                ),
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=2,
                instruction=(
                    "Confirm a generic message + non-actionable correlation ID "
                    "is shown to the user, while detailed errors are logged "
                    "server-side only."
                ),
                expected_result="Generic message + opaque correlation token.",
                capture_evidence=True,
            ),
        ],
    ),
]
