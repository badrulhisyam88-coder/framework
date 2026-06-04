# ruff: noqa: E501
"""Guided actions for defensive hardening findings.

Covers ZAP/Nuclei finding types that previously had no actions:
security_misconfiguration, information_disclosure, tls_weakness,
broken_access_control, http_only_site, cleartext_transmission.
"""

from apps.investigation_core.guided_actions.models.action import (
    ExecutionMode,
    GuidedAction,
    GuidedActionStep,
    RiskLevel,
)

HARDENING_ACTIONS = [
    GuidedAction(
        action_id="security_headers_audit",
        finding_type="security_misconfiguration",
        finding_types=["security_misconfiguration", "information_disclosure"],
        title="Security Headers Audit",
        explanation=(
            "Inspect the HTTP response from the target and document which security "
            "headers are missing or weakly configured. Each header maps to a specific "
            "browser-side defence."
        ),
        why_this_matters=(
            "Security headers are the cheapest hardening control to add. Missing CSP "
            "amplifies XSS impact; missing X-Frame-Options enables clickjacking; "
            "missing HSTS leaves users vulnerable to downgrade attacks."
        ),
        required_skills=["security_header_review"],
        expected_evidence="HTTP response capture + audit note listing each missing header and its purpose.",
        approval_required=False,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.INFORMATIONAL,
        related_learning_path="web_hardening_beginner_01",
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction="Send a normal GET to the target and capture the response headers.",
                example="curl -sI http://target/  →  inspect Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy, Permissions-Policy",
                expected_result="Response captured with full header set.",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=2,
                instruction=(
                    "For each of the standard headers, note: present / missing / weak. "
                    "For headers that are present, check the value (e.g. CSP that allows "
                    "'unsafe-inline' is much weaker than one that doesn't)."
                ),
                expected_result="Per-header audit complete.",
            ),
            GuidedActionStep(
                step_number=3,
                instruction=(
                    "Inspect Set-Cookie headers. Each cookie should have: "
                    "HttpOnly (prevents JS access), Secure (HTTPS-only), SameSite (CSRF defence)."
                ),
                expected_result="Cookie flags documented.",
                capture_evidence=True,
            ),
        ],
        preconditions=["Target HTTP endpoint reachable."],
        outcome_indicators=["Audit note covering all standard security headers and cookie flags."],
        remediation_context=(
            "Modern frameworks (Helmet for Node, django-csp, security middleware) "
            "set these headers correctly by default. Adding them is rarely a code change — "
            "it's a configuration toggle."
        ),
    ),
    GuidedAction(
        action_id="info_disclosure_inspect",
        finding_type="information_disclosure",
        finding_types=["information_disclosure", "security_misconfiguration"],
        title="Information Disclosure Inspection",
        explanation=(
            "Examine what the application reveals about its internals — banners, "
            "stack traces, internal paths, source comments — and document how each "
            "leak narrows the search space for an attacker."
        ),
        why_this_matters=(
            "A leaked version banner immediately maps to a CVE database. A stack trace "
            "exposes the framework and file paths. Source comments often reveal "
            "developer names, ticket IDs, and TODO security notes."
        ),
        required_skills=["information_disclosure_assessment"],
        expected_evidence="Note cataloguing each disclosure + the attack-surface implication.",
        approval_required=False,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.INFORMATIONAL,
        related_learning_path="web_hardening_beginner_01",
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction=(
                    "Trigger an error: malformed JSON, invalid URL, SQL-special characters "
                    "(' \" --), or a non-existent endpoint. Capture the response."
                ),
                example="curl http://target/api/users/' 'malformed'  →  see error response",
                expected_result="Error response captured (with or without stack trace).",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=2,
                instruction=(
                    "Inspect HTTP response headers across multiple endpoints for: "
                    "Server, X-Powered-By, X-AspNet-Version, X-Generator, X-Runtime."
                ),
                expected_result="Banner inventory complete.",
            ),
            GuidedActionStep(
                step_number=3,
                instruction=(
                    "View the HTML source of one or two pages. Search for: "
                    "<!-- comments -->, removed code blocks, TODO/FIXME, internal URLs, "
                    "employee names, ticket IDs."
                ),
                expected_result="Source-comment review complete.",
                capture_evidence=True,
            ),
        ],
        preconditions=["Target reachable."],
        outcome_indicators=["Documented inventory of disclosed elements with security implications."],
        remediation_context=(
            "Production builds should: strip source comments, suppress detailed errors, "
            "remove version banner headers, and review TODO/FIXME blocks before deploy. "
            "Each disclosed item is a free reconnaissance gift to attackers."
        ),
    ),
    GuidedAction(
        action_id="tls_config_audit",
        finding_type="tls_weakness",
        finding_types=["tls_weakness", "ssl_weak", "cleartext_transmission", "http_only_site"],
        title="TLS Configuration Audit",
        explanation=(
            "Verify the target's TLS posture: which protocol versions and cipher suites "
            "are accepted, certificate validity, and whether plain HTTP traffic is "
            "served alongside (or instead of) HTTPS."
        ),
        why_this_matters=(
            "TLS protects credentials and session tokens. A target accepting TLS 1.0 "
            "is exposed to BEAST. A target accepting RC4 ciphers leaks bytes over time. "
            "A target serving HTTP at all is exposed to credential capture and downgrade attacks."
        ),
        required_skills=["tls_configuration_review"],
        expected_evidence="TLS audit note: supported protocols, ciphers, cert details, HTTP-fallback status.",
        approval_required=False,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.LOW,
        related_learning_path="web_hardening_beginner_01",
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction="Determine which TLS protocols the target supports. Document each one.",
                example="curl -v --tls1.0 https://target  /  --tls1.1 / --tls1.2 / --tls1.3",
                expected_result="Per-protocol support status documented.",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=2,
                instruction="Inspect the certificate: subject, issuer, validity dates, key algorithm.",
                example="openssl s_client -connect target:443 -servername target </dev/null 2>/dev/null | openssl x509 -text",
                expected_result="Certificate details documented.",
            ),
            GuidedActionStep(
                step_number=3,
                instruction=(
                    "Test whether plain HTTP is served. If yes, check whether it redirects "
                    "to HTTPS. Test whether HSTS is set on the HTTPS response."
                ),
                example="curl -sI http://target  →  expect 301 to https://; check Strict-Transport-Security header",
                expected_result="HTTP-vs-HTTPS posture documented.",
                capture_evidence=True,
            ),
        ],
        preconditions=["Target reachable on standard ports."],
        outcome_indicators=["TLS audit note covers protocol, ciphers, certificate, HTTP-fallback."],
        remediation_context=(
            "Disable TLS 1.0 and 1.1. Remove RC4, 3DES, and NULL ciphers. "
            "Enable HSTS with includeSubDomains. Redirect all HTTP to HTTPS. "
            "Use a config generator (Mozilla SSL Config Generator) for safe defaults."
        ),
    ),
    GuidedAction(
        action_id="access_control_probe",
        finding_type="broken_access_control",
        finding_types=["broken_access_control", "information_disclosure"],
        title="Access Control Probe",
        explanation=(
            "Test whether the application enforces authorisation server-side on protected "
            "resources. UI-only hiding ('don't show the admin link') is not access control."
        ),
        why_this_matters=(
            "Broken access control is OWASP's #1 risk. The typical bug: server checks "
            "you're logged in, but not whether you're authorised to access this specific "
            "resource. Manipulating the resource ID often returns another user's data."
        ),
        required_skills=["access_control_validation"],
        expected_evidence="Per-endpoint test note + captured response for any successful bypass.",
        approval_required=True,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.MEDIUM,
        related_learning_path="web_hardening_beginner_01",
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction=(
                    "Identify 3 protected endpoints: user profile, admin page, settings. "
                    "Note the URL pattern for each and the resource identifier (numeric ID, UUID, slug)."
                ),
                expected_result="Endpoint inventory complete.",
            ),
            GuidedActionStep(
                step_number=2,
                instruction=(
                    "For each endpoint, change the resource ID to one belonging to a different user. "
                    "Observe the response: 403 (good), 401 (good), data returned (BAD), "
                    "different user's data returned (CRITICAL)."
                ),
                example="/api/users/1/profile  vs  /api/users/2/profile  while authenticated as user 1",
                expected_result="Per-endpoint result documented.",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=3,
                instruction=(
                    "For admin endpoints: try accessing them as a regular user. "
                    "Server should reject; UI may or may not have hidden the link."
                ),
                expected_result="Admin-access enforcement verified.",
                capture_evidence=True,
            ),
        ],
        preconditions=[
            "Authenticated session available.",
            "Lab/CTF environment — do not test against production without authorisation.",
        ],
        outcome_indicators=["Each tested endpoint documented with: enforced / partial / bypassed."],
        remediation_context=(
            "Server-side authorisation must run on every request, not just on login. "
            "Validate that the authenticated principal can access the requested resource. "
            "Prefer opaque identifiers (UUIDs) over sequential integers."
        ),
    ),
]
