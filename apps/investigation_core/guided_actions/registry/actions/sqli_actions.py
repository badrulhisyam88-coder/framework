"""SQLi guided actions — structured investigation steps for SQL injection findings."""

from apps.investigation_core.guided_actions.models.action import (
    ExecutionMode,
    GuidedAction,
    GuidedActionStep,
    RiskLevel,
)

SQLI_ACTIONS = [
    GuidedAction(
        action_id="sqli_injection_probe",
        finding_type="sqli",
        finding_types=["sqli", "sql_injection", "sqli_error_based", "sqli_blind"],
        title="Injection Point Detection",
        explanation=(
            "Systematically identify which parameter accepts unsanitised input that "
            "reaches the SQL layer. A single-quote test triggers a parse error or "
            "behavioural change if injection is possible."
        ),
        why_this_matters=(
            "Precise injection point identification is the foundation of all subsequent "
            "steps. Without it you cannot build reliable payloads or produce a "
            "reproducible proof of concept."
        ),
        required_skills=[],
        expected_evidence=(
            "Screenshot or HTTP response showing different server behaviour when "
            "a single quote is appended to the target parameter."
        ),
        approval_required=True,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.LOW,
        related_learning_path="sqli_beginner_01",
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction=(
                    "Identify all parameters in the request — URL query params, "
                    "POST body fields, cookies, and custom headers."
                ),
                expected_result="A list of parameters to test.",
            ),
            GuidedActionStep(
                step_number=2,
                instruction=(
                    "Append a single quote to the first parameter value"
                    " and send the request."
                ),
                example="GET /item?id=1'  OR  POST body: username=admin'",
                expected_result=(
                    "Database error message, blank page, or different response "
                    "compared to the original request."
                ),
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=3,
                instruction=(
                    "Repeat for each parameter. Note which parameter(s) produce "
                    "a changed response."
                ),
                expected_result="One or more injectable parameters identified.",
                capture_evidence=True,
            ),
        ],
        preconditions=[
            "A live HTTP endpoint that accepts user-supplied parameters.",
            "Ability to replay modified requests (browser DevTools, Burp, curl).",
        ],
        outcome_indicators=[
            "Server returns a SQL error (syntax error, unterminated string literal).",
            "Page content changes (empty result, server error 500).",
            "Response time changes significantly.",
        ],
        remediation_context=(
            "SQL injection exists because user input is concatenated directly into a "
            "SQL query. Fix: use parameterised queries (prepared statements) for all "
            "database interactions. Never build SQL strings with user data."
        ),
    ),
    GuidedAction(
        action_id="sqli_boolean_confirmation",
        finding_type="sqli",
        finding_types=["sqli", "sql_injection", "sqli_error_based", "sqli_blind"],
        title="Boolean-Based Confirmation",
        explanation=(
            "A boolean test proves the injection point is actually executing SQL by "
            "demonstrating a difference between a true condition (AND 1=1) and a "
            "false condition (AND 1=2). This rules out false positives from "
            "non-SQL error handling."
        ),
        why_this_matters=(
            "Boolean confirmation elevates an injection candidate to a confirmed "
            "vulnerability. It also reveals whether blind injection is viable when "
            "error messages are suppressed."
        ),
        required_skills=["Injection point identified (run sqli_injection_probe first)"],
        expected_evidence=(
            "Two screenshots or response bodies: one for AND 1=1 (true — normal page) "
            "and one for AND 1=2 (false — different page). The difference is the proof."
        ),
        approval_required=True,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.LOW,
        related_learning_path="sqli_beginner_01",
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction="Send the request with AND 1=1-- appended after the injectable value.",
                example="id=1' AND 1=1--",
                expected_result="Normal page content (true condition).",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=2,
                instruction="Send the same request with AND 1=2-- instead.",
                example="id=1' AND 1=2--",
                expected_result="Different content — empty results, error, or missing data.",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=3,
                instruction=(
                    "Compare the two responses. Document the specific difference "
                    "(content length, element count, error presence)."
                ),
                expected_result="Clear, reproducible difference between true and false conditions.",
                capture_evidence=True,
            ),
        ],
        preconditions=[
            "Injectable parameter identified.",
            "Single-quote test already confirmed changed behaviour.",
        ],
        outcome_indicators=[
            "True condition returns the original page content.",
            "False condition returns empty results or an error page.",
            "Consistent difference across multiple requests.",
        ],
        remediation_context=(
            "Confirmed SQL injection allows arbitrary SQL execution. "
            "Immediate remediation: parameterised queries. "
            "Interim: apply strict input allowlisting if emergency patch is not possible."
        ),
    ),
    GuidedAction(
        action_id="sqli_version_extraction",
        finding_type="sqli",
        finding_types=["sqli", "sql_injection", "sqli_error_based"],
        title="Database Version Extraction",
        explanation=(
            "Extract the database engine version using a UNION-based or error-based "
            "injection. This is the standard non-destructive proof of data extraction "
            "that demonstrates an attacker could enumerate the database without credentials."
        ),
        why_this_matters=(
            "Version extraction proves the vulnerability allows data exfiltration, "
            "not just error triggering. It gives stakeholders a concrete, "
            "non-destructive demonstration of impact."
        ),
        required_skills=[
            "Boolean confirmation completed (sqli_boolean_confirmation).",
            "Column count determined via ORDER BY.",
        ],
        expected_evidence=(
            "Response body showing the database version string "
            "(e.g. '8.0.35-MySQL Community Server')."
        ),
        approval_required=True,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.MEDIUM,
        related_learning_path="sqli_beginner_01",
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction=(
                    "Determine column count: increment ORDER BY until the page errors. "
                    "The last successful number is the column count."
                ),
                example="id=1' ORDER BY 1-- , id=1' ORDER BY 2-- , id=1' ORDER BY 3--",
                expected_result=(
                    "ORDER BY N succeeds, ORDER BY N+1 errors — column count is N."
                ),
            ),
            GuidedActionStep(
                step_number=2,
                instruction=(
                    "Find which column is reflected in the response using NULL probes."
                ),
                example="id=-1' UNION SELECT NULL,NULL,NULL--  (adjust count to match)",
                expected_result="Page loads without error with all-NULL UNION.",
            ),
            GuidedActionStep(
                step_number=3,
                instruction=(
                    "Replace one NULL with the version function for your database: "
                    "@@version (MySQL/MSSQL) or version() (PostgreSQL)."
                ),
                example="id=-1' UNION SELECT NULL,@@version,NULL--",
                expected_result="Version string visible in page response.",
                capture_evidence=True,
            ),
        ],
        preconditions=[
            "UNION injection confirmed (error-based or UNION technique).",
            "Column count not yet determined.",
        ],
        outcome_indicators=[
            "Database product name and version visible in response.",
            "No tables modified.",
        ],
        remediation_context=(
            "Version extraction confirms the attacker can read database metadata. "
            "This is one step removed from reading table data. "
            "Parameterised queries are the only complete fix."
        ),
    ),
    GuidedAction(
        action_id="sqli_auth_bypass",
        finding_type="auth_bypass",
        finding_types=["auth_bypass", "sqli", "sqli_error_based", "sqli_blind"],
        title="SQL Injection Authentication Bypass",
        explanation=(
            "Test whether the login query is vulnerable to boolean injection. "
            "When user input is concatenated into a SQL WHERE clause, "
            'a payload like "\' OR 1=1--" makes the WHERE clause evaluate '
            "TRUE for every row — returning the first user, typically an admin."
        ),
        why_this_matters=(
            "Authentication bypass via SQLi is one of the highest-impact "
            "consequences of unsafe query construction. A single quote breaks "
            "out of the string context; the OR clause guarantees a match; "
            "the comment terminator removes any password check."
        ),
        required_skills=["sqli_fundamentals"],
        expected_evidence=(
            "Screenshot or HTTP response showing successful authentication, "
            "and the email/identity of the resulting session "
            "(visible in the account menu, JWT payload, or response body)."
        ),
        approval_required=True,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.MEDIUM,
        related_learning_path="auth_beginner_01",
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction=(
                    "Locate the login form on the target. Note the field name "
                    "used for the username/email (e.g. 'email', 'user', 'login')."
                ),
                expected_result="Login endpoint and parameter name documented.",
            ),
            GuidedActionStep(
                step_number=2,
                instruction=(
                    "In the username/email field, paste the boolean-injection "
                    "payload. Any value works for the password field — "
                    "the comment terminator skips the password check."
                ),
                example="' OR 1=1--",
                expected_result=(
                    "Authentication succeeds. Server returns a session cookie, "
                    "JWT, or redirect to an authenticated page."
                ),
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=3,
                instruction=(
                    "Inspect the resulting session: open the account/profile menu, "
                    "decode the JWT, or check response headers. "
                    "Identify the user account you logged in as."
                ),
                expected_result=(
                    "User identity (email or username) visible. "
                    "If admin, document the privilege level."
                ),
                capture_evidence=True,
            ),
        ],
        preconditions=[
            "Login form/endpoint reachable on the target.",
            "Lab/CTF environment — do not run against production.",
        ],
        outcome_indicators=[
            "Authenticated session obtained without valid credentials.",
            "Account identity (often admin) visible in the response.",
        ],
        remediation_context=(
            "Replace string concatenation with parameterised queries. "
            "Treat user input as data, never as code. ORM frameworks typically "
            "handle this correctly by default; raw SQL must use prepared statements."
        ),
    ),
]
