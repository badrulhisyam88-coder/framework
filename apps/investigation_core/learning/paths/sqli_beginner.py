"""SQLi Beginner learning path configuration."""

from apps.investigation_core.models.learning import GuidedStep, LearningPath

SQLI_BEGINNER = LearningPath(
    path_id="sqli_beginner_01",
    title="SQL Injection — Beginner",
    difficulty="beginner",
    finding_types=["sqli", "sql_injection", "sqli_error_based", "sqli_blind"],
    required_skills=[],
    learning_objectives=[
        "Understand what SQL injection is and why it occurs",
        "Identify user-controlled input reaching a SQL query",
        "Craft a basic proof-of-concept payload",
        "Extract database metadata without destructive queries",
        "Document and communicate the finding clearly",
    ],
    guided_steps=[
        GuidedStep(
            step_id="sqli_b01_s01",
            title="Identify the Injection Point",
            explanation=(
                "SQL injection occurs when user-supplied input is embedded directly into a "
                "SQL query without sanitisation. Your first task is to find where the "
                "application accepts input that could reach the database layer."
            ),
            why_this_matters=(
                "Knowing exactly which parameter is injectable is the foundation of everything "
                "that follows. A precise injection point gives you reliable, reproducible results "
                "and avoids wasted effort on non-vulnerable parameters."
            ),
            expected_evidence=(
                "A specific URL, form field, cookie, or header value that produces a different "
                "server response when you append a single quote ( ' ) to its value."
            ),
            learner_input=(
                "Append a single quote to a parameter value and note the response change."
            ),
            completion_validation=(
                "You have identified at least one parameter where a single quote causes a "
                "database error, unexpected output, or different behaviour."
            ),
            next_step="sqli_b01_s02",
        ),
        GuidedStep(
            step_id="sqli_b01_s02",
            title="Confirm Vulnerability with Boolean Test",
            explanation=(
                "A boolean-based test differentiates true and false conditions to confirm "
                "the injection point. Use ' AND 1=1-- and ' AND 1=2-- to compare responses. "
                "Never run destructive payloads (DROP, DELETE, UPDATE) during assessment."
            ),
            why_this_matters=(
                "Error messages alone can be misleading. A consistent true/false response "
                "difference proves the injected SQL is actually being executed by the database, "
                "not just reflected in an error string."
            ),
            expected_evidence=(
                "Two different server responses for ' AND 1=1-- (true condition) versus "
                "' AND 1=2-- (false condition) on the same parameter."
            ),
            learner_input="Test: param=' AND 1=1-- vs param=' AND 1=2-- — document both responses.",
            completion_validation=(
                "Clear difference between true and false condition responses confirmed. "
                "No destructive payloads used."
            ),
            next_step="sqli_b01_s03",
        ),
        GuidedStep(
            step_id="sqli_b01_s03",
            title="Extract Database Version",
            explanation=(
                "Database version extraction is the standard non-destructive proof of impact. "
                "Use database-appropriate syntax: @@version (MySQL/MSSQL), version() (PostgreSQL), "
                "or SELECT banner FROM v$version (Oracle). A UNION-based payload requires "
                "matching column count first."
            ),
            why_this_matters=(
                "Version information determines which vulnerabilities apply to this database "
                "instance and demonstrates to stakeholders that an attacker could enumerate "
                "the backend without any credentials."
            ),
            expected_evidence=(
                "The database product name and version number visible in the application response "
                "or error output."
            ),
            learner_input=(
                "Use ORDER BY to find column count, then: ' UNION SELECT NULL,@@version,NULL-- "
                "(adjust nulls to match column count)."
            ),
            completion_validation=(
                "Database version string extracted and recorded in your evidence notes. "
                "No tables modified."
            ),
            next_step="sqli_b01_s04",
        ),
        GuidedStep(
            step_id="sqli_b01_s04",
            title="Enumerate Table Names",
            explanation=(
                "Enumerating table names demonstrates the blast radius of the vulnerability. "
                "Query information_schema.tables (MySQL/PostgreSQL/MSSQL) or ALL_TABLES (Oracle). "
                "Stop after listing table names — do not retrieve row data."
            ),
            why_this_matters=(
                "Table names reveal the application's data model and help stakeholders "
                "understand which sensitive data (users, payments, sessions) is at risk, "
                "without actually exfiltrating that data."
            ),
            expected_evidence=(
                "A list of table names from the target database schema visible in the response."
            ),
            learner_input=(
                "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables "
                "WHERE table_schema=database()--"
            ),
            completion_validation=(
                "At least one table name extracted and documented. No row-level data retrieved."
            ),
            next_step="sqli_b01_s05",
        ),
        GuidedStep(
            step_id="sqli_b01_s05",
            title="Document and Communicate the Finding",
            explanation=(
                "A well-documented finding is the difference between a report that gets fixed "
                "and one that gets ignored. Include: exact request/response pair, the parameter, "
                "the database version, the table names found, and a CVSS-based severity rating."
            ),
            why_this_matters=(
                "Developers need a reproducible proof-of-concept to fix the vulnerability. "
                "Management needs a risk summary to prioritise. Both need your report to be clear."
            ),
            expected_evidence=(
                "A written finding entry with: affected URL, parameter, payload used, "
                "database version, table names, and recommended remediation "
                "(parameterised queries)."
            ),
            learner_input=None,
            completion_validation=(
                "Finding documented with all required fields. Remediation recommendation included: "
                "use parameterised queries / prepared statements for all database interactions."
            ),
            next_step=None,
        ),
    ],
    completion_checks=[
        "Injection point identified with reproducible evidence",
        "Boolean confirmation test performed (no destructive payloads)",
        "Database version extracted",
        "Table names enumerated",
        "Finding documented with remediation recommendation",
    ],
    next_paths=["sqli_intermediate_01"],
)
