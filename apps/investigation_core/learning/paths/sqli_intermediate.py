# ruff: noqa: E501
"""SQLi Intermediate learning path configuration."""

from apps.investigation_core.models.learning import GuidedStep, LearningPath

SQLI_INTERMEDIATE = LearningPath(
    path_id="sqli_intermediate_01",
    title="SQL Injection — Intermediate",
    difficulty="intermediate",
    finding_types=["sqli_blind", "sqli_error_based", "sqli_union_extraction", "sqli"],
    required_skills=["sqli_fundamentals", "sqli_boolean_testing"],
    learning_objectives=[
        "Perform time-based blind injection to confirm without visible output",
        "Enumerate database schema via UNION-based queries",
        "Extract data from specific tables without destructive payloads",
        "Distinguish between error-based and blind injection channels",
        "Produce investigation-grade documentation with full extraction proof",
    ],
    guided_steps=[
        GuidedStep(
            step_id="sqli_i01_s01",
            title="Confirm with Time-Based Injection",
            explanation=(
                "When a vulnerability produces no visible error or output difference, "
                "time-based injection provides an independent confirmation channel. "
                "Inject a payload that causes the database to sleep for a measurable "
                "duration: `' AND SLEEP(3)--` (MySQL) or `'; WAITFOR DELAY '0:0:3'--` (MSSQL)."
            ),
            why_this_matters=(
                "Time-based confirmation proves injection exists even when the application "
                "returns identical output for both vulnerable and non-vulnerable inputs. "
                "It also confirms the database engine type, which shapes every subsequent step."
            ),
            expected_evidence="Documented HTTP request + response showing measurable delay difference",
            learner_input=(
                "Inject SLEEP/WAITFOR payload. Measure response time difference vs baseline. "
                "Record: injection point, payload, observed delay, baseline delay."
            ),
            completion_validation="Time delay of ≥2s reproducibly observed for injected vs baseline request",
        ),
        GuidedStep(
            step_id="sqli_i01_s02",
            title="Enumerate Columns with UNION",
            explanation=(
                "UNION-based injection requires knowing the number of columns returned by the "
                "original query. Use ORDER BY incrementing: `ORDER BY 1--`, `ORDER BY 2--`, "
                "until the query errors — the last working number is your column count. "
                "Then build: `UNION SELECT NULL,NULL,...--`."
            ),
            why_this_matters=(
                "Column enumeration is the gateway to data extraction. Without knowing the "
                "column count and types, UNION queries fail silently or return errors. "
                "This step transforms a confirmed injection into a controlled extraction channel."
            ),
            expected_evidence="Successful UNION SELECT returning controlled output (e.g. version string)",
            learner_input=(
                "Increment ORDER BY until error. Then attempt: "
                "UNION SELECT NULL,... (match column count). Confirm reflected column by substituting "
                "a string like 'test_string' and verifying it appears in the response."
            ),
            completion_validation="UNION payload returning controlled output in application response",
        ),
        GuidedStep(
            step_id="sqli_i01_s03",
            title="Extract Database Metadata",
            explanation=(
                "With a working UNION channel, extract schema metadata — never production data. "
                "MySQL: `UNION SELECT table_name,NULL FROM information_schema.tables WHERE "
                "table_schema=database()--`. This reveals table names without touching row data."
            ),
            why_this_matters=(
                "Table enumeration demonstrates the blast radius of the vulnerability: what data "
                "could an attacker reach? For a security investigation, proving schema access is "
                "sufficient evidence — actual data extraction is unnecessary and disproportionate."
            ),
            expected_evidence="List of table names from information_schema extraction",
            learner_input=(
                "Use UNION SELECT targeting information_schema.tables or information_schema.columns. "
                "Record table names returned. STOP at schema metadata — do not extract row data."
            ),
            completion_validation="At least one table name extracted from information_schema; no row data extracted",
        ),
        GuidedStep(
            step_id="sqli_i01_s04",
            title="Classify Injection Type and Scope",
            explanation=(
                "Not all SQL injections are equal. Classify the finding: "
                "error-based (verbose errors), union-based (output reflected), "
                "blind boolean (different responses), blind time-based (delay only), "
                "stacked queries (multiple statements). "
                "Each type has different risk and remediation implications."
            ),
            why_this_matters=(
                "Classification drives remediation priority and reporting accuracy. "
                "A stacked query injection (rare) allows writes and stored procedures — "
                "fundamentally higher risk than a read-only time-based injection."
            ),
            expected_evidence="Classification note with supporting evidence for each type tested",
            learner_input=(
                "Test for each type: Does the app show SQL errors? Does UNION output reflect? "
                "Does boolean '1=1' vs '1=2' produce different responses? Do delays work? "
                "Document which techniques confirmed and which did not."
            ),
            completion_validation="Injection type classified with supporting evidence for each category tested",
        ),
        GuidedStep(
            step_id="sqli_i01_s05",
            title="Document Full Technical Scope",
            explanation=(
                "Intermediate-level documentation must go beyond 'SQLi confirmed' to provide "
                "the evidence chain: injection point, confirmed type, demonstrated schema access, "
                "remediation specifics. Include: the exact parameter, the payload, "
                "the database engine, the tables accessible, and parameterisation recommendation."
            ),
            why_this_matters=(
                "Developers need precision to fix the issue — which query, which parameter, "
                "and exactly how parameterisation applies to this code path. "
                "Vague reports lead to incomplete fixes."
            ),
            expected_evidence="Investigation note with full technical scope: parameter, engine, extracted schema, fix",
            learner_input=(
                "Capture a complete evidence note including: exact injection parameter, "
                "database engine (from version extraction), schema accessible, "
                "remediation: 'Replace string concatenation on [parameter] in [function] "
                "with parameterised query using [language]-specific prepared statement.'"
            ),
            completion_validation="Evidence note covers injection point, engine, schema, and parameterised-query fix",
        ),
    ],
    completion_checks=[
        "Time-based injection confirmed with measurable delay difference",
        "Column count established via ORDER BY enumeration",
        "UNION SELECT returning controlled output in response",
        "Database schema metadata extracted (information_schema)",
        "Injection type classified with supporting evidence",
        "Full technical scope documented with parameterised-query fix",
    ],
    next_paths=[],
)
