"""XSS guided actions."""

from apps.investigation_core.guided_actions.models.action import (
    ExecutionMode,
    GuidedAction,
    GuidedActionStep,
    RiskLevel,
)

XSS_ACTIONS = [
    GuidedAction(
        action_id="xss_reflection_probe",
        finding_type="xss",
        finding_types=["xss", "reflected_xss", "xss_reflected", "stored_xss", "xss_stored"],
        title="XSS Reflection Probe",
        explanation=(
            "Submit a unique harmless string to every input field and search the "
            "page source to confirm where and how user input is reflected without encoding."
        ),
        why_this_matters=(
            "XSS payloads only work if your input reaches the DOM without escaping. "
            "Finding the exact reflection context (attribute, body, JS) determines "
            "which payload will succeed — random payload guessing is unreliable."
        ),
        required_skills=[],
        expected_evidence=(
            "Page source showing your unique probe string in an HTML context, "
            "with surrounding HTML structure noted."
        ),
        approval_required=True,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.LOW,
        related_learning_path="xss_beginner_01",
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction=(
                    "Choose a unique probe string that is unlikely to appear in the "
                    "application naturally."
                ),
                example="xss_probe_a1b2c3",
                expected_result="A string you can search for in the page source.",
            ),
            GuidedActionStep(
                step_number=2,
                instruction=(
                    "Submit the probe string in every input field you can find: "
                    "search boxes, form fields, URL parameters."
                ),
                expected_result="Requests sent; one or more return the probe in the response.",
                capture_evidence=True,
            ),
            GuidedActionStep(
                step_number=3,
                instruction=(
                    "View the page source (right-click → View Page Source) and "
                    "search for your probe string. Note the surrounding HTML."
                ),
                expected_result=(
                    "Probe string found inside HTML. Note whether it is in: "
                    "tag body, attribute value, JavaScript string, or CSS."
                ),
                capture_evidence=True,
            ),
        ],
        preconditions=[
            "A live web application with user input fields.",
        ],
        outcome_indicators=[
            "Probe string appears in HTML response without being encoded.",
            "Surrounding context shows the string is interpreted as HTML content.",
        ],
        remediation_context=(
            "XSS occurs when user input reaches the HTML output without encoding. "
            "Remediation: apply output encoding at render time using the template "
            "engine's built-in escaping. Do NOT rely on input sanitisation alone."
        ),
    ),
    GuidedAction(
        action_id="xss_execution_confirm",
        finding_type="xss",
        finding_types=["xss", "reflected_xss", "xss_reflected", "stored_xss", "xss_stored"],
        title="XSS Execution Confirmation",
        explanation=(
            "Confirm that injected JavaScript executes in the target context using "
            "alert(document.domain) — the industry-standard benign proof. "
            "This demonstrates the origin affected without causing harm."
        ),
        why_this_matters=(
            "An alert box screenshot with document.domain is universally understood "
            "as unambiguous proof of JavaScript execution. It shows the exact origin "
            "and that the browser executed untrusted code."
        ),
        required_skills=["Reflection context identified (xss_reflection_probe)."],
        expected_evidence=(
            "Screenshot of browser alert dialogue showing the domain name "
            "(e.g. 'app.internal') triggered by your payload."
        ),
        approval_required=True,
        execution_mode=ExecutionMode.GUIDED_MANUAL,
        risk_level=RiskLevel.LOW,
        related_learning_path="xss_beginner_01",
        steps=[
            GuidedActionStep(
                step_number=1,
                instruction=(
                    "Based on the reflection context, choose an appropriate payload. "
                    "For tag body context use a script tag; for attribute context use "
                    "an event handler."
                ),
                example=(
                    "Tag body: <script>alert(document.domain)</script>\n"
                    "Attribute: \" onmouseover=\"alert(document.domain)"
                ),
                expected_result="Payload submitted to the target parameter.",
            ),
            GuidedActionStep(
                step_number=2,
                instruction=(
                    "If script tags are filtered, try an img tag fallback."
                ),
                example="<img src=x onerror=alert(document.domain)>",
                expected_result="Alternative payload available if script tag is blocked.",
            ),
            GuidedActionStep(
                step_number=3,
                instruction=(
                    "Take a screenshot of the alert dialogue showing the domain. "
                    "Dismiss the alert — do not proceed further."
                ),
                expected_result="Alert box visible with domain name.",
                capture_evidence=True,
            ),
        ],
        preconditions=[
            "Reflection context identified and noted.",
            "Page source shows unencoded probe string in HTML.",
        ],
        outcome_indicators=[
            "Browser alert fires with document.domain.",
            "Domain name in alert matches target application.",
        ],
        remediation_context=(
            "Confirmed XSS allows script injection into victim browsers. "
            "Stored XSS affects all users. Reflected XSS requires a crafted link. "
            "Remediation: context-aware output encoding everywhere user input is rendered."
        ),
    ),
]
