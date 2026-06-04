"""XSS Beginner learning path configuration."""

from apps.investigation_core.models.learning import GuidedStep, LearningPath

XSS_BEGINNER = LearningPath(
    path_id="xss_beginner_01",
    title="Cross-Site Scripting (XSS) — Beginner",
    difficulty="beginner",
    finding_types=["xss", "reflected_xss", "stored_xss", "xss_reflected", "xss_stored"],
    required_skills=[],
    learning_objectives=[
        "Understand the three XSS types and which applies here",
        "Map the input-to-output reflection path",
        "Confirm execution with a benign alert payload",
        "Assess the impact scope (self vs. other users)",
        "Document with remediation recommendation",
    ],
    guided_steps=[
        GuidedStep(
            step_id="xss_b01_s01",
            title="Identify the Reflection Point",
            explanation=(
                "XSS requires user-supplied input to appear in the HTML response without "
                "proper encoding. Start by submitting a unique, harmless string "
                "(e.g. xsstest12345) and search for it in the page source. "
                "Look for reflected, stored, and DOM-based paths."
            ),
            why_this_matters=(
                "Without knowing exactly where your input lands in the DOM, you cannot "
                "craft an effective payload or explain the vulnerability to developers. "
                "The reflection context (HTML attribute, tag body, JavaScript string) "
                "determines which payload will work."
            ),
            expected_evidence=(
                "The test string visible in the page HTML source, with the surrounding context "
                "noted (e.g. inside an <input value='...'> attribute)."
            ),
            learner_input=(
                "Submit 'xsstest12345' in the target field and view page source. "
                "Find and note the surrounding HTML context."
            ),
            completion_validation=(
                "Reflection point located and context documented "
                "(e.g. attribute context, tag body, JavaScript string)."
            ),
            next_step="xss_b01_s02",
        ),
        GuidedStep(
            step_id="xss_b01_s02",
            title="Determine XSS Type",
            explanation=(
                "Reflected XSS: the payload is in the response only when the malicious URL "
                "is visited. Stored XSS: the payload is saved server-side and executes for "
                "every visitor. DOM-based XSS: no server round-trip; the browser processes "
                "the payload directly from the URL fragment or client-side storage."
            ),
            why_this_matters=(
                "Type determines impact. Stored XSS affects all users who view the page. "
                "Reflected XSS requires a victim to click a crafted link. "
                "The remediation strategy differs for each type."
            ),
            expected_evidence=(
                "Confirmation of which type applies: does the payload survive a page reload "
                "without the crafted URL? (stored = yes, reflected = no)"
            ),
            learner_input=(
                "Submit the test string via a form and reload the page without your test URL. "
                "If the string persists, it is stored. If not, it is reflected."
            ),
            completion_validation=(
                "XSS type (reflected / stored / DOM) determined and documented."
            ),
            next_step="xss_b01_s03",
        ),
        GuidedStep(
            step_id="xss_b01_s03",
            title="Confirm Execution with a Benign Payload",
            explanation=(
                "Use <script>alert(document.domain)</script> or an img onerror fallback. "
                "The alert() payload is the industry-standard benign proof of execution. "
                "Always use document.domain (not just 'XSS') so the screenshot shows the "
                "affected origin. Stop after confirming execution — do not steal cookies."
            ),
            why_this_matters=(
                "A screenshot of the alert box with document.domain is universally understood "
                "as proof of execution. It shows the exact origin affected and the browser "
                "actually running injected code."
            ),
            expected_evidence=(
                "Screenshot of browser alert dialogue showing the target domain name, "
                "triggered by your test payload."
            ),
            learner_input=(
                "Test payload: <script>alert(document.domain)</script> "
                "Fallback (if script tags filtered): <img src=x onerror=alert(document.domain)>"
            ),
            completion_validation=(
                "Alert box screenshot captured showing domain name. "
                "No cookie theft or session hijacking attempted."
            ),
            next_step="xss_b01_s04",
        ),
        GuidedStep(
            step_id="xss_b01_s04",
            title="Assess Impact Scope",
            explanation=(
                "Evaluate who is at risk: just the attacker themselves (low impact) or "
                "all authenticated users (high impact). Check whether the vulnerable page "
                "is accessible without authentication. For stored XSS, note which user roles "
                "would see the injected content."
            ),
            why_this_matters=(
                "Impact scope directly determines the CVSS severity score and prioritisation. "
                "A stored XSS on an admin dashboard is critical; a reflected XSS on a "
                "non-authenticated error page may be low."
            ),
            expected_evidence=(
                "Notes on: authentication required to reach vulnerable page, user roles "
                "affected, whether cookies are HttpOnly (limits JS-based theft)."
            ),
            learner_input=(
                "Check: does the page require login? Is the session cookie HttpOnly? "
                "Does the stored payload appear on pages other users would visit?"
            ),
            completion_validation=(
                "Impact scope documented: affected roles, authentication context, "
                "HttpOnly cookie status noted."
            ),
            next_step="xss_b01_s05",
        ),
        GuidedStep(
            step_id="xss_b01_s05",
            title="Document and Communicate the Finding",
            explanation=(
                "Document: URL, parameter/field, XSS type, context (attribute/body/DOM), "
                "proof-of-concept payload, impact scope, CVSS score. Remediation: "
                "output encode all user-supplied data at render time using context-appropriate "
                "encoding (HTML entity, JS string escaping, etc.)."
            ),
            why_this_matters=(
                "Developers need to know exactly where to add encoding. "
                "'Sanitise user input' is too vague — they need the exact template, method, "
                "or view function that renders the vulnerable output."
            ),
            expected_evidence=(
                "Written finding with: URL, parameter, type, proof screenshot, "
                "CVSS score, remediation recommendation."
            ),
            learner_input=None,
            completion_validation=(
                "Finding documented with all required fields. Remediation recommendation included: "
                "context-aware output encoding using the application's template engine escaping "
                "or a security library such as OWASP Java Encoder / DOMPurify."
            ),
            next_step=None,
        ),
    ],
    completion_checks=[
        "Reflection point identified with context noted",
        "XSS type determined (reflected / stored / DOM)",
        "Execution confirmed via alert(document.domain) screenshot",
        "Impact scope assessed (roles, auth context, HttpOnly)",
        "Finding documented with context-aware encoding recommendation",
    ],
    next_paths=["xss_intermediate_01"],
)
