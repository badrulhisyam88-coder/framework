# ruff: noqa: E501
"""Deterministic finding interpretation templates — contextual investigation guidance.

Each entry maps a normalized finding_type to investigation-centric language:
  - headline:           single-line interpretation
  - meaning:            what the finding means to a defender / learner
  - ctf_objectives:     list of CTF/lab objectives this finding may enable
  - evidence_goals:     list of evidence items the user should capture
  - learning_concepts:  list of concepts being exercised
  - actions:            GuidedAction IDs that apply to this finding
  - learning_path:      matching learning path ID
  - severity_class:     UI colour class

NO LLM. NO autonomous reasoning. Templates only.
"""

from __future__ import annotations

import re

DEFAULT_INTERPRETATION: dict[str, object] = {
    "headline":         "Finding identified",
    "meaning":          "Examine the finding details to determine its impact.",
    "ctf_objectives":   [],
    "evidence_goals":   ["Captured note describing the finding and its context"],
    "learning_concepts": [],
    "actions":          [],
    "learning_path":    None,
    "severity_class":   "info",
}


FINDING_INTERPRETATIONS: dict[str, dict[str, object]] = {

    # ── SQL Injection family ─────────────────────────────────────────────
    "sqli": {
        "headline":  "Possible SQL injection identified",
        "meaning":   "User input on this endpoint may be interpreted as SQL code instead of data. The query can be manipulated by crafted input.",
        "ctf_objectives": [
            "Bypass authentication without valid credentials",
            "Enumerate user accounts via UNION queries",
            "Extract database schema and version",
        ],
        "evidence_goals": [
            "HTTP request and response showing the vulnerable parameter",
            "Authenticated session obtained without valid credentials",
            "Database version or table name extracted via injection",
        ],
        "learning_concepts": [
            "Boolean SQL injection",
            "UNION-based extraction",
            "Authentication trust boundaries",
            "Parameterised queries as defence",
        ],
        "actions":          ["sqli_auth_bypass", "sqli_boolean_confirmation"],
        "learning_path":    "sqli_beginner_01",
        "severity_class":   "high",
    },
    "sql_injection": {
        "headline":  "Possible SQL injection identified",
        "meaning":   "User input on this endpoint may be interpreted as SQL code. The application is concatenating input directly into queries.",
        "ctf_objectives": [
            "Bypass authentication without valid credentials",
            "Enumerate user accounts",
            "Extract sensitive data",
        ],
        "evidence_goals": [
            "Reproducible injection payload and the resulting response",
            "Authenticated session captured without valid credentials",
            "Schema or version data extracted from the database",
        ],
        "learning_concepts": [
            "Boolean SQL injection",
            "Authentication trust boundaries",
            "Output context vs query context",
        ],
        "actions":          ["sqli_auth_bypass", "sqli_boolean_confirmation"],
        "learning_path":    "sqli_beginner_01",
        "severity_class":   "high",
    },
    "sqli_error_based": {
        "headline":  "Error-based SQL injection — database errors leaked",
        "meaning":   "The application returns SQL error messages, exposing the database engine and query structure.",
        "ctf_objectives": [
            "Identify database engine and version",
            "Extract data directly via error messages",
        ],
        "evidence_goals": [
            "Captured error response containing SQL details",
            "Database version string extracted from an error",
        ],
        "learning_concepts": [
            "Error-based extraction",
            "Information disclosure via verbose errors",
            "Why production should suppress detailed errors",
        ],
        "actions":          ["sqli_boolean_confirmation", "sqli_version_extraction"],
        "learning_path":    "sqli_beginner_01",
        "severity_class":   "high",
    },
    "sqli_blind": {
        "headline":  "Blind SQL injection — logic differs on truthy payloads",
        "meaning":   "No visible output but response timing or content changes when a SQL clause is true vs false.",
        "ctf_objectives": [
            "Confirm injection via time-based or boolean signals",
            "Extract data character-by-character via blind techniques",
        ],
        "evidence_goals": [
            "Two HTTP responses (truthy vs falsy) showing measurable difference",
            "Timing measurement confirming blind extraction",
        ],
        "learning_concepts": [
            "Blind/time-based SQL injection",
            "Side-channel inference",
            "Response timing as a covert channel",
        ],
        "actions":          ["sqli_boolean_confirmation"],
        "learning_path":    "sqli_intermediate_01",
        "severity_class":   "high",
    },

    # ── XSS family ───────────────────────────────────────────────────────
    "xss": {
        "headline":  "Possible cross-site scripting",
        "meaning":   "Untrusted input may render directly in a user's browser, allowing JavaScript execution in the target origin.",
        "ctf_objectives": [
            "Execute arbitrary JavaScript in a victim's browser",
            "Steal session tokens via document.cookie",
            "Impersonate an authenticated user",
        ],
        "evidence_goals": [
            "Screenshot of alert(document.domain) executing in the target origin",
            "HTTP response showing payload reflected without encoding",
            "Captured session token via JavaScript exfiltration to a controlled endpoint",
        ],
        "learning_concepts": [
            "Output context encoding",
            "Same-origin policy",
            "Session token confidentiality",
        ],
        "actions":          ["xss_reflection_probe"],
        "learning_path":    "xss_beginner_01",
        "severity_class":   "high",
    },
    "reflected_xss": {
        "headline":  "Reflected XSS — input echoed into the response",
        "meaning":   "Input is reflected directly into the HTML response. A crafted payload will execute in the visitor's browser.",
        "ctf_objectives": [
            "Execute JavaScript in a victim's browser via crafted URL",
            "Phish a logged-in user into running attacker JS",
        ],
        "evidence_goals": [
            "URL containing the working XSS payload",
            "Screenshot of alert(document.domain) in the target origin",
            "Captured cookie via JS exfiltration",
        ],
        "learning_concepts": [
            "HTML context encoding",
            "URL-based attack delivery",
            "CSP as defence-in-depth",
        ],
        "actions":          ["xss_reflection_probe", "xss_execution_proof"],
        "learning_path":    "xss_beginner_01",
        "severity_class":   "high",
    },
    "xss_reflected": {
        "headline":  "Reflected XSS — input echoed into the response",
        "meaning":   "Input is reflected directly into the HTML response. A crafted payload will execute in the visitor's browser.",
        "ctf_objectives": [
            "Execute JavaScript via crafted URL",
            "Steal session cookies from logged-in users",
        ],
        "evidence_goals": [
            "URL containing the working payload",
            "Screenshot of executed payload",
        ],
        "learning_concepts": [
            "HTML context encoding",
            "Crafted URL delivery",
        ],
        "actions":          ["xss_reflection_probe", "xss_execution_proof"],
        "learning_path":    "xss_beginner_01",
        "severity_class":   "high",
    },
    "stored_xss": {
        "headline":  "Stored XSS — payload persists in the application",
        "meaning":   "Input is stored and re-rendered to other users, executing in their browsers when they visit the affected page.",
        "ctf_objectives": [
            "Admin account takeover via JavaScript executing in admin's session",
            "Persistent impersonation across page visits",
        ],
        "evidence_goals": [
            "Captured payload in stored content",
            "Screenshot of payload executing for a different user role",
            "Documented scope: who sees the payload",
        ],
        "learning_concepts": [
            "Stored vs reflected XSS",
            "Multi-user impact assessment",
            "Output encoding at render time, not at input time",
        ],
        "actions":          ["xss_reflection_probe"],
        "learning_path":    "xss_intermediate_01",
        "severity_class":   "critical",
    },
    "xss_stored": {
        "headline":  "Stored XSS — payload persists in the application",
        "meaning":   "Input is stored and re-rendered to other users, executing in their browsers.",
        "ctf_objectives": [
            "Admin takeover via persistent JS",
            "Mass session compromise",
        ],
        "evidence_goals": [
            "Stored payload visible in the application data",
            "Payload executing in a second-user session",
        ],
        "learning_concepts": [
            "Stored vs reflected XSS",
            "Render-time encoding",
        ],
        "actions":          ["xss_reflection_probe"],
        "learning_path":    "xss_intermediate_01",
        "severity_class":   "critical",
    },
    "dom_xss": {
        "headline":  "DOM-based XSS — client-side sink",
        "meaning":   "Client-side JavaScript writes attacker input to a DOM sink without sanitisation. Server-side encoding does not help here.",
        "ctf_objectives": [
            "Execute JavaScript via crafted URL fragments",
            "Demonstrate sink-level vulnerability independent of server",
        ],
        "evidence_goals": [
            "URL fragment containing the payload",
            "DOM snapshot showing the sink rendering attacker input",
        ],
        "learning_concepts": [
            "DOM source/sink data flow",
            "Why client-side sanitisation differs from server-side",
        ],
        "actions":          [],
        "learning_path":    "xss_intermediate_01",
        "severity_class":   "high",
    },

    # ── Authentication family ────────────────────────────────────────────
    "auth_bypass": {
        "headline":  "Authentication bypass may be possible",
        "meaning":   "Authentication may be bypassed via injection or logic flaw on this endpoint.",
        "ctf_objectives": [
            "Log in as admin without valid credentials",
            "Identify the email of the bypassed account in the response",
            "Inspect admin-only functionality after bypass",
        ],
        "evidence_goals": [
            "Authenticated response captured (session cookie or JWT)",
            "Account identity (email) visible in the bypassed session",
            "Screenshot of admin-only page after login",
        ],
        "learning_concepts": [
            "SQL injection authentication bypass",
            "Authentication trust boundaries",
            "Server-side authorisation enforcement",
        ],
        "actions":          ["sqli_auth_bypass", "auth_default_cred_test"],
        "learning_path":    "auth_beginner_01",
        "severity_class":   "critical",
    },
    "weak_credentials": {
        "headline":  "Weak credentials accepted",
        "meaning":   "The service accepts predictable username/password combinations.",
        "ctf_objectives": [
            "Authenticate using a guessed or default credential pair",
            "Document which pair worked",
        ],
        "evidence_goals": [
            "The exact credential pair that succeeded",
            "Captured authenticated session (cookie or JWT)",
        ],
        "learning_concepts": [
            "Default credential enumeration",
            "Account-lockout policies",
            "Password policy enforcement",
        ],
        "actions":          ["auth_default_cred_test"],
        "learning_path":    "auth_beginner_01",
        "severity_class":   "high",
    },
    "default_credentials": {
        "headline":  "Vendor default credentials in use",
        "meaning":   "The service still uses out-of-the-box vendor defaults.",
        "ctf_objectives": [
            "Authenticate using vendor-published default credentials",
            "Identify which default pair worked",
        ],
        "evidence_goals": [
            "Vendor-default username and password that succeeded",
            "Authenticated response confirming access",
        ],
        "learning_concepts": [
            "Vendor-default credential databases",
            "Setup checklists during deployment",
        ],
        "actions":          ["auth_default_cred_test"],
        "learning_path":    "auth_beginner_01",
        "severity_class":   "high",
    },
    "credential_exposure": {
        "headline":  "Credentials exposed",
        "meaning":   "Credentials are visible in source, headers, or unencrypted traffic.",
        "ctf_objectives": [
            "Capture the exposed credential and reuse it",
            "Document the exposure path (source comment, header, network capture)",
        ],
        "evidence_goals": [
            "The exact credential, redacted as appropriate",
            "Note describing how it was exposed",
        ],
        "learning_concepts": [
            "Secret management",
            "Source comment hygiene",
            "Transport security",
        ],
        "actions":          ["auth_default_cred_test"],
        "learning_path":    "auth_beginner_01",
        "severity_class":   "high",
    },
    "cleartext_transmission": {
        "headline":  "Cleartext credential transmission",
        "meaning":   "Authentication occurs over an unencrypted protocol.",
        "ctf_objectives": [
            "Capture credentials via network position (lab only)",
            "Demonstrate downgrade risk to compliance auditors",
        ],
        "evidence_goals": [
            "Network capture showing the cleartext credential",
            "Note documenting which port/protocol was unencrypted",
        ],
        "learning_concepts": [
            "Transport-layer encryption",
            "Network-position threat model",
            "HTTPS-only redirects and HSTS",
        ],
        "actions":          ["tls_config_audit"],
        "learning_path":    "web_hardening_beginner_01",
        "severity_class":   "high",
    },

    # ── CVE / vulnerability database ─────────────────────────────────────
    "cve_matched": {
        "headline":  "Known CVE matched against this target",
        "meaning":   "The target's service version matches a publicly disclosed vulnerability with a documented exploitation path.",
        "ctf_objectives": [
            "Confirm exploitability via published PoC",
            "Document the CVE-to-version chain",
        ],
        "evidence_goals": [
            "CVE identifier and CVSS score",
            "Captured response showing the vulnerable version banner",
            "Reference to public advisory or PoC",
        ],
        "learning_concepts": [
            "CVE numbering and CVSS scoring",
            "Patch hygiene as a defensive control",
            "Public exploit databases",
        ],
        "actions":          [],
        "learning_path":    None,
        "severity_class":   "high",
    },
    "known_vulnerability": {
        "headline":  "Known vulnerability detected",
        "meaning":   "The service version is documented as vulnerable in public sources.",
        "ctf_objectives": [
            "Confirm the version-vulnerability mapping",
            "Document the public advisory reference",
        ],
        "evidence_goals": [
            "Version banner confirming the vulnerable version",
            "Reference to the public advisory",
        ],
        "learning_concepts": [
            "Version-banner driven attack",
            "Patch management",
        ],
        "actions":          [],
        "learning_path":    None,
        "severity_class":   "high",
    },

    # ── Recon / surface ──────────────────────────────────────────────────
    "open_port_detected": {
        "headline":  "Open service port",
        "meaning":   "A service is listening on this port — investigation surface.",
        "ctf_objectives": [
            "Identify the service and version",
            "Map the open port to known attack surface",
        ],
        "evidence_goals": [
            "Service banner if available",
            "Port-to-service mapping documented",
        ],
        "learning_concepts": [
            "Service enumeration",
            "Attack-surface mapping",
        ],
        "actions":          [],
        "learning_path":    None,
        "severity_class":   "info",
    },
    "http_service_detected": {
        "headline":  "HTTP/HTTPS service detected",
        "meaning":   "A web service is reachable on this port — primary web attack surface for the investigation.",
        "ctf_objectives": [
            "Identify web framework and version",
            "Enumerate web endpoints and entry points",
        ],
        "evidence_goals": [
            "Response headers captured (Server, X-Powered-By)",
            "Web technology fingerprint documented",
        ],
        "learning_concepts": [
            "Web attack-surface enumeration",
            "HTTP service fingerprinting",
        ],
        "actions":          [],
        "learning_path":    None,
        "severity_class":   "info",
    },
    "service_banner_disclosed": {
        "headline":  "Service banner discloses version",
        "meaning":   "The service banner reveals product and version — useful for CVE lookup and targeted exploitation.",
        "ctf_objectives": [
            "Match the disclosed version against the CVE database",
            "Identify the most relevant known exploit",
        ],
        "evidence_goals": [
            "Captured service banner with exact version string",
            "CVE references matching the version",
        ],
        "learning_concepts": [
            "Banner-based fingerprinting",
            "Version-to-CVE mapping",
            "Banner suppression as a hardening control",
        ],
        "actions":          [],
        "learning_path":    None,
        "severity_class":   "medium",
    },

    # ── Hardening / misconfig family ─────────────────────────────────────
    "security_misconfiguration": {
        "headline":  "Security misconfiguration",
        "meaning":   "A hardening control is missing or weakly applied — missing security headers, permissive CORS, verbose errors, or exposed admin paths. By itself often low risk, but chains with other findings (e.g. missing CSP + reflected XSS).",
        "ctf_objectives": [
            "Combine with other findings for higher-impact exploitation",
            "Identify which controls are missing or misconfigured",
            "Map each missing header to its protection",
        ],
        "evidence_goals": [
            "Captured HTTP response showing the missing header(s)",
            "Audit note listing each missing control and its purpose",
            "Cookie flag audit (HttpOnly, Secure, SameSite)",
        ],
        "learning_concepts": [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "Cookie security flags",
            "Defence-in-depth chaining",
        ],
        "actions":          ["security_headers_audit"],
        "learning_path":    "web_hardening_beginner_01",
        "severity_class":   "medium",
    },
    "information_disclosure": {
        "headline":  "Information disclosure",
        "meaning":   "The application leaks information useful for further investigation: version banners, stack traces, internal paths, error details, or debug data.",
        "ctf_objectives": [
            "Map leaked information to attack surface",
            "Identify framework, library, or product versions",
            "Refine attack approach based on disclosed details",
        ],
        "evidence_goals": [
            "Captured response containing the leak",
            "Catalogue of leaked elements + what each enables",
        ],
        "learning_concepts": [
            "Reconnaissance via error pages",
            "Banner suppression",
            "Production error handling",
        ],
        "actions":          ["info_disclosure_inspect"],
        "learning_path":    "web_hardening_beginner_01",
        "severity_class":   "low",
    },
    "http_only_site": {
        "headline":  "Site served over plain HTTP (no TLS)",
        "meaning":   "Traffic to this site is unencrypted. Credentials, session tokens, and content are visible to anyone on the network path.",
        "ctf_objectives": [
            "Demonstrate credential capture risk on shared networks",
            "Document compliance/audit findings",
        ],
        "evidence_goals": [
            "HTTP request showing cleartext form submission",
            "Note documenting which endpoints are HTTP-only",
        ],
        "learning_concepts": [
            "Transport security",
            "HSTS as enforcement",
            "Network-position threat model",
        ],
        "actions":          ["tls_config_audit"],
        "learning_path":    "web_hardening_beginner_01",
        "severity_class":   "medium",
    },
    "broken_access_control": {
        "headline":  "Broken access control",
        "meaning":   "The application may not enforce authorisation server-side on protected resources. UI-only hiding is not access control.",
        "ctf_objectives": [
            "Access another user's data by changing the resource ID",
            "Reach admin endpoints as a regular user",
            "Document horizontal vs vertical privilege escalation",
        ],
        "evidence_goals": [
            "Two HTTP responses showing the same resource fetched by two users",
            "Admin endpoint accessed as a regular user",
            "Resource ID enumeration showing other users' data",
        ],
        "learning_concepts": [
            "Server-side authorisation enforcement",
            "IDOR (Insecure Direct Object References)",
            "Vertical vs horizontal privilege escalation",
        ],
        "actions":          ["access_control_probe"],
        "learning_path":    "web_hardening_beginner_01",
        "severity_class":   "high",
    },
    "tls_weakness": {
        "headline":  "Weak TLS configuration",
        "meaning":   "TLS version or cipher suite below current best-practice.",
        "ctf_objectives": [
            "Demonstrate exposure to known TLS attacks (BEAST, POODLE, SWEET32)",
            "Document compliance gap",
        ],
        "evidence_goals": [
            "Negotiated TLS version and cipher suite for the target",
            "List of weak ciphers/protocols accepted",
        ],
        "learning_concepts": [
            "TLS protocol versions",
            "Cipher suite selection",
            "Forward secrecy",
        ],
        "actions":          ["tls_config_audit"],
        "learning_path":    "web_hardening_beginner_01",
        "severity_class":   "medium",
    },
    "ssl_weak": {
        "headline":  "Weak SSL/TLS configuration",
        "meaning":   "Deprecated SSL/TLS protocol or cipher in use.",
        "ctf_objectives": [
            "Document deprecated protocols still accepted",
            "Map weaknesses to known CVEs",
        ],
        "evidence_goals": [
            "Audit output showing accepted protocols and ciphers",
            "Certificate details",
        ],
        "learning_concepts": [
            "SSL/TLS deprecation timeline",
            "Cipher suite hardening",
        ],
        "actions":          ["tls_config_audit"],
        "learning_path":    "web_hardening_beginner_01",
        "severity_class":   "medium",
    },
}


# Canonical objective keys used by unlock_rules.py and the milestone chain.
# Maps (finding_type, exact objective text) → stable key. Anything not here
# falls back to a deterministic slug.
_OBJECTIVE_KEY_OVERRIDES: dict[tuple[str, str], str] = {
    # SQLi chain
    ("sqli",         "Bypass authentication without valid credentials"): "sqli:auth_bypass",
    ("sqli",         "Enumerate user accounts via UNION queries"):       "sqli:user_enumeration",
    ("sqli",         "Extract database schema and version"):             "sqli:db_enumerated",
    ("sql_injection","Bypass authentication without valid credentials"): "sqli:auth_bypass",
    ("sql_injection","Enumerate user accounts"):                          "sqli:user_enumeration",
    ("sql_injection","Extract sensitive data"):                           "sqli:db_enumerated",
    ("sqli_error_based","Identify database engine and version"):          "sqli:db_enumerated",
    ("sqli_error_based","Extract data directly via error messages"):      "sqli:error_extraction",
    ("sqli_blind",   "Confirm injection via time-based or boolean signals"): "sqli:injection_confirmed",

    # XSS chain
    ("xss",          "Execute arbitrary JavaScript in a victim's browser"):    "xss:reflection_confirmed",
    ("xss",          "Steal session tokens via document.cookie"):              "xss:session_theft_demonstrated",
    ("reflected_xss","Execute JavaScript in a victim's browser via crafted URL"): "xss:reflection_confirmed",
    ("xss_reflected","Execute JavaScript via crafted URL"):                    "xss:reflection_confirmed",
    ("stored_xss",   "Admin account takeover via JavaScript executing in admin's session"): "xss:stored_admin_takeover",

    # Auth chain
    ("auth_bypass",      "Log in as admin without valid credentials"): "auth:admin_bypass",
    ("weak_credentials", "Authenticate using a guessed or default credential pair"): "auth:default_credentials",
    ("default_credentials","Authenticate using vendor-published default credentials"): "auth:default_credentials",
}


def _slugify(text: str) -> str:
    """Convert an objective string to a stable lowercase slug.

    Length cap is intentionally generous (96) so most CTF objective strings
    survive intact — the slug is the stable identifier referenced by milestone
    records, so trimming it risks collisions across long objective phrases.
    """
    s = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return s[:96]


def objective_key(finding_type: str, objective: str) -> str:
    """Produce a stable identifier for a (finding_type, objective) pair."""
    override = _OBJECTIVE_KEY_OVERRIDES.get((finding_type, objective))
    if override:
        return override
    return f"{finding_type}:{_slugify(objective)}"


def interpret(finding_type: str) -> dict[str, object]:
    """Return the interpretation dict for a finding type, falling back to default.

    Augments the static dict with `ctf_objective_keys` — a parallel list of
    stable identifiers for each ctf_objective. These are used by the milestone
    system to track which CTF objectives the user has confirmed achieving.
    """
    base = FINDING_INTERPRETATIONS.get(finding_type, DEFAULT_INTERPRETATION)
    enriched = dict(base)
    objectives = list(base.get("ctf_objectives") or [])  # type: ignore[arg-type]
    enriched["ctf_objective_keys"] = [
        objective_key(finding_type, o) for o in objectives
    ]
    return enriched
