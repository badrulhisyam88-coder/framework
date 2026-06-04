# ruff: noqa: E501
"""Web Hardening Beginner learning path configuration.

Covers the finding types ZAP/Nuclei commonly produce against modern web targets
(missing headers, information disclosure, TLS gaps, access control issues).
These are the most frequent findings in a typical scan — this path ensures the
Learning tab is populated with actionable guidance after any web scan.
"""

from apps.investigation_core.models.learning import GuidedStep, LearningPath

WEB_HARDENING_BEGINNER = LearningPath(
    path_id="web_hardening_beginner_01",
    title="Web Hardening — Beginner",
    difficulty="beginner",
    finding_types=[
        "security_misconfiguration",
        "information_disclosure",
        "tls_weakness",
        "ssl_weak",
        "http_only_site",
        "cleartext_transmission",
        "broken_access_control",
    ],
    required_skills=[],
    learning_objectives=[
        "Identify which security headers are missing and why each one matters",
        "Assess what an application accidentally reveals about its internals",
        "Evaluate TLS posture: protocols, ciphers, certificates, mixed content",
        "Test authorisation enforcement on protected resources",
        "Combine multiple low-severity findings into a meaningful risk narrative",
    ],
    guided_steps=[
        GuidedStep(
            step_id="webhard_b01_s01",
            title="Audit HTTP Security Headers",
            explanation=(
                "Modern browsers honour a set of HTTP response headers that restrict "
                "what content can be loaded, framed, or transmitted. Missing or weak "
                "headers let downstream attacks (XSS, clickjacking, downgrade) succeed "
                "with higher impact than they otherwise would."
            ),
            why_this_matters=(
                "A single XSS finding combined with a missing CSP becomes a full "
                "browser-side compromise. The same XSS with strict CSP is contained. "
                "Headers are the cheapest defensive control in web hardening."
            ),
            expected_evidence="Captured HTTP response showing the missing headers, with a note explaining what each protects.",
            learner_input=(
                "Open browser DevTools → Network. Reload the target. Inspect the response "
                "headers. List: which of CSP, X-Frame-Options, HSTS, X-Content-Type-Options, "
                "Referrer-Policy, Permissions-Policy are missing? Note the protection each provides."
            ),
            completion_validation="At least one missing header documented with its purpose.",
        ),
        GuidedStep(
            step_id="webhard_b01_s02",
            title="Inspect Information Disclosure",
            explanation=(
                "Applications routinely leak information that helps attackers: version "
                "banners, stack traces, debug output, internal paths, and source comments. "
                "Each leak narrows the search space for an attacker."
            ),
            why_this_matters=(
                "A version banner that exposes 'Apache/2.4.49' immediately maps to "
                "CVE-2021-41773. Stack traces reveal framework, library versions, and "
                "file paths. Reducing disclosure is a free attack-surface reduction."
            ),
            expected_evidence="Note listing each leaked element + what an attacker could do with it.",
            learner_input=(
                "Trigger an error (malformed input, invalid URL). Capture the response. "
                "Check headers (Server, X-Powered-By, X-AspNet-Version). View the page source "
                "for HTML comments and inline error data. Document every leak."
            ),
            completion_validation="At least 2 disclosed elements catalogued with their security implications.",
        ),
        GuidedStep(
            step_id="webhard_b01_s03",
            title="Review TLS Posture",
            explanation=(
                "TLS protects credentials, sessions, and traffic content. Weak protocols "
                "(SSL 3.0, TLS 1.0/1.1), weak ciphers (NULL, RC4, 3DES), invalid or expired "
                "certificates, and HTTP-served sites all create downgrade or capture risk."
            ),
            why_this_matters=(
                "HTTP-only authentication forms let any device on the network path "
                "(open WiFi, captive portal, ISP) read credentials. Outdated TLS lets "
                "old attacks like BEAST/POODLE work on modern targets."
            ),
            expected_evidence="TLS audit note: supported protocols, ciphers, certificate status, mixed-content findings.",
            learner_input=(
                "Run: curl -v https://target  (or use testssl.sh if available). "
                "Note: protocol version negotiated, cipher suite, certificate validity, "
                "whether HTTP redirects to HTTPS. Flag any TLS 1.0/1.1 support, weak ciphers, "
                "or HTTP-only forms."
            ),
            completion_validation="TLS posture documented; at least one weakness or compliance gap identified, OR a clean baseline recorded.",
        ),
        GuidedStep(
            step_id="webhard_b01_s04",
            title="Test Access Control",
            explanation=(
                "Applications often enforce authorisation in the UI ('hide the admin link') "
                "but skip server-side checks on the actual endpoint. Manipulating URLs, "
                "IDs, or HTTP methods often reaches data the current user should not see."
            ),
            why_this_matters=(
                "Broken access control is OWASP's #1 risk for a reason — it's common, "
                "trivial to exploit, and high impact. A user changing /api/users/me to "
                "/api/users/1 should be denied. When it's not, every user's data is exposed."
            ),
            expected_evidence="Note of each endpoint tested + result (enforced, bypassed, partial). Captured response for any bypass.",
            learner_input=(
                "Identify a few protected endpoints (user profile, admin pages, settings). "
                "Try: a) accessing as a different user, b) changing the resource ID in the URL, "
                "c) using HTTP methods the UI doesn't expose. Record each test."
            ),
            completion_validation="At least 3 endpoints tested; each result documented.",
        ),
        GuidedStep(
            step_id="webhard_b01_s05",
            title="Synthesise Findings into a Hardening Brief",
            explanation=(
                "Individual low-severity findings rarely look urgent. Combined, they tell "
                "a hardening-posture story: missing CSP + reflected XSS = full browser compromise. "
                "HTTP + missing HSTS = downgrade-capable credential capture."
            ),
            why_this_matters=(
                "Defenders need a prioritised list of fixes, not a flat dump of low-severity items. "
                "Synthesis turns 'lots of small issues' into 'these three controls would address all of them'."
            ),
            expected_evidence="Hardening brief: top 3 recommended fixes, each with the findings it addresses and the controls it enables.",
            learner_input=(
                "Group your findings: which are 'add a missing control' (headers, HSTS), "
                "which are 'remove a leak' (banners, error verbosity), which are 'enforce on server' "
                "(authorisation, input validation). Write the brief as 3 prioritised recommendations."
            ),
            completion_validation="Synthesised brief covers the major categories detected; remediation is server-side and concrete.",
        ),
    ],
    completion_checks=[
        "Security header audit completed with at least one missing header explained",
        "Information disclosure inventory completed",
        "TLS posture reviewed",
        "Access control tested on at least 3 endpoints",
        "Hardening brief produced with prioritised remediations",
    ],
    next_paths=[],
)
