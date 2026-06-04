"""Auth Bypass / Weak Credentials Beginner learning path configuration."""

from apps.investigation_core.models.learning import GuidedStep, LearningPath

AUTH_BEGINNER = LearningPath(
    path_id="auth_beginner_01",
    title="Authentication Weaknesses — Beginner",
    difficulty="beginner",
    finding_types=[
        "auth_bypass",
        "weak_credentials",
        "default_credentials",
        "ssh_cred",
        "cleartext_transmission",
        "credential_exposure",
    ],
    required_skills=[],
    learning_objectives=[
        "Enumerate authentication surfaces exposed by the target",
        "Test for default and trivially-guessable credentials",
        "Analyse password policy enforcement",
        "Inspect session token strength and transport security",
        "Document findings with actionable remediations",
    ],
    guided_steps=[
        GuidedStep(
            step_id="auth_b01_s01",
            title="Enumerate Authentication Surfaces",
            explanation=(
                "Authentication surfaces are every entry point that accepts credentials: "
                "web login forms, SSH, FTP, SMB/CIFS, admin panels (e.g. /admin, /manager), "
                "API endpoints with Bearer or Basic auth, and database interfaces. "
                "Map every surface before testing any of them."
            ),
            why_this_matters=(
                "Testing one login form while missing a default-credentials SSH service "
                "gives an incomplete picture. Adversaries enumerate all surfaces to find "
                "the weakest link. Your assessment must cover the same attack surface."
            ),
            expected_evidence=(
                "List of every authentication endpoint found: URLs, ports, protocols, "
                "and authentication type for each."
            ),
            learner_input=(
                "Review nmap/service scan output for open ports with auth services. "
                "Browse to common admin paths. List each surface with its protocol and port."
            ),
            completion_validation=(
                "All authentication surfaces documented with port, protocol, and auth type."
            ),
            next_step="auth_b01_s02",
        ),
        GuidedStep(
            step_id="auth_b01_s02",
            title="Test Default and Common Credentials",
            explanation=(
                "Default credentials are vendor-assigned logins that should be changed on "
                "first use but frequently are not. Common defaults: admin/admin, admin/password, "
                "root/root, admin/(empty). For SSH, also test root/root and service account "
                "names matching the running software. Use only credentials from published vendor "
                "default lists — do not brute-force."
            ),
            why_this_matters=(
                "Default credentials are the single most common reason network services are "
                "compromised in practice. A single test against a known default list takes "
                "seconds and reveals a critical vulnerability that is trivial to exploit."
            ),
            expected_evidence=(
                "For each tested service: the credential pairs tried, and whether any succeeded. "
                "If successful: the exact credential pair and the access level it granted."
            ),
            learner_input=(
                "Test admin/admin, admin/password, root/(empty), and any product-specific"
                " defaults. Record every attempt and its outcome. Stop after confirming"
                " access — do not take further action with compromised credentials."
            ),
            completion_validation=(
                "Default credential test completed on all surfaces. "
                "Results (success/failure) documented for each pair tried."
            ),
            next_step="auth_b01_s03",
        ),
        GuidedStep(
            step_id="auth_b01_s03",
            title="Analyse Password Policy Enforcement",
            explanation=(
                "A strong password policy requires: minimum 12 characters, mixed case, "
                "digits, special characters, and should enforce these server-side. "
                "Test whether the application: (a) accepts a 1-character password, "
                "(b) accepts a password identical to the username, "
                "(c) enforces complexity rules after a successful login attempt. "
                "This is a black-box test — do not create real accounts."
            ),
            why_this_matters=(
                "Weak password policies silently permit users to set trivially-guessable passwords "
                "even when no default credentials exist. Policy bypass means password spray "
                "attacks become viable against all accounts."
            ),
            expected_evidence=(
                "Server responses to registration or password-change requests with weak inputs. "
                "Note: does the server reject or accept a 1-character password?"
            ),
            learner_input=(
                "If a registration or password change form exists, attempt to set password='a'. "
                "Check the HTTP response: 400 = policy enforced, 200/redirect = policy absent."
            ),
            completion_validation=(
                "Password policy enforcement tested and result documented: "
                "enforced (with minimum requirements), partial, or absent."
            ),
            next_step="auth_b01_s04",
        ),
        GuidedStep(
            step_id="auth_b01_s04",
            title="Inspect Session Token Strength and Transport",
            explanation=(
                "After authenticating with a valid test account, inspect the session token: "
                "Is it transmitted over HTTPS only? Is the cookie flagged Secure and HttpOnly? "
                "Is the token sufficiently random (128+ bits of entropy)? "
                "Check whether the token is exposed in URLs or logs."
            ),
            why_this_matters=(
                "A strong password policy is meaningless if the resulting session token "
                "can be stolen in transit (no HTTPS) or via script (no HttpOnly). "
                "Token weaknesses turn authentication bypass into a one-step attack."
            ),
            expected_evidence=(
                "Browser DevTools Network tab showing: Set-Cookie header with Secure/HttpOnly "
                "flags, token length and apparent entropy, whether the token appears in URLs."
            ),
            learner_input=(
                "Log in with a test account. Open DevTools → Network → find the Set-Cookie header. "
                "Check flags: Secure, HttpOnly, SameSite. Note the token length."
            ),
            completion_validation=(
                "Session token flags documented: Secure (yes/no), HttpOnly (yes/no), "
                "SameSite policy, token length, and transport (HTTPS/HTTP)."
            ),
            next_step="auth_b01_s05",
        ),
        GuidedStep(
            step_id="auth_b01_s05",
            title="Document Findings and Remediations",
            explanation=(
                "Compile all authentication weaknesses into discrete findings. Each finding "
                "should be independently actionable. Common remediations: rotate default "
                "credentials immediately, enforce password policy server-side, add Secure and "
                "HttpOnly cookie flags, enforce HTTPS via HSTS, implement account lockout "
                "after N failed attempts."
            ),
            why_this_matters=(
                "Authentication findings are typically high or critical severity. "
                "Clear, actionable remediations reduce time-to-fix and demonstrate that "
                "the tester understands both the risk and the fix, not just the vulnerability."
            ),
            expected_evidence=(
                "One finding entry per weakness with: affected service/endpoint, "
                "vulnerability description, proof of concept, CVSS score, and specific remediation."
            ),
            learner_input=None,
            completion_validation=(
                "All authentication weaknesses documented as separate findings. "
                "Each finding includes: surface, evidence, CVSS, and remediation steps."
            ),
            next_step=None,
        ),
    ],
    completion_checks=[
        "All authentication surfaces enumerated",
        "Default credential test performed on all surfaces",
        "Password policy enforcement tested",
        "Session token flags and transport documented",
        "All findings documented with actionable remediations",
    ],
    next_paths=["auth_intermediate_01"],
)
