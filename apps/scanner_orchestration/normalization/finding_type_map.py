"""Canonical finding-type taxonomy and cross-scanner name mappings.

All scanner output runs through normalize_finding_type() to get a canonical
finding_type string that maps into the skill graph and learning system.
"""

from __future__ import annotations

# Canonical finding types → skill graph connection
# (matched against skill.related_findings in apps/investigation_core/skills/)
CANONICAL_FINDING_TYPES: frozenset[str] = frozenset({
    # SQL Injection
    "sqli", "sql_injection", "sqli_error_based", "sqli_blind", "sqli_stored",
    # XSS
    "xss", "reflected_xss", "xss_reflected", "stored_xss", "xss_stored",
    "dom_xss",
    # Authentication
    "auth_bypass", "weak_credentials", "default_credentials",
    "credential_exposure", "cleartext_transmission",
    # Network / Services
    "open_port_detected", "http_service_detected", "service_banner_disclosed",
    "ssh_cred", "smb_exposure",
    "tls_weakness", "ssl_weak",
    # Injection
    "command_injection", "xxe", "ssrf",
    # Access Control
    "broken_access_control", "path_traversal", "csrf",
    # Misc
    "security_misconfiguration", "information_disclosure",
    "cve_matched", "known_vulnerability",
})

# Fuzzy name → canonical type (case-insensitive prefix/substring matching)
_EXACT_MAP: dict[str, str] = {
    # SQL injection variants
    "sql injection": "sqli",
    "sql_injection": "sqli",
    "sqli": "sqli",
    "blind sql injection": "sqli_blind",
    "time-based sql injection": "sqli_blind",
    "time based sql injection": "sqli_blind",
    "boolean-based sql injection": "sqli_blind",
    "error-based sql injection": "sqli_error_based",
    "union-based sql injection": "sqli",
    "sql injection - stored": "sqli_stored",
    "sql injection (stored)": "sqli_stored",
    # XSS
    "cross-site scripting (reflected)": "xss_reflected",
    "cross-site scripting (persistent)": "xss_stored",
    "cross-site scripting (dom)": "dom_xss",
    "cross site scripting": "xss",
    "xss": "xss",
    "reflected xss": "xss_reflected",
    "stored xss": "xss_stored",
    "dom xss": "dom_xss",
    # Auth
    "default credentials": "default_credentials",
    "default password": "default_credentials",
    "weak credentials": "weak_credentials",
    "weak authentication": "weak_credentials",
    "authentication bypass": "auth_bypass",
    "broken authentication": "auth_bypass",
    "cleartext credentials": "cleartext_transmission",
    "cleartext transmission of sensitive information": "cleartext_transmission",
    "password transmitted in cleartext": "cleartext_transmission",
    "ssh - weak mac algorithms": "ssh_cred",
    "ssh weak algorithms": "ssh_cred",
    # Network
    "open port": "open_port_detected",
    "service exposure": "service_banner_disclosed",
    "smb signing disabled": "smb_exposure",
    "ssl/tls": "tls_weakness",
    "ssl certificate expired": "tls_weakness",
    "ssl certificate": "tls_weakness",
    "weak ssl": "ssl_weak",
    "tls weak": "tls_weakness",
    "weak tls": "tls_weakness",
    # Injection
    "command injection": "command_injection",
    "os command injection": "command_injection",
    "remote code execution": "command_injection",
    "xml external entity": "xxe",
    "xxe injection": "xxe",
    "server side request forgery": "ssrf",
    "ssrf": "ssrf",
    # Access
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "broken access control": "broken_access_control",
    "access control bypass": "broken_access_control",
    "csrf": "csrf",
    "cross-site request forgery": "csrf",
    # Misc
    "security misconfiguration": "security_misconfiguration",
    "misconfiguration": "security_misconfiguration",
    "information disclosure": "information_disclosure",
    "sensitive information disclosure": "information_disclosure",
    "information leakage": "information_disclosure",
    # CVE-linked — generic tag "cve" used by nuclei CVE templates
    "cve": "cve_matched",
    "known vulnerability": "known_vulnerability",
    # ── ZAP-specific alert names (Juice Shop / OWASP common findings) ───
    # SQLi
    "sql injection - error based": "sqli_error_based",
    "sql injection - time based (oracle)": "sqli_blind",
    "sql injection - time based (sqlite)": "sqli_blind",
    "sql injection - time based (mysql)": "sqli_blind",
    "sql injection - time based": "sqli_blind",
    "sql injection - authentication bypass": "sqli",
    # XSS
    "cross site scripting (reflected)": "xss_reflected",
    "cross site scripting (persistent)": "xss_stored",
    "cross site scripting (dom based)": "dom_xss",
    "reflected xss - attribute context": "xss_reflected",
    "reflected xss - html context": "xss_reflected",
    # CSRF / Headers
    "absence of anti-csrf tokens": "csrf",
    "anti-csrf tokens check": "csrf",
    # Security headers — map to security_misconfiguration
    "x-content-type-options header missing": "security_misconfiguration",
    "content security policy (csp) header not set": "security_misconfiguration",
    "content security policy header not set": "security_misconfiguration",
    "x-frame-options header not set": "security_misconfiguration",
    "missing anti-clickjacking header": "security_misconfiguration",
    "x-frame-options header": "security_misconfiguration",
    "permissions policy header not set": "security_misconfiguration",
    "strict transport security header not set": "security_misconfiguration",
    "http strict transport security header": "security_misconfiguration",
    # Cookie issues
    "cookie without samesite attribute": "security_misconfiguration",
    "cookies without samesite attribute": "security_misconfiguration",
    "cookie no httponly flag": "security_misconfiguration",
    "cookie without secure flag": "cleartext_transmission",
    "cookie without httponly flag set": "security_misconfiguration",
    "secure pages include mixed content": "cleartext_transmission",
    "http to https insecure transition in form post": "cleartext_transmission",
    # Information disclosure
    "application error disclosure": "information_disclosure",
    "information disclosure - debug error messages": "information_disclosure",
    "information disclosure - sensitive information in url": "information_disclosure",
    "information disclosure - suspicious comments": "information_disclosure",
    "timestamp disclosure - unix": "information_disclosure",
    "timestamp disclosure": "information_disclosure",
    "modern web application": "information_disclosure",
    "user agent fuzzer": "information_disclosure",
    # Auth / Access
    "user controllable html element attribute (potential xss)": "xss",
    "user controllable javascript event (xss)": "xss",
    "username hash found": "information_disclosure",
    "weak authentication method": "weak_credentials",
    "authentication request identified": "weak_credentials",
    # Injection
    "remote os command injection": "command_injection",
    "server side template injection": "command_injection",
    "xpath injection": "sqli",
    "ldap injection": "sqli",
    # Path
    "remote file inclusion": "path_traversal",
    # TLS / Crypto
    "ssl stripping": "tls_weakness",
    "insecure http method": "security_misconfiguration",
    "http methods - arbitrary headers": "security_misconfiguration",
    # Open redirect
    "open redirect": "broken_access_control",
    "external redirect": "broken_access_control",
    # SSRF
}

# Substring triggers (checked if exact match fails)
_SUBSTR_MAP: list[tuple[str, str]] = [
    ("sql inject", "sqli"),
    ("sqli", "sqli"),
    ("cross-site script", "xss"),
    ("cross site script", "xss"),
    ("xss", "xss"),
    ("default credential", "default_credentials"),
    ("default password", "default_credentials"),
    ("weak credential", "weak_credentials"),
    ("auth bypass", "auth_bypass"),
    ("broken auth", "auth_bypass"),
    ("cleartext", "cleartext_transmission"),
    ("command inject", "command_injection"),
    ("path traversal", "path_traversal"),
    ("directory traversal", "path_traversal"),
    ("csrf", "csrf"),
    ("ssrf", "ssrf"),
    ("xxe", "xxe"),
    ("ssl", "tls_weakness"),
    ("tls", "tls_weakness"),
    ("certificate", "tls_weakness"),
    ("smb", "smb_exposure"),
    ("information disclosure", "information_disclosure"),
    ("information leakage", "information_disclosure"),
    ("misconfigur", "security_misconfiguration"),
    ("cve-", "cve_matched"),
    ("vulnerabilit", "known_vulnerability"),
    # ZAP-specific substrings
    ("anti-csrf", "csrf"),
    ("samesite", "security_misconfiguration"),
    ("httponly", "security_misconfiguration"),
    ("x-content-type", "security_misconfiguration"),
    ("content-security-policy", "security_misconfiguration"),
    ("content security policy", "security_misconfiguration"),
    ("strict-transport", "security_misconfiguration"),
    ("x-frame-options", "security_misconfiguration"),
    ("clickjack", "security_misconfiguration"),
    ("timestamp disclosure", "information_disclosure"),
    ("error disclosure", "information_disclosure"),
    ("open redirect", "broken_access_control"),
    ("redirect", "broken_access_control"),
    ("cookie without secure", "cleartext_transmission"),
    ("insecure transmission", "cleartext_transmission"),
]


def normalize_finding_type(raw_name: str) -> str:
    """Return canonical finding_type for any scanner-specific name."""
    key = raw_name.lower().strip()

    # Already canonical?
    if key in CANONICAL_FINDING_TYPES:
        return key

    # Exact map
    if key in _EXACT_MAP:
        return _EXACT_MAP[key]

    # Substring search
    for substr, canonical in _SUBSTR_MAP:
        if substr in key:
            return canonical

    # Fallback: slugify the raw name
    return key.replace(" ", "_").replace("-", "_")


def normalize_severity(raw_severity: str | float | None) -> str:
    """Map any scanner severity format to critical|high|medium|low|info."""
    if raw_severity is None:
        return "info"
    if isinstance(raw_severity, (int, float)):
        score = float(raw_severity)
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score >= 0.1:
            return "low"
        return "info"
    val = str(raw_severity).lower().strip()
    _MAP = {
        "critical": "critical", "urgent": "critical",
        "high": "high", "severe": "high",
        "medium": "medium", "moderate": "medium", "warning": "medium",
        "low": "low", "minor": "low",
        "informational": "info", "info": "info",
        "false positive": "info", "none": "info",
    }
    return _MAP.get(val, "info")
