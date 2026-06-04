"""Export remediation recommendations to knowledge-vault markdown.

Produces remediation playbook documents in remediation/ that correspond to
finding types discovered by ai-assist-tool. One playbook per vulnerability class
(not per finding instance) — idempotent: re-exporting the same type overwrites
the existing file.
"""

from __future__ import annotations

from pathlib import Path

from apps.validation.models import Finding
from exporters.config import get_remediation_path
from exporters.export_validator import validate_markdown_content, validate_remediation_frontmatter
from exporters.frontmatter_builder import (
    build_remediation_frontmatter,
    infer_category,
)
from exporters.markdown_renderer import render_remediation

# Re-use the prefix helper from frontmatter_builder
_CAT_PREFIX = {"web": "WEB", "api": "API", "network": "NET", "cloud": "CLOUD"}

# ---------------------------------------------------------------------------
# Static remediation knowledge base
# ---------------------------------------------------------------------------

_REMEDIATION_CONTENT: dict[str, dict] = {
    "sqli": {
        "summary": (
            "SQL Injection occurs when user-supplied input is concatenated into SQL queries"
            " without sanitisation."
        ),
        "root_cause": (
            "The application constructs SQL queries using string concatenation with"
            " user-controlled input, allowing attackers to inject arbitrary SQL syntax."
        ),
        "affected_components": [
            "Web application query layer",
            "ORM raw query calls",
            "Stored procedure inputs",
        ],
        "short_term_fix": (
            "Deploy a WAF rule to block common SQL injection patterns in all input parameters."
        ),
        "short_term_code": (
            "# Nginx + ModSecurity example\n"
            "SecRule ARGS \"@detectSQLi\" \"id:1001,deny,status:403,msg:'SQL Injection Detected'\""
        ),
        "long_term_guidance": (
            "Replace all dynamic SQL string construction with parameterized queries or prepared"
            " statements. The database driver treats user input as data, never as executable SQL."
        ),
        "lang_table": [
            ("Python", "Use `cursor.execute(sql, params)` — never f-strings in queries"),
            ("JavaScript/Node", "Use `pool.query(sql, [params])` with pg / mysql2"),
            ("Java", "Use `PreparedStatement` — never `Statement.executeQuery(sql + input)`"),
            ("PHP", "Use PDO with `prepare()` and `bindParam()`"),
        ],
        "verification_steps": [
            "Retest the original payload — it should return an error or be rejected cleanly",
            "Run a SQLMap scan against the same parameter — expect no injectable parameters found",
            "Review application logs for rejected queries",
        ],
        "verification_cmd": (
            "sqlmap -u 'https://target/login' --data 'user=test&pass=test'"
            " --level 1 --risk 1 --batch"
        ),
        "references": [
            "[OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)",
            "[CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)",
            "[PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)",
        ],
    },
    "xss": {
        "summary": (
            "Cross-Site Scripting (XSS) occurs when user-supplied data is rendered in HTML"
            " responses without proper output encoding."
        ),
        "root_cause": (
            "The application reflects or stores user input in HTML output without encoding"
            " HTML special characters, allowing script injection."
        ),
        "affected_components": [
            "Any template rendering user input",
            "API responses embedded in HTML",
        ],
        "short_term_fix": (
            "Apply a Content Security Policy (CSP) header to restrict script execution sources."
        ),
        "short_term_code": (
            "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';"
        ),
        "long_term_guidance": (
            "Encode all output: use context-aware encoding (HTML entity encoding for HTML"
            " contexts, JS escaping for script contexts). Use modern frameworks that"
            " auto-escape by default."
        ),
        "lang_table": [
            ("Python / Jinja2", "Use `{{ var }}` — Jinja2 auto-escapes in HTML mode"),
            (
                "JavaScript/React",
                "Use JSX — React auto-escapes, never use `dangerouslySetInnerHTML`",
            ),
            ("Java", "Use OWASP Java Encoder library"),
            ("PHP", "Use `htmlspecialchars($input, ENT_QUOTES, 'UTF-8')`"),
        ],
        "verification_steps": [
            "Retest with `<script>alert(1)</script>` — it should appear as literal text,"
            " not execute",
            "Verify CSP header present in HTTP response",
            "Scan with OWASP ZAP passive scan — expect no XSS findings",
        ],
        "verification_cmd": "curl -sI https://target/page | grep -i content-security-policy",
        "references": [
            "[OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)",
            "[CWE-79](https://cwe.mitre.org/data/definitions/79.html)",
            "[PortSwigger — XSS](https://portswigger.net/web-security/cross-site-scripting)",
        ],
    },
    "ssh_cred": {
        "summary": (
            "SSH service accessible with default or weak credentials allows unauthorised"
            " remote login."
        ),
        "root_cause": (
            "Default credentials were not changed post-deployment, or a weak password"
            " policy allows brute-force access."
        ),
        "affected_components": ["SSH daemon (sshd)", "System accounts"],
        "short_term_fix": (
            "Immediately change the exposed credentials and restrict SSH access by IP."
        ),
        "short_term_code": (
            "# /etc/ssh/sshd_config\nAllowUsers deploy@10.0.0.0/8\n"
            "PasswordAuthentication no\nPermitRootLogin no"
        ),
        "long_term_guidance": (
            "Enforce key-based authentication, disable password login, "
            "use a bastion host, and implement a secrets rotation policy."
        ),
        "lang_table": [
            (
                "Linux",
                "Disable PasswordAuthentication in sshd_config; use ssh-keygen + authorized_keys",
            ),
            (
                "Ansible/Terraform",
                "Provision SSH keys at build time; never bake credentials into images",
            ),
            ("Kubernetes", "Use SSH secrets manager (Vault, AWS Secrets Manager) with rotation"),
        ],
        "verification_steps": [
            "Attempt login with the original credential — it should fail",
            "Confirm PasswordAuthentication is disabled in sshd_config",
            "Run nmap -sV -p22 --script ssh-auth-methods <target> — expect publickey only",
        ],
        "verification_cmd": (
            "ssh -o PasswordAuthentication=yes user@target 2>&1 | grep 'Permission denied'"
        ),
        "references": [
            "[OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)",
            "[CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)",
        ],
    },
    "tls_config": {
        "summary": (
            "TLS misconfiguration exposes services to protocol downgrade or weak cipher"
            " exploitation."
        ),
        "root_cause": (
            "The server accepts deprecated TLS versions (TLS 1.0/1.1), "
            "weak cipher suites (RC4, DES, 3DES), or is missing HSTS."
        ),
        "affected_components": [
            "Web server TLS configuration",
            "Load balancer / reverse proxy TLS termination",
        ],
        "short_term_fix": "Disable TLS 1.0 and 1.1 immediately; remove RC4 and DES cipher suites.",
        "short_term_code": (
            "# Nginx\nssl_protocols TLSv1.2 TLSv1.3;\n"
            "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';\n"
            "ssl_prefer_server_ciphers off;"
        ),
        "long_term_guidance": (
            "Enforce TLS 1.3 where possible, implement HSTS, use Mozilla's "
            "recommended cipher configuration, and automate certificate rotation."
        ),
        "lang_table": [
            ("Nginx", "Use Mozilla SSL Config Generator: https://ssl-config.mozilla.org/"),
            ("Apache", "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1; SSLCipherSuite ECDHE+AESGCM"),
            ("Java", "Set `https.protocols=TLSv1.2,TLSv1.3` in JVM args"),
        ],
        "verification_steps": [
            "Run `testssl.sh <target>` — expect no LOW/WARN/CRITICAL findings",
            "Verify HSTS header present with `curl -sI https://target | grep strict`",
            "Confirm TLS 1.0/1.1 connections fail",
        ],
        "verification_cmd": "testssl.sh --severity MEDIUM https://target",
        "references": [
            "[OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)",
            "[CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)",
        ],
    },
    "telnet_cleartext": {
        "summary": (
            "Telnet transmits all data including credentials in cleartext, enabling"
            " interception by network adversaries."
        ),
        "root_cause": (
            "Legacy telnet service is enabled; encrypted alternatives (SSH) have not been"
            " deployed."
        ),
        "affected_components": ["telnetd daemon", "Network management interfaces using telnet"],
        "short_term_fix": "Immediately disable the telnet service.",
        "short_term_code": (
            "# systemd\nsystemctl stop telnet.socket\n"
            "systemctl disable telnet.socket\n# or\n"
            "iptables -A INPUT -p tcp --dport 23 -j DROP"
        ),
        "long_term_guidance": (
            "Replace telnet with SSH for all interactive access. If telnet is required for"
            " legacy device management, restrict to a dedicated OOB management VLAN."
        ),
        "lang_table": [
            ("Linux", "Disable telnet; install openssh-server"),
            ("Cisco IOS", "`transport input ssh` on vty lines; `no service telnet`"),
        ],
        "verification_steps": [
            "Confirm port 23 is closed: `nmap -p23 <target>` should show filtered/closed",
            "Attempt telnet connection — it should fail",
        ],
        "verification_cmd": "nmap -p23 target",
        "references": [
            "[CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)",
        ],
    },
    "smb_enum": {
        "summary": (
            "SMB null session or weak authentication allows unauthenticated enumeration of"
            " shares, users, and policies."
        ),
        "root_cause": (
            "SMB service allows null (unauthenticated) sessions or guest access, exposing"
            " internal directory information."
        ),
        "affected_components": ["Windows SMB service (smbd)", "Samba on Linux"],
        "short_term_fix": "Disable null sessions and guest access at the registry/config level.",
        "short_term_code": (
            "# Windows registry (run as admin)\n"
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\""
            " /v RestrictAnonymous /t REG_DWORD /d 2 /f\n"
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\""
            " /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f"
        ),
        "long_term_guidance": (
            "Require authentication for all SMB shares. Enforce SMB signing."
            " Block SMB (445/139) at the perimeter firewall."
        ),
        "lang_table": [
            ("Windows", "Enable SMB signing via Group Policy; disable SMBv1"),
            ("Linux/Samba", "`restrict anonymous = 2` in smb.conf; `server signing = mandatory`"),
        ],
        "verification_steps": [
            "Run `enum4linux -a <target>` — expect 'NT_STATUS_ACCESS_DENIED' for null sessions",
            "Verify SMB signing: `nmap --script smb2-security-mode <target>`",
        ],
        "verification_cmd": "enum4linux -a target 2>&1 | grep -i 'null session\\|status'",
        "references": [
            "[CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)",
            "[MITRE ATT&CK T1135 — Network Share Discovery](https://attack.mitre.org/techniques/T1135/)",
        ],
    },
    "web_header": {
        "summary": (
            "Missing or misconfigured HTTP security headers weaken browser-side defences"
            " against XSS, clickjacking, and information disclosure."
        ),
        "root_cause": (
            "Web server or application framework does not set recommended security"
            " response headers."
        ),
        "affected_components": [
            "Web server configuration (Nginx, Apache)",
            "Application middleware / reverse proxy",
        ],
        "short_term_fix": "Add missing headers to the web server configuration immediately.",
        "short_term_code": (
            "# Nginx — add to server{} block\n"
            "add_header X-Content-Type-Options \"nosniff\" always;\n"
            "add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
            "add_header Strict-Transport-Security"
            " \"max-age=31536000; includeSubDomains\" always;\n"
            "add_header Content-Security-Policy \"default-src 'self'\" always;\n"
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
        ),
        "long_term_guidance": (
            "Implement headers in application middleware so they are set regardless of the"
            " web server. Use SecurityHeaders.com to grade and track."
        ),
        "lang_table": [
            ("Python/FastAPI", "Use `slowapi` or custom middleware to set headers globally"),
            ("Node/Express", "Use `helmet` middleware"),
            ("Java/Spring", "Use `HttpSecurity.headers()` configuration"),
        ],
        "verification_steps": [
            "Run `curl -sI https://target | grep -E 'X-Frame|Strict|Content-Security'`",
            "Check score at https://securityheaders.com/",
        ],
        "verification_cmd": "curl -sI https://target",
        "references": [
            "[OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)",
            "[CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)",
        ],
    },
}

# Generic fallback
_DEFAULT_CONTENT: dict = {
    "summary": "Vulnerability requires remediation. Review the finding evidence for details.",
    "root_cause": "See finding evidence for root cause analysis.",
    "affected_components": ["See finding for affected component details"],
    "short_term_fix": "Apply vendor patches and restrict exposure surface.",
    "short_term_code": "# Review vendor advisory for specific mitigations",
    "long_term_guidance": "Follow secure development practices for this vulnerability class.",
    "lang_table": [],
    "verification_steps": ["Retest the original finding after applying the fix"],
    "verification_cmd": "# Retest using original exploit vector",
    "references": ["[OWASP Top 10](https://owasp.org/www-project-top-ten/)"],
}


# ---------------------------------------------------------------------------
# Primary export function
# ---------------------------------------------------------------------------


_VULN_TYPE_TITLE: dict[str, str] = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "ssh_cred": "SSH Default / Weak Credential",
    "tls_config": "TLS/SSL Misconfiguration",
    "telnet_cleartext": "Cleartext Transmission (Telnet)",
    "smb_enum": "SMB Null Session / Enumeration",
    "web_header": "Missing HTTP Security Headers",
    "web_nginx": "Nginx Misconfiguration",
    "web_apache": "Apache Misconfiguration",
    "web_wordpress": "WordPress Vulnerability",
    "web_drupal": "Drupal Vulnerability",
    "cve_poc": "CVE Proof-of-Concept",
}


def export_remediation(
    finding: Finding,
    date_str: str,
    vault_find_id: str | None = None,
    vault_path: Path | None = None,
) -> Path:
    """Export a remediation playbook for the finding's vulnerability class.

    One file per finding_type — idempotent (overwrites existing if present).
    date_str: YYYYMMDD format.
    vault_find_id: The vault FIND-* ID of the triggering finding (e.g. FIND-WEB-20260518-001).
        Used to populate related_findings. Leave None to omit internal UUIDs.

    Returns path of the written file.
    """
    ftype = finding.finding_type.lower()
    category = infer_category(ftype)
    date_iso = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:]}"

    out_dir = (vault_path / "remediation") if vault_path else get_remediation_path()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Deterministic filename — one per vuln class, not per finding instance
    cat_prefix = _CAT_PREFIX.get(category, "WEB")
    rem_id = f"REM-{cat_prefix}-{date_str}-001"
    slug = ftype.replace("_", "-")
    filename = f"remediation-{category}-{slug}.md"

    content_data = _REMEDIATION_CONTENT.get(ftype, _DEFAULT_CONTENT)
    vuln_title = _VULN_TYPE_TITLE.get(ftype, ftype.replace("_", " ").title())

    fm = build_remediation_frontmatter(
        rem_id=rem_id,
        title=f"Remediation: {vuln_title}",
        date=date_iso,
        category=category,
        severity=finding.severity.value,
        finding_type=ftype,
        related_findings=[vault_find_id] if vault_find_id else [],
    )

    vr = validate_remediation_frontmatter(fm)
    if not vr.valid:
        raise ValueError(f"Remediation frontmatter validation failed: {vr.errors}")

    lang_table = [(lang, approach) for lang, approach in content_data.get("lang_table", [])]

    content = render_remediation(
        frontmatter=fm,
        summary=content_data["summary"],
        root_cause=content_data["root_cause"],
        affected_components=content_data["affected_components"],
        short_term_fix=content_data["short_term_fix"],
        short_term_code=content_data["short_term_code"],
        long_term_guidance=content_data["long_term_guidance"],
        lang_table=lang_table,
        verification_steps=content_data["verification_steps"],
        verification_cmd=content_data["verification_cmd"],
        references=content_data["references"],
        related_concept=f"[[concept-{slug}]]",
        related_findings=[f"[[{finding.id}]]"],
    )

    content_vr = validate_markdown_content(content)
    if not content_vr.valid:
        raise ValueError(f"Rendered remediation content invalid: {content_vr.errors}")

    out_path = out_dir / filename
    out_path.write_text(content, encoding="utf-8")
    return out_path
