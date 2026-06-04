"""Curated Metasploit module recipes for the Beginner Guide.

A recipe answers the question: "I found this service open on a target — which
Metasploit modules should I actually try, in what order, and what does success
look like?". The lists are intentionally short (3-5 modules per service) so a
non-MSF expert can pick something without sifting through 50 search results.

The data is static and lives in code so the page stays fully offline.
"""
from __future__ import annotations

from typing import Any

# Intent ordering used when rendering. Lower = earlier on the page.
INTENT_ORDER = {
    "recon": 0,
    "enum": 1,
    "creds": 2,
    "vuln-check": 3,
    "exploit": 4,
}

INTENT_LABELS = {
    "recon": "1. Reconnaissance",
    "enum": "2. Enumeration",
    "creds": "3. Credential testing",
    "vuln-check": "4. Vulnerability check",
    "exploit": "5. Exploit",
}

# Service key → recipe.
# `type` and `path` reuse the same conventions as MSF: `path` is the part
# after the leading type prefix (e.g. exploit/multi/... → multi/...).
RECIPES: dict[str, dict[str, Any]] = {
    "telnet": {
        "title": "Telnet (TCP 23)",
        "summary": (
            "Cleartext remote shell. Common on legacy network kit (Cisco / "
            "HP / older Linux). Anything you type — including credentials "
            "— goes over the wire in the clear."
        ),
        "default_port": 23,
        "modules": [
            {
                "type": "auxiliary",
                "path": "scanner/telnet/telnet_version",
                "intent": "recon",
                "what_it_does": "Connect, grab the banner, and log whatever the daemon advertises.",
                "required": {"RHOSTS": "target IP or CIDR"},
                "success": "[+] 10.0.0.1:23  TELNET\\x0d\\x0aUbuntu 18.04.5 LTS\\x0d\\x0a",
                "failure": "[*] Scanned 1 of 1 hosts (100% complete) — no banner returned",
            },
            {
                "type": "auxiliary",
                "path": "scanner/telnet/telnet_login",
                "intent": "creds",
                "what_it_does": "Try a username/password list. Common starting point on routers.",
                "required": {
                    "RHOSTS": "target IP",
                    "USERPASS_FILE": "wordlist of `user pass` lines, or set USERNAME/PASSWORD",
                },
                "success": "[+] 10.0.0.1:23 - LOGIN SUCCESSFUL: cisco:cisco",
                "failure": "[-] 10.0.0.1:23 - LOGIN FAILED: admin:admin (Incorrect)",
                "note": "If the device prompts for `Password:` only (no username), set BLANK_PASSWORDS=true.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/telnet/telnet_encrypt_overflow",
                "intent": "vuln-check",
                "what_it_does": "Probes for the FreeBSD/Linux telnetd encrypt overflow (CVE-2011-4862).",
                "required": {"RHOSTS": "target IP"},
                "success": "[+] 10.0.0.1:23 appears vulnerable",
                "failure": "[-] 10.0.0.1:23 doesn't appear vulnerable",
            },
        ],
        "tips": [
            "Telnet on non-standard ports happens — set RPORT to match what your scan found.",
            "If you see something Cisco-y in the banner, the `scanner/telnet/telnet_login` module's CISCO option is worth flipping on.",
        ],
    },

    "ssh": {
        "title": "SSH (TCP 22)",
        "summary": "Encrypted shell. Default credential testing and version-specific bugs are the usual angles.",
        "default_port": 22,
        "modules": [
            {
                "type": "auxiliary",
                "path": "scanner/ssh/ssh_version",
                "intent": "recon",
                "what_it_does": "Grab the SSH banner (e.g. OpenSSH_7.4p1) to identify the implementation and version.",
                "required": {"RHOSTS": "target IP/CIDR"},
                "success": "[+] 10.0.0.1:22, SSH server version: SSH-2.0-OpenSSH_7.4p1",
                "failure": "[*] No SSH banner — port may be filtered or the service rejected the probe.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/ssh/ssh_login",
                "intent": "creds",
                "what_it_does": "Spray username/password (or key) combinations against SSH.",
                "required": {
                    "RHOSTS": "target IP",
                    "USERNAME": "single user OR USER_FILE for a list",
                    "PASSWORD": "single pass OR PASS_FILE for a list",
                },
                "success": "[+] 10.0.0.1:22 - Success: 'root:toor' — open session 1",
                "failure": "[-] 10.0.0.1:22 - Failed: 'root:wrongpw'",
                "note": "VERBOSE=true is on by default; set it false on big sprays.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/ssh/ssh_enumusers",
                "intent": "enum",
                "what_it_does": "Test whether usernames exist via SSH's timing/error oracle (older OpenSSH).",
                "required": {"RHOSTS": "target IP", "USER_FILE": "wordlist of usernames"},
                "success": "[+] 10.0.0.1:22 - User 'admin' found",
                "failure": "[-] 10.0.0.1:22 - User 'foo' not found",
                "note": "Only effective against OpenSSH versions vulnerable to CVE-2018-15473.",
            },
        ],
        "tips": [
            "If `ssh_login` keeps locking accounts, drop THREADS to 1 and add DB_ALL_USERS=false.",
            "For key-based auth: set KEY_FILE instead of PASSWORD.",
        ],
    },

    "ftp": {
        "title": "FTP (TCP 21)",
        "summary": "File transfer protocol. Anonymous access + cleartext creds + ancient bugs make this a frequent quick win.",
        "default_port": 21,
        "modules": [
            {
                "type": "auxiliary",
                "path": "scanner/ftp/ftp_version",
                "intent": "recon",
                "what_it_does": "Identify the FTP daemon (vsftpd/ProFTPD/Pure-FTPd/etc.) and version from the 220 banner.",
                "required": {"RHOSTS": "target IP/CIDR"},
                "success": "[+] 10.0.0.1:21 FTP Banner: '220 (vsFTPd 2.3.4)'",
                "failure": "[*] No banner — port closed or filtered.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/ftp/anonymous",
                "intent": "enum",
                "what_it_does": "Check if anonymous login is enabled (RW or RO).",
                "required": {"RHOSTS": "target IP"},
                "success": "[+] 10.0.0.1:21 - Anonymous READ (220 (vsFTPd 2.3.4))",
                "failure": "[-] 10.0.0.1:21 - Anonymous access not permitted",
            },
            {
                "type": "auxiliary",
                "path": "scanner/ftp/ftp_login",
                "intent": "creds",
                "what_it_does": "Wordlist-based FTP brute force.",
                "required": {
                    "RHOSTS": "target IP",
                    "USERPASS_FILE": "wordlist of `user pass` lines, or USER_FILE / PASS_FILE",
                },
                "success": "[+] 10.0.0.1:21 - LOGIN SUCCESSFUL: anonymous:test@x.com",
                "failure": "[-] 10.0.0.1:21 - LOGIN FAILED: admin:admin",
            },
            {
                "type": "exploit",
                "path": "unix/ftp/vsftpd_234_backdoor",
                "intent": "exploit",
                "what_it_does": "Triggers the planted backdoor in vsftpd 2.3.4 (CVE-2011-2523).",
                "required": {"RHOSTS": "target IP", "PAYLOAD": "cmd/unix/interact"},
                "success": "[+] Backdoor service has been spawned, handling… (and you get a shell)",
                "failure": "[!] Exploit completed, but no session was created. — usually means it's not 2.3.4.",
                "note": "Run `check` first to confirm the version is exactly 2.3.4 before firing the real exploit.",
            },
        ],
        "tips": [
            "Banner says vsFTPd 2.3.4? That's the smiley-face backdoor. Run the exploit's check first.",
            "Anonymous access often gives directory listings — check what's exposed before brute-forcing creds.",
        ],
    },

    "smb": {
        "title": "SMB (TCP 445 / 139)",
        "summary": "Windows file sharing. Top of the list for share enumeration, EternalBlue, null sessions, and credential spray.",
        "default_port": 445,
        "modules": [
            {
                "type": "auxiliary",
                "path": "scanner/smb/smb_version",
                "intent": "recon",
                "what_it_does": "Detect the SMB dialect and OS string the host advertises.",
                "required": {"RHOSTS": "target IP/CIDR"},
                "success": "[+] 10.0.0.1:445 - Host is running Windows Server 2012 R2 Standard 9600 …",
                "failure": "[-] 10.0.0.1:445 - No response or port filtered",
            },
            {
                "type": "auxiliary",
                "path": "scanner/smb/smb_enumshares",
                "intent": "enum",
                "what_it_does": "List the shares exposed (anonymous if creds blank).",
                "required": {"RHOSTS": "target IP"},
                "success": "[+] 10.0.0.1:445 - C$, ADMIN$, IPC$ - (DISK|IPC)",
                "failure": "[-] 10.0.0.1:445 - STATUS_ACCESS_DENIED — set SMBUser/SMBPass.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/smb/smb_login",
                "intent": "creds",
                "what_it_does": "SMB credential spray. Frequently used with a list of users + a single common password.",
                "required": {"RHOSTS": "target IP", "SMBUser": "user list", "SMBPass": "password"},
                "success": "[+] 10.0.0.1:445 - Success: WORKGROUP\\Administrator:P@ssw0rd",
                "failure": "[-] 10.0.0.1:445 - LOGIN FAILED",
                "note": "Many AD lockout policies trigger at 3-5 attempts — be careful.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/smb/smb_ms17_010",
                "intent": "vuln-check",
                "what_it_does": "Probe for the EternalBlue family (MS17-010 / CVE-2017-0143/144/145).",
                "required": {"RHOSTS": "target IP"},
                "success": "[+] 10.0.0.1:445 - Host is likely VULNERABLE to MS17-010!",
                "failure": "[-] 10.0.0.1:445 - Host does NOT appear vulnerable.",
            },
            {
                "type": "exploit",
                "path": "windows/smb/ms17_010_eternalblue",
                "intent": "exploit",
                "what_it_does": "EternalBlue RCE against unpatched Win 7 / Server 2008.",
                "required": {
                    "RHOSTS": "target IP",
                    "PAYLOAD": "windows/x64/meterpreter/reverse_tcp",
                    "LHOST": "your IP for callback",
                },
                "success": "[+] WIN-… - meterpreter session opened",
                "failure": "[-] Exploit aborted due to failure: not-vulnerable",
                "note": "Always run scanner/smb/smb_ms17_010 (above) first as a `check`.",
            },
        ],
        "tips": [
            "Set SMBDomain if the target is in a domain — leaving it as WORKGROUP can produce false negatives.",
            "Use SMBUser='' SMBPass='' for null-session enumeration on older Windows.",
        ],
    },

    "http": {
        "title": "HTTP (TCP 80 / 8080 / …)",
        "summary": "Web servers. Start with banner + title, then move to product-specific probes.",
        "default_port": 80,
        "modules": [
            {
                "type": "auxiliary",
                "path": "scanner/http/http_version",
                "intent": "recon",
                "what_it_does": "Grab the Server header and any X-Powered-By to fingerprint the stack.",
                "required": {"RHOSTS": "target IP/CIDR"},
                "success": "[+] 10.0.0.1: 200 Apache/2.4.62 (Debian)",
                "failure": "[*] No response — try a different port (8080, 8443) or RPORT.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/http/title",
                "intent": "recon",
                "what_it_does": "Fetch / and report the HTML <title> + status. Quick way to see what's running.",
                "required": {"RHOSTS": "target IP", "RPORT": "usually 80"},
                "success": "[*] 10.0.0.1:80 - http://10.0.0.1/ — Title: Apache2 Debian Default Page",
                "failure": "[*] 10.0.0.1:80 - Title not detected.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/http/dir_listing",
                "intent": "enum",
                "what_it_does": "Look for directory listings (Index of /…) that leak file paths.",
                "required": {"RHOSTS": "target IP", "PATH": "starting URI, default /"},
                "success": "[+] 10.0.0.1:80 - http://10.0.0.1/backup/ — Index of /backup",
                "failure": "[-] 10.0.0.1:80 - no directory listings found",
            },
            {
                "type": "auxiliary",
                "path": "scanner/http/wordpress_login_enum",
                "intent": "enum",
                "what_it_does": "Enumerate WordPress usernames via the login error oracle. Use only when WP is confirmed.",
                "required": {"RHOSTS": "target IP", "USER_FILE": "wordlist of usernames"},
                "success": "[+] 10.0.0.1:80 - Username 'admin' found",
                "failure": "[-] 10.0.0.1:80 - Not a WordPress site or the endpoint is hidden.",
            },
        ],
        "tips": [
            "Always set RPORT explicitly — 8080/8443/8888 are very common alternatives.",
            "For HTTPS use SSL=true RPORT=443. Or use the `https` recipe.",
        ],
    },

    "https": {
        "title": "HTTPS / TLS (TCP 443 / 8443 / …)",
        "summary": "Same HTTP modules as port 80 but with SSL=true. Plus TLS-specific weakness probes.",
        "default_port": 443,
        "modules": [
            {
                "type": "auxiliary",
                "path": "scanner/http/ssl",
                "intent": "recon",
                "what_it_does": "Fetch the cert chain and report subject/issuer/expiry.",
                "required": {"RHOSTS": "target IP", "RPORT": "443"},
                "success": "[+] 10.0.0.1:443 Subject: CN=example.com; Issuer: Let's Encrypt; expires …",
                "failure": "[-] No TLS handshake — port may not actually be TLS.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/http/ssl_version",
                "intent": "vuln-check",
                "what_it_does": "Enumerate which SSL/TLS versions the server still negotiates.",
                "required": {"RHOSTS": "target IP", "RPORT": "443"},
                "success": "[+] 10.0.0.1:443 Supported versions: TLSv1, TLSv1.1, TLSv1.2",
                "failure": "[*] No legacy versions supported.",
                "note": "TLSv1.0 / 1.1 still listed = PCI-DSS failure.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/ssl/openssl_heartbleed",
                "intent": "vuln-check",
                "what_it_does": "CVE-2014-0160 (Heartbleed) probe — leaks 64 KB of process memory if vulnerable.",
                "required": {"RHOSTS": "target IP", "RPORT": "443"},
                "success": "[+] 10.0.0.1:443 - Heartbleed - Server is vulnerable",
                "failure": "[-] 10.0.0.1:443 - Heartbleed - Server is NOT vulnerable",
            },
        ],
        "tips": [
            "For any HTTP module set SSL=true RPORT=443 to make it work over TLS.",
            "Most modern TLS findings are configuration, not RCE — pair with the `tls_config` plugin in the queue.",
        ],
    },

    "rdp": {
        "title": "RDP (TCP 3389)",
        "summary": "Windows Remote Desktop. BlueKeep and credential spray are the headline angles.",
        "default_port": 3389,
        "modules": [
            {
                "type": "auxiliary",
                "path": "scanner/rdp/rdp_scanner",
                "intent": "recon",
                "what_it_does": "Detect whether RDP is listening, what protocol versions, and NLA status.",
                "required": {"RHOSTS": "target IP/CIDR"},
                "success": "[+] 10.0.0.1:3389 - Detected RDP on 10.0.0.1:3389 (NLA Enabled)",
                "failure": "[-] 10.0.0.1:3389 - Service not detected.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/rdp/cve_2019_0708_bluekeep",
                "intent": "vuln-check",
                "what_it_does": "Probe for BlueKeep (CVE-2019-0708). Safe — does not exploit.",
                "required": {"RHOSTS": "target IP"},
                "success": "[+] 10.0.0.1:3389 - The target is vulnerable.",
                "failure": "[-] 10.0.0.1:3389 - The target is not exploitable.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/rdp/ms12_020_check",
                "intent": "vuln-check",
                "what_it_does": "Probe for the older MS12-020 RDP DoS (CVE-2012-0002).",
                "required": {"RHOSTS": "target IP"},
                "success": "[+] 10.0.0.1:3389 - The target is VULNERABLE to MS12-020",
                "failure": "[-] 10.0.0.1:3389 - The target is not exploitable.",
            },
        ],
        "tips": [
            "RDP brute force triggers Windows account lockout fast — prefer credential reuse over spraying.",
            "NLA enabled = pre-auth network-level checks needed; many old exploits don't work post-NLA.",
        ],
    },

    "mysql": {
        "title": "MySQL (TCP 3306)",
        "summary": "Default creds + version-specific bugs. Confirm the daemon is exposed before brute-forcing.",
        "default_port": 3306,
        "modules": [
            {
                "type": "auxiliary",
                "path": "scanner/mysql/mysql_version",
                "intent": "recon",
                "what_it_does": "Grab the MySQL handshake banner.",
                "required": {"RHOSTS": "target IP/CIDR"},
                "success": "[+] 10.0.0.1:3306 - 5.7.32-log",
                "failure": "[-] 10.0.0.1:3306 - No response.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/mysql/mysql_login",
                "intent": "creds",
                "what_it_does": "Brute-force MySQL logins. Common defaults: root/root, root/'', root/password.",
                "required": {"RHOSTS": "target IP", "USERPASS_FILE": "wordlist (or USERNAME/PASSWORD)"},
                "success": "[+] 10.0.0.1:3306 - Found remote MySQL version 5.7.32, password is 'toor'",
                "failure": "[-] 10.0.0.1:3306 - LOGIN FAILED: root:notthis",
            },
            {
                "type": "auxiliary",
                "path": "admin/mysql/mysql_enum",
                "intent": "enum",
                "what_it_does": "Post-auth enumeration — version, users, databases, hashes.",
                "required": {"RHOSTS": "target IP", "USERNAME": "creds you found", "PASSWORD": "creds you found"},
                "success": "[+] 10.0.0.1:3306 - Server Version: 5.7.32 …",
                "failure": "[-] 10.0.0.1:3306 - Authentication failed.",
            },
        ],
        "tips": [
            "MySQL 5.x default-password root accounts are still distressingly common.",
            "If you've already got creds from another box, try them here before brute-forcing.",
        ],
    },

    "mssql": {
        "title": "MS SQL Server (TCP 1433)",
        "summary": "Microsoft SQL Server. `sa` / weak password is the classic angle; `xp_cmdshell` is the payoff.",
        "default_port": 1433,
        "modules": [
            {
                "type": "auxiliary",
                "path": "scanner/mssql/mssql_ping",
                "intent": "recon",
                "what_it_does": "UDP 1434 probe — reports the SQL instance name and TCP port.",
                "required": {"RHOSTS": "target IP/CIDR"},
                "success": "[+] 10.0.0.1: ServerName=SQL01; InstanceName=SQLEXPRESS; tcp=1433",
                "failure": "[-] 10.0.0.1: No instances enumerated.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/mssql/mssql_login",
                "intent": "creds",
                "what_it_does": "Brute-force the `sa` account (or a list).",
                "required": {"RHOSTS": "target IP", "USERNAME": "sa (or USER_FILE)", "PASSWORD": "(or PASS_FILE)"},
                "success": "[+] 10.0.0.1:1433 - Login Successful: WORKSTATION\\sa:sa",
                "failure": "[-] 10.0.0.1:1433 - LOGIN FAILED: sa:wrongpass",
            },
            {
                "type": "auxiliary",
                "path": "admin/mssql/mssql_exec",
                "intent": "exploit",
                "what_it_does": "Run an OS command via `xp_cmdshell` (if your account has sysadmin).",
                "required": {"RHOSTS": "target IP", "USERNAME": "creds", "PASSWORD": "creds", "CMD": "whoami"},
                "success": "[+] 10.0.0.1:1433 - nt service\\\\mssqlserver",
                "failure": "[-] 10.0.0.1:1433 - xp_cmdshell is disabled or account lacks sysadmin.",
                "note": "If xp_cmdshell is off, the module can re-enable it (RECONFIGURE=true) — visible in audit logs.",
            },
        ],
        "tips": [
            "Try `sa` + blank password before throwing wordlists — sloppy installs.",
            "Browser service on UDP 1434 needs to be reachable for mssql_ping to be useful.",
        ],
    },

    "snmp": {
        "title": "SNMP (UDP 161)",
        "summary": "Network device management. Default community strings (`public`/`private`) leak everything.",
        "default_port": 161,
        "modules": [
            {
                "type": "auxiliary",
                "path": "scanner/snmp/snmp_login",
                "intent": "creds",
                "what_it_does": "Try a community-string wordlist — public, private, cisco, etc.",
                "required": {"RHOSTS": "target IP/CIDR"},
                "success": "[+] 10.0.0.1:161 - 'public' 'APC Web/SNMP Management Card'",
                "failure": "[-] 10.0.0.1:161 - No valid community strings found",
            },
            {
                "type": "auxiliary",
                "path": "scanner/snmp/snmp_enum",
                "intent": "enum",
                "what_it_does": "Dump everything via a known community — system info, interfaces, processes.",
                "required": {"RHOSTS": "target IP", "COMMUNITY": "public (or whatever you found)"},
                "success": "[+] 10.0.0.1, Connected. — followed by a long enum table.",
                "failure": "[-] 10.0.0.1:161 - SNMP request timed out.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/snmp/snmp_enumusers",
                "intent": "enum",
                "what_it_does": "Enumerate Windows local users via the LanMan MIB.",
                "required": {"RHOSTS": "target IP", "COMMUNITY": "public"},
                "success": "[+] 10.0.0.1, Username list: Administrator, Guest, krbtgt",
                "failure": "[-] 10.0.0.1: No users enumerated.",
            },
        ],
        "tips": [
            "SNMP is UDP — packet loss means flakey responses. Bump RETRIES if results look inconsistent.",
            "Found `private`? That's read-write. You can rewrite config via snmpset (outside Metasploit).",
        ],
    },

    "vnc": {
        "title": "VNC (TCP 5900-5910)",
        "summary": "Remote desktop. `no auth` and weak passwords are the usual finds.",
        "default_port": 5900,
        "modules": [
            {
                "type": "auxiliary",
                "path": "scanner/vnc/vnc_none_auth",
                "intent": "vuln-check",
                "what_it_does": "Check if the VNC server accepts a connection with no authentication at all.",
                "required": {"RHOSTS": "target IP/CIDR"},
                "success": "[+] 10.0.0.1:5900 - VNC server security types: None (1) — no auth required!",
                "failure": "[-] 10.0.0.1:5900 - Authentication required.",
            },
            {
                "type": "auxiliary",
                "path": "scanner/vnc/vnc_login",
                "intent": "creds",
                "what_it_does": "VNC password brute force.",
                "required": {"RHOSTS": "target IP", "PASS_FILE": "wordlist"},
                "success": "[+] 10.0.0.1:5900 - Login Successful: password",
                "failure": "[-] 10.0.0.1:5900 - LOGIN FAILED",
                "note": "VNC passwords are limited to 8 chars — small keyspace.",
            },
        ],
        "tips": [
            "If `vnc_none_auth` succeeds, just connect with any VNC client — no module needed afterwards.",
        ],
    },
}


def list_services() -> list[dict[str, Any]]:
    """Lightweight summary for the dropdown."""
    return [
        {
            "key": key,
            "title": recipe["title"],
            "default_port": recipe["default_port"],
            "module_count": len(recipe["modules"]),
        }
        for key, recipe in RECIPES.items()
    ]


def get_recipe(key: str) -> dict[str, Any] | None:
    return RECIPES.get(key)


def grouped_modules(recipe: dict[str, Any]) -> list[tuple[str, str, list[dict[str, Any]]]]:
    """Group a recipe's modules by intent and return (intent_key, label, modules)."""
    buckets: dict[str, list[dict[str, Any]]] = {}
    for mod in recipe.get("modules", []):
        buckets.setdefault(mod["intent"], []).append(mod)
    ordered: list[tuple[str, str, list[dict[str, Any]]]] = []
    for intent_key, label in sorted(
        INTENT_LABELS.items(), key=lambda kv: INTENT_ORDER.get(kv[0], 99)
    ):
        if intent_key in buckets:
            ordered.append((intent_key, label, buckets[intent_key]))
    return ordered
