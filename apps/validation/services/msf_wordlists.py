"""Catalog of wordlists shipped inside the metasploit container.

Files live under /usr/src/metasploit-framework/data/wordlists/ on the
msfrpcd side — backend never reads them directly. When the user picks
one in the UI, the page injects the path string into the corresponding
module option (USER_FILE, PASS_FILE, USERPASS_FILE, etc.) so msfrpcd
opens it from its own filesystem.

Categories used by the frontend dropdown filter:
    user      → username lists  (USER_FILE / USERNAME_FILE)
    password  → password lists  (PASS_FILE / PASSWORD_FILE / WORDLIST / COMMUNITY)
    userpass  → combined user:pass lists (USERPASS_FILE)
"""
from __future__ import annotations

WORDLIST_DIR = "/usr/src/metasploit-framework/data/wordlists"


def _w(filename: str, category: str, title: str, size: str = "", service: str = "") -> dict:
    return {
        "filename": filename,
        "path": f"{WORDLIST_DIR}/{filename}",
        "category": category,
        "title": title,
        "size": size,
        "service": service,  # blank = generic
    }


WORDLISTS: list[dict] = [
    # --- Generic users -----------------------------------------------------
    _w("unix_users.txt", "user", "Common Unix usernames", "~110 names"),
    _w("namelist.txt", "user", "Common first names", "large"),
    _w("default_users_for_services_unhash.txt", "user", "Default users for common services"),

    # --- Generic passwords -------------------------------------------------
    _w("unix_passwords.txt", "password", "Common Unix passwords"),
    _w("common_roots.txt", "password", "Common password roots (large)"),
    _w("burnett_top_500.txt", "password", "Burnett top 500 leaked passwords"),
    _w("burnett_top_1024.txt", "password", "Burnett top 1024 leaked passwords"),
    _w("adobe_top100_pass.txt", "password", "Adobe 2013 breach top 100"),
    _w("keyboard-patterns.txt", "password", "Keyboard walks (qwerty, asdf, …)"),
    _w("default_pass_for_services_unhash.txt", "password", "Default passwords for common services"),

    # --- Generic user:pass combos -----------------------------------------
    _w("default_userpass_for_services_unhash.txt", "userpass", "Default user:pass for common services"),
    _w("root_userpass.txt", "userpass", "root account default combos"),

    # --- HTTP basic-auth / web admin --------------------------------------
    _w("http_default_users.txt", "user", "HTTP default users", service="http"),
    _w("http_default_pass.txt", "password", "HTTP default passwords", service="http"),
    _w("http_default_userpass.txt", "userpass", "HTTP default user:pass", service="http"),
    _w("http_owa_common.txt", "user", "OWA / Exchange common users", service="exchange"),

    # --- SSH / Telnet / network kit ---------------------------------------
    _w("piata_ssh_userpass.txt", "userpass", "Piata SSH brute-force list", service="ssh"),
    _w("routers_userpass.txt", "userpass", "Router default credentials", service="router"),
    _w("dlink_telnet_backdoor_userpass.txt", "userpass", "D-Link telnet backdoor creds", service="telnet"),
    _w("telnet_cdata_ftth_backdoor_userpass.txt", "userpass", "C-Data FTTH telnet backdoor", service="telnet"),
    _w("mirai_user.txt", "user", "Mirai botnet usernames", service="iot"),
    _w("mirai_pass.txt", "password", "Mirai botnet passwords", service="iot"),
    _w("mirai_user_pass.txt", "userpass", "Mirai botnet user:pass", service="iot"),

    # --- IoT / CCTV / industrial ------------------------------------------
    _w("multi_vendor_cctv_dvr_users.txt", "user", "CCTV / DVR default users", service="cctv"),
    _w("multi_vendor_cctv_dvr_pass.txt", "password", "CCTV / DVR default passwords", service="cctv"),
    _w("scada_default_userpass.txt", "userpass", "SCADA / ICS default credentials", service="scada"),

    # --- Databases ---------------------------------------------------------
    _w("postgres_default_user.txt", "user", "Postgres default users", service="postgres"),
    _w("postgres_default_pass.txt", "password", "Postgres default passwords", service="postgres"),
    _w("postgres_default_userpass.txt", "userpass", "Postgres default user:pass", service="postgres"),
    _w("db2_default_user.txt", "user", "DB2 default users", service="db2"),
    _w("db2_default_pass.txt", "password", "DB2 default passwords", service="db2"),
    _w("db2_default_userpass.txt", "userpass", "DB2 default user:pass", service="db2"),
    _w("oracle_default_userpass.txt", "userpass", "Oracle default user:pass", service="oracle"),

    # --- App-specific ------------------------------------------------------
    _w("tomcat_mgr_default_users.txt", "user", "Tomcat manager default users", service="tomcat"),
    _w("tomcat_mgr_default_pass.txt", "password", "Tomcat manager default passwords", service="tomcat"),
    _w("tomcat_mgr_default_userpass.txt", "userpass", "Tomcat manager default user:pass", service="tomcat"),
    _w("cms400net_default_userpass.txt", "userpass", "Ektron CMS400.NET defaults", service="cms"),
    _w("idrac_default_user.txt", "user", "Dell iDRAC default users", service="idrac"),
    _w("idrac_default_pass.txt", "password", "Dell iDRAC default passwords", service="idrac"),

    # --- Management / out-of-band -----------------------------------------
    _w("ipmi_users.txt", "user", "IPMI default users", service="ipmi"),
    _w("ipmi_passwords.txt", "password", "IPMI default passwords", service="ipmi"),

    # --- SNMP communities --------------------------------------------------
    _w("snmp_default_pass.txt", "password", "SNMP community strings", service="snmp"),

    # --- VNC ---------------------------------------------------------------
    _w("vnc_passwords.txt", "password", "VNC common passwords", service="vnc"),

    # --- SAP ---------------------------------------------------------------
    _w("sap_common.txt", "user", "SAP common users", service="sap"),
    _w("sap_default.txt", "userpass", "SAP default user:pass", service="sap"),
]


def list_wordlists() -> list[dict]:
    """Returns the full catalog. Frontend filters by category and service."""
    return list(WORDLISTS)


# Frontend uses these to decide which option fields get a picker.
USER_OPTION_NAMES = {"USER_FILE", "USERNAME_FILE", "USERS_FILE"}
PASS_OPTION_NAMES = {
    "PASS_FILE",
    "PASSWORD_FILE",
    "PASSWORDS_FILE",
    "PASSWORD_LIST",
    "PASS_DB",
    "WORDLIST",
    "COMMUNITY_FILE",
    "COMMUNITIES",
    "DICTIONARY",
}
USERPASS_OPTION_NAMES = {"USERPASS_FILE"}

WORDLIST_OPTION_NAMES = sorted(
    USER_OPTION_NAMES | PASS_OPTION_NAMES | USERPASS_OPTION_NAMES
)
