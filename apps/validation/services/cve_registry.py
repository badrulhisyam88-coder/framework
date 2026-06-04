"""
CVE detection rule registry for the Custom Report scanner.

Each rule maps a CVE ID to a product fingerprint (matched against the HTTP
Server header) and a vulnerable-version window. Versions are ordinary tuples
so comparisons are stdlib-only.

Vulnerability rule: a parsed version V is vulnerable iff
    rule.introduced <= V < rule.fixed

To add a new CVE, append a CVERule to _REGISTRY. Keep the product name
lowercase; matching is case-insensitive against the Server header.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_VERSION_PATTERN = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


@dataclass(frozen=True)
class CVERule:
    cve_id: str
    title: str
    product: str
    severity: str
    cvss: str
    introduced: tuple[int, ...]
    fixed: tuple[int, ...]
    notes: str
    references: tuple[str, ...]


_REGISTRY: dict[str, CVERule] = {
    "CVE-2026-42945": CVERule(
        cve_id="CVE-2026-42945",
        title="NGINX ngx_http_rewrite_module heap buffer overflow",
        product="nginx",
        severity="critical",
        cvss="9.2",
        introduced=(0, 6, 27),
        fixed=(1, 30, 1),
        notes=(
            "Server-header version can be misleading: distro packages may have "
            "backported the fix without bumping it, and nginx bundled inside "
            "Java appliances, vendor products, or Docker containers won't show "
            "up in rpm/apt at all. Confirm by running `nginx -V` against the "
            "actual running binary (find via `ps -ef | grep nginx` then "
            "`readlink /proc/<pid>/exe`); for vendor-bundled nginx, check the "
            "vendor's security advisory. The exploit also requires a specific "
            "rewrite directive pattern in nginx.conf, not detectable remotely."
        ),
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2026-42945",
            "https://www.openwall.com/lists/oss-security/2026/05/13/7",
            "https://nginx.org/en/security_advisories.html",
        ),
    ),
}


def get_rule(cve_id: str) -> CVERule | None:
    return _REGISTRY.get(cve_id.strip().upper())


def known_cves() -> list[CVERule]:
    return list(_REGISTRY.values())


def parse_version(s: str) -> tuple[int, ...] | None:
    """Extract a numeric version from 'nginx/1.30.0' or '1.30.0'. Missing patch defaults to 0."""
    m = _VERSION_PATTERN.search(s)
    if not m:
        return None
    parts = (m.group(1), m.group(2), m.group(3) or "0")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def evaluate(rule: CVERule, version: tuple[int, ...] | None) -> str:
    """Grade a parsed version against a rule. Returns: vulnerable | safe | unknown_version."""
    if version is None:
        return "unknown_version"
    if rule.introduced <= version < rule.fixed:
        return "vulnerable"
    return "safe"
