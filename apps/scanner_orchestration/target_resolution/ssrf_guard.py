"""SSRF guard — validates scan targets against platform policy.

Default policy:
  ALLOW  localhost, 127.x, ::1, 0.0.0.0
  ALLOW  host.docker.internal
  ALLOW  RFC 1918 ranges (10/8, 172.16/12, 192.168/16)
  ALLOW  extra hosts from LAB_ALLOWED_TARGETS env (comma-separated)
  ALLOW  extra CIDRs from LAB_ALLOWED_RANGES env (comma-separated)
  BLOCK  cloud metadata endpoints (169.254.169.254, etc.)
  BLOCK  everything else (public internet)

Returns (allowed: bool, reason: str) — reason is human-readable and
surfaced directly to the user when allowed=False.
"""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse

# Cloud metadata endpoints — always blocked regardless of environment config.
_CLOUD_METADATA_HOSTS = frozenset({
    "169.254.169.254",   # AWS/Azure/GCP instance metadata
    "metadata.google.internal",
    "169.254.170.2",     # ECS task metadata
    "100.100.100.200",   # Alibaba Cloud metadata
})

_CLOUD_METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),  # link-local — includes all cloud metadata
]

# Always allowed — no env override needed.
_ALWAYS_ALLOWED_HOSTS = frozenset({
    "localhost",
    "host.docker.internal",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
})

# Default lab ranges — RFC 1918 + loopback.
_DEFAULT_ALLOWED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


def _extract_host(target: str) -> str:
    """Return the hostname or IP from a target string (URL or bare host:port)."""
    t = target.strip()
    if "://" in t:
        h = urlparse(t).hostname or ""
    else:
        h = t.split(":")[0].split("/")[0]
    return h.lower().strip("[]")  # strip IPv6 brackets


def _extra_allowed_hosts() -> frozenset[str]:
    raw = os.environ.get("LAB_ALLOWED_TARGETS", "")
    return frozenset(h.strip().lower() for h in raw.split(",") if h.strip())


def _extra_allowed_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    raw = os.environ.get("LAB_ALLOWED_RANGES", "")
    nets = []
    for cidr in raw.split(","):
        cidr = cidr.strip()
        if cidr:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
    return nets


def validate_target(target: str) -> tuple[bool, str]:
    """Validate a scan target against platform SSRF policy.

    Returns (allowed, reason).
    reason is empty when allowed, human-readable when blocked.
    """
    host = _extract_host(target)
    if not host:
        return False, "Target must specify a valid hostname or IP address."

    # ── Cloud metadata — absolute block ──────────────────────────────────
    if host in _CLOUD_METADATA_HOSTS:
        return False, (
            "Cloud metadata endpoints cannot be used as scan targets. "
            "This platform is restricted to approved lab environments."
        )

    # ── Always allowed ────────────────────────────────────────────────────
    if host in _ALWAYS_ALLOWED_HOSTS:
        return True, ""

    # ── Extra hostname allowlist (env config) ─────────────────────────────
    if host in _extra_allowed_hosts():
        return True, ""

    # ── IP address validation ─────────────────────────────────────────────
    try:
        ip = ipaddress.ip_address(host)

        # Cloud metadata IP ranges
        for net in _CLOUD_METADATA_NETWORKS:
            if ip in net:
                return False, (
                    "Link-local and cloud metadata addresses cannot be used as scan targets."
                )

        # Default RFC 1918 / loopback
        for net in _DEFAULT_ALLOWED_NETWORKS:
            if ip in net:
                return True, ""

        # Extra configured CIDR ranges
        for net in _extra_allowed_networks():
            if ip in net:
                return True, ""

        # Public IP — not in any allowlist
        return False, (
            f"'{host}' is a public IP address and is not permitted. "
            "This platform supports approved lab targets only. "
            "Configure LAB_ALLOWED_RANGES to add custom IP ranges."
        )

    except ValueError:
        pass

    # ── Hostname not in any allowlist ─────────────────────────────────────
    return False, (
        f"'{host}' is not in the approved target list. "
        "This platform currently supports approved lab targets only. "
        "Configure LAB_ALLOWED_TARGETS to add approved hostnames."
    )
