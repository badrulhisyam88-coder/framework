"""Shared target classification for conductor engines.

Canonical single source of truth for local/private/external classification.
SessionOrchestrator.detect_target_type() delegates here.
NmapEngine uses this to gate execution against non-local targets.
"""
from __future__ import annotations

import ipaddress
import re
from enum import Enum
from urllib.parse import urlparse


class TargetClass(Enum):
    LOCAL = "local"        # loopback: localhost, 127.x, ::1, 0.0.0.0
    PRIVATE = "private"    # RFC1918 + reserved TLDs (.local/.test/.internal)
    EXTERNAL = "external"  # everything else


def classify_target(target: str) -> TargetClass:
    """Classify a target URL or bare hostname/IP.

    Accepts full URLs (https://host:port/path) or bare hosts (10.0.0.1,
    foo.local). Strips scheme and port before classifying.
    """
    parsed = urlparse(target if "://" in target else f"http://{target}")
    host = parsed.hostname or target

    # Explicit loopback hostnames (covers bare "::1" when urlparse returns None)
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return TargetClass.LOCAL

    # Reserved TLDs used in private/test networks
    if re.search(r"\.(local|test|localhost|internal)$", host, re.IGNORECASE):
        return TargetClass.PRIVATE

    # IP-based classification
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return TargetClass.LOCAL
        if ip.is_private or ip.is_link_local:
            return TargetClass.PRIVATE
        return TargetClass.EXTERNAL
    except ValueError:
        pass  # not a bare IP address

    return TargetClass.EXTERNAL
