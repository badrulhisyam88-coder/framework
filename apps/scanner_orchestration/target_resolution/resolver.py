"""TargetResolver — reconstructed after VESTIGE-1 deletion.

Parses the scan target URL and produces a TargetContext for scanner adapters.
localhost/127.x is mapped to host.docker.internal so containers can reach the
Docker host. All other URLs are used as-is (DIRECT strategy).
"""
from __future__ import annotations

from urllib.parse import urlparse

from apps.scanner_orchestration.target_resolution.models import (
    ResolutionStrategy,
    TargetContext,
    TargetType,
)

_LOCALHOST_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})


class TargetResolver:
    """Resolves a raw target string into a TargetContext."""

    def resolve(self, target: str) -> TargetContext:
        """Parse *target* and return a populated TargetContext.

        Handles:
        - Full URLs (https://host/path) → extracts host/port
        - Bare host:port → wraps with http://
        - localhost → host.docker.internal (Docker networking)
        """
        raw = target.strip()

        # Ensure we have a parseable URL
        if "://" not in raw:
            raw = "http://" + raw

        parsed = urlparse(raw)
        scheme = parsed.scheme or "https"
        host = (parsed.hostname or "").lower().strip("[]")
        port = parsed.port

        # Docker host routing
        if host in _LOCALHOST_HOSTS:
            docker_host = "host.docker.internal"
            scanner_url = raw.replace(host, docker_host, 1)
            if parsed.port is None:
                # Replace bare host in scanner_url
                scanner_url = f"{scheme}://{docker_host}{parsed.path or '/'}"
                if parsed.query:
                    scanner_url += "?" + parsed.query
            strategy = ResolutionStrategy.DOCKER_HOST_INTERNAL
            scanner_host = docker_host
        else:
            scanner_url = raw
            strategy = ResolutionStrategy.DIRECT
            scanner_host = host

        # Best-effort target type detection
        path_lower = (parsed.path or "").lower()
        if "juice" in host or "juice" in path_lower:
            target_type = TargetType.JUICE_SHOP
        elif "dvwa" in host or "dvwa" in path_lower:
            target_type = TargetType.DVWA
        elif "webgoat" in host or "webgoat" in path_lower:
            target_type = TargetType.WEBGOAT
        else:
            target_type = TargetType.GENERIC_WEB

        env = "docker_host" if strategy == ResolutionStrategy.DOCKER_HOST_INTERNAL else "remote"

        return TargetContext(
            display_url=target.strip(),
            scanner_url=scanner_url,
            scanner_host=scanner_host,
            scanner_port=port,
            target_type=target_type,
            environment_type=env,
            resolution_strategy=strategy,
        )
