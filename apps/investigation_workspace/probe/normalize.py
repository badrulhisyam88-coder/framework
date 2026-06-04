"""Target URL normalization.

The investigation layer should never forward operator-typed URLs to a
scanner verbatim — they often include client-side routing state like
hash fragments (#/path) that don't belong in HTTP requests. Strip those
and any incidental whitespace before any probing happens.

Phase 47 — also rewrite localhost-style hosts to host.docker.internal
when the backend is running inside a Docker container. Operators
naturally type `localhost:10000` when they mean "the service on my
host machine", but from inside the container localhost is the
container itself. Without this rewrite every dev probe gets
'connection refused' even though the target is up.

Returns (normalized_target, actions_taken) so the runtime can record
the cleanup as part of the bootstrap reasoning ("trimmed whitespace",
"stripped fragment (#/...)", etc.) instead of silently rewriting input.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse, urlunparse

# Hosts that, from a Docker container, mean "the container itself" rather
# than "the host machine". When the backend runs in a container, treat
# operator-typed localhost as a sign they mean the host.
_LOCALHOST_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]", "::1"})

# Cached Docker-presence flag — derived once per process from the standard
# /.dockerenv marker file.
_IN_DOCKER = os.path.exists("/.dockerenv")


def normalize_target(target: str) -> tuple[str, list[str]]:
    """Return (normalized_url, actions). Empty string when unusable."""
    actions: list[str] = []
    raw = target or ""

    # Whitespace
    trimmed = raw.strip()
    if trimmed != raw:
        actions.append("trimmed whitespace")
    if not trimmed:
        return ("", actions + ["empty target after normalization"])

    # Default scheme if missing — operators often paste bare hosts.
    candidate = trimmed
    if "://" not in candidate:
        candidate = "http://" + candidate
        actions.append("defaulted scheme to http://")

    # Parse and rebuild with fragment + query stripped if they look like
    # client-side routing leakage. We deliberately keep ?query because
    # real endpoints often need it; we drop only #fragment which is always
    # client-side.
    parsed = urlparse(candidate)
    if parsed.fragment:
        actions.append(f"stripped fragment (#{parsed.fragment[:32]})")
        parsed = parsed._replace(fragment="")

    # Validate scheme
    if parsed.scheme not in ("http", "https"):
        return ("", actions + [f"unsupported scheme: {parsed.scheme}"])

    # Validate host
    if not parsed.netloc:
        return ("", actions + ["missing host"])

    # Phase 47 — Docker-localhost rewrite. When running in a container,
    # operator-typed localhost almost always means the host machine.
    if _IN_DOCKER and parsed.hostname and parsed.hostname.lower() in _LOCALHOST_HOSTS:
        port = f":{parsed.port}" if parsed.port else ""
        # Preserve userinfo if any (rare on operator-typed URLs but safe).
        userinfo = ""
        if "@" in parsed.netloc:
            userinfo = parsed.netloc.rsplit("@", 1)[0] + "@"
        original_host = parsed.hostname
        parsed = parsed._replace(netloc=f"{userinfo}host.docker.internal{port}")
        actions.append(
            f"rewrote {original_host} → host.docker.internal "
            "(container cannot reach its own localhost)"
        )

    # Reassemble. urlunparse preserves netloc, path, query, drops fragment.
    normalized = urlunparse(parsed)
    return (normalized, actions)
