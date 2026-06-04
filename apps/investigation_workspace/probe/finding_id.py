"""Deterministic finding ID generator for V1.6 probe findings.

Contract
--------
generate_finding_id(probe_id, target, path, finding_type) -> "fnd_<12 hex chars>"

The ID is a SHA-256 digest of the four inputs joined by "|", truncated to the
first 12 hex characters and prefixed with "fnd_" (total length 16).

Determinism guarantee: the same four inputs always produce the same ID, across
process restarts and across runs. This is load-bearing for two downstream uses:

1. Dedup (PR3) — re-running a probe against the same target skips persistence
   when a finding with the same ID already exists in the DB.

2. Cross-finding links (PR3 `related_findings`) — a probe can reference another
   probe's finding by ID without needing to read the DB.

Do NOT change the hash inputs, the digest length, or the prefix without a
migration that re-IDs all existing findings. The V1.6 audit (docs/audits/
v1.6-recon-enum-audit.md) documents this as the stable ID contract.
"""
from __future__ import annotations

import hashlib


def generate_finding_id(
    probe_id:     str,
    target:       str,
    path:         str,
    finding_type: str,
) -> str:
    """Return a stable 16-char finding ID derived from the four inputs.

    >>> a = generate_finding_id("passive", "http://x", "/", "http_service_detected")
    >>> a.startswith("fnd_") and len(a) == 16
    True
    >>> a == generate_finding_id("passive", "http://x", "/", "http_service_detected")
    True
    """
    raw = f"{probe_id}|{target}|{path}|{finding_type}"
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return f"fnd_{digest[:12]}"
