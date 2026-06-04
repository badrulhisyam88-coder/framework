"""Phase 58 — post-exploit artifact capture.

When a probe succeeds at exploiting a vulnerability, it can call
`capture_post_exploit` to collect a bundle of follow-up artifacts
(authenticated GETs against post-exploit endpoints, plus the
exploit request/response/session that triggered the capture). The
bundle becomes a Capture node downstream of the Outcome on the
graph; the operator browses the artifacts in the side panel.

Storage is in-memory, mirroring execution/runtime.py's _RUNS/_BY_INV
pattern. Restart-bound; no DB.

Public API:
    from apps.investigation_workspace.capture import (
        capture_post_exploit,    # build + store a bundle
        get_bundle,              # bundle_id -> ArtifactBundle | None
        bundles_for_investigation,
        Artifact,
        ArtifactBundle,
    )
"""
from apps.investigation_workspace.capture.bundler import (
    Artifact,
    ArtifactBundle,
    bundles_for_investigation,
    capture_post_exploit,
    get_bundle,
)

__all__ = [
    "Artifact",
    "ArtifactBundle",
    "bundles_for_investigation",
    "capture_post_exploit",
    "get_bundle",
]
