"""Application framework: manifest loading only.

No concrete Application manifests live here -- see /examples for the one
demonstration Application manifest.yaml. Loading here means "parse YAML into
an ApplicationRecord" -- composition data, not business logic. Checking a
manifest against what Registry actually has is registry/validator.py's job
(checks #2 and #9); this module does not duplicate that logic.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from framework_final.registry.models import ApplicationRecord


class ManifestError(ValueError):
    pass


def load_manifest(path: Path | str) -> ApplicationRecord:
    path = Path(path)
    data = yaml.safe_load(path.read_text()) or {}
    if data.get("kind") != "application":
        raise ManifestError(f"{path}: expected kind: application, got {data.get('kind')!r}")
    return ApplicationRecord.model_validate(data)
