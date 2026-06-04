"""System-wide conductor constants.

Single source of truth for threshold values and domain mappings.
Populate the domain maps below when adopting this framework for your use case.
"""

# Vault similarity threshold below which the model advisor is invoked.
# Lower = model invoked more often. Calibrate against your vault content.
SIM_FLOOR: float = 0.55

# Feature flag: three-zone selection card UI.
SELECTION_CARD_ENABLED: bool = True


# ── Domain mappings — populate per your engines and concepts ──────────────────

# Maps each vault concept file's canonical CONCEPT-* ID to the engine that
# executes it. None = advisory concept only, no automated engine.
CONCEPT_ENGINE_MAP: dict[str, str | None] = {}

# Engines that require a captured session to operate.
# VaultSelector sets requires_session=True when the resolved engine_id is here.
SESSION_REQUIRED_ENGINES: set[str] = set()

# Which finding_types each concept's engine GENERATES as output.
# Used to remove self-recommendations (a concept shouldn't suggest itself).
CONCEPT_PRODUCES: dict[str, list[str]] = {}

# Technique family groupings — used to surface sibling concepts.
# Concepts in the same family are co-surfaced when any family member appears.
CONCEPT_FAMILY: dict[str, str] = {}

# Objective-technology keyword → concept_ids that handle it.
# Used for deterministic ranking when operator names an explicit technology.
OBJECTIVE_TECH_CONCEPTS: dict[str, list[str]] = {}

# Canonical titles for each concept — shown in operator UI.
CONCEPT_TITLES: dict[str, str] = {}

# For a given finding_type, which technique families are worth surfacing.
FINDING_FAMILY_HINTS: dict[str, list[str]] = {}
