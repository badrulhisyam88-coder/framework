"""Drift: comparing Registry's declared intent against the Discovery
Index's observed reality.

This lives in registry/, not discovery/ -- Discovery Index's own allowed
dependencies are empty (see discovery/index.py): it must never import
Registry, or it would start inferring intent from declarations instead of
just reporting what it finds, which would violate its descriptive-only
charter. The comparison itself is a Registry-side concern, consistent with
Validator's own allowed dependencies (Registry, Discovery Index, Meta-Model).
"""

from __future__ import annotations

from dataclasses import dataclass

from framework_final.discovery.index import DiscoveryIndex
from framework_final.registry.models import CapabilityRecord, ModuleRecord


def _pascal(snake: str) -> str:
    return "".join(part.capitalize() for part in snake.split("_"))


@dataclass(frozen=True)
class DriftFinding:
    record_id: str
    kind: str  # "contract" or "event"
    declared_name: str
    expected_symbol: str
    message: str


def find_drift(
    owner: ModuleRecord | CapabilityRecord, index: DiscoveryIndex
) -> list[DriftFinding]:
    """For every declared Contract/Event, confirm a matching symbol was
    actually found by scanning the owner's own folder.

    Naming convention: a Contract/Event named `create_task` is expected to
    have a class named `CreateTask` somewhere in the owner's code -- a
    deliberately simple, explicit, checkable convention, not general-purpose
    type inference.
    """
    found = index.all_symbol_names()
    findings: list[DriftFinding] = []

    for contract in owner.contracts:
        expected = _pascal(contract.name)
        if expected not in found:
            findings.append(
                DriftFinding(
                    record_id=owner.id,
                    kind="contract",
                    declared_name=contract.name,
                    expected_symbol=expected,
                    message=(
                        f"{owner.id} declares Contract '{contract.name}' but no "
                        f"class '{expected}' was found in its own folder"
                    ),
                )
            )

    if isinstance(owner, ModuleRecord):
        for event in owner.events:
            expected = _pascal(event.name)
            if expected not in found:
                findings.append(
                    DriftFinding(
                        record_id=owner.id,
                        kind="event",
                        declared_name=event.name,
                        expected_symbol=expected,
                        message=(
                            f"{owner.id} declares Event '{event.name}' but no "
                            f"class '{expected}' was found in its own folder"
                        ),
                    )
                )
    return findings
