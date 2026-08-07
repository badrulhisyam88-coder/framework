"""Concept Model operations: canonical-name resolution, alias handling, and
relationship validation over a set of ConceptRecord entries.

Business/domain vocabulary belongs only to Modules (see docs/GLOSSARY.md).
Capabilities never own Concept Model entries -- they are domain-agnostic by
definition and have nothing to canonicalize; the Validator enforces this
(see registry/validator.py, vocabulary conformance).
"""

from __future__ import annotations

from dataclasses import dataclass

from framework_final.registry.models import ConceptRecord


@dataclass(frozen=True)
class ConceptModel:
    concepts: tuple[ConceptRecord, ...]

    def resolve(self, name: str, scope: str) -> ConceptRecord | None:
        """Resolve a name to its canonical ConceptRecord within a scope.

        Canonical labels are checked first, then aliases -- an alias always
        resolves back to the canonical record, it never stands as an
        independently valid name.
        """
        for c in self.concepts:
            if c.scope == scope and c.label == name:
                return c
        for c in self.concepts:
            if c.scope == scope and name in c.aliases:
                return c
        return None

    def duplicate_canonical_names(self) -> list[tuple[str, str, list[str]]]:
        """(scope, label, [concept ids]) for every canonical label used by
        more than one Concept in the same scope -- the exact "one word,
        several meanings" collision the Concept Model exists to catch.
        """
        by_scope_label: dict[tuple[str, str], list[str]] = {}
        for c in self.concepts:
            by_scope_label.setdefault((c.scope, c.label), []).append(c.id)
        return [
            (scope, label, ids)
            for (scope, label), ids in by_scope_label.items()
            if len(ids) > 1
        ]

    def alias_violations(self) -> list[tuple[str, str]]:
        """(scope, alias) for every alias string that is *also* used as a
        different Concept's canonical label in the same scope -- using a
        forbidden synonym where a canonical name already claims it.
        """
        canonical_by_scope: dict[str, set[str]] = {}
        for c in self.concepts:
            canonical_by_scope.setdefault(c.scope, set()).add(c.label)
        violations: list[tuple[str, str]] = []
        for c in self.concepts:
            for alias in c.aliases:
                if alias in canonical_by_scope.get(c.scope, set()):
                    violations.append((c.scope, alias))
        return violations

    def dangling_relationships(self) -> list[tuple[str, str, str]]:
        """(concept_id, relationship, target_id) for every specializes /
        supersedes / references pointer that doesn't resolve to a real
        Concept id. These three are the *only* relationship types this
        model allows -- deliberately not an open-ended ontology graph.
        """
        ids = {c.id for c in self.concepts}
        problems: list[tuple[str, str, str]] = []
        for c in self.concepts:
            if c.specializes and c.specializes not in ids:
                problems.append((c.id, "specializes", c.specializes))
            if c.supersedes and c.supersedes not in ids:
                problems.append((c.id, "supersedes", c.supersedes))
            for ref in c.references:
                if ref not in ids:
                    problems.append((c.id, "references", ref))
        return problems

    def retired_ids_reused(self) -> list[str]:
        """A retired Concept id must never be reused by an active Concept --
        historical Events may reference it indefinitely.
        """
        retired = {c.id for c in self.concepts if c.status == "removed"}
        active = {c.id for c in self.concepts if c.status != "removed"}
        return sorted(retired & active)
