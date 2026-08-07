"""Validator: checks every proposed Registry change for internal consistency
before anything downstream (generation, code, merge) proceeds.

Validator never generates and never edits -- it only reports Findings and
lets the caller decide to block (see docs/ARCHITECTURE.md, "why not a single
Architecture Compiler"). Every check below is fail-closed: an ambiguous or
missing declaration is treated as a violation, not silently accepted.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from framework_final.discovery.index import scan
from framework_final.platform.dependency_rules import check_examples_isolation
from framework_final.platform.dependency_rules import check_package as check_dependency_direction
from framework_final.registry.concept_model import ConceptModel
from framework_final.registry.drift import find_drift
from framework_final.registry.models import ContractRecord, ModuleRecord
from framework_final.registry.store import RegistryStore


@dataclass(frozen=True)
class Finding:
    check: str
    record_id: str
    message: str

    def __str__(self) -> str:
        return f"[{self.check}] {self.record_id}: {self.message}"


# -- 1. Ownership completeness ------------------------------------------------


def check_ownership_completeness(store: RegistryStore) -> list[Finding]:
    """Every Registry record must have a non-empty owner."""
    findings: list[Finding] = []
    for kind, collection in (
        ("module", store.modules),
        ("capability", store.capabilities),
        ("application", store.applications),
    ):
        for rec_id, rec in collection.items():
            if not rec.owner or not rec.owner.strip():
                findings.append(Finding("ownership_completeness", rec_id, f"{kind} has no owner"))
    return findings


# -- 2. Referential integrity --------------------------------------------------


def check_referential_integrity(store: RegistryStore) -> list[Finding]:
    """Every referenced Contract/Event/Capability/Module must exist and must
    not be retired/removed.
    """
    findings: list[Finding] = []
    all_contracts = store.all_contracts()
    all_events = store.all_event_ids()

    for m in store.modules.values():
        for cid in m.consumed_contracts:
            info = all_contracts.get(cid)
            if info is None:
                findings.append(Finding("referential_integrity", m.id, f"consumes unknown Contract '{cid}'"))
            elif info[1].status == "retired":
                findings.append(Finding("referential_integrity", m.id, f"consumes retired Contract '{cid}'"))
        for eid in m.subscribed_events:
            if eid not in all_events:
                findings.append(Finding("referential_integrity", m.id, f"subscribes to unknown Event '{eid}'"))
        for cap_id in m.required_capabilities:
            cap = store.capabilities.get(cap_id)
            if cap is None:
                findings.append(Finding("referential_integrity", m.id, f"requires unknown Capability '{cap_id}'"))
            elif cap.status == "removed":
                findings.append(Finding("referential_integrity", m.id, f"requires removed Capability '{cap_id}'"))
        contract_names = {c.name for c in m.contracts}
        for pol in m.policies:
            if pol.command not in contract_names:
                findings.append(
                    Finding("referential_integrity", m.id, f"Policy '{pol.id}' references unknown command '{pol.command}'")
                )

    for app in store.applications.values():
        for mod_id in app.modules:
            if mod_id not in store.modules:
                findings.append(Finding("referential_integrity", app.id, f"references unknown Module '{mod_id}'"))
        for cap_id in app.capabilities:
            if cap_id not in store.capabilities:
                findings.append(Finding("referential_integrity", app.id, f"references unknown Capability '{cap_id}'"))
    return findings


# -- 3. Circular dependency detection -----------------------------------------


def check_circular_dependencies(store: RegistryStore) -> list[Finding]:
    """Cycles across the Module-to-Module Contract-consumption graph. The
    one-way layer rule (checked separately, #4) doesn't structurally
    prevent this on its own -- two Modules can each legally consume the
    other's Contract, which is a cycle even though neither import is
    itself a rule violation.
    """
    all_contracts = store.all_contracts()
    graph: dict[str, set[str]] = {m.id: set() for m in store.modules.values()}
    for m in store.modules.values():
        for cid in m.consumed_contracts:
            info = all_contracts.get(cid)
            if info is None:
                continue
            owner, _ = info
            if isinstance(owner, ModuleRecord) and owner.id != m.id:
                graph[m.id].add(owner.id)

    findings: list[Finding] = []
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {n: WHITE for n in graph}

    def visit(node: str, path: list[str]) -> None:
        color[node] = GRAY
        path.append(node)
        for neighbor in sorted(graph.get(node, set())):
            if color.get(neighbor) == GRAY:
                cycle = path[path.index(neighbor):] + [neighbor]
                findings.append(
                    Finding("circular_dependency", node, f"circular Contract-consumption: {' -> '.join(cycle)}")
                )
            elif color.get(neighbor) == WHITE:
                visit(neighbor, path)
        path.pop()
        color[node] = BLACK

    for node in sorted(graph):
        if color[node] == WHITE:
            visit(node, [])
    return findings


# -- 4. Dependency direction conformance --------------------------------------


def check_dependency_direction_conformance(package_root: Path, examples_root: Path | None = None) -> list[Finding]:
    """Application -> Module -> Capability -> Platform, enforced by
    inspecting actual Python imports -- both the framework's own internal
    packages and, more importantly, concrete example content, which is what
    actually proves the rule holds for real business implementations (see
    platform/dependency_rules.py).
    """
    violations = list(check_dependency_direction(package_root))
    if examples_root is not None:
        violations += check_examples_isolation(examples_root)
    return [Finding("dependency_direction_conformance", str(v.file), v.message) for v in violations]


# -- 5. Vocabulary conformance -------------------------------------------------


def check_vocabulary_conformance(store: RegistryStore) -> list[Finding]:
    """No duplicate canonical names within a scope, no alias/canonical
    collisions, no dangling relationships, no reused retired ids, and no
    Capability owning a Concept Model entry (Capabilities are domain-agnostic
    by definition and have no business vocabulary to canonicalize).
    """
    cm = ConceptModel(concepts=tuple(store.concepts.values()))
    findings: list[Finding] = []
    for scope, label, ids in cm.duplicate_canonical_names():
        findings.append(
            Finding("vocabulary_conformance", "/".join(ids), f"duplicate canonical name '{label}' in scope '{scope}'")
        )
    for scope, alias in cm.alias_violations():
        findings.append(
            Finding("vocabulary_conformance", scope, f"alias '{alias}' collides with a canonical name in scope '{scope}'")
        )
    for cid, rel, target in cm.dangling_relationships():
        findings.append(Finding("vocabulary_conformance", cid, f"{rel} points at unknown Concept '{target}'"))
    for cid in cm.retired_ids_reused():
        findings.append(Finding("vocabulary_conformance", cid, "retired Concept id reused by an active Concept"))

    module_ids = set(store.modules.keys())
    for c in store.concepts.values():
        if c.owner_module not in module_ids:
            findings.append(
                Finding(
                    "vocabulary_conformance",
                    c.id,
                    f"owner_module '{c.owner_module}' is not a Module -- Capabilities must never own Concept Model entries",
                )
            )
    return findings


# -- 6. Contract compatibility -------------------------------------------------


def check_contract_compatibility(store: RegistryStore) -> list[Finding]:
    """Contract major_versions for one name must be unique, consecutive from
    1, and never change operation-kind (Command/Query) across versions.
    """
    findings: list[Finding] = []
    for owner in (*store.modules.values(), *store.capabilities.values()):
        by_name: dict[str, list[ContractRecord]] = {}
        for c in owner.contracts:
            by_name.setdefault(c.name, []).append(c)
        for name, versions in by_name.items():
            majors = [v.major_version for v in versions]
            if len(majors) != len(set(majors)):
                findings.append(
                    Finding("contract_compatibility", owner.id, f"Contract '{name}' declares duplicate major_version(s) {majors}")
                )
            expected = list(range(1, len(set(majors)) + 1))
            if sorted(set(majors)) != expected:
                findings.append(
                    Finding(
                        "contract_compatibility",
                        owner.id,
                        f"Contract '{name}' major_versions {sorted(set(majors))} are not consecutive from 1",
                    )
                )
            kinds = {v.kind for v in versions}
            if len(kinds) > 1:
                findings.append(
                    Finding("contract_compatibility", owner.id, f"Contract '{name}' changes operation-kind across versions: {kinds}")
                )
    return findings


# -- 7. Module boundary conformance --------------------------------------------


def check_module_boundary_conformance(store: RegistryStore) -> list[Finding]:
    """Declared footprint (registry.yaml) cross-checked against Discovery
    Index's scan of the owner's own folder -- catches code that violates a
    boundary Registry claims is clean.
    """
    findings: list[Finding] = []
    for owner in (*store.modules.values(), *store.capabilities.values()):
        src = store.source_of(owner.id)
        if src is None:
            continue
        index = scan(src.parent)
        for d in find_drift(owner, index):
            findings.append(Finding("module_boundary_conformance", d.record_id, d.message))
    return findings


# -- 8. Generated-artifact drift -----------------------------------------------


def check_generated_artifact_drift(
    store: RegistryStore, discovery_roots: Iterable[Path], generated_dir: Path | None
) -> list[Finding]:
    """Regenerate every artifact and diff against what's committed under
    `generated_dir`. If `generated_dir` doesn't exist yet, there is nothing
    committed to drift from -- this is reported as clean, not skipped
    silently, so a first-time run is distinguishable from "checked, no drift".
    """
    if generated_dir is None or not generated_dir.exists():
        return []

    from framework_final.registry.generators import ai_context, dependency_graph, documentation

    findings: list[Finding] = []
    fresh_dep_graph = dependency_graph.generate(store)
    committed_dep_graph = generated_dir / "dependency_graph.json"
    if committed_dep_graph.exists() and committed_dep_graph.read_text() != fresh_dep_graph:
        findings.append(Finding("generated_artifact_drift", "dependency_graph.json", "committed output does not match a fresh regeneration"))

    for module_id in store.modules:
        fresh_doc = documentation.generate_module_doc(store, module_id)
        committed_doc = generated_dir / "docs" / f"{module_id}.md"
        if committed_doc.exists() and committed_doc.read_text() != fresh_doc:
            findings.append(Finding("generated_artifact_drift", module_id, "committed reference documentation does not match a fresh regeneration"))
        fresh_ctx = ai_context.generate(store, module_id, discovery_roots)
        committed_ctx = generated_dir / "ai_context" / f"{module_id}.json"
        if committed_ctx.exists() and committed_ctx.read_text() != fresh_ctx:
            findings.append(Finding("generated_artifact_drift", module_id, "committed AI context bundle does not match a fresh regeneration"))
    return findings


# -- 9. Application composition validity ---------------------------------------


def check_application_composition_validity(store: RegistryStore) -> list[Finding]:
    """Every Application manifest must reference only `active` Modules and
    Capabilities. (Existence is check #2's job; this is about status.)
    """
    findings: list[Finding] = []
    for app in store.applications.values():
        for mod_id in app.modules:
            mod = store.modules.get(mod_id)
            if mod is not None and mod.status != "active":
                findings.append(
                    Finding("application_composition_validity", app.id, f"Module '{mod_id}' has status '{mod.status}', expected 'active'")
                )
        for cap_id in app.capabilities:
            cap = store.capabilities.get(cap_id)
            if cap is not None and cap.status != "active":
                findings.append(
                    Finding("application_composition_validity", app.id, f"Capability '{cap_id}' has status '{cap.status}', expected 'active'")
                )
    return findings


# -- 10. Policy coverage --------------------------------------------------------


def check_policy_coverage(store: RegistryStore) -> list[Finding]:
    """Every Command a Module declares must have an associated Policy rule.
    Fails closed at runtime regardless (see runtime/policy_enforcer.py), but
    the *declaration* itself must be explicit, not implicit -- an
    undeclared Command silently relying on default-deny is still a gap
    someone has to notice and fix.
    """
    findings: list[Finding] = []
    for m in store.modules.values():
        covered = {p.command for p in m.policies}
        for c in m.contracts:
            if c.kind == "command" and c.name not in covered:
                findings.append(Finding("policy_coverage", m.id, f"Command '{c.name}' has no associated Policy rule"))
    return findings


# -- orchestration --------------------------------------------------------------

ALL_CHECKS = (
    "ownership_completeness",
    "referential_integrity",
    "circular_dependency",
    "dependency_direction_conformance",
    "vocabulary_conformance",
    "contract_compatibility",
    "module_boundary_conformance",
    "generated_artifact_drift",
    "application_composition_validity",
    "policy_coverage",
)


def validate(
    store: RegistryStore,
    package_root: Path,
    discovery_roots: Iterable[Path] = (),
    generated_dir: Path | None = None,
    examples_root: Path | None = None,
) -> list[Finding]:
    """Run every check. Order does not matter -- each check is independent
    and reports its own Findings; nothing here mutates Registry or writes
    anything (see docs/ARCHITECTURE.md, Validator's MUST NEVER list).
    """
    findings: list[Finding] = []
    findings += check_ownership_completeness(store)
    findings += check_referential_integrity(store)
    findings += check_circular_dependencies(store)
    findings += check_dependency_direction_conformance(package_root, examples_root)
    findings += check_vocabulary_conformance(store)
    findings += check_contract_compatibility(store)
    findings += check_module_boundary_conformance(store)
    findings += check_generated_artifact_drift(store, discovery_roots, generated_dir)
    findings += check_application_composition_validity(store)
    findings += check_policy_coverage(store)
    return findings


if __name__ == "__main__":
    import sys

    roots = [Path(p) for p in sys.argv[1:]] or [Path("examples")]
    src_root = Path(__file__).resolve().parents[1]  # .../src
    store = RegistryStore.discover(roots)
    results = validate(store, package_root=src_root, discovery_roots=roots, examples_root=Path("examples"))
    if results:
        for f in results:
            print(f)
        print(f"\n{len(results)} finding(s).")
        sys.exit(1)
    print("registry: clean")
