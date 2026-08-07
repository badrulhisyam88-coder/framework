"""Tests for registry/validator.py -- the ten architecture-integrity checks.
Each is exercised both by a deliberately-broken synthetic fixture and, once,
against the real example content, which must pass every check cleanly.
"""

from pathlib import Path

from framework_final.registry.models import (
    ApplicationRecord,
    CapabilityRecord,
    ConceptRecord,
    ContractRecord,
    ModuleRecord,
    PolicyRecordEntry,
)
from framework_final.registry.store import RegistryStore
from framework_final.registry.validator import (
    check_application_composition_validity,
    check_circular_dependencies,
    check_contract_compatibility,
    check_ownership_completeness,
    check_policy_coverage,
    check_referential_integrity,
    check_vocabulary_conformance,
    validate,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _store(modules=None, capabilities=None, applications=None, concepts=None) -> RegistryStore:
    store = RegistryStore()
    store.modules.update(modules or {})
    store.capabilities.update(capabilities or {})
    store.applications.update(applications or {})
    store.concepts.update(concepts or {})
    return store


def test_real_examples_pass_every_check():
    examples_root = REPO_ROOT / "examples"
    store = RegistryStore.discover([examples_root])
    findings = validate(
        store,
        package_root=REPO_ROOT / "src",
        discovery_roots=[examples_root],
        examples_root=examples_root,
    )
    assert findings == []


def test_ownership_completeness_catches_missing_owner():
    m = ModuleRecord(id="x", owner="   ")
    findings = check_ownership_completeness(_store(modules={"x": m}))
    assert len(findings) == 1
    assert findings[0].check == "ownership_completeness"


def test_referential_integrity_catches_unknown_contract():
    m = ModuleRecord(id="x", owner="team", consumed_contracts=["nonexistent.thing.v1"])
    findings = check_referential_integrity(_store(modules={"x": m}))
    assert any("nonexistent.thing.v1" in f.message for f in findings)


def test_referential_integrity_catches_retired_contract():
    a = ModuleRecord(
        id="a", owner="team", contracts=[ContractRecord(name="op", kind="command", status="retired")]
    )
    b = ModuleRecord(id="b", owner="team", consumed_contracts=["a.op.v1"])
    findings = check_referential_integrity(_store(modules={"a": a, "b": b}))
    assert any("retired" in f.message for f in findings)


def test_referential_integrity_catches_unknown_required_capability():
    m = ModuleRecord(id="x", owner="team", required_capabilities=["ghost"])
    findings = check_referential_integrity(_store(modules={"x": m}))
    assert any("ghost" in f.message for f in findings)


def test_referential_integrity_catches_policy_on_unknown_command():
    m = ModuleRecord(id="x", owner="team", policies=[PolicyRecordEntry(id="x.p", command="nope")])
    findings = check_referential_integrity(_store(modules={"x": m}))
    assert any("nope" in f.message for f in findings)


def test_circular_dependency_is_caught():
    a = ModuleRecord(
        id="a",
        owner="team",
        contracts=[ContractRecord(name="op_a", kind="command")],
        consumed_contracts=["b.op_b.v1"],
    )
    b = ModuleRecord(
        id="b",
        owner="team",
        contracts=[ContractRecord(name="op_b", kind="command")],
        consumed_contracts=["a.op_a.v1"],
    )
    findings = check_circular_dependencies(_store(modules={"a": a, "b": b}))
    assert len(findings) >= 1
    assert findings[0].check == "circular_dependency"


def test_no_circular_dependency_for_a_simple_chain():
    a = ModuleRecord(id="a", owner="team", contracts=[ContractRecord(name="op", kind="command")])
    b = ModuleRecord(id="b", owner="team", consumed_contracts=["a.op.v1"])
    assert check_circular_dependencies(_store(modules={"a": a, "b": b})) == []


def test_contract_compatibility_catches_kind_change_and_version_gap():
    m = ModuleRecord(
        id="x",
        owner="team",
        contracts=[
            ContractRecord(name="op", kind="command", major_version=1),
            ContractRecord(name="op", kind="query", major_version=3),
        ],
    )
    findings = check_contract_compatibility(_store(modules={"x": m}))
    messages = " ".join(f.message for f in findings)
    assert "not consecutive" in messages
    assert "changes operation-kind" in messages


def test_contract_compatibility_passes_for_clean_sequential_versions():
    m = ModuleRecord(
        id="x",
        owner="team",
        contracts=[
            ContractRecord(name="op", kind="command", major_version=1, status="deprecated"),
            ContractRecord(name="op", kind="command", major_version=2, status="published"),
        ],
    )
    assert check_contract_compatibility(_store(modules={"x": m})) == []


def test_policy_coverage_catches_uncovered_command():
    m = ModuleRecord(id="x", owner="team", contracts=[ContractRecord(name="op", kind="command")])
    findings = check_policy_coverage(_store(modules={"x": m}))
    assert len(findings) == 1
    assert "op" in findings[0].message


def test_policy_coverage_passes_when_declared():
    m = ModuleRecord(
        id="x",
        owner="team",
        contracts=[ContractRecord(name="op", kind="command")],
        policies=[PolicyRecordEntry(id="x.op.policy", command="op")],
    )
    assert check_policy_coverage(_store(modules={"x": m})) == []


def test_policy_coverage_does_not_require_a_rule_for_queries():
    m = ModuleRecord(id="x", owner="team", contracts=[ContractRecord(name="op", kind="query")])
    assert check_policy_coverage(_store(modules={"x": m})) == []


def test_vocabulary_conformance_catches_duplicate_canonical_name():
    c1 = ConceptRecord(id="a.thing", label="Thing", definition="d", meta_model_type="Entity", owner_module="a", scope="app")
    c2 = ConceptRecord(id="a.other", label="Thing", definition="d2", meta_model_type="Entity", owner_module="a", scope="app")
    m = ModuleRecord(id="a", owner="team")
    findings = check_vocabulary_conformance(_store(modules={"a": m}, concepts={"a.thing": c1, "a.other": c2}))
    assert any("duplicate canonical name" in f.message for f in findings)


def test_vocabulary_conformance_catches_capability_owning_concept():
    cap = CapabilityRecord(id="cap", owner="team")
    c = ConceptRecord(id="cap.thing", label="Thing", definition="d", meta_model_type="Entity", owner_module="cap", scope="app")
    findings = check_vocabulary_conformance(_store(capabilities={"cap": cap}, concepts={"cap.thing": c}))
    assert any("Capabilities must never own" in f.message for f in findings)


def test_vocabulary_conformance_catches_dangling_relationship():
    c = ConceptRecord(
        id="a.thing", label="Thing", definition="d", meta_model_type="Entity",
        owner_module="a", scope="app", specializes="a.ghost",
    )
    m = ModuleRecord(id="a", owner="team")
    findings = check_vocabulary_conformance(_store(modules={"a": m}, concepts={"a.thing": c}))
    assert any("specializes" in f.message and "a.ghost" in f.message for f in findings)


def test_application_composition_validity_catches_inactive_module():
    app = ApplicationRecord(id="app", owner="team", modules=["x"])
    m = ModuleRecord(id="x", owner="team", status="deprecated")
    findings = check_application_composition_validity(_store(applications={"app": app}, modules={"x": m}))
    assert len(findings) == 1


def test_application_composition_validity_passes_for_active_module():
    app = ApplicationRecord(id="app", owner="team", modules=["x"])
    m = ModuleRecord(id="x", owner="team", status="active")
    assert check_application_composition_validity(_store(applications={"app": app}, modules={"x": m})) == []
