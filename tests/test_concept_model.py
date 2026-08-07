"""Tests for registry/concept_model.py -- canonical-name resolution, alias
handling, and the three fixed relationship types."""

from framework_final.registry.concept_model import ConceptModel
from framework_final.registry.models import ConceptRecord


def _concept(**kw) -> ConceptRecord:
    base = dict(definition="d", meta_model_type="Entity", owner_module="m", scope="app", status="active")
    base.update(kw)
    return ConceptRecord(**base)


def test_resolve_by_canonical_label():
    c = _concept(id="m.task", label="Task")
    cm = ConceptModel(concepts=(c,))
    assert cm.resolve("Task", "app") is c


def test_resolve_by_alias_returns_the_canonical_record():
    c = _concept(id="m.task", label="Task", aliases=["todo", "ticket"])
    cm = ConceptModel(concepts=(c,))
    assert cm.resolve("todo", "app") is c
    assert cm.resolve("nonexistent", "app") is None


def test_resolution_never_crosses_scopes():
    c = _concept(id="m.task", label="Task", scope="app_one")
    cm = ConceptModel(concepts=(c,))
    assert cm.resolve("Task", "app_two") is None


def test_duplicate_canonical_names_detected():
    c1 = _concept(id="m.a", label="Thing")
    c2 = _concept(id="m.b", label="Thing")
    cm = ConceptModel(concepts=(c1, c2))
    dups = cm.duplicate_canonical_names()
    assert len(dups) == 1
    assert dups[0][1] == "Thing"


def test_no_duplicate_across_different_scopes():
    c1 = _concept(id="m.a", label="Thing", scope="app_one")
    c2 = _concept(id="m.b", label="Thing", scope="app_two")
    cm = ConceptModel(concepts=(c1, c2))
    assert cm.duplicate_canonical_names() == []


def test_alias_colliding_with_a_canonical_name_is_a_violation():
    c1 = _concept(id="m.a", label="Thing")
    c2 = _concept(id="m.b", label="Other", aliases=["Thing"])
    cm = ConceptModel(concepts=(c1, c2))
    assert cm.alias_violations() == [("app", "Thing")]


def test_dangling_relationships_detected_for_all_three_kinds():
    c = _concept(
        id="m.a", label="A",
        specializes="m.ghost1", supersedes="m.ghost2", references=["m.ghost3"],
    )
    cm = ConceptModel(concepts=(c,))
    problems = {p[1] for p in cm.dangling_relationships()}
    assert problems == {"specializes", "supersedes", "references"}


def test_valid_relationships_produce_no_findings():
    a = _concept(id="m.a", label="A")
    b = _concept(id="m.b", label="B", specializes="m.a", references=["m.a"])
    cm = ConceptModel(concepts=(a, b))
    assert cm.dangling_relationships() == []


def test_retired_id_reused_by_an_active_concept_is_detected():
    retired = _concept(id="m.a", label="Old", status="removed")
    active = _concept(id="m.a", label="New", status="active")
    cm = ConceptModel(concepts=(retired, active))
    assert cm.retired_ids_reused() == ["m.a"]
