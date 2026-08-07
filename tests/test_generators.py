"""Tests for registry/generators/ -- deterministic, disposable derived
artifacts that carry zero authority over Registry."""

import json
from pathlib import Path

from framework_final.registry.generators import ai_context, dependency_graph, documentation
from framework_final.registry.store import RegistryStore

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples"


def _store() -> RegistryStore:
    return RegistryStore.discover([EXAMPLES])


def test_dependency_graph_is_deterministic_and_well_formed():
    store = _store()
    first = dependency_graph.generate(store)
    second = dependency_graph.generate(store)
    assert first == second
    data = json.loads(first)
    assert {"nodes", "edges"} == set(data)
    node_ids = {n["id"] for n in data["nodes"]}
    assert {"example_task_module", "example_logging", "example_application"} <= node_ids


def test_dependency_graph_captures_capability_requirement_edge():
    data = json.loads(dependency_graph.generate(_store()))
    requires_edges = [e for e in data["edges"] if e["kind"] == "requires_capability"]
    assert {"from": "example_task_module", "to": "example_logging", "via": None, "kind": "requires_capability"} in requires_edges


def test_ai_context_bundle_is_deterministic_and_scoped():
    store = _store()
    first = ai_context.generate(store, "example_task_module", [EXAMPLES])
    second = ai_context.generate(store, "example_task_module", [EXAMPLES])
    assert first == second
    bundle = json.loads(first)
    assert bundle["module_id"] == "example_task_module"
    assert "example_task_module.create_task.v1" in bundle["published_contracts"]
    assert any(p.endswith("module.py") for p in bundle["file_scope"])


def test_documentation_renders_contracts_events_and_policies():
    doc = documentation.generate_module_doc(_store(), "example_task_module")
    assert "# example_task_module" in doc
    assert "create_task" in doc
    assert "task_created" in doc
    assert "Policies" in doc
