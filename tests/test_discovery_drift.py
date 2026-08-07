"""Tests for discovery/index.py + registry/drift.py -- comparing Registry's
declared intent against Discovery Index's observed reality."""

from pathlib import Path

import yaml

from framework_final.discovery.index import scan
from framework_final.registry.drift import find_drift
from framework_final.registry.models import ContractRecord, ModuleRecord

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_scan_finds_top_level_classes_and_functions(tmp_path):
    (tmp_path / "thing.py").write_text("class Foo:\n    pass\n\ndef bar():\n    pass\n")
    index = scan(tmp_path)
    assert index.all_symbol_names() == {"Foo", "bar"}


def test_drift_detects_missing_symbol_for_a_declared_contract(tmp_path):
    (tmp_path / "impl.py").write_text("class SomethingElse:\n    pass\n")
    index = scan(tmp_path)
    m = ModuleRecord(id="x", owner="team", contracts=[ContractRecord(name="do_thing", kind="command")])
    findings = find_drift(m, index)
    assert len(findings) == 1
    assert findings[0].expected_symbol == "DoThing"


def test_drift_is_clean_when_the_symbol_is_present(tmp_path):
    (tmp_path / "impl.py").write_text("class DoThing:\n    pass\n")
    index = scan(tmp_path)
    m = ModuleRecord(id="x", owner="team", contracts=[ContractRecord(name="do_thing", kind="command")])
    assert find_drift(m, index) == []


def test_real_example_module_has_no_drift():
    module_dir = REPO_ROOT / "examples" / "example_task_module"
    index = scan(module_dir)
    record = ModuleRecord.model_validate(yaml.safe_load((module_dir / "registry.yaml").read_text()))
    assert find_drift(record, index) == []
