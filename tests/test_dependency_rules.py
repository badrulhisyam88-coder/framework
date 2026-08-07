"""Tests for platform/dependency_rules.py -- the one-way dependency rule,
enforced mechanically rather than by convention."""

from pathlib import Path

from framework_final.platform.dependency_rules import (
    check_examples_isolation,
    check_package,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_real_framework_package_is_clean():
    assert check_package(REPO_ROOT / "src") == []


def test_real_examples_are_isolated():
    assert check_examples_isolation(REPO_ROOT / "examples") == []


def test_forbidden_upward_import_is_caught(tmp_path):
    fw = tmp_path / "framework_final"
    (fw / "platform").mkdir(parents=True)
    (fw / "registry").mkdir(parents=True)
    (fw / "platform" / "__init__.py").write_text("")
    (fw / "registry" / "__init__.py").write_text("")
    (fw / "platform" / "bad.py").write_text("from framework_final.registry import store\n")

    violations = check_package(tmp_path)
    assert len(violations) == 1
    assert violations[0].layer == "platform"
    assert violations[0].imported == "framework_final.registry"


def test_allowed_import_produces_no_violation(tmp_path):
    fw = tmp_path / "framework_final"
    (fw / "runtime").mkdir(parents=True)
    (fw / "registry").mkdir(parents=True)
    (fw / "runtime" / "__init__.py").write_text("")
    (fw / "registry" / "__init__.py").write_text("")
    (fw / "runtime" / "ok.py").write_text("from framework_final.registry import store\n")

    assert check_package(tmp_path) == []


def test_sibling_example_cross_import_is_caught(tmp_path):
    (tmp_path / "example_a").mkdir()
    (tmp_path / "example_b").mkdir()
    (tmp_path / "example_a" / "__init__.py").write_text("")
    (tmp_path / "example_b" / "__init__.py").write_text("")
    (tmp_path / "example_a" / "code.py").write_text("from examples.example_b import thing\n")

    violations = check_examples_isolation(tmp_path)
    assert len(violations) == 1
    assert "example_b" in violations[0].imported


def test_import_of_framework_final_from_examples_is_not_a_violation(tmp_path):
    (tmp_path / "example_a").mkdir()
    (tmp_path / "example_a" / "__init__.py").write_text("")
    (tmp_path / "example_a" / "code.py").write_text("from framework_final.platform.contract import Command\n")

    assert check_examples_isolation(tmp_path) == []
