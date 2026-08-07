"""The one-way dependency rule, enforced mechanically, not just documented.

    Application -> Module -> Capability -> Platform

Nothing points upward. This module provides two checks, over two different
things:

- `check_package`: the framework's *own* internal packages (platform/,
  runtime/, registry/, discovery/, applications/ as Python code). The
  Capability/Module *behavioral* base classes live in platform/ itself
  (platform/capability.py, platform/module.py) rather than in their own
  packages, precisely because Runtime must reference them to orchestrate
  anything -- there is no framework-internal "capabilities/" or "modules/"
  package to route around that need. applications/'s manifest loader is
  infrastructure, exactly like runtime/, so it may consult Registry and
  Discovery Index for the same reason Runtime does. platform/ and
  discovery/ stay the two purest layers, forbidden from importing anything
  project-local at all.

- `check_examples_isolation`: concrete business content under /examples.
  This is the stricter, more important check -- it is what actually proves
  "Capabilities never depend on Modules" and "Modules never depend on
  Modules" holds for real implementations, not just the framework's own
  plumbing. A concrete Capability or Module must never import a sibling
  example directly; cross-boundary communication only ever happens through
  a Contract, resolved at runtime by runtime/container.py.

Both are what Validator check #4 (dependency direction conformance) calls --
the rule is real code, not a comment someone can silently violate.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

LAYER_RULES: dict[str, frozenset[str]] = {
    "platform": frozenset(),
    "discovery": frozenset(),
    "registry": frozenset({"platform", "discovery"}),
    "runtime": frozenset({"platform", "registry", "discovery"}),
    "applications": frozenset({"platform", "registry", "discovery"}),
}


@dataclass(frozen=True)
class Violation:
    file: Path
    layer: str
    imported: str
    message: str

    def __str__(self) -> str:
        return f"{self.file}: {self.message} (imported {self.imported!r})"


def _layer_of(module_path: str) -> str | None:
    """`framework_final.registry.store` -> `registry`."""
    parts = module_path.split(".")
    if len(parts) >= 2 and parts[0] == "framework_final":
        return parts[1]
    return None


def _absolute_imports(tree: ast.Module) -> list[str]:
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.append(node.module)
    return sorted(set(names))


# -- framework-internal check --------------------------------------------------


def check_file(path: Path, package_root: Path) -> list[Violation]:
    """Check one .py file's imports against LAYER_RULES.

    `package_root` is the directory containing the framework_final package
    (i.e. the `src/` directory).
    """
    fw_root = package_root / "framework_final"
    rel = path.relative_to(fw_root)
    layer = rel.parts[0] if rel.parts else None
    if layer not in LAYER_RULES:
        return []  # not a governed layer (e.g. the package's own __init__.py)

    tree = ast.parse(path.read_text(), filename=str(path))
    violations: list[Violation] = []
    for imported_full in _absolute_imports(tree):
        imported_layer = _layer_of(imported_full)
        if imported_layer is None or imported_layer == layer:
            continue
        allowed = LAYER_RULES[layer]
        if imported_layer not in allowed:
            violations.append(
                Violation(
                    file=path,
                    layer=layer,
                    imported=imported_full,
                    message=(
                        f"{layer}/ must not import from {imported_layer}/ "
                        f"(allowed: {sorted(allowed) or 'nothing'})"
                    ),
                )
            )
    return violations


def check_package(package_root: Path) -> list[Violation]:
    """Walk every .py file under package_root/framework_final and check it."""
    fw_root = package_root / "framework_final"
    violations: list[Violation] = []
    for path in sorted(fw_root.rglob("*.py")):
        violations.extend(check_file(path, package_root))
    return violations


# -- concrete example-content check ---------------------------------------------


def check_examples_isolation(examples_root: Path) -> list[Violation]:
    """Concrete example content must never import a sibling example folder
    directly. This is the check that proves the architecture holds for
    real business content, not just the framework's own internals -- the
    same rule a real Hospital or ERP Application built on this platform
    would be held to.
    """
    examples_root = Path(examples_root)
    if not examples_root.exists():
        return []
    violations: list[Violation] = []
    for folder in sorted(p for p in examples_root.iterdir() if p.is_dir()):
        for path in sorted(folder.rglob("*.py")):
            tree = ast.parse(path.read_text(), filename=str(path))
            for imported_full in _absolute_imports(tree):
                parts = imported_full.split(".")
                if parts[0] == "examples" and len(parts) >= 2 and parts[1] != folder.name:
                    violations.append(
                        Violation(
                            file=path,
                            layer=f"examples/{folder.name}",
                            imported=imported_full,
                            message=(
                                f"examples/{folder.name} must not import "
                                f"examples/{parts[1]} directly -- cross "
                                "boundaries only through a Contract, resolved "
                                "at runtime by runtime/container.py"
                            ),
                        )
                    )
    return violations


if __name__ == "__main__":
    import sys

    src_dir = Path(__file__).resolve().parents[2]
    repo_root = src_dir.parent
    found = check_package(src_dir) + check_examples_isolation(repo_root / "examples")
    if found:
        for v in found:
            print(v)
        sys.exit(1)
    print("dependency direction: clean")
