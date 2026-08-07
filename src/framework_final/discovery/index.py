"""Discovery Index: a descriptive, disposable, fully regenerable structural
index of what actually exists in code right now.

This is an architectural *role*. Any concrete indexing tool -- this
ast-based scanner, or a product such as "Graphify" -- is one possible
implementation of the role, never the role itself (see docs/GLOSSARY.md,
retired terms). Descriptive only: this module never decides what should
exist or where new work belongs, and it never reads Registry -- doing so
would let it start inferring intent instead of just reporting reality.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Symbol:
    name: str
    kind: str  # "class" or "function"
    lineno: int


@dataclass(frozen=True)
class FileIndex:
    path: Path
    symbols: tuple[Symbol, ...]


@dataclass(frozen=True)
class DiscoveryIndex:
    """A snapshot of one folder's actual structure. Never hand-edited;
    always produced fresh by `scan()`. Carries no history beyond "what did
    this folder look like right now".
    """

    root: Path
    files: tuple[FileIndex, ...]

    def all_symbol_names(self) -> set[str]:
        return {s.name for f in self.files for s in f.symbols}

    def all_files(self) -> tuple[Path, ...]:
        return tuple(f.path for f in self.files)


def _scan_file(path: Path) -> FileIndex:
    tree = ast.parse(path.read_text(), filename=str(path))
    symbols: list[Symbol] = []
    for node in tree.body:  # top-level only: structural discovery, not exhaustive analysis
        if isinstance(node, ast.ClassDef):
            symbols.append(Symbol(name=node.name, kind="class", lineno=node.lineno))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            symbols.append(Symbol(name=node.name, kind="function", lineno=node.lineno))
    return FileIndex(path=path, symbols=tuple(symbols))


def scan(root: Path | str) -> DiscoveryIndex:
    """Scan every .py file under `root`.

    Callers pass one Module's or Capability's own folder -- never the whole
    repository -- which is what keeps this consistent with "AI never scans
    the whole repo": Discovery Index is always invoked at a scope Registry
    already told the caller to look at.
    """
    root = Path(root)
    files = tuple(_scan_file(p) for p in sorted(root.rglob("*.py")))
    return DiscoveryIndex(root=root, files=files)
