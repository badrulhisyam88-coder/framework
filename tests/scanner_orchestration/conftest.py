"""Test configuration for scanner_orchestration tests.

nuclei_adapter.py and zap_adapter.py have no pydantic dependencies themselves,
but the parent package adapters/__init__.py eagerly imports nmap_adapter which
chains through pydantic. Load each adapter directly via importlib to bypass
the __init__ cascade.

This conftest pre-registers:
  - Stub entries for the pydantic-dependent adapters (nmap, base)
  - The real nuclei_adapter and zap_adapter, loaded directly from disk
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_ADAPTER_PKG = "apps.scanner_orchestration.adapters"
_ADAPTERS_DIR = Path(__file__).parents[2] / "apps/scanner_orchestration/adapters"

_NUCLEI_PATH = _ADAPTERS_DIR / "nuclei_adapter.py"
_ZAP_PATH = _ADAPTERS_DIR / "zap_adapter.py"


def _ensure_adapter_pkg_stub() -> None:
    """Stub the parent package and pydantic-dependent siblings if not done."""
    if _ADAPTER_PKG not in sys.modules:
        stub_pkg = MagicMock()
        stub_pkg.__name__ = _ADAPTER_PKG
        stub_pkg.__path__ = []
        stub_pkg.__spec__ = None
        sys.modules[_ADAPTER_PKG] = stub_pkg
        for sibling in ("nmap_adapter", "base"):
            sys.modules[f"{_ADAPTER_PKG}.{sibling}"] = MagicMock()


def _load_adapter_direct(mod_name: str, path: Path) -> None:
    """Load an adapter module directly from disk, bypassing the package __init__."""
    _ensure_adapter_pkg_stub()
    if mod_name not in sys.modules:
        spec = importlib.util.spec_from_file_location(mod_name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)


def _load_all() -> None:
    _load_adapter_direct(f"{_ADAPTER_PKG}.nuclei_adapter", _NUCLEI_PATH)
    _load_adapter_direct(f"{_ADAPTER_PKG}.zap_adapter", _ZAP_PATH)


_load_all()


@pytest.fixture(autouse=True)
def ensure_adapters_loaded():
    """Ensure both adapters are in sys.modules before each test."""
    _load_all()
