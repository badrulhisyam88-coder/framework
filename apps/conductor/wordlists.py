"""Wordlist registry — ID-based lookup and format-aware loading.

Engines and probes request wordlists by stable ID. The registry resolves
the file path, validates existence, and parses according to format.

Supported formats:
  yaml — parsed with yaml.safe_load; must be a list at the top level
  csv  — parsed with csv.DictReader; returns list of row dicts
  txt  — one entry per line; empty lines and # comments stripped

All paths are computed relative to REPO_ROOT so tests run correctly
regardless of the working directory.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORDLISTS_ROOT = REPO_ROOT / "data" / "wordlists"


@dataclass(frozen=True)
class Wordlist:
    id: str
    path: Path
    purpose: str
    format: str
    description: str
    source: str


REGISTERED_WORDLISTS: dict[str, Wordlist] = {
    "ssh_credentials_default": Wordlist(
        id="ssh_credentials_default",
        path=WORDLISTS_ROOT / "credentials" / "ssh-defaults.yaml",
        purpose="ssh_credentials",
        format="yaml",
        description=(
            "12 common SSH default credentials (admin/admin, "
            "root/root, pi/raspberry, etc.)"
        ),
        source="curated",
    ),
    "api_paths_default": Wordlist(
        id="api_paths_default",
        path=WORDLISTS_ROOT / "paths" / "api-endpoints.txt",
        purpose="api_paths",
        format="txt",
        description=(
            "269 common REST API endpoint paths for wordlist-driven "
            "endpoint discovery."
        ),
        source="vendored from SecLists",
    ),
    "credentials_extended": Wordlist(
        id="credentials_extended",
        path=WORDLISTS_ROOT / "credentials" / "general-defaults.csv",
        purpose="multi_protocol_credentials",
        format="csv",
        description=(
            "2,876 default vendor credentials covering routers, IoT "
            "devices, NAS, and network appliances. Suitable for "
            "multi-protocol credential stuffing."
        ),
        source="curated",
    ),
}


class WordlistNotFoundError(KeyError):
    """Raised when an unknown wordlist ID is requested."""


class WordlistFileNotFoundError(FileNotFoundError):
    """Raised when the registered file path does not exist on disk."""


def get_wordlist(wordlist_id: str) -> Wordlist:
    """Return the Wordlist metadata for a registered ID."""
    if wordlist_id not in REGISTERED_WORDLISTS:
        raise WordlistNotFoundError(
            f"Unknown wordlist: {wordlist_id}. "
            f"Registered: {sorted(REGISTERED_WORDLISTS.keys())}"
        )
    return REGISTERED_WORDLISTS[wordlist_id]


def load_entries(wordlist_id: str) -> list[Any]:
    """Load and parse wordlist entries based on registered format.

    yaml → parsed yaml content (top-level list of dicts)
    csv  → list of dict rows (csv.DictReader output)
    txt  → list of non-empty stripped lines, # comments excluded
    """
    wordlist = get_wordlist(wordlist_id)

    if not wordlist.path.exists():
        raise WordlistFileNotFoundError(
            f"Wordlist {wordlist_id!r} registered at {wordlist.path} "
            f"but file does not exist on disk."
        )

    if wordlist.format == "yaml":
        import yaml  # lazy — PyYAML available via impacket/paramiko transitive dep
        with wordlist.path.open() as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, list) else [data]

    if wordlist.format == "csv":
        with wordlist.path.open(encoding="utf-8", errors="replace") as f:
            return list(csv.DictReader(f))

    if wordlist.format == "txt":
        with wordlist.path.open(encoding="utf-8") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]

    raise ValueError(f"Unsupported wordlist format: {wordlist.format!r}")


def list_wordlists() -> list[Wordlist]:
    """Return all registered wordlists for inventory display."""
    return list(REGISTERED_WORDLISTS.values())
