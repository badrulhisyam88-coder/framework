"""
Validation app configuration helpers.

Workers — global concurrency setting applied to:
- nmap probes (--min-parallelism / --max-parallelism)
- queue execution (asyncio.Semaphore in ExecutorService.execute_many)
- credential testing inside plugins (asyncio.Semaphore)

Source order: settings override file > TOOL_SCAN_WORKERS env > built-in default.
"""

from __future__ import annotations

import os
from pathlib import Path

WORKERS_MIN = 1
WORKERS_MAX = 32
WORKERS_DEFAULT = 4

# Retention defaults (in days). Items older than these become archivable.
RETAIN_EXPLOITABLE_DEFAULT = 90
RETAIN_NOT_EXPLOITABLE_DEFAULT = 30
RETAIN_REJECTED_DEFAULT = 30
AUTO_ARCHIVE_DEFAULT = True

# Mapping of retention keys to their built-in defaults. Used by callers that
# don't want to hard-code the integer.
RETENTION_KEYS: dict[str, int] = {
    "TOOL_RETAIN_EXPLOITABLE": RETAIN_EXPLOITABLE_DEFAULT,
    "TOOL_RETAIN_NOT_EXPLOITABLE": RETAIN_NOT_EXPLOITABLE_DEFAULT,
    "TOOL_RETAIN_REJECTED": RETAIN_REJECTED_DEFAULT,
}

_OVERRIDE_PATH = Path("/app/data/tool_settings.txt")


def clamp_workers(n: int) -> int:
    return max(WORKERS_MIN, min(WORKERS_MAX, int(n)))


def _read_overrides() -> dict[str, str]:
    if not _OVERRIDE_PATH.exists():
        return {}
    out: dict[str, str] = {}
    for raw in _OVERRIDE_PATH.read_text().splitlines():
        line = raw.strip()
        if not line or "=" not in line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip()
    return out


def get_default_workers() -> int:
    raw = _read_overrides().get("TOOL_SCAN_WORKERS") or os.getenv("TOOL_SCAN_WORKERS", "")
    if not raw:
        return WORKERS_DEFAULT
    try:
        return clamp_workers(int(raw))
    except ValueError:
        return WORKERS_DEFAULT


def set_default_workers(n: int) -> int:
    value = clamp_workers(n)
    _write_override("TOOL_SCAN_WORKERS", str(value))
    return value


# ---------------------------------------------------------------------------
# Retention & auto-archive helpers
# ---------------------------------------------------------------------------


def _write_override(key: str, value: str) -> None:
    """Persist a single key in the override file, preserving other entries."""
    _OVERRIDE_PATH.parent.mkdir(parents=True, exist_ok=True)
    overrides = _read_overrides()
    overrides[key] = value
    body = "\n".join(f"{k}={v}" for k, v in overrides.items()) + "\n"
    _OVERRIDE_PATH.write_text(body)


def _clamp_days(n: int) -> int:
    return max(0, int(n))


def get_retention_days(key: str, default: int) -> int:
    """
    Source order for retention windows:
      override file > matching env var > caller-supplied default.
    Values are clamped to >= 0 days.
    """
    raw = _read_overrides().get(key) or os.getenv(key, "")
    if not raw:
        return _clamp_days(default)
    try:
        return _clamp_days(int(raw))
    except ValueError:
        return _clamp_days(default)


def set_retention_days(key: str, value: int) -> int:
    clamped = _clamp_days(value)
    _write_override(key, str(clamped))
    return clamped


def _parse_bool(raw: str | None) -> bool | None:
    if raw is None:
        return None
    raw = raw.strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return None


def get_auto_archive() -> bool:
    """Read TOOL_AUTO_ARCHIVE from override file > env var > default."""
    overrides = _read_overrides()
    parsed = _parse_bool(overrides.get("TOOL_AUTO_ARCHIVE"))
    if parsed is not None:
        return parsed
    parsed = _parse_bool(os.getenv("TOOL_AUTO_ARCHIVE"))
    if parsed is not None:
        return parsed
    return AUTO_ARCHIVE_DEFAULT


def set_auto_archive(enabled: bool) -> bool:
    value = bool(enabled)
    _write_override("TOOL_AUTO_ARCHIVE", "true" if value else "false")
    return value
