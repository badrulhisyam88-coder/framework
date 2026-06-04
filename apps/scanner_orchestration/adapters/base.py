"""ScannerAdapter — protocol (interface) all scanner adapters must implement."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


class ScannerUnavailable(RuntimeError):
    """Raised when a scanner tool is not installed or unreachable."""


@runtime_checkable
class ScannerAdapter(Protocol):
    """All scanner adapters must implement this protocol."""

    scanner_type: str   # nmap | zap | nuclei

    async def check_available(self) -> bool:
        """Return True if the scanner is reachable/installed."""
        ...

    async def run_scan(
        self,
        target: str,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute a scan and return raw results as a dict.

        The dict is passed directly to the matching normalizer.
        Keys are scanner-specific; normalizers know how to handle them.
        """
        ...
