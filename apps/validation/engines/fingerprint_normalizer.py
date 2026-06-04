"""
Fingerprint normalizer.

Maps messy Nmap service strings into clean vendor/product/version
that can be matched against CVE affected_products.

Nmap gives you: "OpenSSH 8.9p1 Ubuntu 3ubuntu0.6"
CVE needs:      vendor="openssh_project", product="openssh", version="8.9"

External config: config/fingerprints/service_map.yaml
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from apps.validation.models import Service
from sdk import Logger

CONFIG_PATH = Path("config/fingerprints/service_map.yaml")


class NormalizedService:
    __slots__ = ("vendor", "product", "version", "original")

    def __init__(self, vendor: str, product: str, version: str | None, original: str) -> None:
        self.vendor = vendor.lower()
        self.product = product.lower()
        self.version = version
        self.original = original

    def __repr__(self) -> str:
        return f"NormalizedService({self.vendor}/{self.product}@{self.version})"


class FingerprintNormalizer:
    """
    Normalizes Nmap service output to CVE-compatible identifiers.

    Loads rules from config/fingerprints/service_map.yaml.
    Falls back to heuristic parsing if no rule matches.
    """

    def __init__(self) -> None:
        self._rules: list[dict[str, Any]] = []
        self._load_rules()

    def _load_rules(self) -> None:
        if CONFIG_PATH.exists():
            with CONFIG_PATH.open() as f:
                data = yaml.safe_load(f)
                self._rules = data.get("mappings", [])
            Logger.info("fingerprint.rules.loaded", extra={"count": len(self._rules)})
        else:
            Logger.info("fingerprint.rules.missing", extra={"path": str(CONFIG_PATH)})
            self._rules = []

    def normalize(self, service: Service) -> NormalizedService | None:
        """
        Normalize a Service into CVE-matchable identifiers.
        Returns None if service has no version info to match against.
        """
        # Build a search string from available fields
        parts = [
            service.service_name or "",
            service.product or "",
            service.version or "",
            service.banner or "",
        ]
        raw = " ".join(p for p in parts if p).strip()

        if not raw:
            return None

        # Try rules first
        for rule in self._rules:
            pattern = rule.get("pattern", "")
            if re.search(pattern, raw, re.IGNORECASE):
                version = self._extract_version(raw, rule.get("version_pattern"))
                return NormalizedService(
                    vendor=rule["vendor"],
                    product=rule["product"],
                    version=version or service.version,
                    original=raw,
                )

        # Heuristic fallback
        return self._heuristic_normalize(service, raw)

    def _heuristic_normalize(self, service: Service, raw: str) -> NormalizedService | None:
        """
        Best-effort normalization when no rule matches.
        Extracts product name and version from banner/product fields.
        """
        product = service.product or service.service_name
        if not product:
            return None

        # Clean product name: "Apache httpd" → "apache_http_server"
        product_clean = re.sub(r"\s+", "_", product.strip().lower())
        product_clean = re.sub(r"[^a-z0-9_]", "", product_clean)

        # Extract version: first semver-like pattern
        version = service.version
        if not version:
            version_match = re.search(r"(\d+\.\d+[\.\d]*)", raw)
            version = version_match.group(1) if version_match else None

        return NormalizedService(
            vendor=product_clean,
            product=product_clean,
            version=version,
            original=raw,
        )

    def _extract_version(self, raw: str, pattern: str | None) -> str | None:
        if not pattern:
            match = re.search(r"(\d+\.\d+[\.\d]*)", raw)
            return match.group(1) if match else None
        match = re.search(pattern, raw)
        return match.group(1) if match else None
