"""
CVE matcher engine.

Takes a normalized service (vendor/product/version) and returns
matching CVEs from the local database.

Version matching logic:
- Exact version match
- Range match (versionStartIncluding, versionEndExcluding, etc.)
- Wildcard match (CVE affects all versions of a product)

This is the bridge between "what Nmap found" and "what CVEs apply."
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering
from typing import Any

from apps.validation.database import get_db
from apps.validation.engines.fingerprint_normalizer import NormalizedService
from apps.validation.models import CVE, Service
from apps.validation.repositories import CVERepository
from sdk import Logger


@dataclass
class CVEMatch:
    cve: CVE
    service: Service
    normalized: NormalizedService
    match_confidence: str  # exact / range / product_only


class CVEMatcher:
    """
    Match a service against the local CVE database.

    Usage:
        matcher = CVEMatcher()
        matches = await matcher.match(service, normalized)
    """

    async def match(
        self, service: Service, normalized: NormalizedService
    ) -> list[CVEMatch]:
        """
        Find CVEs that apply to this service.
        Returns matches sorted by CVSS score descending.
        """
        async with await get_db() as db:
            repo = CVERepository(db)

            # Search by product name
            candidates = await repo.search_by_product(
                normalized.product, normalized.version
            )

        if not candidates:
            return []

        matches = []
        for cve in candidates:
            confidence = _check_version_match(
                cve.affected_products, normalized.product, normalized.version
            )
            if confidence:
                matches.append(CVEMatch(
                    cve=cve,
                    service=service,
                    normalized=normalized,
                    match_confidence=confidence,
                ))

        # Sort by CVSS score descending, None scores last
        matches.sort(
            key=lambda m: m.cve.cvss_score if m.cve.cvss_score is not None else -1,
            reverse=True,
        )

        Logger.info(
            "cve.match.result",
            extra={
                "product": normalized.product,
                "version": normalized.version,
                "candidates": len(candidates),
                "matches": len(matches),
            },
        )

        return matches


def _check_version_match(
    affected_products: list[dict[str, Any]],
    product: str,
    version: str | None,
) -> str | None:
    """
    Check if the given product/version is in the CVE's affected list.

    Returns:
        "exact"        — version matches exactly or within range
        "product_only" — product matches but no version info to compare
        None           — no match
    """
    product_lower = product.lower()

    for ap in affected_products:
        ap_product = (ap.get("product") or "").lower()
        ap_vendor = (ap.get("vendor") or "").lower()

        # Product name must match (either product or vendor field)
        if product_lower not in ap_product and product_lower not in ap_vendor:
            # Also try partial match for compound product names
            if not (ap_product in product_lower or product_lower in ap_product):
                continue

        # No version info in CVE record — product-level match only
        ap_version = ap.get("version")
        version_start = ap.get("version_start_including")
        version_end_excl = ap.get("version_end_excluding")
        version_end_incl = ap.get("version_end_including")

        if not any([ap_version, version_start, version_end_excl, version_end_incl]):
            return "product_only"

        # No version info from scanner — can only do product match
        if not version:
            return "product_only"

        # Exact version match
        if ap_version and ap_version != "*":
            if _versions_equal(version, ap_version):
                return "exact"
            continue

        # Range match
        if _version_in_range(version, version_start, version_end_excl, version_end_incl):
            return "exact"

    return None


def _versions_equal(v1: str, v2: str) -> bool:
    """Compare two version strings."""
    return v1.strip() == v2.strip()


def _version_in_range(
    version: str,
    start_incl: str | None,
    end_excl: str | None,
    end_incl: str | None,
) -> bool:
    """
    Check if version falls within a CVE version range.
    Uses tuple comparison on numeric parts — handles most semver cases.
    """
    try:
        v = _parse_version(version)

        if start_incl:
            if v < _parse_version(start_incl):
                return False

        if end_excl:
            if v >= _parse_version(end_excl):
                return False

        if end_incl:
            if v > _parse_version(end_incl):
                return False

        return True
    except Exception:
        # Version parsing failed — fall back to string comparison
        return False


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse version string into comparable tuple. '8.9p1' → (8, 9, 1)"""
    # Extract all numeric sequences
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)
