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
        async with get_db() as db:
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
                cve.affected_products,
                normalized.product,
                normalized.version,
                cve_id=cve.cve_id,
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
    cve_id: str | None = None,
) -> str | None:
    """
    Check if the given product/version is in the CVE's affected list.

    Returns:
        "exact"        — version matches an explicit version or falls inside
                         a declared range.
        "product_only" — at least one affected-products entry names this
                         product with NO version constraints at all
                         (i.e. CVE truly affects every version).
        None           — product matched but every constrained entry
                         excludes our version.

    A discovered version that sits *outside* every declared range is
    rejected. We never return "product_only" when the CVE record has any
    version constraints, because doing so produces false positives like
    flagging nginx 1.26 for a CVE that only affects nginx < 0.8.14.
    """
    product_lower = product.lower()
    rejected_for_version = False  # product matched but version was out of range

    for ap in affected_products:
        ap_product = (ap.get("product") or "").lower()
        ap_vendor = (ap.get("vendor") or "").lower()

        # Product name must match (either product or vendor field)
        if product_lower not in ap_product and product_lower not in ap_vendor:
            # Also try partial match for compound product names
            if not (ap_product in product_lower or product_lower in ap_product):
                continue

        ap_version = ap.get("version")
        version_start = ap.get("version_start_including")
        version_end_excl = ap.get("version_end_excluding")
        version_end_incl = ap.get("version_end_including")

        has_exact = bool(ap_version) and ap_version != "*"
        has_range = any([version_start, version_end_excl, version_end_incl])
        has_constraints = has_exact or has_range

        # CVE entry truly affects every version of this product.
        if not has_constraints:
            return "product_only"

        # CVE record has version constraints. If we don't know the discovered
        # version we can't confirm a match — keep scanning other ap entries.
        if not version:
            continue

        if has_exact:
            if _versions_equal(version, ap_version):
                return "exact"
            rejected_for_version = True
            continue

        # Range entry — discovered version must fall inside it.
        if has_range:
            if version_end_excl and not _is_version_less_than(version, version_end_excl):
                rejected_for_version = True
                continue
            if version_end_incl and _is_version_greater_than(version, version_end_incl):
                rejected_for_version = True
                continue
            if version_start and _is_version_less_than(version, version_start):
                rejected_for_version = True
                continue
            return "exact"

    if rejected_for_version and cve_id:
        Logger.info(
            "cve.match.rejected",
            extra={
                "cve_id": cve_id,
                "product": product,
                "discovered_version": version,
                "reason": "version out of range",
            },
        )
    return None


def _versions_equal(v1: str, v2: str) -> bool:
    """Compare two version strings."""
    return v1.strip() == v2.strip()


def _is_version_greater_than(v1: str, v2: str) -> bool:
    """True iff v1 > v2 in numeric-tuple version order."""
    try:
        return _parse_version(v1) > _parse_version(v2)
    except Exception:
        return False


def _is_version_less_than(v1: str, v2: str) -> bool:
    """True iff v1 < v2 in numeric-tuple version order."""
    try:
        return _parse_version(v1) < _parse_version(v2)
    except Exception:
        return False


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse version string into comparable tuple. '8.9p1' → (8, 9, 1)"""
    # Extract all numeric sequences
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)
