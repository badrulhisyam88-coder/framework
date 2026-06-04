"""
Correlator service.

Takes discovered hosts and services, runs CVE matching,
and creates queue items for user approval.

This is the bridge between discovery and the validation queue.
It does NOT execute anything. It only creates pending queue items.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from apps.validation.database import get_db
from apps.validation.engines.cve_matcher import CVEMatcher, CVEMatch
from apps.validation.engines.fingerprint_normalizer import FingerprintNormalizer
from apps.validation.models import Host, QueueItem, Service, ValidationType
from apps.validation.repositories import QueueRepository, ServiceRepository
from sdk import Logger

PROFILES_PATH = Path("config/validation_profiles")


class Correlator:
    """
    For each discovered service:
    1. Normalize the fingerprint
    2. Match against CVE database
    3. Check if any validation plugin applies
    4. Create pending queue items for user approval

    Usage:
        correlator = Correlator()
        items = await correlator.correlate(hosts, services)
    """

    def __init__(self) -> None:
        self.normalizer = FingerprintNormalizer()
        self.matcher = CVEMatcher()
        self._profiles = self._load_profiles()

    def _load_profiles(self) -> dict[str, dict]:
        """Load all validation profiles from config/validation_profiles/"""
        profiles = {}
        if not PROFILES_PATH.exists():
            return profiles
        for profile_file in PROFILES_PATH.glob("*.yaml"):
            with profile_file.open() as f:
                data = yaml.safe_load(f)
                if data:
                    profiles[profile_file.stem] = data
        Logger.info("correlator.profiles.loaded", extra={"count": len(profiles)})
        return profiles

    async def correlate(
        self, hosts: list[Host], services: list[Service]
    ) -> list[QueueItem]:
        """
        Correlate discovered services into validation queue items.
        Returns all newly created queue items.
        """
        queue_items: list[QueueItem] = []

        async with await get_db() as db:
            queue_repo = QueueRepository(db)

            for service in services:
                # Normalize fingerprint for CVE matching
                normalized = self.normalizer.normalize(service)

                # CVE-based queue items
                if normalized:
                    cve_matches = await self.matcher.match(service, normalized)
                    for match in cve_matches[:5]:  # cap at 5 CVEs per service
                        item = QueueItem(
                            host_id=service.host_id,
                            service_id=service.id,
                            cve_id=match.cve.cve_id,
                            validation_type=ValidationType.CVE_POC,
                            plugin_name=self._select_plugin(service, match),
                            profile_name="cve_poc",
                        )
                        await queue_repo.insert(item)
                        queue_items.append(item)
                        Logger.info(
                            "correlator.queue.cve",
                            extra={
                                "cve_id": match.cve.cve_id,
                                "port": service.port,
                                "confidence": match.match_confidence,
                            },
                        )

                # Profile-based queue items (service-type checks, not CVE-specific)
                profile_items = self._match_profiles(service)
                for validation_type, plugin_name, profile_name in profile_items:
                    item = QueueItem(
                        host_id=service.host_id,
                        service_id=service.id,
                        cve_id=None,
                        validation_type=validation_type,
                        plugin_name=plugin_name,
                        profile_name=profile_name,
                    )
                    await queue_repo.insert(item)
                    queue_items.append(item)
                    Logger.info(
                        "correlator.queue.profile",
                        extra={
                            "port": service.port,
                            "type": validation_type,
                            "plugin": plugin_name,
                        },
                    )

        Logger.info(
            "correlator.complete",
            extra={"services": len(services), "queue_items": len(queue_items)},
        )
        return queue_items

    def _match_profiles(
        self, service: Service
    ) -> list[tuple[ValidationType, str, str]]:
        """
        Match service against validation profiles.
        Returns list of (validation_type, plugin_name, profile_name).
        """
        results = []
        service_name = (service.service_name or "").lower()
        product = (service.product or "").lower()
        port = service.port

        # SSH
        if "ssh" in service_name or port == 22:
            results.append((ValidationType.SSH_CRED, "ssh_plugin", "ssh"))

        # Telnet — cleartext credential capture
        if "telnet" in service_name or port == 23:
            results.append((ValidationType.TELNET_CLEARTEXT, "telnet_plugin", "telnet"))

        # HTTP/HTTPS — web checks
        if any(x in service_name for x in ("http", "www", "web")) or port in (80, 443, 8080, 8443):
            results.append((ValidationType.WEB_HEADER, "web_plugin", "web"))
            if port in (443, 8443) or "ssl" in service_name:
                results.append((ValidationType.TLS_CONFIG, "web_plugin", "tls"))

        # SMB — enumeration
        if any(x in service_name for x in ("smb", "netbios", "microsoft-ds")) or port in (445, 139):
            results.append((ValidationType.SMB_ENUM, "smb_plugin", "smb"))

        # SQL — injection surface check
        if any(x in service_name for x in ("mysql", "mssql", "postgresql", "oracle")) or port in (3306, 1433, 5432, 1521):
            results.append((ValidationType.SQLI, "sqli_plugin", "sql"))

        return results

    def _select_plugin(self, service: Service, match: CVEMatch) -> str:
        """Select the appropriate plugin for a CVE match based on service type."""
        service_name = (service.service_name or "").lower()
        port = service.port

        if "ssh" in service_name or port == 22:
            return "ssh_plugin"
        if any(x in service_name for x in ("http", "www", "web")) or port in (80, 443, 8080, 8443):
            return "web_plugin"
        if "smb" in service_name or port in (445, 139):
            return "smb_plugin"
        if any(x in service_name for x in ("mysql", "mssql", "postgresql")) or port in (3306, 1433, 5432):
            return "sqli_plugin"

        return "generic_plugin"
