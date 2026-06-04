"""
Correlator service.

Takes discovered hosts and services, runs CVE matching,
and creates queue items for user approval.

This is the bridge between discovery and the validation queue.
It does NOT execute anything. It only creates pending queue items.

Single network side-effect: a lightweight WordPress fingerprint probe
runs against HTTP services so a wordpress_plugin queue item can be
queued when CMS indicators are present.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import yaml

from apps.validation.config import get_default_workers
from apps.validation.database import get_db
from apps.validation.engines.cve_matcher import CVEMatch, CVEMatcher
from apps.validation.engines.fingerprint_normalizer import FingerprintNormalizer
from apps.validation.models import Host, QueueItem, QueueStatus, Service, ValidationType
from apps.validation.repositories import (
    QueueRepository,
    WatchlistRepository,
)
from sdk import Logger

PROFILES_PATH = Path("config/validation_profiles")

# CMS fingerprint heuristics — see _detect_cms.
# WordPress and Drupal are checked in one probe per service; whichever
# signal hits first wins so we never queue both plugins for one target.
_WP_INDICATORS = ("wp-content", "wp-login", "wp-admin", "wp-includes")
_DRUPAL_BODY_INDICATORS = (
    "/sites/default/files",
    "drupal.settings",
    "/core/misc/drupal.js",
    "/misc/drupal.js",
)
_DRUPAL_GENERATOR_PREFIX = "drupal"  # matched against the X-Generator header
_CMS_PROBE_TIMEOUT = httpx.Timeout(4.0, connect=3.0)
_CMS_WEB_PORTS = (80, 443, 8000, 8080, 8443, 8888)

# Back-compat aliases — older test code may import these
_WP_PROBE_TIMEOUT = _CMS_PROBE_TIMEOUT
_WP_WEB_PORTS = _CMS_WEB_PORTS


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
        skipped = 0

        # Probe HTTP services for CMS indicators (WordPress, Drupal) concurrently
        # before the DB phase. Whichever matches first wins per service — a target
        # is queued for at most one CMS plugin. Failures are silent.
        cms_by_service = await self._detect_cms(hosts, services)

        async with get_db() as db:
            queue_repo = QueueRepository(db)

            for service in services:
                # Normalize fingerprint for CVE matching
                normalized = self.normalizer.normalize(service)

                # CVE-based queue items
                if normalized:
                    cve_matches = await self.matcher.match(service, normalized)
                    for match in cve_matches[:5]:  # cap at 5 CVEs per service
                        if await queue_repo.exists_pending(
                            service.host_id, service.id, ValidationType.CVE_POC
                        ):
                            skipped += 1
                            continue
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

                # CMS-specific queue item — at most one per service.
                cms = cms_by_service.get(service.id)
                if cms == "wordpress":
                    cms_type = ValidationType.WEB_WORDPRESS
                    plugin = "wordpress_plugin"
                    profile = "wordpress"
                elif cms == "drupal":
                    cms_type = ValidationType.WEB_DRUPAL
                    plugin = "drupal_plugin"
                    profile = "drupal"
                else:
                    cms_type = None
                    plugin = None
                    profile = None

                if cms_type is not None:
                    if not await queue_repo.exists_pending(
                        service.host_id, service.id, cms_type
                    ):
                        item = QueueItem(
                            host_id=service.host_id,
                            service_id=service.id,
                            cve_id=None,
                            validation_type=cms_type,
                            plugin_name=plugin,
                            profile_name=profile,
                        )
                        await queue_repo.insert(item)
                        queue_items.append(item)
                        Logger.info(
                            f"correlator.queue.{cms}",
                            extra={"port": service.port, "host_id": service.host_id},
                        )
                    else:
                        skipped += 1

                # Profile-based queue items (service-type checks, not CVE-specific)
                profile_items = self._match_profiles(service)
                for validation_type, plugin_name, profile_name in profile_items:
                    if await queue_repo.exists_pending(
                        service.host_id, service.id, validation_type
                    ):
                        skipped += 1
                        continue
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
            extra={
                "services": len(services),
                "queue_items": len(queue_items),
                "skipped_duplicates": skipped,
            },
        )

        try:
            await self._check_watchlist(hosts, services)
        except Exception as e:
            Logger.error("watchlist.sweep.error", extra={"error": str(e)})

        return queue_items

    async def _check_watchlist(
        self, hosts: list[Host], services: list[Service]
    ) -> int:
        """
        Re-run CVE matching against every service and auto-execute any match
        whose cve_id is on the watchlist. Returns the number of hits.
        """
        # Local import to avoid the correlator <-> executor circular path.
        from apps.validation.services.executor import ExecutorService

        async with get_db() as db:
            watchlist_repo = WatchlistRepository(db)
            entries = await watchlist_repo.list_all()

        if not entries:
            return 0

        watched = {e.cve_id for e in entries}
        executor = ExecutorService()
        hits = 0

        for service in services:
            normalized = self.normalizer.normalize(service)
            if not normalized:
                continue

            try:
                cve_matches = await self.matcher.match(service, normalized)
            except Exception as e:
                Logger.error(
                    "watchlist.match.error",
                    extra={"service_id": service.id, "error": str(e)},
                )
                continue

            for match in cve_matches:
                if match.cve.cve_id not in watched:
                    continue
                try:
                    async with get_db() as db:
                        queue_repo = QueueRepository(db)
                        if await queue_repo.exists_pending(
                            service.host_id, service.id, ValidationType.CVE_POC
                        ):
                            continue
                        item = QueueItem(
                            host_id=service.host_id,
                            service_id=service.id,
                            cve_id=match.cve.cve_id,
                            validation_type=ValidationType.CVE_POC,
                            plugin_name=self._select_plugin(service, match),
                            profile_name="cve_poc",
                            status=QueueStatus.APPROVED,
                            notes="Auto-approved: CVE Watchlist",
                        )
                        await queue_repo.insert(item)
                        await queue_repo.approve(item.id, "Auto-approved: CVE Watchlist")

                    Logger.info(
                        "watchlist.hit",
                        extra={
                            "cve_id": match.cve.cve_id,
                            "service_id": service.id,
                            "host_id": service.host_id,
                        },
                    )

                    async with get_db() as db:
                        watchlist_repo = WatchlistRepository(db)
                        await watchlist_repo.increment_hit(match.cve.cve_id)

                    await executor.execute(item.id)
                    hits += 1
                except Exception as e:
                    Logger.error(
                        "watchlist.execute.error",
                        extra={
                            "cve_id": match.cve.cve_id,
                            "service_id": service.id,
                            "error": str(e),
                        },
                    )
                    continue

        Logger.info(
            "watchlist.sweep.complete",
            extra={
                "entries": len(entries),
                "services": len(services),
                "hits": hits,
            },
        )
        return hits

    async def _detect_cms(
        self, hosts: list[Host], services: list[Service]
    ) -> dict[str, str]:
        """
        Probe each plausibly-HTTP service for CMS indicators.
        Returns {service.id: "wordpress" | "drupal"} for services that matched.

        WordPress signals: wp-content / wp-login / wp-admin / wp-includes in
        the root body OR a /wp-login.php that returns the login form.

        Drupal signals: X-Generator response header starting with "Drupal",
        body containing /sites/default/files, Drupal.settings, or
        /core/misc/drupal.js OR /misc/drupal.js.

        Mutually exclusive — whichever signal hits first wins, with
        Drupal checked first because its X-Generator header is a more
        authoritative signal than WordPress's body-content match.
        """
        ip_by_host = {h.id: h.ip for h in hosts}
        candidates = [s for s in services if _looks_like_web(s)]
        if not candidates:
            return {}

        sem = asyncio.Semaphore(get_default_workers())

        async def _probe(svc: Service) -> tuple[str, str | None]:
            ip = ip_by_host.get(svc.host_id)
            if not ip:
                return svc.id, None
            async with sem:
                return svc.id, await _detect_cms_target(ip, svc.port, svc.service_name or "")

        gathered = await asyncio.gather(
            *(_probe(s) for s in candidates), return_exceptions=True
        )
        results: dict[str, str] = {}
        for entry in gathered:
            if isinstance(entry, BaseException):
                continue
            sid, cms = entry
            if cms:
                results[sid] = cms

        wp_count = sum(1 for v in results.values() if v == "wordpress")
        dr_count = sum(1 for v in results.values() if v == "drupal")
        Logger.info(
            "correlator.cms.probed",
            extra={
                "candidates": len(candidates),
                "wordpress": wp_count,
                "drupal": dr_count,
            },
        )
        return results

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
        banner = (service.banner or "").lower()
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

        # Apache-specific checks — only when product or banner identifies Apache
        # over a service that already speaks HTTP. Tomcat is a different product
        # so we exclude it here.
        if (("http" in service_name and "apache" in product and "tomcat" not in product)
                or ("apache" in banner and "tomcat" not in banner)):
            results.append((ValidationType.WEB_APACHE, "apache_plugin", "apache"))

        # Nginx-specific checks
        if "nginx" in product or "nginx" in banner:
            results.append((ValidationType.WEB_NGINX, "nginx_plugin", "nginx"))

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


def _looks_like_web(service: Service) -> bool:
    """Cheap pre-filter — only probe services that could plausibly speak HTTP."""
    name = (service.service_name or "").lower()
    if any(x in name for x in ("http", "www", "web", "ssl")):
        return True
    if service.port in _WP_WEB_PORTS:
        return True
    return False


def _scheme_for(port: int, service_name: str) -> str:
    if port in (443, 8443) or "ssl" in (service_name or "").lower() or "https" in (service_name or "").lower():
        return "https"
    return "http"


async def _detect_cms_target(ip: str, port: int, service_name: str) -> str | None:
    """
    Single-probe CMS detection.

    Sequence (returns the first CMS that matches):
      1. GET / — inspect X-Generator header (Drupal authoritative signal)
         and body for Drupal then WordPress indicators
      2. If still unknown, GET /wp-login.php — WordPress login form
         confirms WordPress

    Returns "wordpress" | "drupal" | None.
    """
    scheme = _scheme_for(port, service_name)
    base = f"{scheme}://{ip}:{port}"
    try:
        async with httpx.AsyncClient(
            verify=False, timeout=_CMS_PROBE_TIMEOUT, follow_redirects=True,
            headers={"User-Agent": "ai-assist-tool/correlator-probe"},
        ) as client:
            try:
                root = await client.get(base + "/")
            except httpx.HTTPError:
                root = None

            if root is not None and root.status_code < 500:
                gen = (root.headers.get("X-Generator") or root.headers.get("x-generator") or "").lower()
                if gen.startswith(_DRUPAL_GENERATOR_PREFIX):
                    return "drupal"

                body = (root.text or "")[:8000]
                body_lc = body.lower()
                if any(ind in body_lc for ind in _DRUPAL_BODY_INDICATORS):
                    return "drupal"
                if any(ind in body_lc for ind in _WP_INDICATORS):
                    return "wordpress"

            # WordPress-only fallback probe
            try:
                login = await client.get(base + "/wp-login.php")
            except httpx.HTTPError:
                return None
            if login.status_code == 200:
                body = (login.text or "")[:4000].lower()
                if "wordpress" in body or "wp-submit" in body or "user_login" in body:
                    return "wordpress"
            return None
    except Exception:
        return None


async def _is_wordpress(ip: str, port: int, service_name: str) -> bool:
    """Back-compat shim — older callers / tests can still ask just for WP."""
    return await _detect_cms_target(ip, port, service_name) == "wordpress"
