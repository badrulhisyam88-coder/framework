"""
NVD sync engine.

Pulls CVE data from the NVD 2.0 API into local SQLite.
Manual trigger from Settings page OR scheduled weekly pull.

API: https://services.nvd.nist.gov/rest/json/cves/2.0
No key required for basic use. Key needed for higher rate limits.
Key configured via TOOL_NVD_API_KEY env var.

Never stores raw API responses. Only extracts and stores what the
CVE repository schema defines.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta

import httpx

from apps.validation.database import get_db
from apps.validation.models import CVE, NVDSyncResult
from apps.validation.repositories import CVERepository
from sdk import Logger

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
RATE_LIMIT_DELAY = 6.0   # seconds between requests without API key
RATE_LIMIT_DELAY_KEY = 0.6  # seconds between requests with API key


class InvalidNVDApiKey(RuntimeError):
    """Raised when NVD rejects the configured TOOL_NVD_API_KEY.

    NVD signals this with HTTP 404 + `message: Invalid apiKey.` response
    header (rather than the conventional 401/403), so we surface it
    explicitly so it isn't confused with an empty date window.
    """


class NVDSyncEngine:
    """
    Synchronizes NVD CVE data into local database.

    Usage:
        engine = NVDSyncEngine(api_key="optional")
        result = await engine.sync_recent(days=7)
        result = await engine.sync_full()  # first run only, slow
    """

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key
        self.delay = RATE_LIMIT_DELAY_KEY if api_key else RATE_LIMIT_DELAY
        self.headers = {"apiKey": api_key} if api_key else {}

    async def sync_recent(self, days: int = 7) -> NVDSyncResult:
        """
        Pull CVEs published or modified in the last N days.
        Use this for regular updates.
        """
        since = datetime.utcnow() - timedelta(days=days)
        pub_start = since.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")

        Logger.info("nvd.sync.start", extra={"mode": "recent", "days": days})
        return await self._sync(
            params={"lastModStartDate": pub_start, "lastModEndDate": pub_end}
        )

    async def sync_full(self) -> NVDSyncResult:
        """
        Pull all CVEs in 120-day chunks from 1999-01-01 to now.

        NVD's 2.0 API rejects unscoped queries with 404 — pubStartDate +
        pubEndDate are required for a backfill. Each chunk is internally
        paginated by `_sync`. Rate-limit pause between chunks.
        """
        Logger.info("nvd.sync.start", extra={"mode": "full"})

        total_added = 0
        total_updated = 0

        start = datetime(1999, 1, 1)
        end = datetime.utcnow()
        chunk_days = 120

        current = start
        while current < end:
            chunk_end = min(current + timedelta(days=chunk_days), end)

            pub_start = current.strftime("%Y-%m-%dT%H:%M:%S.000")
            pub_end = chunk_end.strftime("%Y-%m-%dT%H:%M:%S.000")

            Logger.info(
                "nvd.sync.chunk",
                extra={"from": pub_start, "to": pub_end},
            )
            try:
                result = await self._sync(
                    params={"pubStartDate": pub_start, "pubEndDate": pub_end}
                )
                total_added += result.cves_added
                total_updated += result.cves_updated
            except InvalidNVDApiKey:
                # Bad credential — fail loudly so the user fixes .env.
                raise
            except RuntimeError as e:
                # NVD returns 404 for some empty windows (especially pre-2000).
                # Skip this chunk and keep going — one bad window must not
                # abort a 27-year backfill.
                Logger.info(
                    "nvd.sync.chunk_skipped",
                    extra={"from": pub_start, "to": pub_end, "error": str(e)[:200]},
                )

            current = chunk_end + timedelta(seconds=1)
            await asyncio.sleep(self.delay)

        return NVDSyncResult(
            cves_added=total_added,
            cves_updated=total_updated,
            duration_ms=0,
            last_sync=datetime.utcnow(),
        )

    async def _sync(self, params: dict) -> NVDSyncResult:
        start = time.monotonic()
        added = 0
        updated = 0
        start_index = 0

        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                page_params = {**params, "startIndex": start_index, "resultsPerPage": PAGE_SIZE}

                try:
                    response = await client.get(
                        NVD_BASE_URL, params=page_params, headers=self.headers
                    )
                    if response.status_code == 404:
                        nvd_message = response.headers.get("message", "")
                        if "Invalid apiKey" in nvd_message:
                            Logger.error(
                                "nvd.sync.invalid_api_key",
                                extra={"nvd_message": nvd_message},
                            )
                            raise InvalidNVDApiKey(
                                "TOOL_NVD_API_KEY rejected by NVD "
                                "(message: 'Invalid apiKey.'). "
                                "Either fix the key in .env or remove it "
                                "to use unauthenticated sync."
                            )
                    response.raise_for_status()
                    data = response.json()
                except InvalidNVDApiKey:
                    raise
                except httpx.HTTPError as e:
                    Logger.error("nvd.sync.http_error", extra={"error": str(e)})
                    raise RuntimeError(f"NVD API request failed: {e}") from e

                vulnerabilities = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)

                if not vulnerabilities:
                    break

                async with get_db() as db:
                    repo = CVERepository(db)
                    for vuln in vulnerabilities:
                        cve, is_new = _parse_nvd_item(vuln)
                        if cve:
                            await repo.upsert(cve)
                            if is_new:
                                added += 1
                            else:
                                updated += 1
                    await repo.set_sync_meta(
                        "last_sync", datetime.utcnow().isoformat()
                    )
                    await repo.set_sync_meta("total_cves", str(added + updated))
                    await db.commit()

                Logger.info(
                    "nvd.sync.page",
                    extra={
                        "start_index": start_index,
                        "total": total_results,
                        "added": added,
                        "updated": updated,
                    },
                )

                start_index += len(vulnerabilities)
                if start_index >= total_results:
                    break

                # Respect NVD rate limits
                await asyncio.sleep(self.delay)

        duration_ms = int((time.monotonic() - start) * 1000)
        Logger.info(
            "nvd.sync.complete",
            extra={"added": added, "updated": updated, "duration_ms": duration_ms},
        )

        return NVDSyncResult(
            cves_added=added,
            cves_updated=updated,
            duration_ms=duration_ms,
            last_sync=datetime.utcnow(),
        )


def _parse_nvd_item(item: dict) -> tuple[CVE | None, bool]:
    """
    Parse a single NVD vulnerability item into a CVE model.
    Returns (cve, is_new_to_us) — is_new_to_us is always True here;
    the repo handles dedup via INSERT OR REPLACE.
    """
    try:
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id:
            return None, False

        # Description — prefer English
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # CVSS score — prefer v3.1, fallback to v3.0, then v2
        cvss_score = None
        cvss_vector = None
        cvss_version = None

        metrics = cve_data.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                cvss_version = cvss_data.get("version")
                break

        # Affected products — CPE configurations
        affected_products = _extract_affected_products(cve_data)

        # Dates
        published_str = cve_data.get("published", "")
        modified_str = cve_data.get("lastModified", "")

        published = _parse_date(published_str)
        modified = _parse_date(modified_str)

        if not published or not modified:
            return None, False

        cve = CVE(
            cve_id=cve_id,
            description=description[:2000],  # cap for storage
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cvss_version=cvss_version,
            affected_products=affected_products,
            published_date=published,
            last_modified=modified,
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        )
        return cve, True

    except Exception as e:
        Logger.error("nvd.parse.error", extra={"error": str(e)})
        return None, False


def _extract_affected_products(cve_data: dict) -> list[dict]:
    """
    Extract vendor/product/version info from CPE configurations.
    Returns a simplified list for storage and matching.
    """
    products = []
    configurations = cve_data.get("configurations", [])

    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue
                cpe_name = cpe_match.get("criteria", "")
                # CPE format: cpe:2.3:a:vendor:product:version:...
                parts = cpe_name.split(":")
                if len(parts) >= 6:
                    products.append({
                        "vendor": parts[3],
                        "product": parts[4],
                        "version": parts[5] if parts[5] != "*" else None,
                        "version_start_including": cpe_match.get("versionStartIncluding"),
                        "version_end_including": cpe_match.get("versionEndIncluding"),
                        "version_end_excluding": cpe_match.get("versionEndExcluding"),
                    })

    return products[:50]  # cap to avoid massive JSON blobs


def _parse_date(date_str: str) -> datetime | None:
    if not date_str:
        return None
    try:
        # NVD format: 2023-01-01T00:00:00.000
        return datetime.fromisoformat(date_str.replace("Z", "+00:00").split("+")[0])
    except ValueError:
        return None
