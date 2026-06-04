"""
WordPress validation plugin.

Runs five single-attempt checks against a WordPress target and packs
the results into one Evidence record. Correlator decides WHEN to queue
this plugin (by probing for WP indicators); this plugin trusts that
decision and just runs the checks.

Checks:
1. SQLi exposure on common parameters (s, p, cat)
2. Version disclosure via /  and /feed/ generator tags
3. User enumeration via /?author=1 redirect
4. XML-RPC enabled (/xmlrpc.php)
5. wp-config.php / wp-config.php.bak public exposure
"""

from __future__ import annotations

import re

import httpx

from apps.validation.models import CVE, Evidence, QueueItem, Service, ValidationStatus

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_UA = "ai-assist-tool/validation"

_SQL_ERROR_SIGNATURES = (
    "WordPress database error",
    "You have an error in your SQL syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "supplied argument is not a valid MySQL",
)

_SQLI_TEST_PATHS = (
    "/?s=test%27",
    "/?p=1%27",
    "/?cat=1%27",
)

_GENERATOR_RE = re.compile(
    r'<(?:meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']'
    r'|generator>([^<]+)</generator)',
    re.IGNORECASE,
)


async def run(item: QueueItem, service: Service | None, cve: CVE | None) -> Evidence:
    if not service:
        return Evidence(context={"validation_status": ValidationStatus.CVE_MATCHED,
                                 "environment_context": "Service not found"})

    host_ip = await _get_host_ip(item.host_id)
    scheme = "https" if (service.port in (443, 8443) or "ssl" in (service.service_name or "")) else "http"
    base_url = f"{scheme}://{host_ip}:{service.port}"

    checks: list[dict] = []
    async with httpx.AsyncClient(
        verify=False, timeout=_TIMEOUT, headers={"User-Agent": _UA},
        follow_redirects=False,
    ) as client:
        checks.append(await _check_sqli_exposure(client, base_url))
        checks.append(await _check_version_disclosure(client, base_url))
        checks.append(await _check_user_enumeration(client, base_url))
        checks.append(await _check_xmlrpc(client, base_url))
        checks.append(await _check_wp_config_exposure(client, base_url))

    return _aggregate(base_url, checks)


# ---------------------------------------------------------------------------
# Individual checks — each returns a dict the aggregator understands
# ---------------------------------------------------------------------------


async def _check_sqli_exposure(client: httpx.AsyncClient, base_url: str) -> dict:
    for path in _SQLI_TEST_PATHS:
        url = base_url + path
        try:
            resp = await client.get(url)
        except httpx.HTTPError as e:
            continue  # try the next probe; one transport error shouldn't kill the check
        body = resp.text[:4000]
        for sig in _SQL_ERROR_SIGNATURES:
            if sig in body:
                snippet_start = max(0, body.find(sig) - 60)
                snippet = body[snippet_start:snippet_start + 200]
                return {
                    "name": "sqli_exposure",
                    "exploitable": True,
                    "severity": "high",
                    "sent": f"GET {url}",
                    "received": snippet,
                    "detail": f"SQL error signature '{sig}' returned by {url}",
                    "context": "SQL errors exposed — input reaches database unfiltered",
                }
    return {
        "name": "sqli_exposure",
        "exploitable": False,
        "severity": "info",
        "detail": "No SQL error signatures returned on common WordPress endpoints",
    }


async def _check_version_disclosure(client: httpx.AsyncClient, base_url: str) -> dict:
    versions: list[tuple[str, str]] = []
    for path in ("/", "/feed/"):
        url = base_url + path
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            continue
        match = _GENERATOR_RE.search(resp.text or "")
        if match:
            value = (match.group(1) or match.group(2) or "").strip()
            if value:
                versions.append((url, value))
    if versions:
        url, value = versions[0]
        return {
            "name": "version_disclosure",
            "exploitable": False,
            "severity": "medium",
            "sent": f"GET {url}",
            "received": value,
            "detail": f"Generator string '{value}' returned at {url}",
            "context": "Version disclosure helps attackers target known CVEs",
            "extra": {"all_sources": versions},
        }
    return {
        "name": "version_disclosure",
        "exploitable": False,
        "severity": "info",
        "detail": "No WordPress generator tag found at / or /feed/",
    }


async def _check_user_enumeration(client: httpx.AsyncClient, base_url: str) -> dict:
    url = f"{base_url}/?author=1"
    try:
        resp = await client.get(url)
    except httpx.HTTPError as e:
        return {
            "name": "user_enum",
            "exploitable": False,
            "severity": "info",
            "detail": f"Could not reach {url}: {e}",
        }
    location = resp.headers.get("location") or resp.headers.get("Location") or ""
    if resp.status_code in (301, 302, 307, 308) and "/author/" in location:
        username = location.rstrip("/").rsplit("/author/", 1)[-1].split("/")[0]
        return {
            "name": "user_enum",
            "exploitable": False,
            "severity": "low",
            "sent": f"GET {url}",
            "received": f"HTTP {resp.status_code} → Location: {location}",
            "detail": f"Username '{username}' exposed via author redirect",
            "context": "Admin username exposed via author enumeration",
            "extra": {"username": username},
        }
    return {
        "name": "user_enum",
        "exploitable": False,
        "severity": "info",
        "detail": f"GET /?author=1 returned {resp.status_code}, no author redirect",
    }


async def _check_xmlrpc(client: httpx.AsyncClient, base_url: str) -> dict:
    url = f"{base_url}/xmlrpc.php"
    try:
        head = await client.get(url)
    except httpx.HTTPError as e:
        return {
            "name": "xmlrpc",
            "exploitable": False,
            "severity": "info",
            "detail": f"Could not reach {url}: {e}",
        }
    if head.status_code != 200 and head.status_code != 405:
        return {
            "name": "xmlrpc",
            "exploitable": False,
            "severity": "info",
            "detail": f"GET {url} returned {head.status_code}",
        }
    body_payload = (
        '<?xml version="1.0"?>'
        "<methodCall><methodName>system.listMethods</methodName>"
        "<params/></methodCall>"
    )
    try:
        resp = await client.post(
            url, content=body_payload, headers={"Content-Type": "text/xml"}
        )
    except httpx.HTTPError as e:
        return {
            "name": "xmlrpc",
            "exploitable": False,
            "severity": "info",
            "detail": f"POST {url}: {e}",
        }
    text = resp.text[:1500]
    if resp.status_code == 200 and "methodResponse" in text:
        return {
            "name": "xmlrpc",
            "exploitable": True,
            "severity": "medium",
            "sent": f"POST {url} (system.listMethods)",
            "received": text[:400],
            "detail": "xmlrpc.php is enabled and responds to method calls",
            "context": "XML-RPC enables brute force amplification attacks",
        }
    return {
        "name": "xmlrpc",
        "exploitable": False,
        "severity": "info",
        "detail": f"xmlrpc.php returned status {resp.status_code} on POST",
    }


async def _check_wp_config_exposure(client: httpx.AsyncClient, base_url: str) -> dict:
    for path in ("/wp-config.php", "/wp-config.php.bak", "/wp-config.php~"):
        url = base_url + path
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            continue
        if resp.status_code == 200 and resp.content:
            preview = resp.content[:100].decode(errors="replace")
            return {
                "name": "config_exposure",
                "exploitable": True,
                "severity": "critical",
                "sent": f"GET {url}",
                "received": f"HTTP 200, first 100 bytes: {preview!r}",
                "detail": f"{path} is publicly readable",
                "context": "Database credentials exposed",
            }
    return {
        "name": "config_exposure",
        "exploitable": False,
        "severity": "info",
        "detail": "wp-config.php and known backup paths are not publicly readable",
    }


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _aggregate(base_url: str, checks: list[dict]) -> Evidence:
    exploitable_checks = [c for c in checks if c.get("exploitable")]
    worst = max(checks, key=lambda c: _SEVERITY_ORDER.get(c.get("severity", "info"), 0))

    if exploitable_checks:
        validation_status = ValidationStatus.VALIDATED_EXPLOITABLE
        worst_exploit = max(
            exploitable_checks,
            key=lambda c: _SEVERITY_ORDER.get(c.get("severity", "info"), 0),
        )
        sent = worst_exploit.get("sent", f"WordPress checks against {base_url}")
        received = worst_exploit.get("received", "")
        env_ctx = worst_exploit.get("context", "WordPress weakness confirmed")
    elif worst.get("severity", "info") != "info":
        # Issues found, none exploitable on their own (disclosures, weak config).
        validation_status = ValidationStatus.VALIDATED_NOT_EXPLOITABLE
        sent = f"WordPress checks against {base_url}"
        received = "; ".join(
            f"{c['name']}={c.get('severity')}" for c in checks
            if c.get("severity", "info") != "info"
        )
        env_ctx = worst.get("context", "Information disclosure on WordPress site")
    else:
        validation_status = ValidationStatus.VALIDATED_NOT_EXPLOITABLE
        sent = f"WordPress checks against {base_url}"
        received = "All 5 checks returned clean"
        env_ctx = "WordPress site passed sqli / version / user-enum / xmlrpc / config checks"

    return Evidence(
        sent=sent,
        received=received,
        context={
            "validation_status": validation_status,
            "environment_context": env_ctx,
            "severity": worst.get("severity", "info"),
            "base_url": base_url,
            "checks": checks,
            "exploitable_check_names": [c["name"] for c in exploitable_checks],
        },
    )


# ---------------------------------------------------------------------------
# Helper — host IP lookup (mirrors pattern in other plugins)
# ---------------------------------------------------------------------------


async def _get_host_ip(host_id: str) -> str:
    from apps.validation.database import get_db
    from apps.validation.repositories import HostRepository
    async with get_db() as db:
        repo = HostRepository(db)
        host = await repo.get_by_id(host_id)
    return host.ip if host else "unknown"
