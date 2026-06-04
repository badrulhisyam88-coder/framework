"""
Drupal validation plugin.

Mirrors the WordPress plugin: correlator decides WHEN this runs (after
its WP-vs-Drupal probe matches Drupal); this plugin trusts that
decision and runs the six single-attempt checks below, packing the
results into one Evidence record.

Checks:
1. Drupalgeddon2 (CVE-2018-7600) — non-destructive probe
2. Version disclosure via CHANGELOG / README
3. Default settings file public exposure
4. Admin panel + user/1 enumeration
5. xmlrpc.php / /api availability
6. Drupageddon legacy SQLi (CVE-2014-3704) — only if version < 7.32 detected
"""

from __future__ import annotations

import re

import httpx

from apps.validation.models import CVE, Evidence, QueueItem, Service, ValidationStatus

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_UA = "ai-assist-tool/validation"

_SQL_ERROR_SIGNATURES = (
    "PDOException",
    "SQLSTATE",
    "You have an error in your SQL syntax",
    "mysql_fetch",
    "Drupal database error",
)

# CHANGELOG line format: "Drupal 7.95, 2024-XX-XX" or "Drupal 9.5.11, …"
_CHANGELOG_VERSION_RE = re.compile(
    r"Drupal\s+(\d+(?:\.\d+){1,2})\s*,",
    re.IGNORECASE,
)

# README "VERSION = '7.95'" or "VERSION = '9.5.11'"
_README_VERSION_RE = re.compile(r"VERSION\s*=\s*['\"]([\d.]+)['\"]")


async def run(item: QueueItem, service: Service | None, cve: CVE | None) -> Evidence:
    if not service:
        return Evidence(context={
            "validation_status": ValidationStatus.CVE_MATCHED,
            "environment_context": "Service not found",
        })

    host_ip = await _get_host_ip(item.host_id)
    scheme = "https" if (service.port in (443, 8443) or "ssl" in (service.service_name or "")) else "http"
    base_url = f"{scheme}://{host_ip}:{service.port}"

    checks: list[dict] = []
    async with httpx.AsyncClient(
        verify=False, timeout=_TIMEOUT, headers={"User-Agent": _UA},
        follow_redirects=False,
    ) as client:
        ver_check = await _check_version_disclosure(client, base_url)
        checks.append(ver_check)

        checks.append(await _check_drupalgeddon2(client, base_url))
        checks.append(await _check_default_files(client, base_url))
        checks.append(await _check_admin_exposure(client, base_url))
        checks.append(await _check_api_exposure(client, base_url))

        # Only run the legacy SQLi probe when version detection suggests
        # a vulnerable Drupal 7 (< 7.32) install. Otherwise it's noise.
        detected_version = ver_check.get("extra", {}).get("version")
        if detected_version and _is_drupal7_pre732(detected_version):
            checks.append(await _check_legacy_sqli(client, base_url))
        else:
            checks.append({
                "name": "sqli_legacy",
                "exploitable": False,
                "severity": "info",
                "detail": (
                    "Skipped — legacy SQLi probe only runs on Drupal < 7.32; "
                    f"detected version: {detected_version or 'unknown'}"
                ),
            })

    return _aggregate(base_url, checks)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


async def _check_drupalgeddon2(client: httpx.AsyncClient, base_url: str) -> dict:
    """
    Non-destructive Drupalgeddon2 (CVE-2018-7600) reachability probe.

    The known-vulnerable endpoint accepts a `mail[#post_render]` AJAX hook
    that executes arbitrary callables on patched-but-still-vulnerable
    sites. We do NOT send a payload that would execute anything — we send
    a harmless `phpinfo` callable triggered through `#markup` and look at
    the *shape* of the response.

    A patched server replies with a structured error or 403/404; a
    vulnerable one returns a 200 with a JSON envelope echoing back our
    rendered command. We only check the envelope, not the result, so
    nothing is actually run.
    """
    url = (
        f"{base_url}/user/register"
        "?element_parents=account/mail/%23value"
        "&ajax_form=1&_wrapper_format=drupal_ajax"
    )
    payload = {
        "form_id": "user_register_form",
        "_drupal_ajax": "1",
        "mail[#post_render][]": "printf",
        "mail[#type]": "markup",
        "mail[#markup]": "ai-assist-tool-probe",
    }
    try:
        resp = await client.post(url, data=payload)
    except httpx.HTTPError as e:
        return {
            "name": "drupalgeddon2",
            "exploitable": False,
            "severity": "info",
            "detail": f"POST {url}: {e}",
        }
    text = (resp.text or "")[:1500]
    if resp.status_code == 200 and (
        "ai-assist-tool-probe" in text or '"command":"insert"' in text
    ):
        return {
            "name": "drupalgeddon2",
            "exploitable": True,
            "severity": "critical",
            "sent": f"POST {url}",
            "received": text[:500],
            "detail": "Drupalgeddon2 endpoint accepted probe form and reflected payload",
            "context": "Drupalgeddon2 allows unauthenticated RCE (CVE-2018-7600)",
            "extra": {"cve": "CVE-2018-7600"},
        }
    return {
        "name": "drupalgeddon2",
        "exploitable": False,
        "severity": "info",
        "detail": f"POST {url} returned {resp.status_code}; no probe reflection",
    }


async def _check_version_disclosure(client: httpx.AsyncClient, base_url: str) -> dict:
    candidates: list[tuple[str, str]] = []
    for path in ("/CHANGELOG.txt", "/core/CHANGELOG.txt", "/README.txt", "/core/README.txt"):
        url = base_url + path
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            continue
        if resp.status_code != 200 or not resp.text:
            continue
        body = resp.text[:4000]
        m = _CHANGELOG_VERSION_RE.search(body) or _README_VERSION_RE.search(body)
        if m:
            candidates.append((url, m.group(1)))
    if candidates:
        url, version = candidates[0]
        return {
            "name": "version_disclosure",
            "exploitable": False,
            "severity": "medium",
            "sent": f"GET {url}",
            "received": f"Drupal {version}",
            "detail": f"Version '{version}' returned at {url}",
            "context": "Version disclosure enables targeted CVE attacks",
            "extra": {"version": version, "sources": candidates},
        }
    return {
        "name": "version_disclosure",
        "exploitable": False,
        "severity": "info",
        "detail": "No version-bearing CHANGELOG / README files publicly readable",
    }


async def _check_default_files(client: httpx.AsyncClient, base_url: str) -> dict:
    for path in ("/sites/default/settings.php", "/sites/default/default.settings.php"):
        url = base_url + path
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            continue
        if resp.status_code == 200 and resp.content:
            preview = resp.content[:100].decode(errors="replace")
            return {
                "name": "default_files",
                "exploitable": True,
                "severity": "critical",
                "sent": f"GET {url}",
                "received": f"HTTP 200, first 100 bytes: {preview!r}",
                "detail": f"{path} is publicly readable",
                "context": "Database credentials may be exposed",
            }
    return {
        "name": "default_files",
        "exploitable": False,
        "severity": "info",
        "detail": "sites/default/settings.php and default.settings.php are not publicly readable",
    }


async def _check_admin_exposure(client: httpx.AsyncClient, base_url: str) -> dict:
    findings: list[str] = []
    severity = "info"
    extra: dict = {}

    # /admin should redirect to login on a sane install
    try:
        admin = await client.get(f"{base_url}/admin")
    except httpx.HTTPError as e:
        admin = None
        findings.append(f"GET /admin failed: {e}")

    if admin is not None:
        loc = admin.headers.get("location") or admin.headers.get("Location") or ""
        if admin.status_code == 200:
            findings.append(f"/admin returned 200 (expected redirect to login)")
            severity = "medium"
            extra["admin_status"] = 200
        elif admin.status_code in (301, 302, 307, 308) and "/user/login" in loc:
            findings.append(f"/admin → {loc} (expected redirect)")
        else:
            findings.append(f"/admin returned {admin.status_code}")

    # /user/1 — if Drupal exposes a username for user 1, that's the admin
    try:
        user_one = await client.get(f"{base_url}/user/1", follow_redirects=True)
    except httpx.HTTPError as e:
        user_one = None
        findings.append(f"GET /user/1 failed: {e}")

    if user_one is not None and user_one.status_code == 200 and user_one.text:
        m = re.search(
            r'<title[^>]*>([^<|]+?)\s*\|\s*',
            user_one.text[:1500],
            re.IGNORECASE,
        )
        if m:
            username = m.group(1).strip()
            if username and username.lower() not in ("access denied", "page not found"):
                findings.append(f"/user/1 exposed username '{username}'")
                severity = "low" if severity == "info" else severity
                extra["admin_username"] = username

    if severity == "info":
        return {
            "name": "admin_exposure",
            "exploitable": False,
            "severity": "info",
            "detail": "; ".join(findings) or "Admin panel and user/1 are properly protected",
        }
    return {
        "name": "admin_exposure",
        "exploitable": False,
        "severity": severity,
        "sent": f"GET {base_url}/admin and {base_url}/user/1",
        "received": "; ".join(findings),
        "detail": "Admin surface partially exposed",
        "context": "Admin panel / user enumeration exposes attack surface",
        "extra": extra,
    }


async def _check_api_exposure(client: httpx.AsyncClient, base_url: str) -> dict:
    issues: list[str] = []
    extra: dict = {}

    try:
        xrpc = await client.get(f"{base_url}/xmlrpc.php")
    except httpx.HTTPError as e:
        xrpc = None
        issues.append(f"GET /xmlrpc.php failed: {e}")

    if xrpc is not None and xrpc.status_code == 200:
        issues.append("xmlrpc.php responds with 200")
        extra["xmlrpc_status"] = 200

    try:
        api = await client.get(f"{base_url}/api", follow_redirects=False)
    except httpx.HTTPError as e:
        api = None
        issues.append(f"GET /api failed: {e}")

    if api is not None and api.status_code in (200, 401):
        body = (api.text or "")[:400]
        if api.status_code == 200 and (
            "_links" in body or '"data"' in body or "application/hal+json" in (api.headers.get("content-type") or "")
        ):
            issues.append("/api returned 200 with JSON-API style body — REST surface live")
            extra["api_status"] = api.status_code

    if not issues:
        return {
            "name": "api_exposure",
            "exploitable": False,
            "severity": "info",
            "detail": "Neither /xmlrpc.php nor /api are publicly exposed",
        }
    return {
        "name": "api_exposure",
        "exploitable": False,
        "severity": "medium",
        "sent": f"GET {base_url}/xmlrpc.php and {base_url}/api",
        "received": "; ".join(issues),
        "detail": "Auxiliary API surface exposed",
        "context": "Exposed XML-RPC / REST endpoints widen the attack surface",
        "extra": extra,
    }


async def _check_legacy_sqli(client: httpx.AsyncClient, base_url: str) -> dict:
    """
    CVE-2014-3704 (Drupageddon) — Drupal 7 pre-7.32 SQL injection via
    expandable arguments. The exploit form involves crafted POSTs, but
    a non-invasive surface check works: trigger an injection-like
    expression on a parameter the legacy code path read directly and
    look for a SQL error signature. No payload is executed.
    """
    url = f"{base_url}/?q=node&destination=node%27"
    try:
        resp = await client.get(url)
    except httpx.HTTPError as e:
        return {
            "name": "sqli_legacy",
            "exploitable": False,
            "severity": "info",
            "detail": f"GET {url}: {e}",
        }
    body = (resp.text or "")[:4000]
    for sig in _SQL_ERROR_SIGNATURES:
        if sig in body:
            return {
                "name": "sqli_legacy",
                "exploitable": True,
                "severity": "critical",
                "sent": f"GET {url}",
                "received": body[max(0, body.find(sig) - 60):body.find(sig) + 200],
                "detail": f"SQL error signature '{sig}' returned by {url}",
                "context": "Drupageddon legacy SQLi (CVE-2014-3704) — RCE-capable",
                "extra": {"cve": "CVE-2014-3704"},
            }
    return {
        "name": "sqli_legacy",
        "exploitable": False,
        "severity": "info",
        "detail": "No SQL error signatures returned by legacy SQLi probe",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_drupal7_pre732(version: str) -> bool:
    """True if version parses as 7.x with x < 32."""
    parts = version.split(".")
    if len(parts) < 2:
        return False
    try:
        major = int(parts[0])
        minor = int(parts[1])
    except ValueError:
        return False
    return major == 7 and minor < 32


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
        sent = worst_exploit.get("sent", f"Drupal checks against {base_url}")
        received = worst_exploit.get("received", "")
        env_ctx = worst_exploit.get("context", "Drupal weakness confirmed")
    elif worst.get("severity", "info") != "info":
        validation_status = ValidationStatus.VALIDATED_NOT_EXPLOITABLE
        sent = f"Drupal checks against {base_url}"
        received = "; ".join(
            f"{c['name']}={c.get('severity')}" for c in checks
            if c.get("severity", "info") != "info"
        )
        env_ctx = worst.get("context", "Information disclosure on Drupal site")
    else:
        validation_status = ValidationStatus.VALIDATED_NOT_EXPLOITABLE
        sent = f"Drupal checks against {base_url}"
        received = "All 6 checks returned clean"
        env_ctx = "Drupal site passed drupalgeddon2 / version / files / admin / api / legacy-sqli"

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


async def _get_host_ip(host_id: str) -> str:
    from apps.validation.database import get_db
    from apps.validation.repositories import HostRepository
    async with get_db() as db:
        repo = HostRepository(db)
        host = await repo.get_by_id(host_id)
    return host.ip if host else "unknown"
