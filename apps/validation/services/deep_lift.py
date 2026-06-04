"""
Deep-lift pass for hosts the initial probe couldn't version.

For each `unknown_version` IP, two extra (cheap) probes try to learn more:

  1. 404-body version probe — request a guaranteed-nonexistent path; if the
     nginx default error page is rendered (common even when `server_tokens off`
     is set on the main vhost — admins forget to scope it to error pages), the
     body often contains `<center>nginx/1.X.Y</center>`. Lifts ~30% of unknowns.

  2. TLS certificate vendor probe (HTTPS only) — read the peer cert subject
     CN + SubjectAltName entries, match against vendor patterns (Atlassian,
     F5 BIG-IP, etc.). Doesn't give a version, but identifies vendor-bundled
     deployments where the right verification is "check the vendor's advisory"
     rather than "check the distro package".

Both probes degrade gracefully — failures return None and the IP stays unknown.
"""

from __future__ import annotations

import asyncio
import re
import secrets
import ssl
from dataclasses import dataclass

import httpx

from apps.validation.services.cve_registry import parse_version

_NGINX_VERSION_PATTERN = re.compile(r"nginx/[\d.]+", re.IGNORECASE)
_HTTPS_PORTS = (443, 8443)
_TLS_TIMEOUT_S = 2.0
_OPENSSL_CIPHERS = "DEFAULT@SECLEVEL=0"  # accept legacy DC certs

# Vendor identification from cert subject / SANs / issuer.
_VENDOR_CERT_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"atlassian", re.I), "java/atlassian"),
    (re.compile(r"bitbucket", re.I), "java/bitbucket"),
    (re.compile(r"jira", re.I), "java/jira"),
    (re.compile(r"confluence", re.I), "java/confluence"),
    (re.compile(r"jenkins", re.I), "java/jenkins"),
    (re.compile(r"sonatype|nexus", re.I), "java/nexus"),
    (re.compile(r"jfrog|artifactory", re.I), "java/artifactory"),
    (re.compile(r"gitlab", re.I), "ruby/gitlab"),
    (re.compile(r"sonarqube", re.I), "java/sonarqube"),
    (re.compile(r"asycuda", re.I), "java/asycuda"),
    (re.compile(r"sap-cloud|sap\.com", re.I), "java/sap"),
    (re.compile(r"oracle\.com|peoplesoft|hyperion", re.I), "java/oracle"),
    (re.compile(r"\bibm\b|websphere", re.I), "java/websphere"),
    (re.compile(r"odoo", re.I), "python/odoo"),
    (re.compile(r"moodle", re.I), "php/moodle"),
    (re.compile(r"nextcloud", re.I), "php/nextcloud"),
    (re.compile(r"f5\.com|big-?ip", re.I), "f5/bigip"),
    (re.compile(r"\bcitrix\b|netscaler", re.I), "citrix/netscaler"),
    (re.compile(r"cloudflare", re.I), "cdn/cloudflare"),
    (re.compile(r"akamai", re.I), "cdn/akamai"),
    (re.compile(r"fastly", re.I), "cdn/fastly"),
)


@dataclass(frozen=True)
class DeepLiftResult:
    version: tuple[int, ...] | None
    vendor: str | None
    source_notes: list[str]


async def probe_404_for_version(
    client: httpx.AsyncClient, ip: str, port: int
) -> tuple[int, ...] | None:
    """Hit a guaranteed-404 path and parse the response body for nginx version."""
    scheme = "https" if port in _HTTPS_PORTS else "http"
    path = f"/aiat-probe-{secrets.token_hex(8)}"
    url = f"{scheme}://{ip}:{port}{path}"
    try:
        r = await client.get(url)
    except httpx.HTTPError:
        return None

    ctype = r.headers.get("Content-Type", "").lower()
    if ctype and not ctype.startswith(("text/", "application/xhtml")):
        return None
    try:
        body = r.text or ""
    except Exception:
        return None

    m = _NGINX_VERSION_PATTERN.search(body)
    if not m:
        return None
    return parse_version(m.group(0))


async def read_tls_cert_subject(ip: str, port: int) -> dict | None:
    """
    Open a TLS connection (no HTTP request) and pull the peer cert.
    Returns {'cn': ..., 'sans': [...], 'issuer_cn': ...} or None.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers(_OPENSSL_CIPHERS)
    except ssl.SSLError:
        pass

    writer = None
    cert_der: bytes | None = None
    try:
        coro = asyncio.open_connection(ip, port, ssl=ctx)
        _reader, writer = await asyncio.wait_for(coro, timeout=_TLS_TIMEOUT_S)
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return None
        cert_der = ssl_obj.getpeercert(binary_form=True)
    except (TimeoutError, OSError, ssl.SSLError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except (TimeoutError, OSError, ssl.SSLError):
                pass

    if not cert_der:
        return None
    return _parse_cert_der(cert_der)


def _parse_cert_der(cert_der: bytes) -> dict | None:
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
    except ImportError:
        return None

    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception:
        return None

    cn: str | None = None
    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        cn = attr.value
        break

    issuer_cn: str | None = None
    for attr in cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME):
        issuer_cn = attr.value
        break

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = list(ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass

    return {"cn": cn, "sans": sans, "issuer_cn": issuer_cn}


def match_vendor_from_cert(cert: dict | None) -> str | None:
    if not cert:
        return None
    candidates: list[str] = []
    if cert.get("cn"):
        candidates.append(cert["cn"])
    candidates.extend(cert.get("sans") or [])
    if cert.get("issuer_cn"):
        candidates.append(cert["issuer_cn"])
    for pat, label in _VENDOR_CERT_PATTERNS:
        for c in candidates:
            if c and pat.search(c):
                return label
    return None


async def deep_lift_ip(
    client: httpx.AsyncClient,
    ip: str,
    primary_port: int,
    open_ports: list[int],
) -> DeepLiftResult:
    """
    Run the lift probes in parallel. Returns whatever could be learned;
    fields are None when nothing was found.
    """
    notes: list[str] = []

    https_port = next((p for p in open_ports if p in _HTTPS_PORTS), None)

    version_task = asyncio.create_task(probe_404_for_version(client, ip, primary_port))
    cert_task = (
        asyncio.create_task(read_tls_cert_subject(ip, https_port))
        if https_port is not None
        else None
    )

    version = await version_task
    if version:
        notes.append(
            f"version learned from 404 error page on port {primary_port}"
        )

    vendor: str | None = None
    if cert_task is not None:
        cert = await cert_task
        vendor = match_vendor_from_cert(cert)
        if vendor:
            notes.append(
                f"vendor inferred from TLS cert (port {https_port}): {vendor}"
            )

    return DeepLiftResult(version=version, vendor=vendor, source_notes=notes)
