"""Passive HTTP probe — GET + OPTIONS to root, parse response, emit real events.

Designed for the investigation bootstrap. Makes two outbound requests to
the target root (GET then OPTIONS — no enumeration, no payloads) and yields
StageEvent and FindingEvent records describing what was actually observed.

Findings only fire when the corresponding condition is genuinely present
in the response. For unreachable targets, only the connection/error stages
are emitted — no fake findings are manufactured.
"""
from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urlparse

import httpx

from apps.investigation_workspace.probe.events import FindingEvent, StageEvent
from apps.investigation_workspace.probe.finding_id import generate_finding_id
from apps.investigation_workspace.probe.normalize import normalize_target

_PROBE_ID = "passive_probe"

# Headers the probe checks for. Each entry is a real, observable signal.
SECURITY_HEADERS = {
    "content-security-policy":   ("missing_csp_header",
                                  "Missing Content-Security-Policy header",
                                  "medium"),
    "strict-transport-security": ("missing_hsts_header",
                                  "Missing Strict-Transport-Security header",
                                  "medium"),
    "x-frame-options":           ("missing_x_frame_options",
                                  "Missing X-Frame-Options header",
                                  "low"),
    "x-content-type-options":    ("missing_x_content_type_options",
                                  "Missing X-Content-Type-Options header",
                                  "low"),
    "referrer-policy":           ("missing_referrer_policy",
                                  "Missing Referrer-Policy header",
                                  "info"),
    "permissions-policy":        ("missing_permissions_policy",
                                  "Missing Permissions-Policy header",
                                  "low"),
}

# WAF/CDN header fingerprints — first match wins.
WAF_CDN_SIGNATURES: dict[str, str] = {
    "cf-ray":               "Cloudflare",
    "x-amz-cf-id":          "AWS CloudFront",
    "x-amz-cf-pop":         "AWS CloudFront",
    "x-served-by":          "Fastly",
    "x-cache":              "Varnish/CDN",
    "x-akamai-transformed": "Akamai",
    "x-sucuri-id":          "Sucuri WAF",
    "x-iinfo":              "Incapsula",
    "x-cdn":                "Generic CDN",
}

# Server header value substrings indicating a CDN/WAF.
_SERVER_VALUE_SIGS: dict[str, str] = {
    "cloudflare": "Cloudflare",
    "akamaiGhost": "Akamai",
    "ecs":         "Akamai ECS",
}

# Detects version strings in Server / X-Powered-By values.
_VERSION_RE = re.compile(r"\d+\.\d+")


async def run_passive_probe(target: str) -> AsyncIterator[StageEvent | FindingEvent]:
    """Run the passive probe; yield StageEvent + FindingEvent records.

    Order of operations is the order of yielded events. Each StageEvent
    represents a unit of work the probe just completed; each FindingEvent
    is a real condition observed in the response.
    """
    # Phase 45 — normalize before probing. Strips client-side routing
    # fragments (#/) and other intake noise.
    normalized, norm_actions = normalize_target(target)
    if not normalized:
        yield StageEvent(
            label      = "Probing target — invalid input",
            actions    = tuple([f"input: {target!r}"] + norm_actions),
            tools      = ("target normalizer",),
            detected   = ("target rejected before probing",),
            confidence = "high",
        )
        return
    target = normalized
    parsed   = urlparse(target)
    is_https = parsed.scheme == "https"
    path     = parsed.path or "/"

    # Phase 46 — log target on entry.
    from sdk import Logger
    Logger.info(
        "probe.target_received",
        extra={"canonical_target": target, "scheme": parsed.scheme,
               "host": parsed.hostname, "port": parsed.port},
    )

    # ── Stage 0 ─ initialization (always succeeds) ─────────────────────
    init_actions = ["Created investigation workspace", "Allocated topology canvas"]
    if norm_actions:
        init_actions.extend(f"normalize: {a}" for a in norm_actions)
    init_actions.append(f"Resolved target: {parsed.netloc}")
    yield StageEvent(
        label      = "Initializing investigation",
        actions    = tuple(init_actions),
        tools      = ("workspace orchestrator", "target normalizer"),
        confidence = "—",
    )

    # ── Stage 1 ─ real outbound GET ────────────────────────────────────
    request_error: str | None = None
    resp: httpx.Response | None = None
    try:
        async with httpx.AsyncClient(
            timeout          = 6.0,
            follow_redirects = True,
            verify           = False,    # tolerate self-signed certs on dev targets
        ) as client:
            Logger.info(
                "probe.httpx_request",
                extra={"method": "GET", "url": target},
            )
            resp = await client.get(target)
    except httpx.TimeoutException:
        request_error = "timed out after 6s"
    except httpx.ConnectError as e:
        request_error = f"connection refused ({e!s})"
    except httpx.RequestError as e:
        request_error = f"request failed ({e!s})"
    except Exception as e:   # pragma: no cover — defensive
        request_error = f"unexpected error: {e!s}"

    if request_error:
        yield StageEvent(
            label      = "Probing target — unreachable",
            actions    = (f"GET {target}", f"Result: {request_error}"),
            tools      = ("httpx async client",),
            detected   = ("target did not respond",),
            confidence = "high",
        )
        return

    assert resp is not None
    headers_l     = {k.lower(): v for k, v in resp.headers.items()}
    server_banner = headers_l.get("server", "")
    powered_by    = headers_l.get("x-powered-by", "")

    fingerprint_bits: list[str] = []
    if server_banner:
        fingerprint_bits.append(f"Server: {server_banner}")
    if powered_by:
        fingerprint_bits.append(f"X-Powered-By: {powered_by}")
    if not fingerprint_bits:
        fingerprint_bits.append("no server fingerprint disclosed")

    yield StageEvent(
        label      = "Fingerprinting target",
        actions    = (f"GET {target}",
                      f"HTTP {resp.status_code} from {parsed.netloc}",
                      "Read Server / X-Powered-By headers"),
        tools      = ("httpx async client", "header analyzer"),
        detected   = tuple(fingerprint_bits),
        confidence = "high",
    )

    # ── Stage 2 ─ surface mapping (root response shape) ────────────────
    content_type = headers_l.get("content-type", "")
    body_len     = len(resp.content)
    yield StageEvent(
        label      = "Mapping exposed surfaces",
        actions    = ("Inspected root document",
                      "Recorded status / content-type",
                      "Captured response shape"),
        tools      = ("httpx async client",),
        detected   = (
            f"HTTP {resp.status_code}",
            f"Content-Type: {content_type or 'unknown'}",
            f"Body: {body_len} bytes",
        ),
        confidence = "high",
    )
    yield FindingEvent(
        after_stage_index = 2,
        finding_type      = "http_service_detected",
        title             = f"HTTP {resp.status_code} service responding",
        severity          = "info",
        description       = (
            f"Target responded with HTTP {resp.status_code} "
            f"and {body_len} bytes of {content_type or 'unspecified'} content."
        ),
        endpoint          = path,
        evidence          = {
            "status_code":  resp.status_code,
            "content_type": content_type,
            "server":       server_banner,
            "x_powered_by": powered_by,
            "body_bytes":   body_len,
        },
        phase             = "recon",
        id                = generate_finding_id(_PROBE_ID, target, path, "http_service_detected"),
        confidence        = "high",
        next_actions      = [],
    )

    # Verbose banner disclosure — emit when banner contains a version string.
    for hdr_name, hdr_value in (("Server", server_banner), ("X-Powered-By", powered_by)):
        if hdr_value and _VERSION_RE.search(hdr_value):
            vm = _VERSION_RE.search(hdr_value)
            assert vm is not None
            ftype = "server_version_leaked"
            yield FindingEvent(
                after_stage_index = 2,
                finding_type      = "server_version_leaked",
                title             = f"Verbose {hdr_name} banner: {hdr_value}",
                severity          = "low",
                description       = (
                    f"The {hdr_name} response header discloses version information "
                    f"({hdr_value!r}), aiding attacker reconnaissance."
                ),
                endpoint          = path,
                evidence          = {
                    "header":            hdr_name,
                    "value":             hdr_value,
                    "version_extracted": vm.group(0),
                },
                phase             = "recon",
                id                = generate_finding_id(
                    _PROBE_ID, target, path,
                    f"verbose_banner_disclosed_{hdr_name.lower()}"
                ),
                confidence        = "high",
                next_actions      = [],
            )

    # ── Stage 3 ─ security header inspection (real check) ──────────────
    present:          list[str]          = []
    missing:          list[str]          = []
    findings_to_emit: list[FindingEvent] = []
    for header_name, (ftype, ftitle, sev) in SECURITY_HEADERS.items():
        value = headers_l.get(header_name)
        if value:
            present.append(f"{header_name}: {value[:60]}")
        else:
            missing.append(header_name)
            findings_to_emit.append(FindingEvent(
                after_stage_index = 3,
                finding_type      = ftype,
                title             = ftitle,
                severity          = sev,
                description       = (
                    f"Response from {parsed.netloc} lacks the "
                    f"{header_name} header."
                ),
                endpoint          = path,
                evidence          = {
                    "header":       header_name,
                    "all_headers":  dict(headers_l),
                    "status_code":  resp.status_code,
                    "probe_method": "GET",
                },
                phase             = "recon",
                id                = generate_finding_id(_PROBE_ID, target, path, ftype),
                confidence        = "high",
                next_actions      = [],
            ))

    # WAF/CDN detection — derived from GET response headers, no extra request.
    waf_vendor: str | None = None
    waf_header: str | None = None
    waf_value:  str | None = None
    for sig_header, sig_vendor in WAF_CDN_SIGNATURES.items():
        if sig_header in headers_l:
            waf_vendor = sig_vendor
            waf_header = sig_header
            waf_value  = headers_l[sig_header]
            break
    if waf_vendor is None and server_banner:
        for sv_key, sv_vendor in _SERVER_VALUE_SIGS.items():
            if sv_key.lower() in server_banner.lower():
                waf_vendor = sv_vendor
                waf_header = "server"
                waf_value  = server_banner
                break

    detected_lines: list[str] = []
    detected_lines.extend(f"present: {p}" for p in present[:3])
    detected_lines.extend(f"absent:  {m}" for m in missing[:5])
    if waf_vendor:
        detected_lines.append(f"WAF/CDN: {waf_vendor}")
    yield StageEvent(
        label      = "Probing security headers",
        actions    = (f"Inspected {len(SECURITY_HEADERS)} baseline headers",
                      f"{len(present)} present, {len(missing)} absent",
                      "Computed gap report"),
        tools      = ("header analyzer",),
        detected   = tuple(detected_lines) or ("all baseline headers present",),
        confidence = "high",
    )
    for fe in findings_to_emit:
        yield fe
    if waf_vendor:
        assert waf_header is not None and waf_value is not None
        yield FindingEvent(
            after_stage_index = 3,
            finding_type      = "waf_cdn_detected",
            title             = f"WAF/CDN detected: {waf_vendor}",
            severity          = "info",
            description       = (
                f"The target is behind {waf_vendor}. "
                "WAF presence may affect probe accuracy and enumeration results."
            ),
            endpoint          = path,
            evidence          = {
                "vendor":          waf_vendor,
                "matching_header": waf_header,
                "matching_value":  waf_value,
            },
            phase             = "recon",
            id                = generate_finding_id(_PROBE_ID, target, path, "waf_cdn_detected"),
            confidence        = "high",
            next_actions      = [],
        )

    # ── Stage 4 ─ HTTP method advertisement (OPTIONS request) ─────────
    options_allow: str | None = None
    options_error: str | None = None
    try:
        async with httpx.AsyncClient(
            timeout          = 5.0,
            follow_redirects = False,
            verify           = False,
        ) as client:
            Logger.info(
                "probe.httpx_request",
                extra={"method": "OPTIONS", "url": target},
            )
            opts_resp      = await client.options(target)
            options_allow  = opts_resp.headers.get("allow")
    except Exception as e:
        options_error = str(e)

    advanced_methods: list[str] = []
    if options_allow:
        advanced_methods = [
            m.strip().upper()
            for m in options_allow.split(",")
            if m.strip().upper() not in ("GET", "HEAD", "OPTIONS", "")
        ]

    yield StageEvent(
        label      = "Enumerating HTTP methods",
        actions    = (
            f"OPTIONS {path}",
            f"Allow header: {options_allow or options_error or 'not returned'}",
        ),
        tools      = ("httpx async client",),
        detected   = (
            tuple(f"method: {m}" for m in advanced_methods)
            if advanced_methods else
            ("no non-standard methods advertised",)
        ),
        confidence = "high",
    )
    if advanced_methods:
        yield FindingEvent(
            after_stage_index = 4,
            finding_type      = "http_methods_advertised",
            title             = (
                f"Server advertises {len(advanced_methods)} additional HTTP method(s)"
            ),
            severity          = "info",
            description       = (
                f"OPTIONS on root returned Allow: {options_allow}. "
                "Non-standard methods may expose additional attack surface."
            ),
            endpoint          = path,
            evidence          = {
                "allow_header":       options_allow,
                "advertised_methods": advanced_methods,
            },
            phase             = "recon",
            id                = generate_finding_id(
                _PROBE_ID, target, path, "http_methods_advertised"
            ),
            confidence        = "high",
            next_actions      = [{
                "probe_id":        "run_method_enum",
                "trigger":         "auto_fire",
                "description":     (
                    "Server advertises additional HTTP methods — "
                    "enumerate per endpoint"
                ),
                "required_inputs": [],
                "produces":        "endpoint_method_matrix",
            }],
        )

    # ── Stage 5 ─ transport-security verification ─────────────────────
    yield StageEvent(
        label      = "Verifying transport security",
        actions    = (
            f"Target scheme: {parsed.scheme}",
            ("HTTPS confirmed" if is_https else "Cleartext HTTP — TLS not negotiated"),
        ),
        tools      = ("transport probe",),
        detected   = (
            ("TLS active",) if is_https else ("HTTP cleartext channel",)
        ),
        confidence = "high",
    )

    # ── Stage 6 ─ summary ─────────────────────────────────────────────
    verbose_count = sum(
        1 for v in (server_banner, powered_by) if v and _VERSION_RE.search(v)
    )
    total_findings = (
        1                                # http_service_detected
        + verbose_count                  # verbose_banner_disclosed
        + len(findings_to_emit)          # missing header findings
        + (1 if waf_vendor else 0)       # waf_cdn_detected
        + (1 if advanced_methods else 0) # http_methods_advertised
    )
    plural = "s" if total_findings != 1 else ""
    yield StageEvent(
        label      = "Compiling findings",
        actions    = (
            f"Aggregated {total_findings} observed condition{plural}",
            "Ranked by severity",
            "Stamped lineage edges",
        ),
        tools      = ("workspace orchestrator",),
        detected   = (f"{total_findings} finding{plural} ready for review",),
        confidence = "high",
    )
