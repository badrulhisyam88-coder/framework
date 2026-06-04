"""
Custom Report scanner — remote, unauthenticated CVE probe.

Per-IP flow:
  1. Probe every configured port in parallel (HTTP/HTTPS GET /).
  2. If every port returns a connection error, the IP is unreachable —
     it is counted toward the unreachable total but produces no result row.
  3. Otherwise aggregate the open-port findings into a single IPResult,
     status set to the most severe verdict across the open ports.

Each successful probe also records a backend fingerprint (java, php, node,
python, etc.) so the operator can route verification to the right place
(distro package vs vendor advisory vs container).

Stateless: no database writes. Streams per-IP results through an async
generator the SSE endpoint forwards to the browser.

Tuning:
  * MAX_TARGETS caps (IP × port) combinations to avoid runaway scans.
  * Connect timeout is 1.5s (LAN-tuned) so dead hosts are skipped fast.
  * `verify=False` is intentional — DC hosts often present self-signed certs.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import httpx

from apps.validation.services.backend_detect import detect_backend
from apps.validation.services.cve_registry import (
    CVERule,
    evaluate,
    get_rule,
    parse_version,
)
from apps.validation.services.deep_lift import deep_lift_ip
from sdk import Logger

DEFAULT_PORTS: tuple[int, ...] = (80, 443, 8080, 8443)
DEFAULT_READ_TIMEOUT_S = 5.0
DEFAULT_CONNECT_TIMEOUT_S = 1.5
MAX_TARGETS = 4096
MAX_WORKERS = 32

# Lower rank = more severe. Drives per-IP aggregation.
_AGG_RANK: dict[str, int] = {
    "vulnerable": 0,
    "unknown_version": 1,
    "safe": 2,
    "not_applicable": 3,
}


@dataclass(frozen=True)
class PortProbe:
    port: int
    status: str
    server_header: str
    detected_version: str
    backend: str
    notes: str


@dataclass(frozen=True)
class IPResult:
    ip: str
    status: str
    open_ports: list[int]
    server_header: str
    detected_version: str
    backend: str
    notes: str

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "status": self.status,
            "open_ports": self.open_ports,
            "server_header": self.server_header,
            "detected_version": self.detected_version,
            "backend": self.backend,
            "notes": self.notes,
        }


@dataclass
class ScanSummary:
    cve_id: str
    total_ips: int
    vulnerable: int = 0
    safe: int = 0
    unknown_version: int = 0
    not_applicable: int = 0
    unreachable: int = 0
    duration_s: float = 0.0
    results: list[IPResult] = field(default_factory=list)

    def update(self, r: IPResult) -> None:
        self.results.append(r)
        if r.status == "vulnerable":
            self.vulnerable += 1
        elif r.status == "safe":
            self.safe += 1
        elif r.status == "unknown_version":
            self.unknown_version += 1
        elif r.status == "not_applicable":
            self.not_applicable += 1

    def alive(self) -> int:
        return self.vulnerable + self.safe + self.unknown_version + self.not_applicable

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "total_ips": self.total_ips,
            "alive": self.alive(),
            "vulnerable": self.vulnerable,
            "safe": self.safe,
            "unknown_version": self.unknown_version,
            "not_applicable": self.not_applicable,
            "unreachable": self.unreachable,
            "duration_s": round(self.duration_s, 2),
        }


def expand_ips(ip_range: str) -> list[str]:
    """Expand 'a, b, c/24' into a flat IP list."""
    ips: list[str] = []
    for chunk in (s.strip() for s in ip_range.split(",")):
        if not chunk:
            continue
        if "/" in chunk:
            try:
                net = ipaddress.ip_network(chunk, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid CIDR '{chunk}': {e}") from e
            ips.extend(str(h) for h in net.hosts())
        else:
            try:
                ipaddress.ip_address(chunk)
            except ValueError as e:
                raise ValueError(f"Invalid IP '{chunk}': {e}") from e
            ips.append(chunk)
    return ips


def parse_ports(raw: str) -> list[int]:
    if not raw or not raw.strip():
        return list(DEFAULT_PORTS)
    out: list[int] = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            p = int(chunk)
        except ValueError as e:
            raise ValueError(f"Invalid port '{chunk}'") from e
        if not 1 <= p <= 65535:
            raise ValueError(f"Port out of range: {p}")
        out.append(p)
    return out


def _v(t: tuple[int, ...]) -> str:
    return ".".join(str(p) for p in t)


async def probe_port(
    client: httpx.AsyncClient, ip: str, port: int, rule: CVERule
) -> PortProbe:
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        r = await client.get(url)
    except httpx.HTTPError:
        return PortProbe(port=port, status="unreachable", server_header="",
                         detected_version="", backend="unknown", notes="")

    backend = detect_backend(r)
    server = r.headers.get("Server", "").strip()

    if not server:
        return PortProbe(
            port=port, status="unknown_version", server_header="(none)",
            detected_version="", backend=backend,
            notes="no Server header (server_tokens off, or non-HTTP service)",
        )

    if rule.product.lower() not in server.lower():
        return PortProbe(
            port=port, status="not_applicable", server_header=server,
            detected_version="", backend=backend, notes=f"not {rule.product}",
        )

    version = parse_version(server)
    verdict = evaluate(rule, version)
    version_str = _v(version) if version else ""

    if verdict == "vulnerable":
        notes = (
            f"version {version_str} is in affected range "
            f"[{_v(rule.introduced)} – {_v(rule.fixed)}). {rule.notes}"
        )
    elif verdict == "safe":
        notes = f"version {version_str} is at or above fixed release {_v(rule.fixed)}"
    else:
        notes = "Server header has no parseable version"

    return PortProbe(
        port=port, status=verdict, server_header=server,
        detected_version=version_str, backend=backend, notes=notes,
    )


def _aggregate_backend(probes: list[PortProbe], primary: PortProbe) -> str:
    """
    Pick the most useful backend label across a host's open ports.
    Prefer the primary port's backend if it's specific (not 'unknown'),
    else fall back to the first non-unknown across other ports.
    """
    if primary.backend and primary.backend != "unknown":
        return primary.backend
    for p in probes:
        if p.backend and p.backend != "unknown":
            return p.backend
    return "unknown"


def aggregate_ip(ip: str, probes: list[PortProbe]) -> IPResult | None:
    """
    Collapse per-port probes into one row.

    Returns None if every port was unreachable (dead host). Otherwise picks
    the most severe verdict across the open ports as the row's status; the
    server header / version come from that driving port. If multiple ports
    are open, the notes are prefixed with the driving port number.
    """
    open_probes = [p for p in probes if p.status != "unreachable"]
    if not open_probes:
        return None

    open_ports = sorted(p.port for p in open_probes)
    primary = min(open_probes, key=lambda p: _AGG_RANK.get(p.status, 9))
    backend = _aggregate_backend(open_probes, primary)

    notes = primary.notes
    if len(open_ports) > 1:
        notes = f"port {primary.port}: {primary.notes}"

    return IPResult(
        ip=ip,
        status=primary.status,
        open_ports=open_ports,
        server_header=primary.server_header,
        detected_version=primary.detected_version,
        backend=backend,
        notes=notes,
    )


async def _apply_deep_lift(
    client: httpx.AsyncClient,
    result: IPResult,
    primary_port: int,
    rule: CVERule,
) -> IPResult:
    """
    Run the deep-lift pass on an unknown_version IPResult.

    If the 404-body probe returns a parseable version, re-grade the row
    (status, version, notes update). If the TLS cert reveals a vendor and
    the backend was previously 'unknown', upgrade the backend label too.
    Either way, the lift attempt is recorded in the notes for transparency.
    """
    lift = await deep_lift_ip(client, result.ip, primary_port, result.open_ports)

    new_version_str = result.detected_version
    new_status = result.status
    new_backend = result.backend
    extra_notes = list(lift.source_notes)

    if lift.version:
        new_version_str = _v(lift.version)
        verdict = evaluate(rule, lift.version)
        new_status = verdict
        if verdict == "vulnerable":
            extra_notes.append(
                f"version {new_version_str} is in affected range "
                f"[{_v(rule.introduced)} – {_v(rule.fixed)})"
            )
        elif verdict == "safe":
            extra_notes.append(
                f"version {new_version_str} is at or above fixed {_v(rule.fixed)}"
            )

    if lift.vendor and _backend_is_vague(result.backend):
        # Cert-derived vendor wins over generic labels like "unknown" or
        # "default/rocky-test-page". Note the displaced label so it isn't lost.
        if result.backend != "unknown":
            extra_notes.append(f"also serves {result.backend} on another port")
        new_backend = lift.vendor

    if not extra_notes:
        extra_notes.append("deep probe found no additional info")

    sep = " | " if result.notes else ""
    new_notes = f"{result.notes}{sep}{'; '.join(extra_notes)}"

    return IPResult(
        ip=result.ip,
        status=new_status,
        open_ports=result.open_ports,
        server_header=result.server_header,
        detected_version=new_version_str,
        backend=new_backend,
        notes=new_notes,
    )


def _backend_is_vague(backend: str) -> bool:
    """True if the backend label is generic enough that a TLS-cert vendor hit
    would meaningfully improve it."""
    return backend == "unknown" or backend.startswith("default/")


async def scan_ip(
    client: httpx.AsyncClient, ip: str, ports: list[int], rule: CVERule
) -> IPResult | None:
    probes = await asyncio.gather(*[probe_port(client, ip, p, rule) for p in ports])
    result = aggregate_ip(ip, list(probes))
    if result is None:
        return None

    has_https = any(p in (443, 8443) for p in result.open_ports)
    needs_version_lift = result.status == "unknown_version"
    needs_vendor_lift = _backend_is_vague(result.backend) and has_https

    if not (needs_version_lift or needs_vendor_lift):
        return result

    # Pick a port for the 404 probe. Prefer the port that actually answered as
    # nginx-but-no-version (so the body comes from the same vhost); otherwise
    # the most severe primary port.
    primary_port = next(
        (p.port for p in probes if p.status == "unknown_version"),
        next(
            (p.port for p in probes if p.status == result.status),
            result.open_ports[0],
        ),
    )
    return await _apply_deep_lift(client, result, primary_port, rule)


async def run_scan_stream(
    cve_id: str, ip_range: str, ports_raw: str, workers: int = 16
) -> AsyncIterator[dict]:
    rule = get_rule(cve_id)
    if rule is None:
        yield {"type": "error",
               "message": f"Unknown CVE '{cve_id}'. No detection rule registered."}
        return

    try:
        ports = parse_ports(ports_raw)
        ips = expand_ips(ip_range)
    except ValueError as e:
        yield {"type": "error", "message": str(e)}
        return

    if not ips:
        yield {"type": "error", "message": "No IPs to scan."}
        return

    if len(ips) * len(ports) > MAX_TARGETS:
        yield {
            "type": "error",
            "message": (
                f"Target set too large ({len(ips)} IPs × {len(ports)} ports = "
                f"{len(ips) * len(ports)} probes > cap of {MAX_TARGETS}). "
                "Narrow the range or reduce ports."
            ),
        }
        return

    summary = ScanSummary(cve_id=rule.cve_id, total_ips=len(ips))
    yield {
        "type": "status",
        "message": (
            f"Scanning {len(ips)} IP(s) × {len(ports)} port(s) "
            f"for {rule.cve_id}…"
        ),
    }

    sem = asyncio.Semaphore(max(1, min(workers, MAX_WORKERS)))
    started = time.monotonic()
    timeout = httpx.Timeout(DEFAULT_READ_TIMEOUT_S, connect=DEFAULT_CONNECT_TIMEOUT_S)

    async with httpx.AsyncClient(
        verify=False,
        timeout=timeout,
        follow_redirects=False,
        headers={"User-Agent": "ai-assist-tool/custom-report"},
    ) as client:
        async def run(ip: str) -> tuple[str, IPResult | None]:
            async with sem:
                try:
                    return ip, await scan_ip(client, ip, ports, rule)
                except Exception as e:
                    Logger.error(
                        "custom_report.scan_ip_failed",
                        extra={"error": str(e), "ip": ip},
                    )
                    return ip, None

        tasks = [asyncio.create_task(run(ip)) for ip in ips]
        checked = 0
        for fut in asyncio.as_completed(tasks):
            ip, ip_result = await fut
            checked += 1
            if ip_result is None:
                summary.unreachable += 1
                yield {
                    "type": "progress",
                    "checked": checked,
                    "total": summary.total_ips,
                    "alive": summary.alive(),
                    "unreachable": summary.unreachable,
                }
            else:
                summary.update(ip_result)
                yield {
                    "type": "result",
                    "result": ip_result.to_dict(),
                    "checked": checked,
                    "total": summary.total_ips,
                    "alive": summary.alive(),
                    "unreachable": summary.unreachable,
                }

    summary.duration_s = time.monotonic() - started
    yield {"type": "complete", "summary": summary.to_dict()}
