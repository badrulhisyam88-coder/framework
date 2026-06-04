"""
Nmap adapter.

Responsibilities:
- Execute nmap with correct arguments
- Parse XML output into structured Host/Service models
- Never store raw output — return parsed models only

Does NOT:
- Decide what to scan (that's the service layer)
- Store results (that's the repository layer)
- Correlate findings (that's the correlator)
"""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import tempfile
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from xml.etree import ElementTree

from apps.validation.config import clamp_workers
from apps.validation.models import Host, Service, ServiceProtocol
from sdk import Logger

# Matches "(N up)" or "(N host up)" inside nmap --stats-every / Ping Scan lines
_HOSTS_UP_RE = re.compile(r"\((\d+)\s+(?:host\s+)?up\)")
# Matches "Discovered open port ..." lines — count opens as progress
_DISCOVERED_RE = re.compile(r"^Discovered open port")


SCAN_PROFILES = {
    "quick": "-sV --version-intensity 3 -T4 -F",
    "full": "-sV --version-intensity 5 -T4 -p-",
    "custom": "",  # args passed directly
}


@dataclass
class NmapScanResult:
    hosts: list[Host]
    services: list[Service]          # flat list, host_id populated
    duration_ms: int
    raw_command: str


class NmapAdapter:
    """
    Execute nmap and return parsed results.

    Usage:
        adapter = NmapAdapter()
        result = await adapter.scan("192.168.1.0/24", scan_type="quick")
    """

    async def scan(
        self,
        target: str,
        scan_type: str = "quick",
        custom_args: str | None = None,
        timeout: int = 300,
        workers: int = 4,
    ) -> NmapScanResult:
        """
        Run nmap against target. Returns parsed hosts and services.

        Args:
            target: IP, CIDR, hostname, or range
            scan_type: quick / full / custom
            custom_args: used only when scan_type=custom
            timeout: seconds before aborting
            workers: nmap internal parallelism (1..32)
        """
        if scan_type == "custom" and custom_args:
            profile_args = custom_args
        else:
            profile_args = SCAN_PROFILES.get(scan_type, SCAN_PROFILES["quick"])

        parallel_args = _parallelism_flags(workers)
        command = f"nmap {parallel_args} {profile_args} -oX - {shlex.quote(target)}"
        Logger.info("nmap.scan.start", extra={"command": command, "target": target})

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            Logger.error("nmap.scan.timeout", extra={"target": target, "timeout": timeout})
            raise RuntimeError(f"Nmap scan timed out after {timeout}s")

        duration_ms = int((time.monotonic() - start) * 1000)

        if proc.returncode != 0:
            error = stderr.decode(errors="replace")
            Logger.error("nmap.scan.failed", extra={"stderr": error[:500]})
            raise RuntimeError(f"Nmap failed: {error[:200]}")

        xml_output = stdout.decode(errors="replace")
        hosts, services = _parse_nmap_xml(xml_output)

        Logger.info(
            "nmap.scan.complete",
            extra={
                "target": target,
                "hosts": len(hosts),
                "services": len(services),
                "duration_ms": duration_ms,
            },
        )

        return NmapScanResult(
            hosts=hosts,
            services=services,
            duration_ms=duration_ms,
            raw_command=command,
        )

    async def scan_stream(
        self,
        target: str,
        scan_type: str = "quick",
        custom_args: str | None = None,
        timeout: int = 1800,
        workers: int = 4,
    ) -> AsyncIterator[dict]:
        """
        Streaming variant of scan().

        Runs nmap with --stats-every 5s -v and XML written to a temp file
        so nmap's human-readable progress (including periodic "Stats:" lines
        and "Discovered open port ..." lines) is emitted on stdout where
        we can stream it line-by-line.

        Yields:
            {"type": "progress", "message": str, "hosts_up": int | None}
            {"type": "result",   "result": NmapScanResult}
        """
        if scan_type == "custom" and custom_args:
            profile_args = custom_args
        else:
            profile_args = SCAN_PROFILES.get(scan_type, SCAN_PROFILES["quick"])

        parallel_args = _parallelism_flags(workers)

        fd, xml_path = tempfile.mkstemp(prefix="nmap-stream-", suffix=".xml")
        os.close(fd)

        command = (
            f"nmap -v --stats-every 5s {parallel_args} {profile_args} "
            f"-oX {shlex.quote(xml_path)} {shlex.quote(target)}"
        )
        Logger.info("nmap.scan.start", extra={"command": command, "target": target, "stream": True})

        start = time.monotonic()
        hosts_up_seen = 0
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stderr_chunks: list[bytes] = []

            async def _drain_stderr() -> None:
                assert proc.stderr is not None
                while True:
                    chunk = await proc.stderr.read(4096)
                    if not chunk:
                        break
                    stderr_chunks.append(chunk)

            stderr_task = asyncio.create_task(_drain_stderr())

            try:
                async with asyncio.timeout(timeout):
                    assert proc.stdout is not None
                    while True:
                        line = await proc.stdout.readline()
                        if not line:
                            break
                        text = line.decode(errors="replace").rstrip()
                        if not text:
                            continue
                        m = _HOSTS_UP_RE.search(text)
                        if m:
                            hosts_up_seen = max(hosts_up_seen, int(m.group(1)))
                        elif _DISCOVERED_RE.match(text) and hosts_up_seen == 0:
                            hosts_up_seen = 1
                        yield {
                            "type": "progress",
                            "message": text,
                            "hosts_up": hosts_up_seen,
                        }

                    await stderr_task
                    await proc.wait()
            except TimeoutError:
                proc.kill()
                await proc.wait()
                Logger.error("nmap.scan.timeout", extra={"target": target, "timeout": timeout})
                raise RuntimeError(f"Nmap scan timed out after {timeout}s")

            duration_ms = int((time.monotonic() - start) * 1000)

            if proc.returncode != 0:
                err = b"".join(stderr_chunks).decode(errors="replace")[:500]
                Logger.error("nmap.scan.failed", extra={"returncode": proc.returncode, "stderr": err})
                raise RuntimeError(f"Nmap failed (rc={proc.returncode}): {err[:200]}")

            with open(xml_path, encoding="utf-8", errors="replace") as f:
                xml_output = f.read()
            hosts, services = _parse_nmap_xml(xml_output)

            Logger.info(
                "nmap.scan.complete",
                extra={
                    "target": target,
                    "hosts": len(hosts),
                    "services": len(services),
                    "duration_ms": duration_ms,
                    "stream": True,
                },
            )

            yield {
                "type": "result",
                "result": NmapScanResult(
                    hosts=hosts,
                    services=services,
                    duration_ms=duration_ms,
                    raw_command=command,
                ),
            }
        finally:
            try:
                os.unlink(xml_path)
            except FileNotFoundError:
                pass


def _parallelism_flags(workers: int) -> str:
    """Build nmap --min-parallelism / --max-parallelism flags from worker count."""
    n = clamp_workers(workers)
    return f"--min-parallelism={n} --max-parallelism={n}"


def _parse_nmap_xml(xml: str) -> tuple[list[Host], list[Service]]:
    """
    Parse nmap XML output into Host and Service models.
    Only returns hosts that are UP.
    """
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError as e:
        raise RuntimeError(f"Failed to parse nmap XML: {e}") from e

    hosts: list[Host] = []
    services: list[Service] = []

    for host_el in root.findall("host"):
        # Only process hosts that are up
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        ip = _extract_ip(host_el)
        if not ip:
            continue

        hostname = _extract_hostname(host_el)
        os_guess = _extract_os_guess(host_el)

        host = Host(ip=ip, hostname=hostname, os_guess=os_guess)
        hosts.append(host)

        for port_el in host_el.findall("ports/port"):
            port_state = port_el.find("state")
            if port_state is None or port_state.get("state") != "open":
                continue

            port_num = int(port_el.get("portid", 0))
            protocol = port_el.get("protocol", "tcp")

            service_el = port_el.find("service")
            service_name = None
            product = None
            version = None
            banner = None

            if service_el is not None:
                service_name = service_el.get("name")
                product = service_el.get("product")
                version = service_el.get("version")
                extra = service_el.get("extrainfo", "")
                tunnel = service_el.get("tunnel", "")

                # Build banner from available info
                parts = [p for p in [product, version, extra] if p]
                banner = " ".join(parts) if parts else None

                # Handle SSL/TLS tunneled services
                if tunnel == "ssl":
                    service_name = f"ssl/{service_name}" if service_name else "ssl"

            service = Service(
                host_id=host.id,
                port=port_num,
                protocol=ServiceProtocol(protocol) if protocol in ("tcp", "udp") else ServiceProtocol.TCP,
                service_name=service_name,
                product=product,
                version=version,
                banner=banner,
            )
            services.append(service)

    return hosts, services


def _extract_ip(host_el: ElementTree.Element) -> str | None:
    for addr in host_el.findall("address"):
        if addr.get("addrtype") == "ipv4":
            return addr.get("addr")
    for addr in host_el.findall("address"):
        if addr.get("addrtype") == "ipv6":
            return addr.get("addr")
    return None


def _extract_hostname(host_el: ElementTree.Element) -> str | None:
    hostnames = host_el.find("hostnames")
    if hostnames is not None:
        for hn in hostnames.findall("hostname"):
            if hn.get("type") == "PTR":
                return hn.get("name")
        for hn in hostnames.findall("hostname"):
            return hn.get("name")
    return None


def _extract_os_guess(host_el: ElementTree.Element) -> str | None:
    os_el = host_el.find("os")
    if os_el is None:
        return None
    best = None
    best_accuracy = 0
    for osmatch in os_el.findall("osmatch"):
        accuracy = int(osmatch.get("accuracy", 0))
        if accuracy > best_accuracy:
            best_accuracy = accuracy
            best = osmatch.get("name")
    return best
