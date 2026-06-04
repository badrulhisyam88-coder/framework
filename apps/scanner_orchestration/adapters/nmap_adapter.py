"""Nmap adapter — wraps the existing NmapAdapter from validation module."""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from typing import Any
from xml.etree import ElementTree

from sdk import Logger


class NmapAdapter:
    scanner_type = "nmap"

    async def check_available(self) -> bool:
        return shutil.which("nmap") is not None

    async def run_scan(
        self,
        ctx: Any,  # TargetContext — avoids hard import at module level
        config: dict[str, Any],
    ) -> dict[str, Any]:
        from apps.scanner_orchestration.target_resolution.models import TargetContext

        # Use the resolved hostname (not the full URL) — nmap doesn't accept http:// URLs
        target = ctx.scanner_host if isinstance(ctx, TargetContext) else str(ctx)
        display = ctx.display_url if isinstance(ctx, TargetContext) else target

        args_str = config.get("args", "-sV -T4 -F")
        timeout = int(config.get("timeout_seconds", 300))

        if not await self.check_available():
            from apps.scanner_orchestration.adapters.base import ScannerUnavailable
            raise ScannerUnavailable("nmap is not installed or not on PATH")

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        try:
            cmd = f"nmap {args_str} -oX {xml_path} {target}"
            Logger.info(
                "nmap.scan_start",
                extra={"display": display, "resolved": target, "cmd": cmd},
            )
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except TimeoutError:
                proc.kill()
                await proc.communicate()
                raise TimeoutError(f"nmap scan timed out after {timeout}s") from None

            if proc.returncode not in (0, 1):
                raise RuntimeError(
                    f"nmap exited {proc.returncode}: {stderr.decode()[:500]}"
                )

            raw = _parse_nmap_xml(xml_path, target)
            Logger.info(
                "nmap.scan_complete",
                extra={
                    "display": display,
                    "resolved": target,
                    "hosts_found": len(raw.get("hosts", [])),
                },
            )
            return raw
        finally:
            try:
                os.unlink(xml_path)
            except OSError:
                pass


def _parse_nmap_xml(xml_path: str, target: str) -> dict[str, Any]:
    """Parse nmap XML output into a normalizer-friendly dict."""
    hosts: list[dict] = []
    try:
        tree = ElementTree.parse(xml_path)
        root = tree.getroot()
    except (ElementTree.ParseError, FileNotFoundError):
        return {"hosts": [], "target": target, "error": "xml_parse_failed"}

    for host_el in root.findall("host"):
        # Status
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        # IP
        ip = ""
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == "ipv4":
                ip = addr_el.get("addr", target)
                break
        if not ip:
            ip = target

        # Hostname
        hostnames_el = host_el.find("hostnames")
        hostname = ""
        if hostnames_el is not None:
            hn_el = hostnames_el.find("hostname")
            if hn_el is not None:
                hostname = hn_el.get("name", "")

        # Services
        services: list[dict] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                svc: dict[str, Any] = {
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                    "service_name": (
                        service_el.get("name", "") if service_el is not None else ""
                    ),
                    "product": (
                        service_el.get("product", "") if service_el is not None else ""
                    ),
                    "version": (
                        service_el.get("version", "") if service_el is not None else ""
                    ),
                    "banner": (
                        service_el.get("extrainfo", "") if service_el is not None else ""
                    ),
                }
                # NSE scripts for this port
                scripts: list[dict] = []
                for script_el in port_el.findall("script"):
                    scripts.append({
                        "id": script_el.get("id", ""),
                        "output": script_el.get("output", ""),
                    })
                svc["scripts"] = scripts
                services.append(svc)

        # Host-level scripts
        host_scripts: list[dict] = []
        hostscript_el = host_el.find("hostscript")
        if hostscript_el is not None:
            for script_el in hostscript_el.findall("script"):
                host_scripts.append({
                    "id": script_el.get("id", ""),
                    "output": script_el.get("output", ""),
                })

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "services": services,
            "scripts": host_scripts,
        })

    return {"hosts": hosts, "target": target}
