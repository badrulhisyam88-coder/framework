"""Metasploit RPC client wrapper.

This module is the ONLY entry point for talking to msfrpcd. Nothing else
in the codebase imports it. The scanner / correlator / executor / queue do
not — and will not — call into here. Every invocation originates from an
explicit user action on the Metasploit page.

Lifecycle: a single MsfClient is held per-process and reconnected lazily
if the underlying TCP connection drops. msfrpcd inside the metasploit
container takes ~30-60s on cold start (loads all modules into memory).
"""
from __future__ import annotations

import asyncio
import os
import re
import time
from typing import Any

from sdk import Logger

_CVE_RE = re.compile(r"(?i)^\s*cve[-_ ]?(\d{4}-\d+)\s*$")


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


class MsfNotConfigured(RuntimeError):
    pass


class MsfNotReachable(RuntimeError):
    pass


class MsfClient:
    """Thin async-friendly wrapper around pymetasploit3.

    pymetasploit3 is synchronous (blocking HTTP under the hood) so all
    calls go through `asyncio.to_thread` to avoid stalling the event loop.
    """

    def __init__(self) -> None:
        self._client = None
        self._lock = asyncio.Lock()

    @property
    def host(self) -> str:
        return os.environ.get("MSF_RPC_HOST", "metasploit")

    @property
    def port(self) -> int:
        return int(os.environ.get("MSF_RPC_PORT", "55553"))

    @property
    def user(self) -> str:
        return os.environ.get("MSF_RPC_USER", "msf")

    @property
    def password(self) -> str | None:
        return os.environ.get("MSF_RPC_PASSWORD")

    @property
    def ssl(self) -> bool:
        return _truthy(os.environ.get("MSF_RPC_SSL"))

    async def _connect(self):
        """Establish (or reuse) the pymetasploit3 client. Returns the client.
        Raises MsfNotReachable on failure.
        """
        if not self.password:
            raise MsfNotConfigured(
                "MSF_RPC_PASSWORD is not set — Metasploit RPC is disabled."
            )

        async with self._lock:
            if self._client is not None:
                return self._client
            try:
                from pymetasploit3.msfrpc import MsfRpcClient
            except ImportError as e:
                raise MsfNotConfigured(
                    f"pymetasploit3 not installed: {e}"
                ) from e

            try:
                client = await asyncio.to_thread(
                    MsfRpcClient,
                    self.password,
                    server=self.host,
                    port=self.port,
                    username=self.user,
                    ssl=self.ssl,
                )
            except Exception as e:
                raise MsfNotReachable(
                    f"Could not connect to msfrpcd at {self.host}:{self.port}: {e}"
                ) from e

            self._client = client
            Logger.info(
                "msf.client.connected",
                extra={"host": self.host, "port": self.port},
            )
            return client

    def _drop(self) -> None:
        self._client = None

    async def status(self) -> dict[str, Any]:
        """Connectivity probe + server-info bundle used by the page header
        and the Server Info card. msfrpcd caches the module listings after
        first load so the len() calls are O(1) on subsequent probes.
        """
        try:
            client = await self._connect()

            def _gather() -> tuple[dict[str, Any], dict[str, int]]:
                v = client.core.version
                m = client.modules
                counts = {
                    "exploit": len(m.exploits),
                    "auxiliary": len(m.auxiliary),
                    "post": len(m.post),
                    "payload": len(m.payloads),
                    "encoder": len(m.encoders),
                    "nop": len(m.nops),
                }
                return v, counts

            version, module_counts = await asyncio.to_thread(_gather)
            return {
                "connected": True,
                "host": self.host,
                "port": self.port,
                "version": version.get("version") if isinstance(version, dict) else None,
                "ruby": version.get("ruby") if isinstance(version, dict) else None,
                "api": version.get("api") if isinstance(version, dict) else None,
                "module_counts": module_counts,
            }
        except (MsfNotConfigured, MsfNotReachable) as e:
            return {"connected": False, "host": self.host, "port": self.port, "error": str(e)}
        except Exception as e:  # noqa: BLE001 — surface the error verbatim
            self._drop()
            return {"connected": False, "host": self.host, "port": self.port, "error": str(e)}

    async def search(
        self,
        query: str,
        module_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Search modules via Metasploit's native `module.search` RPC.

        Query syntax matches msfconsole's `search` command and supports
        keyword filters:
            cve:2021-44228 — match by CVE id
            type:exploit   — restrict to a module type
            name:wordpress — match in module name
            path:smb       — match in module path
            description:rce
            platform:windows
            rank:excellent

        A bare CVE id like "CVE-2021-44228" is auto-rewritten to
        `cve:2021-44228` so users can paste IDs straight from findings.
        """
        client = await self._connect()
        msf_query = _build_msf_query(query, module_type)
        if not msf_query:
            return []

        def _do() -> list[dict[str, Any]]:
            try:
                raw = client.modules.search(msf_query)
            except Exception as e:  # noqa: BLE001
                Logger.error(
                    "msf.search.failed",
                    extra={"query": msf_query, "error": str(e)},
                )
                return []
            out: list[dict[str, Any]] = []
            for r in (raw or [])[:limit]:
                full = r.get("fullname") or ""
                mtype, _, path = full.partition("/")
                refs_raw = r.get("references") or []
                cves: list[str] = []
                other_refs: list[str] = []
                for ref in refs_raw:
                    if isinstance(ref, (list, tuple)) and len(ref) >= 2:
                        if str(ref[0]).upper() == "CVE":
                            cves.append(f"CVE-{ref[1]}")
                        else:
                            other_refs.append(f"{ref[0]}:{ref[1]}")
                    else:
                        other_refs.append(str(ref))
                out.append({
                    "type": r.get("type") or mtype,
                    "fullname": full,
                    "path": path or full,
                    "name": r.get("name") or "",
                    "rank": r.get("rank"),
                    "disclosure_date": r.get("disclosuredate") or "",
                    "cves": cves,
                    "other_refs": other_refs,
                })
            return out

        return await asyncio.to_thread(_do)

    async def module_info(self, module_type: str, module_path: str) -> dict[str, Any]:
        """Return the module's description, options, references, rank, etc."""
        client = await self._connect()

        def _do() -> dict[str, Any]:
            mod = client.modules.use(module_type, module_path)
            options: list[dict[str, Any]] = []
            for opt_name in (mod.options or []):
                spec = mod.optioninfo(opt_name) or {}
                options.append({
                    "name": opt_name,
                    "required": bool(spec.get("required")),
                    "advanced": bool(spec.get("advanced")),
                    "type": spec.get("type"),
                    "default": spec.get("default"),
                    "description": spec.get("desc"),
                    "current": mod[opt_name],
                })
            refs = []
            for r in (mod.references or []):
                if isinstance(r, (list, tuple)) and len(r) >= 2:
                    refs.append({"source": r[0], "value": r[1]})
                else:
                    refs.append({"value": str(r)})
            return {
                "path": module_path,
                "type": module_type,
                "name": mod.name,
                "description": (mod.description or "").strip(),
                "rank": getattr(mod, "rank", None),
                "references": refs,
                "options": options,
            }

        return await asyncio.to_thread(_do)

    async def run_via_console(
        self,
        module_type: str,
        module_path: str,
        options: dict[str, Any],
        mode: str = "run",
        timeout_s: int = 300,
    ) -> str:
        """Drive the module through an msfconsole session: `use`, `set OPT
        VAL`, then `run` (or `check`). Returns the full console output.

        Console-driven invocation captures output cleanly across module
        types and matches what an operator would type interactively. The
        alternative — `module.execute(**opts)` — returns immediately with
        a job_id and forces us to poll the job table for output, which is
        flakier for auxiliary scanners that complete in seconds.
        """
        client = await self._connect()

        def _do() -> str:
            console_id = client.consoles.console().cid
            try:
                console = client.consoles.console(console_id)
                # Drain banner output.
                _drain(console, total_timeout=5)

                cmds = [
                    f"use {module_type}/{module_path}",
                ]
                for k, v in (options or {}).items():
                    if v is None or v == "":
                        continue
                    cmds.append(f"set {k} {v}")
                cmds.append("check" if mode == "check" else "run")

                buffer: list[str] = []
                for cmd in cmds:
                    res = console.write(cmd + "\n")
                    if isinstance(res, dict) and res.get("error"):
                        buffer.append(f"[!] msfrpcd rejected `{cmd}`: {res.get('error_message')}\n")
                output = _drain(console, total_timeout=timeout_s)
                buffer.append(output)
                return "".join(buffer)
            finally:
                try:
                    client.consoles.destroy(console_id)
                except Exception:
                    pass

        try:
            return await asyncio.wait_for(
                asyncio.to_thread(_do),
                timeout=timeout_s + 30,
            )
        except asyncio.TimeoutError as e:
            raise TimeoutError(
                f"Module {module_path} did not finish within {timeout_s}s"
            ) from e


def _build_msf_query(query: str, module_type: str | None) -> str:
    """Translate the page's (query, type) inputs into a msfconsole-style
    search expression. See MsfClient.search for filter docs.
    """
    parts: list[str] = []
    q = (query or "").strip()
    if q:
        cve_match = _CVE_RE.match(q)
        if cve_match:
            parts.append(f"cve:{cve_match.group(1)}")
        else:
            parts.append(q)
    if module_type:
        parts.append(f"type:{module_type}")
    return " ".join(parts)


def _drain(console, total_timeout: int) -> str:
    """Block until the console becomes idle or the timeout elapses.
    Returns accumulated stdout.
    """
    start = time.monotonic()
    chunks: list[str] = []
    last_change = start
    while True:
        if time.monotonic() - start > total_timeout:
            chunks.append("\n[!] timeout — output truncated.\n")
            break
        try:
            res = console.read()
        except Exception as e:
            chunks.append(f"\n[!] console.read failed: {e}\n")
            break
        data = res.get("data") if isinstance(res, dict) else None
        busy = res.get("busy") if isinstance(res, dict) else False
        if data:
            chunks.append(data)
            last_change = time.monotonic()
        if not busy:
            # Give modules a brief grace period to flush trailing lines after
            # 'busy' flips false — otherwise we miss the last line or two.
            if time.monotonic() - last_change > 1.5:
                break
        time.sleep(0.4)
    return "".join(chunks)


# Process-wide singleton so reconnects are amortised.
_msf_client = MsfClient()


def get_msf_client() -> MsfClient:
    return _msf_client
