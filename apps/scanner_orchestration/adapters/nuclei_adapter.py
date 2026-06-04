"""Nuclei adapter — thin subprocess wrapper for nuclei v3.

Module-level run_scan() is the primary API. Adapter has no opinion on
template scope or severity defaults — those belong at the engine layer
where operator gates feed in.

NucleiAdapter class is retained for backward compat with dormant
scanner_orchestration consumers (orchestration_service, api/routes).
New code should call run_scan() directly.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

_BINARY = "nuclei"


async def run_scan(
    target: str,
    config: dict,
    timeout_seconds: int = 300,
) -> dict:
    """Run nuclei v3 against *target*.

    config keys:
      severity   : list[str]  REQUIRED — severities to scan (info, low,
                              medium, high, critical). Raises ValueError
                              if absent or empty. Omitted from CLI when
                              templates is non-empty (templates carry their
                              own severity metadata).
      templates  : list[str]  OPTIONAL — specific -t template paths.
                              If absent nuclei uses its built-in defaults.
      tags       : list[str]  OPTIONAL — nuclei -tags filter.
      extra_args : list[str]  OPTIONAL — additional raw CLI flags.

    Returns:
      findings : list[dict]  — parsed nuclei findings (one per JSONL line)
      status   : str         — "success" | "failed" | "timeout"
      error    : str | None  — description if status != "success"
      command  : list[str]   — command that was invoked (for debug logging)
    """
    severity: list[str] = config.get("severity") or []
    if not severity:
        raise ValueError("nuclei adapter requires a non-empty 'severity' list in config")

    templates: list[str] = config.get("templates") or []
    tags: list[str] = config.get("tags") or []
    extra_args: list[str] = config.get("extra_args") or []

    binary = shutil.which(_BINARY) or _BINARY

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        out_path = Path(f.name)

    try:
        cmd: list[str] = [binary, "-u", target, "-jsonl-export", str(out_path), "-silent"]
        # When specific templates are requested, omit -severity — templates carry
        # their own severity metadata and -severity would over-filter results.
        if templates:
            for tmpl in templates:
                cmd.extend(["-t", tmpl])
        else:
            cmd.extend(["-severity", ",".join(severity)])
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        cmd.extend(extra_args)

        logger.info("nuclei: invoking %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            _, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=float(timeout_seconds),
            )
        except TimeoutError:
            proc.terminate()
            await proc.wait()
            logger.warning(
                "nuclei: timeout after %ds for %s", timeout_seconds, target
            )
            return {
                "findings": [],
                "status": "timeout",
                "error": f"nuclei exceeded {timeout_seconds}s timeout",
                "command": cmd,
            }

        if proc.returncode != 0:
            error_msg = (stderr or b"").decode("utf-8", errors="replace")[:500]
            logger.warning(
                "nuclei: exit %d for %s: %s", proc.returncode, target, error_msg
            )
            return {
                "findings": [],
                "status": "failed",
                "error": f"nuclei exited {proc.returncode}: {error_msg}",
                "command": cmd,
            }

        findings = _parse_jsonl(out_path)
        logger.info("nuclei: %d findings for %s", len(findings), target)
        return {
            "findings": findings,
            "status": "success",
            "error": None,
            "command": cmd,
        }

    finally:
        try:
            out_path.unlink()
        except OSError:
            pass


def _parse_jsonl(path: Path) -> list[dict]:
    """Parse nuclei JSONL output. One JSON object per non-empty line."""
    findings: list[dict] = []
    try:
        with path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    logger.warning("nuclei: skipping malformed line: %s", exc)
    except FileNotFoundError:
        logger.warning("nuclei: output file not found at %s", path)
    return findings


class NucleiAdapter:
    """Backward-compatible adapter class.

    Delegates to the module-level run_scan(). Kept because dormant
    scanner_orchestration consumers (orchestration_service, api/routes)
    reference NucleiAdapter by class name.
    """

    scanner_type = "nuclei"

    async def check_available(self) -> bool:
        return shutil.which(_BINARY) is not None

    async def run_scan(self, ctx, config: dict) -> dict:
        """Legacy interface — translates old-style args and delegates to run_scan().

        Returns old-format dict ({results: [...], target: ...}) for
        backward compat with scanner_orchestration consumers.
        """
        try:
            from apps.scanner_orchestration.target_resolution.models import TargetContext
            target = ctx.scanner_url if isinstance(ctx, TargetContext) else str(ctx)
        except Exception:
            target = str(ctx)

        severity: list[str] = config.get("severity") or ["critical", "high", "medium"]
        timeout = int(config.get("timeout_seconds", 300))
        templates: list[str] = config.get("templates") or []

        adapter_config: dict = {"severity": severity}
        if templates:
            adapter_config["templates"] = templates

        result = await run_scan(
            target=target,
            config=adapter_config,
            timeout_seconds=timeout,
        )

        if result["status"] == "success":
            return {"results": result["findings"], "target": target}
        return {
            "results": [],
            "target": target,
            "skipped": True,
            "reason": result.get("error") or "nuclei subprocess failed",
        }
