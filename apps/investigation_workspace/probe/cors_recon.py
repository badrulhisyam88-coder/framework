"""CORS posture probe — Recon phase.

Bootstrap-wired. Sends one OPTIONS request with a cross-origin header to
detect permissive CORS misconfigurations on the target root.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlparse

import httpx

from apps.investigation_workspace.probe.events import FindingEvent, StageEvent
from apps.investigation_workspace.probe.finding_id import generate_finding_id

_ATTACKER_ORIGIN = "https://attacker.example"
_PROBE_ID        = "cors_recon"


async def run_cors_probe(
    target: str,
    *,
    after_stage_index: int = 1,
) -> AsyncIterator[StageEvent | FindingEvent]:
    """Send a crafted OPTIONS request and evaluate CORS response headers."""
    parsed    = urlparse(target)
    root_path = parsed.path or "/"

    yield StageEvent(
        label   = "Probing CORS posture",
        actions = (
            f"OPTIONS {root_path}",
            f"Origin: {_ATTACKER_ORIGIN}",
            "Access-Control-Request-Method: GET",
            "Access-Control-Request-Headers: Authorization",
        ),
        tools      = ("httpx async client",),
        confidence = "—",
    )

    resp: httpx.Response | None = None
    try:
        async with httpx.AsyncClient(
            timeout          = 5.0,
            follow_redirects = True,
            verify           = False,
        ) as client:
            resp = await client.options(
                target,
                headers={
                    "Origin":                         _ATTACKER_ORIGIN,
                    "Access-Control-Request-Method":  "GET",
                    "Access-Control-Request-Headers": "Authorization",
                },
            )
    except Exception:
        pass

    finding: FindingEvent | None = None

    if resp is not None:
        headers_l = {k.lower(): v for k, v in resp.headers.items()}
        acao = headers_l.get("access-control-allow-origin", "")
        acac = headers_l.get("access-control-allow-credentials", "")
        acam = headers_l.get("access-control-allow-methods")
        acah = headers_l.get("access-control-allow-headers")

        severity:          str | None = None
        trigger_condition: str | None = None

        if acao == _ATTACKER_ORIGIN and acac.lower() == "true":
            severity          = "critical"
            trigger_condition = (
                "ACAO reflects attacker origin AND ACAC=true — "
                "enables cross-origin credentialed requests"
            )
        elif acao == "*" and acac.lower() == "true":
            severity          = "critical"
            trigger_condition = (
                "ACAO=* AND ACAC=true — invalid combo sometimes accepted by "
                "non-standard implementations"
            )
        elif acao.lower() == "null":
            severity          = "high"
            trigger_condition = (
                "ACAO=null — exploitable from sandboxed iframes or "
                "null-origin requests"
            )
        elif acao == "*":
            severity          = "low"
            trigger_condition = "ACAO=* (no credentials) — information only"

        if severity and trigger_condition:
            finding_type = "permissive_cors"
            finding = FindingEvent(
                after_stage_index = after_stage_index,
                finding_type      = finding_type,
                title             = f"Permissive CORS configuration ({severity})",
                severity          = severity,
                description       = (
                    f"The CORS policy is misconfigured. {trigger_condition}."
                ),
                endpoint          = root_path,
                evidence          = {
                    "access_control_allow_origin":      acao,
                    "access_control_allow_credentials": acac or None,
                    "access_control_allow_methods":     acam,
                    "access_control_allow_headers":     acah,
                    "trigger_condition":                trigger_condition,
                },
                phase             = "recon",
                id                = generate_finding_id(_PROBE_ID, target, root_path, finding_type),
                confidence        = "high",
                next_actions      = None,
            )

    yield StageEvent(
        label   = "CORS scan complete",
        actions = ("Evaluated Access-Control-* response headers",),
        tools      = ("httpx async client",),
        detected   = (
            (f"CORS misconfiguration: {finding.evidence['trigger_condition']}",)  # type: ignore[index]
            if finding else
            ("no CORS misconfiguration detected",)
        ),
        confidence = "high",
    )
    if finding:
        yield finding
