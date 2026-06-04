"""Framework fingerprinting probe — Recon phase.

Bootstrap-wired. Makes 3 GET requests: root, forced-404 (random UUID path),
forced-error (/%00). Collects signals from meta tags, cookies, asset paths,
HTML comments, and error pages. Emits findings for detected frameworks,
stack trace disclosures, and catch-all routing.
"""
from __future__ import annotations

import re
import uuid
from collections.abc import AsyncIterator
from urllib.parse import urlparse

import httpx

from apps.investigation_workspace.probe.events import FindingEvent, StageEvent
from apps.investigation_workspace.probe.finding_id import generate_finding_id

_META_GENERATOR = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_HTML_COMMENT = re.compile(
    r"<!--.*?(WordPress|Drupal|Joomla|Django|Rails|Express|Next\.js|"
    r"Flask|Laravel|Symfony|version\s*[:=]\s*[\d.]+).*?-->",
    re.IGNORECASE | re.DOTALL,
)

_COOKIE_FRAMEWORKS: dict[str, str] = {
    "jsessionid":        "Java",
    "phpsessid":         "PHP",
    "connect.sid":       "Express/Node.js",
    "laravel_session":   "Laravel",
    "ci_session":        "CodeIgniter",
    "_rails_session":    "Rails",
    "django":            "Django",
    "asp.net_sessionid": "ASP.NET",
}

_ASSET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"/wp-content/|/wp-includes/", re.IGNORECASE), "WordPress"),
    (re.compile(r"/sites/default/",             re.IGNORECASE), "Drupal"),
    (re.compile(r"/_next/",                     re.IGNORECASE), "Next.js"),
    (re.compile(r"/_nuxt/",                     re.IGNORECASE), "Nuxt"),
    (re.compile(r"/static/django/",             re.IGNORECASE), "Django"),
    (re.compile(r"/assets/rails/",              re.IGNORECASE), "Rails"),
]

_STACK_TRACE = re.compile(
    r"Traceback|at\s+\w+\(|\.java:|\.py:|error\.php:|"
    r"NullPointerException|undefined\s+method\s+`",
    re.IGNORECASE,
)

_PROBE_ID = "fingerprint_recon"


def _normalise_framework(raw: str) -> str:
    """Extract a clean framework name from a raw signal string."""
    for known in ("WordPress", "Drupal", "Joomla", "Django", "Rails",
                  "Express", "Next.js", "Flask", "Laravel", "Symfony"):
        if known.lower() in raw.lower():
            return known
    return raw.split()[0] if raw else raw


async def run_fingerprint_probe(
    target: str,
    *,
    after_stage_index: int = 1,
) -> AsyncIterator[StageEvent | FindingEvent]:
    """Fingerprint the target framework from root response, 404, and error signals."""
    parsed    = urlparse(target)
    base_url  = f"{parsed.scheme}://{parsed.netloc}"
    root_path = parsed.path or "/"
    fake_path = f"/{uuid.uuid4().hex}"

    yield StageEvent(
        label   = "Fingerprinting framework",
        actions = (
            f"GET {root_path} — collect meta tags, cookies, asset paths",
            f"GET {fake_path} — force 404 for error page fingerprint",
            "GET /%00 — attempt forced error response",
        ),
        tools      = ("httpx async client", "framework signal analyzer"),
        confidence = "—",
    )

    root_resp: httpx.Response | None = None
    resp_404:  httpx.Response | None = None
    resp_err:  httpx.Response | None = None

    async with httpx.AsyncClient(
        timeout          = 5.0,
        follow_redirects = True,
        verify           = False,
    ) as client:
        try:
            root_resp = await client.get(target)
        except Exception:
            pass

        try:
            resp_404 = await client.get(base_url + fake_path)
        except Exception:
            pass

        try:
            resp_err = await client.get(base_url + "/%00")
        except Exception:
            pass

    collected: list[FindingEvent] = []

    # ── Framework signal collection ───────────────────────────────────────
    if root_resp is not None:
        body             = root_resp.text
        framework_votes: dict[str, list[str]] = {}

        m = _META_GENERATOR.search(body)
        if m:
            gen_val = m.group(1)
            fw      = _normalise_framework(gen_val)
            framework_votes.setdefault(fw, []).append(f"meta generator: {gen_val}")

        for cm in _HTML_COMMENT.finditer(body):
            fw_hint = cm.group(1)
            fw      = _normalise_framework(fw_hint)
            snippet = cm.group(0)[:80]
            framework_votes.setdefault(fw, []).append(f"HTML comment: {snippet}")

        for cookie_name in root_resp.cookies:
            fw = _COOKIE_FRAMEWORKS.get(cookie_name.lower())
            if fw:
                framework_votes.setdefault(fw, []).append(f"cookie: {cookie_name}")

        for pattern, fw in _ASSET_PATTERNS:
            if pattern.search(body):
                framework_votes.setdefault(fw, []).append(
                    f"asset path matches {pattern.pattern}"
                )

        for fw, signals in framework_votes.items():
            if not signals:
                continue
            sig_count    = len(signals)
            confidence   = "high" if sig_count >= 2 else "medium"
            finding_type = "framework_fingerprinted"
            collected.append(FindingEvent(
                after_stage_index = after_stage_index,
                finding_type      = finding_type,
                title             = f"Framework identified: {fw}",
                severity          = "info",
                description       = (
                    f"Target shows {sig_count} corroborating signal(s) for {fw}. "
                    f"Enumeration probes can target framework-specific paths."
                ),
                endpoint          = root_path,
                evidence          = {
                    "framework":    fw,
                    "signals":      signals,
                    "signal_count": sig_count,
                },
                phase             = "recon",
                id                = generate_finding_id(
                    _PROBE_ID, target, root_path, f"{finding_type}_{fw}"
                ),
                confidence        = confidence,
                next_actions      = None,
            ))

    # ── Stack trace / error page analysis ────────────────────────────────
    for suffix, error_resp, trigger_path in (
        ("404", resp_404, fake_path),
        ("error", resp_err, "/%00"),
    ):
        if error_resp is None:
            continue
        body = error_resp.text
        if _STACK_TRACE.search(body):
            finding_type = "stack_trace_leaked"
            collected.append(FindingEvent(
                after_stage_index = after_stage_index,
                finding_type      = finding_type,
                title             = f"Stack trace disclosed in {suffix} response",
                severity          = "medium",
                description       = (
                    f"The server returned a stack trace in its {suffix} response, "
                    f"leaking internal paths or framework details."
                ),
                endpoint          = trigger_path,
                evidence          = {
                    "trigger_path": trigger_path,
                    "status_code":  error_resp.status_code,
                    "stack_sample": body[:500],
                },
                phase             = "recon",
                id                = generate_finding_id(
                    _PROBE_ID, target, trigger_path, finding_type
                ),
                confidence        = "high",
                next_actions      = None,
            ))

    # ── Custom 404 / catch-all routing detection ──────────────────────────
    if resp_404 is not None and resp_404.status_code == 200:
        finding_type = "custom_404_handler"
        collected.append(FindingEvent(
            after_stage_index = after_stage_index,
            finding_type      = finding_type,
            title             = "Custom 404 handler detected (catch-all routing)",
            severity          = "info",
            description       = (
                "A request to a random non-existent path returned HTTP 200. "
                "Directory brute-forcing must compare responses against this "
                "baseline to avoid false positives."
            ),
            endpoint          = fake_path,
            evidence          = {
                "trigger_path":    fake_path,
                "status_code":     resp_404.status_code,
                "body_bytes":      len(resp_404.content),
                "body_fingerprint": resp_404.text[:200],
            },
            phase             = "recon",
            id                = generate_finding_id(_PROBE_ID, target, fake_path, finding_type),
            confidence        = "high",
            next_actions      = [{
                "probe_id":        "run_endpoint_enum",
                "trigger":         "auto_fire",
                "description":     (
                    "Custom 404 handler detected — endpoint enumeration must use "
                    "baseline detection to avoid false positives"
                ),
                "required_inputs": [],
                "produces":        "endpoint_inventory",
            }],
        ))

    total = len(collected)
    yield StageEvent(
        label   = "Framework fingerprint complete",
        actions = (
            "Analysed meta tags, cookies, and asset paths from root response",
            "Inspected error responses for stack traces and custom handlers",
        ),
        tools      = ("framework signal analyzer",),
        detected   = (
            (f"{total} fingerprint finding(s) recorded",)
            if total else
            ("no framework signals detected",)
        ),
        confidence = "high",
    )
    for fe in collected:
        yield fe
