"""Artifact-bundle construction + in-memory registry.

A probe that successfully exploits a vulnerability hands off to this
module: pass the session state obtained during the exploit + a list
of follow-up endpoints, get back an ArtifactBundle ready to surface
as a Capture node on the graph.

The bundle always contains three "standard" artifacts at the top:
exploit_request.txt, exploit_response.txt, session.txt. Then one
artifact per requested endpoint (or a placeholder noting the
endpoint returned 404 / errored).

Heuristic limits to keep panels usable:
  • per-artifact content cap at 100 KB (truncate + marker)
  • per-endpoint timeout 5 s
"""
from __future__ import annotations

import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

_MAX_ARTIFACT_BYTES = 100_000
_PER_ENDPOINT_TIMEOUT = 5.0


def _esc_js(s: str) -> str:
    """Escape a string for safe embedding inside a JS single-quoted literal."""
    return (str(s).replace("\\", "\\\\").replace("'", "\\'")
                  .replace("\n", "\\n").replace("\r", "\\r"))


def _build_bookmarklet(session_state: dict) -> str | None:
    """Auto-generate an impersonation bookmarklet from captured session credentials.

    JWT (Authorization: Bearer …) → localStorage.setItem('token', …) — works for
    Juice Shop and any JWT-based API where the client stores the token in localStorage.

    Session cookies → document.cookie = … — works for non-httpOnly cookie sessions
    (PortSwigger labs, DVWA). The browser silently ignores httpOnly cookies set via JS.

    Returns None when neither credential type is present so the probe can still
    decide to skip the bookmarklet entirely by not providing session credentials.

    OPERATOR-ACCEPTED RISK: same affordance as the existing probe-supplied
    bookmarklet; see ArtifactBundle.bookmarklet_href field docstring and
    CLAUDE.md Accepted Risks for the full risk record.
    """
    headers = (session_state.get("headers") or {})
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        if token:
            safe = _esc_js(token)
            return (
                "javascript:(function(){"
                f"localStorage.setItem('token','{safe}');"
                "location.reload();"
                "})()"
            )

    cookies = session_state.get("cookies") or {}
    if cookies:
        stmts = "".join(
            f"document.cookie='{_esc_js(k)}={_esc_js(v)};path=/';"
            for k, v in cookies.items()
            if k and v
        )
        if stmts:
            return "javascript:(function(){" + stmts + "location.reload();})()"

    return None


@dataclass(frozen=True)
class Artifact:
    """One named file in an ArtifactBundle."""
    filename:    str
    content_type: str
    content:     str
    size_bytes:  int
    description: str


@dataclass
class ArtifactBundle:
    """A capture bundle — artifacts gathered after a successful exploit."""
    bundle_id:       str
    investigation_id: str
    finding_id:      str
    action_id:       str
    exploit_path_id: str
    created_at:      float
    label:           str
    artifacts:       list[Artifact] = field(default_factory=list)
    # Phase 59z — operator-accepted-risk affordance. When the probe
    # captured a session token AND knows the target's storage convention,
    # it builds a `javascript:` bookmarklet that, when clicked while the
    # operator is on the target tab, writes the token into localStorage
    # and reloads. None when the probe couldn't construct one.
    #
    # OPERATOR-ACCEPTED RISK: this affordance provides one-click
    # impersonation using captured session tokens. The operator has
    # explicitly accepted that:
    #   • the button operates against ANY target regardless of trust
    #     level (lab, staging, production, customer engagement),
    #   • accidental clicks result in unauthorized session use on
    #     whatever target was last exploited,
    #   • browser history records the launcher URL but not the
    #     impersonation,
    #   • the feature does not differentiate between lab and
    #     production contexts.
    # Acceptable for a personal dev/lab tool with a single operator.
    # If this tool is ever used in a multi-operator or non-lab
    # context, this feature should be reviewed and potentially gated.
    bookmarklet_href: str | None = None
    # The single most important value this capture produced — surfaced
    # prominently in the panel header so the operator sees it immediately.
    # Each probe populates this with its primary artifact value (e.g.
    # "admin:password", "root", "admin@juice-sh.op"). None → header omitted.
    captured_value: str | None = None


# ── In-memory registry (mirrors execution/runtime.py) ────────────────────
_BUNDLES: dict[str, ArtifactBundle]    = {}
_BY_INV:  dict[str, list[str]]         = {}


def get_bundle(bundle_id: str) -> ArtifactBundle | None:
    return _BUNDLES.get(bundle_id)


def bundles_for_investigation(investigation_id: str) -> list[ArtifactBundle]:
    ids = _BY_INV.get(investigation_id, [])
    return [_BUNDLES[i] for i in ids if i in _BUNDLES]


# ── Capture helper ──────────────────────────────────────────────────────


async def capture_post_exploit(
    *,
    investigation_id: str,
    finding_id:       str,
    action_id:        str,
    exploit_path_id:  str,
    session_state:    dict,
    target_base_url:  str,
    endpoints:        Iterable[str],
    exploit_request:  dict,
    exploit_response: dict,
    label:            str = "Post-exploit capture",
    reproduction_artifact: dict | None = None,
    bookmarklet_href: str | None = None,
    extra_artifacts:  list[dict] | None = None,
    captured_value:   str | None = None,
) -> ArtifactBundle:
    """Build + store an ArtifactBundle. Returns it.

    `session_state` shape:
        {"cookies": {...}, "headers": {...}}
        — both optional. Auth tokens belong in headers (Authorization).

    `exploit_request` / `exploit_response` shape:
        {"method": ..., "url": ..., "headers": ..., "body": ...}
        These are surfaced as the first two "standard" artifacts so
        the operator can see what triggered the capture without
        clicking back upstream.
    """
    # Auto-generate bookmarklet from session credentials when the probe
    # didn't supply one explicitly. JWT in Authorization header takes
    # priority (localStorage); cookie sessions fall back to document.cookie.
    if bookmarklet_href is None:
        bookmarklet_href = _build_bookmarklet(session_state)

    bundle = ArtifactBundle(
        bundle_id        = uuid.uuid4().hex[:12],
        investigation_id = investigation_id,
        finding_id       = finding_id,
        action_id        = action_id,
        exploit_path_id  = exploit_path_id,
        created_at       = time.time(),
        label            = label,
        bookmarklet_href = bookmarklet_href,
        captured_value   = captured_value,
    )

    # ── Standard top artifacts ──────────────────────────────────────────
    bundle.artifacts.append(_artifact_from_request(exploit_request))
    bundle.artifacts.append(_artifact_from_response(exploit_response))
    bundle.artifacts.append(_artifact_from_session(session_state))

    # ── Per-endpoint follow-up captures ─────────────────────────────────
    cookies = dict(session_state.get("cookies") or {})
    headers = dict(session_state.get("headers") or {})
    base = target_base_url.rstrip("/")

    async with httpx.AsyncClient(
        timeout         = _PER_ENDPOINT_TIMEOUT,
        follow_redirects = True,
        verify           = False,
    ) as client:
        for ep in endpoints:
            full_url = ep if ep.startswith(("http://", "https://")) \
                       else (base + ("" if ep.startswith("/") else "/") + ep)
            bundle.artifacts.append(
                await _capture_endpoint(client, full_url, ep, cookies, headers),
            )

    # Phase 57c — probe-supplied reproduction guide prepended so it
    # is the FIRST file in the bundle. Optional: bundles without one
    # render exactly as before (graceful no-op).
    if reproduction_artifact:
        text, n = _truncate(reproduction_artifact.get("content", ""))
        readme = Artifact(
            filename     = reproduction_artifact.get("filename",
                                                     "HOW_TO_REPRODUCE.md"),
            content_type = reproduction_artifact.get("content_type",
                                                     "text/markdown"),
            content      = text,
            size_bytes   = n,
            description  = reproduction_artifact.get(
                "description",
                "Operator-facing reproduction guide — start here",
            ),
        )
        bundle.artifacts.insert(0, readme)

    # Phase 60a — probe-supplied extra artifacts (e.g. whoami_output.txt,
    # id_output.txt, detected_separator.txt). Entries with empty content
    # are silently skipped so no hollow artifact files appear in the panel.
    if extra_artifacts:
        existing_names = {a.filename for a in bundle.artifacts}
        for ea in extra_artifacts:
            content = ea.get("content") or ""
            if not content:
                continue
            filename = ea["filename"]
            if filename in existing_names:
                raise ValueError(
                    f"extra_artifacts filename {filename!r} collides with an "
                    "existing bundle artifact — caller bug"
                )
            text, n = _truncate(content)
            bundle.artifacts.append(Artifact(
                filename     = filename,
                content_type = ea.get("mime_type") or "text/plain",
                content      = text,
                size_bytes   = n,
                description  = ea.get("description") or filename,
            ))
            existing_names.add(filename)

    _BUNDLES[bundle.bundle_id] = bundle
    _BY_INV.setdefault(investigation_id, []).append(bundle.bundle_id)
    return bundle


# ── Internal — artifact constructors ────────────────────────────────────


def _truncate(text: str) -> tuple[str, int]:
    """Cap content at _MAX_ARTIFACT_BYTES; return (capped_text, original_size)."""
    raw = text or ""
    n = len(raw.encode("utf-8", errors="replace"))
    if n <= _MAX_ARTIFACT_BYTES:
        return raw, n
    return (
        raw[:_MAX_ARTIFACT_BYTES] + f"\n\n…[truncated, original {n} bytes]",
        n,
    )


def _artifact_from_request(req: dict) -> Artifact:
    """Render the exploit request as a readable text artifact."""
    method  = req.get("method", "GET")
    url     = req.get("url", "")
    headers = req.get("headers") or {}
    body    = req.get("body") or ""
    if isinstance(body, dict):
        import json
        body = json.dumps(body, indent=2)
    lines = [f"{method} {url}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append("")
        lines.append(str(body))
    text, n = _truncate("\n".join(lines))
    return Artifact(
        filename     = "exploit_request.txt",
        content_type = "text/plain",
        content      = text,
        size_bytes   = n,
        description  = f"{method} {url} — request that triggered the exploit",
    )


def _artifact_from_response(resp: dict) -> Artifact:
    """Render the exploit response as a readable text artifact."""
    status  = resp.get("status", "?")
    headers = resp.get("headers") or {}
    body    = resp.get("body") or ""
    if isinstance(body, dict):
        import json
        body = json.dumps(body, indent=2)
    lines = [f"HTTP {status}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append("")
        lines.append(str(body))
    text, n = _truncate("\n".join(lines))
    return Artifact(
        filename     = "exploit_response.txt",
        content_type = "text/plain",
        content      = text,
        size_bytes   = n,
        description  = f"HTTP {status} — response confirming exploit success",
    )


def _artifact_from_session(session: dict) -> Artifact:
    """Render the captured session state (cookies + headers/tokens)."""
    import json
    text, n = _truncate(json.dumps(session, indent=2, default=str))
    cookie_count = len(session.get("cookies") or {})
    header_count = len(session.get("headers") or {})
    return Artifact(
        filename     = "session.txt",
        content_type = "application/json",
        content      = text,
        size_bytes   = n,
        description  = f"Captured session — {cookie_count} cookie(s), {header_count} header(s)",
    )


def _filename_from_endpoint(ep: str) -> str:
    """Derive a safe filename from a URL path: '/rest/user/whoami' →
    'rest_user_whoami_response.json'.
    """
    path = urlparse(ep).path or ep
    safe = "".join(c if c.isalnum() else "_" for c in path).strip("_")
    if not safe:
        safe = "root"
    return f"{safe}_response.json"


async def _capture_endpoint(
    client:  httpx.AsyncClient,
    url:     str,
    ep_path: str,
    cookies: dict,
    headers: dict,
) -> Artifact:
    """Fetch one post-exploit endpoint and wrap the response as an Artifact."""
    filename = _filename_from_endpoint(ep_path)
    try:
        resp = await client.get(url, cookies=cookies, headers=headers)
    except httpx.RequestError as e:
        return Artifact(
            filename     = filename,
            content_type = "text/plain",
            content      = f"endpoint fetch failed: {type(e).__name__}: {e!s}",
            size_bytes   = 0,
            description  = f"{ep_path} — network error",
        )

    ct = resp.headers.get("content-type", "application/octet-stream")
    ct_main = ct.split(";", 1)[0].strip().lower()

    if resp.status_code == 404:
        return Artifact(
            filename     = filename,
            content_type = "text/plain",
            content      = (
                f"endpoint returned 404 — not present on this target\n\n"
                f"URL: {url}\nstatus: {resp.status_code}"
            ),
            size_bytes   = 0,
            description  = f"{ep_path} — 404, endpoint absent",
        )

    text, n = _truncate(resp.text)

    if ct_main == "application/json":
        # Try to pretty-print JSON for readability.
        try:
            import json
            parsed = json.loads(resp.text)
            pretty, _ = _truncate(json.dumps(parsed, indent=2))
            text = pretty
            field_count = (len(parsed) if isinstance(parsed, (list, dict)) else 1)
            desc = f"JSON response — {field_count} top-level field(s)"
        except Exception:
            desc = f"JSON response — unparsable ({n} bytes)"
    elif ct_main.startswith("text/html"):
        desc = f"HTML page — {n} bytes"
    elif ct_main.startswith("text/"):
        desc = f"text response — {n} bytes"
    else:
        desc = f"{ct_main} response — {n} bytes"

    return Artifact(
        filename     = filename,
        content_type = ct_main,
        content      = text,
        size_bytes   = n,
        description  = f"{ep_path} — HTTP {resp.status_code}, {desc}",
    )
