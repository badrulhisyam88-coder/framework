"""HTTP method enumeration — probe each verb on discovered endpoints.

For each endpoint supplied:
1. Send OPTIONS — parse Allow header for declared methods.
2. Then send GET, POST, PUT, PATCH, DELETE in parallel.
3. Record (endpoint, method) pairs where status != 405.
4. Flag "unusual method" when a non-GET method returns 2xx or 3xx
   on an endpoint that looks like a resource (has path params or
   is known from spec).
5. For 400/422 responses (body validation): send an empty JSON body
   probe to extract field names from the error message. READ-SAFE —
   an empty body is rejected before any state mutation can occur.
   Build per-field action cards with the inferred schema.

Concurrency: asyncio.Semaphore(8) — 8 concurrent requests.
Body-shape probing: asyncio.Semaphore(3) — lower concurrency, read-safe.

Emits:
- StageEvent per endpoint batch
- ResultEvent with the method matrix: {endpoint: {method: status_code}}
- next_actions for each endpoint+method pair where method is non-GET
  and status is 2xx/401/403 (server accepted or would accept if authed)
- next_actions with inferred body fields for 400/422 pairs
"""
from __future__ import annotations

import asyncio
import json as _json
import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import AsyncIterator
from urllib.parse import urlparse

import httpx

from apps.investigation_workspace.probe.events import ResultEvent, StageEvent

# ── Constants ─────────────────────────────────────────────────────────────────

HTTP_VERBS: tuple[str, ...] = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")
# Verbs fired during read-only enumeration (OPTIONS is always probed separately)
HTTP_SAFE_VERBS: tuple[str, ...] = ("GET", "HEAD")
_MUTATION_VERBS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_METHOD_TIMEOUT = 6.0
_CONCURRENCY = 8
_SHAPE_CONCURRENCY = 3  # lower concurrency for read-safe body shape probing

# Methods that should carry a body input in the action card
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# ── Body-shape inference ──────────────────────────────────────────────────────

# Common words that appear in error messages but are not API field names.
_FIELD_EXCLUDE = frozenset({
    "body", "request", "response", "error", "message", "detail",
    "status", "code", "type", "path", "url", "method", "data",
    "the", "a", "an", "is", "are", "not", "no", "yes", "this",
    "field", "value", "parameter", "property", "attribute",
})

# Ordered regex patterns for extracting field names from free-text error messages.
# Each tuple is (compiled_pattern, capture_group_index).
_FIELD_PATTERNS: list[tuple[re.Pattern[str], int]] = [
    # JSON Schema: "'field_name' is a required property"
    (re.compile(r"'([a-z_][a-z0-9_]*)'\s+is\s+a\s+required\s+property", re.I), 1),
    # "required: field_name"  or  "required field: field_name"
    (re.compile(r"required(?:\s+field)?[:\s]+['\"]?([a-z_][a-z0-9_]*)['\"]?", re.I), 1),
    # "Missing required field field_name"  or  "field_name field is missing"
    (re.compile(
        r"missing\s+(?:required\s+)?(?:field|param(?:eter)?)\s+['\"]?([a-z_][a-z0-9_]*)['\"]?",
        re.I,
    ), 1),
    # "[field_name] is required"
    (re.compile(r"\b([a-z_][a-z0-9_]{1,63})\b\s+is\s+required", re.I), 1),
    # "[field_name] parameter missing"
    (re.compile(r"\b([a-z_][a-z0-9_]{1,63})\b\s+parameter\s+(?:is\s+)?missing", re.I), 1),
]

# Matches Content-Type hints embedded in error messages.
_CT_PATTERN = re.compile(r"content[_-]?type[:\s]+['\"]?([a-z]+/[a-z\-+]+)", re.I)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _mutation_verbs_from_allow(allow_header: str) -> list[str]:
    """Return mutation verbs (POST/PUT/PATCH/DELETE) declared in an Allow header."""
    declared = {v.strip().upper() for v in allow_header.split(",") if v.strip()}
    return [v for v in ("POST", "PUT", "PATCH", "DELETE") if v in declared]


def _is_unusual(method: str, status: int) -> bool:
    """True when a non-GET method returned a status that indicates server acceptance."""
    if method == "GET":
        return False
    return status != 404 and status != 405 and status != 0


def _make_action_kind(method: str, path: str) -> str:
    """Stable, URL-safe action_kind encoding (method, path) as base64url."""
    encoded = urlsafe_b64encode(path.encode()).decode().rstrip("=")
    return f"api_method_{method.lower()}_{encoded}"


def decode_action_kind(action_kind: str) -> tuple[str, str]:
    """Decode 'api_method_{method}_{b64url_path}' → (METHOD, path).

    Called by probe_api_method_execute to reconstruct the endpoint from the
    action_kind stored in ACTION_ID_CTX without needing extra form fields.
    Returns ("GET", "/") on any parse failure.
    """
    prefix = "api_method_"
    if not action_kind.startswith(prefix):
        return ("GET", "/")
    rest = action_kind[len(prefix):]
    sep = rest.find("_")
    if sep <= 0:
        return ("GET", "/")
    method = rest[:sep].upper()
    encoded = rest[sep + 1:]
    # Re-pad URL-safe base64 to a multiple of 4
    padding = (4 - len(encoded) % 4) % 4
    encoded += "=" * padding
    try:
        path = urlsafe_b64decode(encoded).decode("utf-8")
    except Exception:
        path = "/"
    return (method, path)


def _extract_fields_from_error(body: str) -> list[str]:
    """Parse a 400/422 response body and return inferred API field names.

    Handles structured JSON (FastAPI/Pydantic, DRF, Laravel, Express) and
    falls back to regex patterns over raw text.  Field names are deduplicated
    and filtered against a common-word exclusion list.
    """
    fields: list[str] = []
    seen: set[str] = set()

    def _add(f: str) -> None:
        f = f.strip().strip("'\"")
        if (
            f
            and f not in seen
            and 1 <= len(f) <= 64
            and re.match(r"^[a-z_][a-z0-9_]*$", f, re.I)
            and f.lower() not in _FIELD_EXCLUDE
        ):
            seen.add(f)
            fields.append(f)

    # ── Structured JSON parsing ──────────────────────────────────────────
    try:
        data = _json.loads(body)

        # FastAPI / Pydantic: {"detail": [{"loc": ["body", "field"], "msg": "..."}]}
        detail = data.get("detail") if isinstance(data, dict) else None
        if isinstance(detail, list):
            for item in detail:
                if isinstance(item, dict):
                    loc = item.get("loc", [])
                    if isinstance(loc, list) and len(loc) >= 2:
                        field = str(loc[-1])
                        if field != "body" and not field.isdigit():
                            _add(field)

        if isinstance(data, dict):
            # Django DRF: {"field_name": ["error message"]}
            for k, v in data.items():
                if k in ("detail", "error", "message", "errors", "status", "code"):
                    continue
                if isinstance(v, list) and v and isinstance(v[0], str):
                    _add(k)

            # Express / JSON:API: {"errors": [{"param": "field", ...}]}
            errors = data.get("errors")
            if isinstance(errors, list):
                for item in errors:
                    if isinstance(item, dict):
                        param = (
                            item.get("param")
                            or item.get("field")
                            or item.get("name")
                            or item.get("source", {}).get("pointer", "").lstrip("/")
                        )
                        if param:
                            _add(str(param))

            # Laravel: {"message": "...", "errors": {"field": ["msg"]}}
            elif isinstance(errors, dict):
                for k in errors:
                    _add(k)

    except (ValueError, TypeError, AttributeError):
        pass

    # ── Regex fallback — raw body text ───────────────────────────────────
    for pattern, group_idx in _FIELD_PATTERNS:
        for m in pattern.finditer(body):
            g = m.group(group_idx)
            if g:
                _add(g)

    return fields


def _content_type_from_error(body: str) -> str | None:
    """Extract a Content-Type hint from a validation error message."""
    m = _CT_PATTERN.search(body)
    if m:
        ct = m.group(1).strip()
        if "/" in ct:
            return ct
    return None


async def _probe_body_shape(
    client: httpx.AsyncClient,
    url: str,
    method: str,
    sem: asyncio.Semaphore,
) -> dict:
    """Send an empty JSON body to extract field-validation hints.

    READ-SAFE: an empty {} body is rejected by the server's validation layer
    before any state mutation can occur.  Returns:
        {"fields": list[str], "content_type": str | None}
    """
    async with sem:
        try:
            resp = await client.request(
                method,
                url,
                json={},
                headers={"Content-Type": "application/json"},
                timeout=_METHOD_TIMEOUT,
            )
        except httpx.RequestError:
            return {"fields": [], "content_type": None}

    if resp.status_code not in (400, 422):
        return {"fields": [], "content_type": None}

    body_text = resp.text
    fields = _extract_fields_from_error(body_text)
    ct_hint = _content_type_from_error(body_text)
    return {"fields": fields, "content_type": ct_hint}


def _build_action_card(
    method: str,
    path: str,
    status: int,
    inferred_fields: list[str] | None = None,
    inferred_content_type: str | None = None,
    label: str | None = None,
) -> dict:
    """Build a next_action card for a (method, path, status) combination.

    When inferred_fields is provided the card renders one input box per field
    (body shape inferred from 400/422 error parsing).  Otherwise falls back
    to a single generic body textarea for _BODY_METHODS.

    Meta fields (_method, _path, _content_type) are included so
    probe_api_method_execute can read them from OPERATOR_INPUTS_CTX without
    needing ACTION_ID_CTX decoding.
    """
    ct = inferred_content_type or "application/json"
    if inferred_fields:
        reason = (
            f"HTTP {status} — body validation error; "
            f"inferred field(s): {', '.join(inferred_fields)}"
        )
    else:
        reason = f"HTTP {status} — server accepted {method} on this endpoint"

    card: dict = {
        "action_kind": _make_action_kind(method, path),
        "label": label if label is not None else f"{method} {path}",
        "reason": reason,
    }

    inputs: list[dict] = [
        # Meta fields: pre-filled, visible so operator can verify before Execute.
        {
            "name": "_method",
            "location": "meta",
            "placeholder": "HTTP method",
            "default": method,
        },
        {
            "name": "_path",
            "location": "meta",
            "placeholder": "endpoint path",
            "default": path,
        },
        {
            "name": "_content_type",
            "location": "meta",
            "placeholder": "Content-Type",
            "default": ct,
        },
    ]

    if inferred_fields:
        inputs.extend(
            {
                "name": field,
                "location": "body",
                "placeholder": f"value for {field}",
                "default": "",
            }
            for field in inferred_fields
        )
    elif method in _BODY_METHODS:
        inputs.append(
            {
                "name": "body",
                "location": "body",
                "placeholder": '{"key": "value"}',
                "default": "",
            }
        )

    card["inputs"] = inputs
    return card


# ── Per-endpoint probe ────────────────────────────────────────────────────────


async def _probe_endpoint(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    base: str,
    path: str,
    verbs: tuple[str, ...] = HTTP_VERBS,
) -> dict:
    """Fire OPTIONS + the given verbs against one endpoint; return result dict."""
    url = base + path

    # OPTIONS first — separate from verb batch so we can include Allow header
    async with sem:
        try:
            opts_resp = await client.options(url)
            allow_header = opts_resp.headers.get("allow", opts_resp.headers.get("Allow", ""))
            options_status = opts_resp.status_code
        except httpx.RequestError:
            allow_header = ""
            options_status = 0

    # Verb probes in parallel (still respect semaphore per-request)
    async def _verb_probe(method: str) -> tuple[str, int]:
        async with sem:
            try:
                resp = await client.request(method, url)
                return (method, resp.status_code)
            except httpx.RequestError:
                return (method, 0)

    verb_results = await asyncio.gather(*[_verb_probe(v) for v in verbs])

    method_matrix: dict[str, int] = {"OPTIONS": options_status}
    for method, status in verb_results:
        method_matrix[method] = status

    return {
        "path": path,
        "allow_header": allow_header,
        "matrix": method_matrix,
    }


# ── Main async generator ──────────────────────────────────────────────────────


async def run_method_enum(
    target: str,
    endpoints: list[str],
    session_cookies: dict,
    read_only: bool = True,
) -> AsyncIterator[StageEvent | ResultEvent]:
    """Enumerate supported HTTP methods for each supplied endpoint.

    Args:
        target:          Base URL or host of the target.
        endpoints:       List of paths to probe (e.g. ["/api/users", "/api/orders"]).
        session_cookies: Authenticated session cookies (may be empty).
        read_only:       When True (default) only fire GET/HEAD/OPTIONS — no mutations.
                         Emits "Untested method" cards from Allow headers for declared
                         mutation verbs. Set False for exploitation-phase full enumeration.
    """
    parsed = urlparse(target if "://" in target else f"http://{target}")
    base = f"{parsed.scheme}://{parsed.netloc}"

    if not endpoints:
        yield StageEvent(
            label="No endpoints supplied for method enumeration",
            actions=("supply endpoints from authed recon or endpoint enum",),
            tools=(),
            confidence="low",
        )
        yield ResultEvent(
            label="Method enumeration skipped — no endpoints",
            kind="note",
            payload={
                "analysis": {
                    "confirmed": False,
                    "severity": "info",
                    "exploitability_notes": "No endpoints supplied.",
                    "references": [],
                },
                "observed": {"indicators": ["no endpoints provided"]},
            },
        )
        return

    active_verbs = HTTP_SAFE_VERBS if read_only else HTTP_VERBS
    _verb_desc = (
        f"{len(active_verbs)} safe verb(s) (GET/HEAD) + OPTIONS"
        if read_only else
        f"{len(HTTP_VERBS)} verb(s) + OPTIONS"
    )
    yield StageEvent(
        label=(
            "Enumerating safe HTTP methods on endpoints (read-only)"
            if read_only else
            "Probing HTTP methods on discovered endpoints"
        ),
        actions=(
            f"testing {len(endpoints)} endpoint(s) × {_verb_desc}",
            f"base URL: {base}",
        ),
        tools=("httpx async client",),
        confidence="medium",
    )

    sem = asyncio.Semaphore(_CONCURRENCY)
    shape_sem = asyncio.Semaphore(_SHAPE_CONCURRENCY)
    all_results: list[dict] = []

    async with httpx.AsyncClient(
        timeout=_METHOD_TIMEOUT,
        follow_redirects=False,
        verify=False,
        cookies=session_cookies,
    ) as client:
        # Phase 1 — method enumeration (concurrent)
        batch_size = max(1, _CONCURRENCY // (len(active_verbs) + 1))
        for i in range(0, len(endpoints), batch_size):
            batch = endpoints[i : i + batch_size]
            batch_results = await asyncio.gather(
                *[_probe_endpoint(client, sem, base, path, active_verbs) for path in batch]
            )
            all_results.extend(batch_results)

        # Phase 2 — body-shape probing for 400/422 responses (skipped in read-only mode).
        # READ-SAFE: empty {} body is rejected before any state mutation can occur.
        body_shapes: dict[tuple[str, str], dict] = {}
        if not read_only:
            for ep in all_results:
                ep_path = ep["path"]
                for verb, status in ep["matrix"].items():
                    if verb in ("OPTIONS", "GET", "HEAD") or status not in (400, 422):
                        continue
                    shape = await _probe_body_shape(client, base + ep_path, verb, shape_sem)
                    if shape["fields"] or shape["content_type"]:
                        body_shapes[(ep_path, verb)] = shape

    # ── Untested-method cards (read-only mode) ────────────────────────────────
    untested_cards: list[dict] = []
    if read_only:
        seen_untested: set[str] = set()
        for ep in all_results:
            for verb in _mutation_verbs_from_allow(ep["allow_header"]):
                ak = _make_action_kind(verb, ep["path"])
                if ak not in seen_untested:
                    seen_untested.add(ak)
                    untested_cards.append(
                        _build_action_card(
                            verb, ep["path"], 0,
                            label=f"Untested method — {verb} {ep['path']}",
                        )
                    )

    # ── Classify results ──────────────────────────────────────────────────────
    method_matrix_out: dict[str, dict[str, int]] = {}
    unusual_pairs: list[tuple[str, str, int]] = []  # (path, method, status)

    for ep in all_results:
        path = ep["path"]
        matrix = ep["matrix"]
        method_matrix_out[path] = matrix

        for method, status in matrix.items():
            if method == "OPTIONS":
                continue
            if _is_unusual(method, status):
                unusual_pairs.append((path, method, status))

    # Plain unusual-method cards (2xx / 401 / 403).
    plain_cards = [
        _build_action_card(method, path, status)
        for (path, method, status) in unusual_pairs
        if status in (200, 201, 204, 301, 302, 401, 403)
    ]

    # Body-shape cards (400/422 with inferred fields) take priority; they carry
    # richer input information and replace the plain card for the same endpoint.
    shape_cards = [
        _build_action_card(
            method, path, status,
            inferred_fields=body_shapes[(path, method)]["fields"] or None,
            inferred_content_type=body_shapes[(path, method)].get("content_type"),
        )
        for (path, method, status) in unusual_pairs
        if (path, method) in body_shapes
    ]

    # Deduplicate: untested_cards first, then shape_cards (richer), then plain_cards.
    seen_ak: set[str] = set()
    deduped_actions: list[dict] = list(untested_cards)
    seen_ak.update(c["action_kind"] for c in untested_cards)
    for card in shape_cards + plain_cards:
        ak = card["action_kind"]
        if ak not in seen_ak:
            seen_ak.add(ak)
            deduped_actions.append(card)

    if read_only:
        yield StageEvent(
            label="Safe method scan complete",
            actions=(
                f"tested {len(endpoints)} endpoint(s) (GET/HEAD/OPTIONS only)",
                f"{len(untested_cards)} mutation method(s) declared in Allow headers",
            ),
            tools=("httpx async client",),
            detected=tuple(
                f"Allow: {v} on {ep['path']}"
                for ep in all_results[:5]
                for v in _mutation_verbs_from_allow(ep["allow_header"])
            ) or ("no mutation verbs declared in Allow headers",),
            confidence="high" if untested_cards else "medium",
        )
    else:
        yield StageEvent(
            label="HTTP method enumeration complete",
            actions=(
                f"tested {len(endpoints)} endpoint(s)",
                f"{len(unusual_pairs)} unusual method/endpoint combination(s) found",
                f"{len(body_shapes)} body-shape probe(s) ran (400/422 → field inference)",
                f"{len(shape_cards)} action card(s) with inferred body fields",
            ),
            tools=("httpx async client",),
            detected=tuple(
                f"{method} {path} → HTTP {status}"
                for (path, method, status) in unusual_pairs[:10]
            ),
            confidence="high" if unusual_pairs else "medium",
        )

    if len(unusual_pairs) > 5:
        severity = "high"
    elif unusual_pairs:
        severity = "medium"
    else:
        severity = "info"

    yield ResultEvent(
        label=(
            f"Safe method scan: {len(untested_cards)} untested mutation method(s) declared"
            if read_only else
            f"Method enumeration: {len(unusual_pairs)} unusual combination(s)"
        ),
        kind="detected" if (untested_cards if read_only else unusual_pairs) else "note",
        evidence={
            "method_matrix": method_matrix_out,
            "unusual_pairs": [
                {"path": p, "method": m, "status": s}
                for (p, m, s) in unusual_pairs
            ],
            "allow_headers": {
                ep["path"]: ep["allow_header"]
                for ep in all_results
                if ep["allow_header"]
            },
        },
        payload={
            "request": {
                "method": "multiple",
                "url": base,
                "headers": {},
                "body": None,
            },
            "response": {
                "status": len(unusual_pairs),
                "headers": {},
                "body_excerpt": (
                    f"Tested {len(endpoints)} endpoint(s). "
                    f"Found {len(unusual_pairs)} unusual method/endpoint pair(s)."
                ),
            },
            "sent": {
                "payload_string": (
                    f"{len(active_verbs)} safe verbs (GET/HEAD) × "
                    f"{len(endpoints)} endpoints + OPTIONS"
                    if read_only else
                    f"{len(HTTP_VERBS)} verbs × {len(endpoints)} endpoints + OPTIONS"
                ),
                "encoding": "HTTP methods",
                "injection_point": "HTTP method",
            },
            "observed": {
                "indicators": (
                    [
                        f"{len(untested_cards)} mutation method(s) declared in Allow headers",
                        f"method matrix (GET/HEAD/OPTIONS) built for {len(endpoints)} endpoint(s)",
                        "mutation verbs not probed — re-run with read_only=False for full results",
                    ]
                    if read_only else
                    [
                        f"{len(unusual_pairs)} non-GET method(s) accepted (not 404/405)",
                        f"method matrix built for {len(endpoints)} endpoint(s)",
                        f"{len(body_shapes)} endpoint(s) revealed body schema via 400/422 error",
                        f"{len(shape_cards)} action card(s) carry inferred field names",
                    ]
                ),
            },
            "analysis": {
                "confirmed": bool(untested_cards if read_only else unusual_pairs),
                "severity": severity,
                "exploitability_notes": (
                    (
                        f"{len(untested_cards)} mutation method(s) declared in Allow headers "
                        "but not probed (read-only enumeration). Click an 'Untested method' "
                        "card to fire the mutation when you are ready to test."
                    )
                    if read_only else
                    (
                        f"Server accepted non-GET verbs on {len(unusual_pairs)} endpoint(s). "
                        + (
                            f"{len(shape_cards)} card(s) include inferred body field names "
                            "extracted from 400/422 validation errors — fill the fields and "
                            "click Execute to fire the mutation. "
                            if shape_cards else ""
                        )
                        + "Unexpected PATCH/DELETE/PUT responses indicate possible broken "
                        "access control or unintended method exposure."
                        if unusual_pairs
                        else (
                            "All non-GET methods returned 404 or 405 on the tested endpoints. "
                            "The server appears to enforce method restrictions correctly."
                        )
                    )
                ),
                "references": [
                    {
                        "label": "OWASP API Security — Broken Function Level Authorization",
                        "url": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                    }
                ],
            },
            "next_actions": deduped_actions,
        },
    )
