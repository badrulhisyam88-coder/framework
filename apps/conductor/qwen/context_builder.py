"""V2.5 Step 3 — investigation context builder for Qwen chat.

Reads from DB only (no runtime memory). Returns a formatted string describing
the current investigation state so Qwen can give actionable advice.

V2.6 Step 1 — API context enrichment:
  _fetch_openapi_schema  — pulls /openapi.json or /api/openapi.json from target
  _fetch_product_catalog — pulls /api/products or /api/store/products with session cookies
  Both helpers: 5s timeout, verify=False, never raise.
  Sections are added to the context only when data is available; graceful degradation
  if any fetch fails.

V2.7 — Knowledge vault context injection:
  _search_vault_by_tags  — tag-based fallback search over vault findings/web/ + labs/
  Vault section appended to context when entries found; silently omitted when vault
  not mounted or empty.

Never raises — returns "Investigation context unavailable." on any DB error.
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger("conductor.qwen.context_builder")

_VAULT_PATH = Path(os.environ.get("KNOWLEDGE_VAULT_PATH", "/app/knowledge-vault"))

# ── finding_type → search tags mapping ───────────────────────────────────────

_FINDING_TYPE_SEARCH_TAGS: dict[str, list[str]] = {
    "sqli":             ["sqli", "auth-bypass"],
    "sqli_auth_bypass": ["sqli", "auth-bypass"],
    "api_exposure":     ["idor", "mass-assignment", "api"],
    "login_form_detected": ["auth-bypass", "brute-force"],
    "ai_probe":         ["ai-probe", "mass-assignment"],
    "xss":              ["xss", "reflected-xss"],
    "cmdi":             ["cmdi", "rce"],
    "default_creds":    ["default-credentials", "auth-bypass"],
    "idor":             ["idor", "mass-assignment", "api"],
    "rce":              ["rce", "metasploit"],
}


def _base_url(target_url: str) -> str:
    """Strip path/query/fragment from target_url so we hit the root."""
    parts = urlsplit(target_url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


async def _fetch_openapi_schema(target_url: str) -> dict | None:
    """Attempt to fetch /openapi.json (or /api/openapi.json) from the target.

    Returns the parsed schema dict on success, None on any failure.
    Never raises.
    """
    try:
        import httpx
    except ImportError:
        return None

    base = _base_url(target_url) if target_url and target_url != "unknown" else ""
    if not base:
        return None

    urls = [f"{base}/openapi.json", f"{base}/api/openapi.json"]
    try:
        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            for url in urls:
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if isinstance(data, dict):
                                logger.debug("openapi schema fetched from %s", url)
                                return data
                        except Exception:
                            pass
                except Exception:
                    pass
    except Exception:
        pass
    return None


async def _fetch_product_catalog(
    target_url: str,
    session_cookies: dict,
) -> list | None:
    """Attempt to fetch /api/products (or /api/store/products) from the target.

    Passes session_cookies as request cookies.
    Returns list of up to 10 product dicts (productId/id, name, price) on success.
    Returns None on any failure.
    Never raises.
    """
    try:
        import httpx
    except ImportError:
        return None

    base = _base_url(target_url) if target_url and target_url != "unknown" else ""
    if not base:
        return None

    urls = [f"{base}/api/products", f"{base}/api/store/products"]
    try:
        async with httpx.AsyncClient(
            timeout=5.0, verify=False, cookies=session_cookies
        ) as client:
            for url in urls:
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        try:
                            raw = resp.json()
                            items: list = []
                            if isinstance(raw, list):
                                items = raw
                            elif isinstance(raw, dict):
                                items = raw.get("products", [])
                            result = []
                            for item in items[:10]:
                                if not isinstance(item, dict):
                                    continue
                                product_id = (
                                    item.get("productId")
                                    or item.get("id")
                                    or ""
                                )
                                name = item.get("name", "")
                                price = (
                                    item.get("price")
                                    or item.get("item_price")
                                    or ""
                                )
                                result.append({
                                    "productId": product_id,
                                    "name": name,
                                    "price": price,
                                })
                            if result:
                                logger.debug(
                                    "product catalog fetched %d items from %s",
                                    len(result), url,
                                )
                                return result
                        except Exception:
                            pass
                except Exception:
                    pass
    except Exception:
        pass
    return None


def _parse_frontmatter_tags(filepath: Path) -> dict:
    """Parse YAML frontmatter from a vault markdown file.

    Returns dict with keys: id, title, tags (list), type.
    Returns {} on any parse error. Never raises.
    """
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
        if not text.startswith("---"):
            return {}
        end = text.find("\n---", 3)
        if end == -1:
            return {}
        fm_block = text[3:end]
        result: dict = {"id": "", "title": "", "tags": [], "type": ""}
        for line in fm_block.splitlines():
            line = line.rstrip()
            if line.startswith("id:"):
                result["id"] = line[3:].strip().strip('"\'')
            elif line.startswith("title:"):
                result["title"] = line[6:].strip().strip('"\'')
            elif line.startswith("type:"):
                result["type"] = line[5:].strip().strip('"\'')
            elif re.match(r"^\s+-\s+", line):
                tag = re.sub(r"^\s+-\s+", "", line).strip()
                if tag:
                    result["tags"].append(tag)
        return result
    except Exception:
        return {}


def _search_vault_by_tags(finding_types: list[str]) -> list[dict]:
    """Tag-based vault search. Returns top 3 matches by tag overlap.

    Scans vault findings/ and labs/ frontmatter for files whose tags overlap
    with the search tags derived from finding_types. Silently returns [] when
    vault not mounted or on any error.

    Returns list of dicts: [{id, title, tags, payload_hint, outcome_hint}]
    """
    if not _VAULT_PATH.exists() or not _VAULT_PATH.is_dir():
        return []

    # Collect search tags from all finding_types
    search_tags: set[str] = set()
    for ft in finding_types:
        mapped = _FINDING_TYPE_SEARCH_TAGS.get(ft, [])
        search_tags.update(mapped)
        # Also add the finding_type itself as a search tag
        search_tags.add(ft.replace("_", "-"))

    if not search_tags:
        return []

    candidates: list[tuple[int, dict]] = []

    try:
        # Scan findings/, labs/, and concepts/ (V2.7 concept files)
        scan_dirs = [
            _VAULT_PATH / "findings" / "web",
            _VAULT_PATH / "findings" / "api",
            _VAULT_PATH / "findings" / "network",
            _VAULT_PATH / "labs",
            _VAULT_PATH / "concepts",
        ]
        for scan_dir in scan_dirs:
            if not scan_dir.is_dir():
                continue
            for filepath in scan_dir.glob("*.md"):
                fm = _parse_frontmatter_tags(filepath)
                if not fm or not fm.get("id"):
                    continue
                file_tags = set(fm.get("tags", []))
                overlap = len(search_tags & file_tags)
                if overlap > 0:
                    entry = {
                        "id": fm["id"],
                        "title": fm["title"],
                        "tags": list(file_tags),
                        "payload_hint": "",
                        "outcome_hint": "",
                    }
                    # Extract brief outcome hint from body (first summary line)
                    try:
                        text = filepath.read_text(encoding="utf-8", errors="replace")
                        m = re.search(r"##\s+Summary\s*\n+>\s*(.+)", text)
                        if m:
                            entry["outcome_hint"] = m.group(1).strip()[:120]
                    except Exception:
                        pass
                    candidates.append((overlap, entry))
    except Exception as exc:
        logger.debug("_search_vault_by_tags scan failed: %s", exc)
        return []

    # Sort by overlap descending, return top 3
    candidates.sort(key=lambda x: x[0], reverse=True)
    return [entry for _, entry in candidates[:3]]


async def build_investigation_context(investigation_id: str, operator_message: str = "") -> str:
    """Build a formatted context string for the given investigation.

    Sources (DB only):
      - normalized_findings    → findings discovered during recon/enumeration
      - exploitation_branches  → engine execution state and artifacts
      - investigations         → target URL (best-effort)

    Returns a human-readable string Qwen receives as the system message context.
    Never raises — returns the unavailable string on any exception.
    """
    try:
        return await _build(investigation_id, operator_message=operator_message)
    except Exception as exc:
        logger.warning("context_builder failed for %s: %s", investigation_id, exc)
        return "Investigation context unavailable."


async def _build(investigation_id: str, operator_message: str = "") -> str:
    from apps.validation.database import get_db

    # ── Target URL ────────────────────────────────────────────────────────────
    target_url = "unknown"
    try:
        async with get_db() as db:
            async with db.execute(
                "SELECT targets FROM investigations WHERE investigation_id=?",
                (investigation_id,),
            ) as cur:
                row = await cur.fetchone()
        if row and row[0]:
            targets = json.loads(row[0])
            if targets:
                target_url = targets[0]
    except Exception:
        pass

    # ── Findings ──────────────────────────────────────────────────────────────
    findings: list[dict] = []
    try:
        async with get_db() as db:
            async with db.execute(
                """SELECT finding_type, title, severity, endpoint, finding_id
                   FROM normalized_findings
                   WHERE investigation_id=?
                   ORDER BY finding_type""",
                (investigation_id,),
            ) as cur:
                rows = await cur.fetchall()
        for r in rows:
            findings.append({
                "finding_type": r[0] or "",
                "title":        r[1] or "",
                "severity":     r[2] or "",
                "endpoint":     r[3] or "",
                "finding_id":   r[4] or "",
            })
    except Exception as exc:
        logger.debug("context_builder findings query failed: %s", exc)

    # ── Exploitation branches ─────────────────────────────────────────────────
    branches: list[dict] = []
    try:
        async with get_db() as db:
            async with db.execute(
                """SELECT engine_id, state, artifact, exhaustion_record
                   FROM exploitation_branches
                   WHERE investigation_id=?
                   ORDER BY created_at""",
                (investigation_id,),
            ) as cur:
                rows = await cur.fetchall()
        for r in rows:
            artifact = None
            if r[2]:
                try:
                    artifact = json.loads(r[2])
                except Exception:
                    pass
            exhaustion = None
            if r[3]:
                try:
                    exhaustion = json.loads(r[3])
                except Exception:
                    pass
            branches.append({
                "engine_id":        r[0] or "",
                "state":            r[1] or "",
                "artifact":         artifact,
                "exhaustion_record": exhaustion,
            })
    except Exception as exc:
        logger.debug("context_builder branches query failed: %s", exc)

    # ── API surface details (for Qwen endpoint path inference) ───────────────
    api_endpoints: list[str] = []
    try:
        async with get_db() as db:
            async with db.execute(
                """SELECT DISTINCT endpoint FROM normalized_findings
                   WHERE investigation_id=? AND finding_type='api_exposure'
                   LIMIT 10""",
                (investigation_id,),
            ) as cur:
                rows = await cur.fetchall()
        api_endpoints = [row[0] for row in rows if row[0]]
    except Exception as exc:
        logger.debug("context_builder api_endpoints query failed: %s", exc)

    # ── V2.6 — Discovered endpoints from recon/enum findings ─────────────────
    # Broader query: api_exposure + wellknown_file_disclosed with non-empty endpoint.
    discovered_endpoints: list[str] = []
    try:
        async with get_db() as db:
            async with db.execute(
                """SELECT DISTINCT endpoint FROM normalized_findings
                   WHERE investigation_id=?
                     AND finding_type IN ('api_exposure', 'wellknown_file_disclosed')
                     AND endpoint IS NOT NULL AND endpoint != ''
                   LIMIT 20""",
                (investigation_id,),
            ) as cur:
                rows = await cur.fetchall()
        discovered_endpoints = [row[0] for row in rows if row[0]]
    except Exception as exc:
        logger.debug("context_builder discovered_endpoints query failed: %s", exc)

    # ── V2.6 — Captured session cookies from exploitation_branches ────────────
    session_cookies: dict = {}
    try:
        async with get_db() as db:
            async with db.execute(
                """SELECT artifact FROM exploitation_branches
                   WHERE investigation_id=? AND artifact IS NOT NULL
                   ORDER BY created_at""",
                (investigation_id,),
            ) as cur:
                rows = await cur.fetchall()
        for row in rows:
            try:
                art_outer = json.loads(row[0])
                # Artifact may be stored as {"artifact": {...}} or directly as {...}
                art = art_outer.get("artifact", art_outer) if isinstance(art_outer, dict) else art_outer
                if isinstance(art, dict) and art.get("artifact_type") == "captured_session":
                    cookies = art.get("session_cookies", {})
                    if isinstance(cookies, dict) and cookies:
                        session_cookies = cookies
                        break
            except Exception:
                pass
    except Exception as exc:
        logger.debug("context_builder session_cookies query failed: %s", exc)

    # ── V2.6 — Live API fetches (best-effort, 5s timeout each) ───────────────
    openapi_schema: dict | None = None
    product_catalog: list | None = None
    if target_url and target_url != "unknown":
        openapi_schema = await _fetch_openapi_schema(target_url)
        product_catalog = await _fetch_product_catalog(target_url, session_cookies)

    # ── Assemble context string ───────────────────────────────────────────────
    lines: list[str] = [
        f"Investigation target: {target_url}",
        "",
    ]

    # Cap findings to the 25 most interesting (high/critical first, then others)
    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}
    findings_sorted = sorted(findings, key=lambda f: _SEV_ORDER.get(f["severity"], 5))
    findings_display = findings_sorted[:25]
    omitted_count = len(findings) - len(findings_display)

    if findings_display:
        lines.append(f"Findings discovered ({len(findings)} total — showing top {len(findings_display)}):")
        for f in findings_display:
            ep_raw = f["endpoint"] or ""
            # Truncate long URLs to 80 chars to keep context compact
            ep_short = (ep_raw[:80] + "…") if len(ep_raw) > 80 else ep_raw
            ep_part = f"endpoint={ep_short}" if ep_short else ""
            sev_part = f"severity={f['severity']}" if f["severity"] else ""
            meta = ", ".join(x for x in [ep_part, sev_part] if x)
            lines.append(
                f"- {f['finding_type']}: \"{f['title']}\""
                + (f" [{meta}]" if meta else "")
            )
        if omitted_count > 0:
            lines.append(f"  … and {omitted_count} more findings (lower severity)")
    else:
        lines.append("Findings discovered: none yet")

    lines.append("")

    if api_endpoints:
        lines.append("API endpoints discovered:")
        for ep in api_endpoints:
            lines.append(f"  - {ep}")
        lines.append("")

    if branches:
        lines.append("Engine results:")
        for b in branches:
            state = b["state"]
            detail = ""
            if state == "succeeded" and b["artifact"]:
                art = b["artifact"]
                atype = art.get("artifact_type", "")
                # Pull key readable fields from the artifact
                keys = [k for k in art if k not in ("artifact_type",)]
                sample = []
                for k in keys[:3]:
                    v = art[k]
                    if isinstance(v, str) and len(v) < 80:
                        sample.append(f"{k}={v}")
                    elif isinstance(v, (int, float, bool)):
                        sample.append(f"{k}={v}")
                detail_parts = [f"artifact: {atype}"] + sample
                detail = f" [{', '.join(detail_parts)}]"
            elif state == "exhausted" and b["exhaustion_record"]:
                exh = b["exhaustion_record"]
                tried = exh.get("payloads_tried", [])
                n = len(tried) if isinstance(tried, list) else tried
                detail = f" [payloads_tried={n}]"
            lines.append(f"- {b['engine_id']}: {state.upper()}{detail}")
    else:
        lines.append("Engine results: no engines have run yet")

    lines.append("")

    # ── Captured artifacts summary ────────────────────────────────────────────
    succeeded = [b for b in branches if b["state"] == "succeeded" and b["artifact"]]
    if succeeded:
        lines.append("Captured artifacts:")
        for b in succeeded:
            art = b["artifact"]
            atype = art.get("artifact_type", "unknown")
            # Summarise key credential or interesting fields
            interesting_keys = ["username", "user", "password", "cookies", "session"]
            parts = []
            for k in interesting_keys:
                if k in art:
                    v = art[k]
                    if isinstance(v, str) and len(v) < 60:
                        parts.append(f"{k}={v}")
                    elif isinstance(v, (int, bool)):
                        parts.append(f"{k}={v}")
            extra = f" — {', '.join(parts)}" if parts else ""
            lines.append(f"- {b['engine_id']}: {atype}{extra}")

    # ── V2.6 — Discovered endpoints from recon/enum (DB-only, no fetch) ──────
    if discovered_endpoints:
        lines.append("")
        lines.append("Discovered endpoints (from recon/enum):")
        for ep in discovered_endpoints:
            lines.append(f"  {ep} — accessible")

    # ── V2.6 — OpenAPI schema (from live fetch) ───────────────────────────────
    if openapi_schema and isinstance(openapi_schema, dict):
        paths = openapi_schema.get("paths", {})
        if paths:
            lines.append("")
            lines.append("API Schema (from /openapi.json):")
            for path, methods_obj in list(paths.items())[:10]:
                if isinstance(methods_obj, dict):
                    methods_str = ", ".join(m.upper() for m in methods_obj if m != "parameters")
                    # Extract brief parameter hint from first method
                    params_hint = ""
                    for method_data in methods_obj.values():
                        if isinstance(method_data, dict):
                            params = method_data.get("parameters", [])
                            if params:
                                param_names = [
                                    p.get("name", "") for p in params[:3]
                                    if isinstance(p, dict)
                                ]
                                params_hint = f" params=[{', '.join(p for p in param_names if p)}]"
                            break
                    lines.append(f"  [{methods_str}] {path}{params_hint}")

    # ── V2.6 — Product catalog (from live fetch) ─────────────────────────────
    if product_catalog:
        lines.append("")
        lines.append("Product catalog:")
        for item in product_catalog:
            pid   = item.get("productId", "")
            name  = item.get("name", "unknown")
            price = item.get("price", "")
            # Format price: if numeric, show as $X.XX; if string, show as-is
            if price != "" and price is not None:
                try:
                    price_fmt = f"${float(price):.2f}"
                except (ValueError, TypeError):
                    price_fmt = str(price)
            else:
                price_fmt = "n/a"
            lines.append(f"  productId={pid}: {name} — {price_fmt}")

    # ── V2.7 — Knowledge vault context injection ──────────────────────────────
    # Collect finding_types for vault search
    vault_finding_types = list({f["finding_type"] for f in findings if f.get("finding_type")})
    vault_hits: list[dict] = []
    try:
        from apps.conductor.qwen.vault_embedder import search_vault_semantic
        # Filter to findings — context injection wants past successful/failed exploits,
        # not concept definitions. Concepts would pollute the Qwen context with
        # technique descriptions rather than concrete past-exploit records.
        vault_hits = await search_vault_semantic(
            query=f"{' '.join(vault_finding_types)} {operator_message}".strip(),
            top_k=3,
            entry_type="finding",
        )
    except Exception:
        vault_hits = []
    if not vault_hits:
        vault_hits = _search_vault_by_tags(vault_finding_types)

    if vault_hits:
        lines.append("")
        lines.append("Past successful exploits (from knowledge vault):")
        for hit in vault_hits:
            hit_id = hit.get("id", "—")
            hit_title = hit.get("title", "—")
            hit_tags = ", ".join(hit.get("tags", [])[:5])
            hit_outcome = hit.get("outcome_hint", "")
            tag_str = f"\n    Tags: {hit_tags}" if hit_tags else ""
            outcome_str = f"\n    Outcome: {hit_outcome}" if hit_outcome else ""
            lines.append(f"  {hit_id} — {hit_title}{tag_str}{outcome_str}")

    return "\n".join(lines)
