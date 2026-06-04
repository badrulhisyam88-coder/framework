"""Phase D1 — Vault template loader and payload renderer.

Vault concept files may contain an EXEC-TEMPLATE block:

  <!-- EXEC-TEMPLATE-START -->
  ```yaml
  execution_template:
    engine_id: access_control
    method: GET
    endpoint_pattern: "/user/lookup"
    payload_template:
      user: "{{username}}'||'1'=='1"
    success_condition:
      status_codes: [200]
      response_contains: "administrator"
    requires_session: false
  ```
  <!-- EXEC-TEMPLATE-END -->

load_template() extracts and parses this block.
render_payload() substitutes {{placeholder}} values from a context dict.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from apps.conductor.qwen.vault_embedder import (
    EXEC_TEMPLATE_RE, EXEC_EXTRACT_RE, EXEC_ENUM_RE, EXEC_AUTH_BYPASS_RE, VAULT_PATH,
)

_EXEC_EXTRACT_INNER_RE = re.compile(
    r"<!--\s*EXEC-EXTRACT-START\s*-->(.*?)<!--\s*EXEC-EXTRACT-END\s*-->",
    re.DOTALL | re.IGNORECASE,
)
_EXEC_ENUM_INNER_RE = re.compile(
    r"<!--\s*EXEC-ENUM-START\s*-->(.*?)<!--\s*EXEC-ENUM-END\s*-->",
    re.DOTALL | re.IGNORECASE,
)
_EXEC_AUTH_BYPASS_INNER_RE = re.compile(
    r"<!--\s*EXEC-AUTH-BYPASS-START\s*-->(.*?)<!--\s*EXEC-AUTH-BYPASS-END\s*-->",
    re.DOTALL | re.IGNORECASE,
)


class MissingContext(Exception):
    """A required context key is missing for payload rendering."""
    def __init__(self, key: str) -> None:
        super().__init__(f"Missing required context key: {key!r}")
        self.key = key


class NeedsSession(Exception):
    """Engine requires a captured session but none is available."""
    def __init__(self, engine_id: str) -> None:
        super().__init__(f"Engine {engine_id!r} requires a captured session")
        self.engine_id = engine_id


@dataclass
class ExecutionTemplate:
    engine_id:         str
    method:            str            # GET | POST
    endpoint_pattern:  str            # e.g. "/user/lookup" or "{{endpoint}}"
    payload_template:  dict           # {"user": "{{username}}'||'1'=='1"}
    success_condition: dict           # {"status_codes": [...], "response_contains": "..."}
    requires_session:  bool


@dataclass
class ExtractionTemplate:
    """Template for oracle-driven blind value extraction (EXEC-EXTRACT block).

    All lab-specific knowledge (endpoint, field names, oracle signal, payload syntax)
    lives here. OracleSearchEngine reads this at runtime — it never contains any
    target-specific string itself.
    """
    endpoint_pattern: str           # e.g. "/user/lookup"
    method:           str           # GET | POST
    base_param:       str           # query/body param name (e.g. "user")
    target_field:     str           # field being extracted (e.g. "password")
    length_payload:   str           # template with {{length}} slot
    char_payload:     str           # template with {{position}}, {{range}}, {{field}} slots
    charset:          str           # ordered characters to search (e.g. "abc...Z0-9")
    max_length:       int           # stop length search here
    max_requests:     int           # abort + return partial if exceeded
    concurrency:      int           # asyncio.Semaphore bound for per-char positions
    oracle_spec:      dict          # {"type": "content_match", "signal": "..."}
    content_type:          str = "params"  # "params" | "json"
    body_template:         str = ""        # full JSON body template (when content_type="json")
    length_body_template:  str = ""        # separate body template for length scan (json mode)
                                           # slot: {{length}}; default: uses body_template


@dataclass
class EnumerationTemplate:
    """Template for oracle-driven field-name enumeration (EXEC-ENUM block).

    Strategy: dictionary_scan — iterate candidate names from a wordlist file,
    test each for existence via the oracle, collect names that return True.
    All lab-specific knowledge lives here; OracleSearchEngine is generic.

    content_type controls transport:
    - "params": GET ?base_param=RENDERED_PAYLOAD or POST form-encoded
    - "json":   POST JSON body rendered from body_template (overrides existence_payload)
    Slots: {{field}}, {{target_account}}.
    """
    strategy:          str    # "dictionary_scan"
    endpoint_pattern:  str    # e.g. "/login"
    method:            str    # GET | POST
    base_param:        str    # param name for content_type="params"
    target_account:    str    # {{target_account}} slot — filled from objective at runtime
    existence_payload: str    # template with {{field}} and {{target_account}} (params mode)
    body_template:     str    # full JSON body template string (json mode)
    wordlist_ref:      str    # path relative to VAULT_PATH (e.g. "wordlists/nosql-field-names.txt")
    oracle_spec:       dict   # {"type": "content_match", "signal": "..."}
    content_type:      str    # "params" | "json"
    concurrency:       int    # asyncio.Semaphore bound
    max_requests:      int    # abort + flag incomplete if exceeded


# ── File location ──────────────────────────────────────────────────────────────

_SCAN_DIRS = [
    VAULT_PATH / "concepts",
    VAULT_PATH / "findings" / "web",
    VAULT_PATH / "findings" / "api",
    VAULT_PATH / "findings" / "network",
    VAULT_PATH / "labs",
]

_YAML_FENCE_RE = re.compile(r"```ya?ml\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")


def _find_concept_file(concept_id: str) -> Path | None:
    """Locate the vault markdown file for a CONCEPT-* id. Case-insensitive stem match."""
    stem_target = concept_id.lower().replace("concept-", "concept-", 1)
    for scan_dir in _SCAN_DIRS:
        if not scan_dir.is_dir():
            continue
        for filepath in scan_dir.glob("*.md"):
            if filepath.stem.lower() == stem_target:
                return filepath
            # Also check frontmatter id field
    return None


def _extract_template_yaml(content: str) -> str | None:
    """Extract the YAML string inside an EXEC-TEMPLATE block. Returns None if absent."""
    m = EXEC_TEMPLATE_RE.search(content)
    if not m:
        return None
    block = m.group(0)
    # Strip outer HTML comment markers
    inner = block
    inner = re.sub(r"<!--\s*EXEC-TEMPLATE-START\s*-->", "", inner)
    inner = re.sub(r"<!--\s*EXEC-TEMPLATE-END\s*-->", "", inner)
    # Extract YAML from inside ```yaml ... ``` fence
    ym = _YAML_FENCE_RE.search(inner)
    if ym:
        return ym.group(1).strip()
    return inner.strip()


def load_template(concept_id: str) -> ExecutionTemplate | None:
    """Load and parse the EXEC-TEMPLATE block from a concept file.

    Returns None if no template is present or on any parse error.
    Never raises.
    """
    try:
        return _load(concept_id)
    except Exception:
        return None


def _load(concept_id: str) -> ExecutionTemplate | None:
    filepath = _find_concept_file(concept_id)
    if filepath is None:
        return None
    content = filepath.read_text(encoding="utf-8", errors="replace")
    yaml_str = _extract_template_yaml(content)
    if not yaml_str:
        return None

    import yaml as _yaml
    data = _yaml.safe_load(yaml_str)
    if not isinstance(data, dict):
        return None

    tmpl = data.get("execution_template")
    if not isinstance(tmpl, dict):
        return None

    return ExecutionTemplate(
        engine_id        = str(tmpl.get("engine_id", "")),
        method           = str(tmpl.get("method", "GET")).upper(),
        endpoint_pattern = str(tmpl.get("endpoint_pattern", "")),
        payload_template = dict(tmpl.get("payload_template") or {}),
        success_condition = dict(tmpl.get("success_condition") or {}),
        requires_session = bool(tmpl.get("requires_session", False)),
    )


_VARIANT_SECTION_RE = re.compile(r"##\s+Payload Variants\s*\n(.*?)(?=\n##|\Z)", re.DOTALL)
_VARIANT_BULLET_RE  = re.compile(
    r"\*\*([^*]+)\*\*[:\s]+(.*?)(?=\n-\s+\*\*|\Z)", re.DOTALL
)


def load_payload_variants(concept_id: str) -> list[dict]:
    """Parse the ## Payload Variants section from a concept file.

    Returns list of {"title": str, "description": str, "payload_hint": str}.
    Returns [] if section absent or on any parse error. Never raises.
    """
    try:
        return _load_variants(concept_id)
    except Exception:
        return []


def _load_variants(concept_id: str) -> list[dict]:
    filepath = _find_concept_file(concept_id)
    if filepath is None:
        return []
    content = filepath.read_text(encoding="utf-8", errors="replace")

    # Strip EXEC-TEMPLATE block before searching so template YAML isn't parsed as variants
    from apps.conductor.qwen.vault_embedder import embeddable_text
    content = embeddable_text(content)

    m = _VARIANT_SECTION_RE.search(content)
    if not m:
        return []

    section = m.group(1).strip()
    variants: list[dict] = []

    # Split on bullet items starting with "- **Title**"
    bullet_re = re.compile(r"^-\s+\*\*(.+?)\*\*[:\s]*(.*?)(?=^-\s+\*\*|\Z)", re.MULTILINE | re.DOTALL)
    for bm in bullet_re.finditer(section):
        title = bm.group(1).strip()
        body  = bm.group(2).strip()
        # First non-empty line of body is the payload hint; rest is description
        lines = [l.strip() for l in body.splitlines() if l.strip()]
        payload_hint = lines[0] if lines else ""
        description  = " ".join(lines[1:]) if len(lines) > 1 else ""
        variants.append({
            "title":        title,
            "description":  description,
            "payload_hint": payload_hint,
        })

    return variants


def load_extraction_template(concept_id: str) -> ExtractionTemplate | None:
    """Load and parse the EXEC-EXTRACT block from a concept file.

    Returns None if no extraction template is present or on any parse error.
    Never raises.
    """
    try:
        return _load_extraction(concept_id)
    except Exception:
        return None


def _load_extraction(concept_id: str) -> ExtractionTemplate | None:
    filepath = _find_concept_file(concept_id)
    if filepath is None:
        return None
    content = filepath.read_text(encoding="utf-8", errors="replace")

    m = _EXEC_EXTRACT_INNER_RE.search(content)
    if not m:
        return None
    inner = m.group(1)

    ym = _YAML_FENCE_RE.search(inner)
    yaml_str = ym.group(1).strip() if ym else inner.strip()
    if not yaml_str:
        return None

    import yaml as _yaml
    data = _yaml.safe_load(yaml_str)
    if not isinstance(data, dict):
        return None

    tmpl = data.get("extraction_template")
    if not isinstance(tmpl, dict):
        return None

    return ExtractionTemplate(
        endpoint_pattern = str(tmpl.get("endpoint_pattern", "")),
        method           = str(tmpl.get("method", "GET")).upper(),
        base_param       = str(tmpl.get("base_param", "")),
        target_field     = str(tmpl.get("target_field", "")),
        length_payload   = str(tmpl.get("length_payload", "")),
        char_payload     = str(tmpl.get("char_payload", "")),
        charset          = str(tmpl.get("charset", "abcdefghijklmnopqrstuvwxyz0123456789")),
        max_length       = int(tmpl.get("max_length", 30)),
        max_requests     = int(tmpl.get("max_requests", 600)),
        concurrency      = int(tmpl.get("concurrency", 8)),
        oracle_spec      = dict(tmpl.get("oracle") or {}),
        content_type          = str(tmpl.get("content_type", "params")),
        body_template         = str(tmpl.get("body_template", "")),
        length_body_template  = str(tmpl.get("length_body_template", "")),
    )


# ── Enumeration template loader ───────────────────────────────────────────────


def load_enumeration_template(concept_id: str) -> "EnumerationTemplate | None":
    """Load and parse the EXEC-ENUM block from a concept file.

    Returns None if no enumeration template is present or on any parse error.
    Never raises.
    """
    try:
        return _load_enumeration(concept_id)
    except Exception:
        return None


def _load_enumeration(concept_id: str) -> "EnumerationTemplate | None":
    filepath = _find_concept_file(concept_id)
    if filepath is None:
        return None
    content = filepath.read_text(encoding="utf-8", errors="replace")

    m = _EXEC_ENUM_INNER_RE.search(content)
    if not m:
        return None
    inner = m.group(1)

    ym = _YAML_FENCE_RE.search(inner)
    yaml_str = ym.group(1).strip() if ym else inner.strip()
    if not yaml_str:
        return None

    import yaml as _yaml
    data = _yaml.safe_load(yaml_str)
    if not isinstance(data, dict):
        return None

    tmpl = data.get("enumeration_template")
    if not isinstance(tmpl, dict):
        return None

    return EnumerationTemplate(
        strategy          = str(tmpl.get("strategy", "dictionary_scan")),
        endpoint_pattern  = str(tmpl.get("endpoint_pattern", "")),
        method            = str(tmpl.get("method", "GET")).upper(),
        base_param        = str(tmpl.get("base_param", "")),
        target_account    = str(tmpl.get("target_account", "{{target_account}}")),
        existence_payload = str(tmpl.get("existence_payload", "")),
        body_template     = str(tmpl.get("body_template", "")),
        wordlist_ref      = str(tmpl.get("wordlist_ref", "")),
        oracle_spec       = dict(tmpl.get("oracle") or {}),
        content_type      = str(tmpl.get("content_type", "params")),
        concurrency       = int(tmpl.get("concurrency", 8)),
        max_requests      = int(tmpl.get("max_requests", 600)),
    )


# ── Auth bypass template (EXEC-AUTH-BYPASS block) ─────────────────────────────


@dataclass
class AuthBypassTemplate:
    """Template for operator-injection authentication bypass (EXEC-AUTH-BYPASS block).

    The bypass_payloads list is the VARIES-METHOD principle: each entry is a dict
    fragment merged into the login body. The engine iterates the list — $ne is just
    the first entry, not hardcoded. Adding new variants is a data edit, not a code change.

    username_field / password_field: form/JSON field names (e.g. "username"/"password").
    target_account slot: {{target_account}} in string values is replaced at runtime.
    oracle_type: "redirect" = _is_login_success (302 away from login) — extendable.
    """
    endpoint_pattern: str        # e.g. "/login"
    method:           str        # POST
    username_field:   str        # e.g. "username"
    password_field:   str        # e.g. "password"
    bypass_payloads:  list[dict] # each dict is merged into the login body; {{target_account}} rendered
    oracle_type:      str        # "redirect"
    max_attempts:     int        # cap on payload tries
    concurrency:      int        # parallel attempts (usually 1 for auth)


def load_auth_bypass_template(concept_id: str) -> "AuthBypassTemplate | None":
    """Load and parse the EXEC-AUTH-BYPASS block from a concept file. Never raises."""
    try:
        return _load_auth_bypass(concept_id)
    except Exception:
        return None


def _load_auth_bypass(concept_id: str) -> "AuthBypassTemplate | None":
    filepath = _find_concept_file(concept_id)
    if filepath is None:
        return None
    content = filepath.read_text(encoding="utf-8", errors="replace")

    m = _EXEC_AUTH_BYPASS_INNER_RE.search(content)
    if not m:
        return None
    inner = m.group(1)

    ym = _YAML_FENCE_RE.search(inner)
    yaml_str = ym.group(1).strip() if ym else inner.strip()
    if not yaml_str:
        return None

    import yaml as _yaml
    data = _yaml.safe_load(yaml_str)
    if not isinstance(data, dict):
        return None

    tmpl = data.get("auth_bypass_template")
    if not isinstance(tmpl, dict):
        return None

    raw_payloads = tmpl.get("bypass_payloads", [])
    if not isinstance(raw_payloads, list):
        raw_payloads = []

    return AuthBypassTemplate(
        endpoint_pattern = str(tmpl.get("endpoint_pattern", "/login")),
        method           = str(tmpl.get("method", "POST")).upper(),
        username_field   = str(tmpl.get("username_field", "username")),
        password_field   = str(tmpl.get("password_field", "password")),
        bypass_payloads  = [dict(p) for p in raw_payloads if isinstance(p, dict)],
        oracle_type      = str(tmpl.get("oracle_type", "redirect")),
        max_attempts     = int(tmpl.get("max_attempts", 10)),
        concurrency      = int(tmpl.get("concurrency", 1)),
    )


# ── Objective → target_account extractor ─────────────────────────────────────

_TARGET_PATTERNS = [
    r"log\s+in\s+as\s+(?:the\s+)?([a-zA-Z0-9_]+)",
    r"as\s+the\s+([a-zA-Z0-9_]+)\s+user",
    r"(?:extract|retrieve|get)\s+([a-zA-Z0-9_]+)(?:'s|s')?\s+password",
    r"password\s+for\s+(?:the\s+)?([a-zA-Z0-9_]+)(?:\s+user)?",
    r"(?:log\s+in|login)\s+as\s+([a-zA-Z0-9_]+)",
]


@dataclass
class WhereEnumTemplate:
    """Template for $where JavaScript injection field-name enumeration (EXEC-WHERE-ENUM block).

    Strategy: keys_enumeration — reads real field names from a MongoDB document via
    Object.keys(this) in a $where expression. Superior to dictionary_scan because it
    reads the ACTUAL schema instead of guessing from a wordlist.

    All lab-specific knowledge (endpoint, payloads, oracle signal, validation endpoint)
    lives here. OracleSearchEngine is generic — the technique is reusable on any
    $where-vulnerable MongoDB target.

    Slots: {{target_account}}, {{count}}, {{index}}, {{prefix}}, {{range}}, {{field}}.
    """
    endpoint_pattern:   str    # e.g. "/login"
    method:             str    # POST
    content_type:       str    # "json"
    key_count_body:     str    # body template with {{target_account}}, {{count}}
    key_name_body:      str    # body template with {{target_account}}, {{index}}, {{prefix}}, {{range}}
    validate_endpoint:  str    # e.g. "/forgot-password"
    validate_method:    str    # GET
    validate_param:     str    # e.g. "{{field}}"
    validate_value:     str    # e.g. "invalid_test"
    validate_oracle:    dict   # {type: content_match, signal: "Invalid token"}
    validate_status:    int    # expected HTTP status (e.g. 400)
    charset:            str    # field-name charset
    max_keys:           int    # stop after this many keys
    max_key_length:     int    # stop key name extraction here
    oracle_spec:        dict   # {type: content_match, signal: "Account locked"}
    max_requests:       int    # cap
    concurrency:        int    # Semaphore bound (usually 1 for sequential)


# regex for EXEC-WHERE-ENUM blocks
_EXEC_WHERE_ENUM_INNER_RE = re.compile(
    r"<!--\s*EXEC-WHERE-ENUM-START\s*-->(.*?)<!--\s*EXEC-WHERE-ENUM-END\s*-->",
    re.DOTALL | re.IGNORECASE,
)
_EXEC_WHERE_EXTRACT_INNER_RE = re.compile(
    r"<!--\s*EXEC-WHERE-EXTRACT-START\s*-->(.*?)<!--\s*EXEC-WHERE-EXTRACT-END\s*-->",
    re.DOTALL | re.IGNORECASE,
)


def load_where_extract_template(concept_id: str) -> "ExtractionTemplate | None":
    """Load EXEC-WHERE-EXTRACT block — reuses ExtractionTemplate (body_template=json). Never raises."""
    try:
        return _load_where_extract(concept_id)
    except Exception:
        return None


def _load_where_extract(concept_id: str) -> "ExtractionTemplate | None":
    filepath = _find_concept_file(concept_id)
    if filepath is None:
        return None
    content = filepath.read_text(encoding="utf-8", errors="replace")

    m = _EXEC_WHERE_EXTRACT_INNER_RE.search(content)
    if not m:
        return None
    inner = m.group(1)
    ym = _YAML_FENCE_RE.search(inner)
    yaml_str = ym.group(1).strip() if ym else inner.strip()
    if not yaml_str:
        return None

    import yaml as _yaml
    data = _yaml.safe_load(yaml_str)
    if not isinstance(data, dict):
        return None

    tmpl = data.get("where_extract_template")
    if not isinstance(tmpl, dict):
        return None

    # Reuse ExtractionTemplate — same dataclass, different body_template
    return ExtractionTemplate(
        endpoint_pattern      = str(tmpl.get("endpoint_pattern", "/login")),
        method                = str(tmpl.get("method", "POST")).upper(),
        base_param            = str(tmpl.get("base_param", "")),
        target_field          = str(tmpl.get("target_field", "")),
        length_payload        = str(tmpl.get("length_payload", "")),
        char_payload          = str(tmpl.get("char_payload", "")),
        charset               = str(tmpl.get("charset", "abcdefghijklmnopqrstuvwxyz0123456789")),
        max_length            = int(tmpl.get("max_length", 30)),
        max_requests          = int(tmpl.get("max_requests", 600)),
        concurrency           = int(tmpl.get("concurrency", 1)),
        oracle_spec           = dict(tmpl.get("oracle") or {}),
        content_type          = "json",
        body_template         = str(tmpl.get("body_template", "")),
        length_body_template  = str(tmpl.get("length_body_template", "")),
    )


def load_where_enum_template(concept_id: str) -> "WhereEnumTemplate | None":
    """Load and parse the EXEC-WHERE-ENUM block from a concept file. Never raises."""
    try:
        return _load_where_enum(concept_id)
    except Exception:
        return None


def _load_where_enum(concept_id: str) -> "WhereEnumTemplate | None":
    filepath = _find_concept_file(concept_id)
    if filepath is None:
        return None
    content = filepath.read_text(encoding="utf-8", errors="replace")

    m = _EXEC_WHERE_ENUM_INNER_RE.search(content)
    if not m:
        return None
    inner = m.group(1)
    ym = _YAML_FENCE_RE.search(inner)
    yaml_str = ym.group(1).strip() if ym else inner.strip()
    if not yaml_str:
        return None

    import yaml as _yaml
    data = _yaml.safe_load(yaml_str)
    if not isinstance(data, dict):
        return None

    tmpl = data.get("where_enum_template")
    if not isinstance(tmpl, dict):
        return None

    return WhereEnumTemplate(
        endpoint_pattern  = str(tmpl.get("endpoint_pattern", "/login")),
        method            = str(tmpl.get("method", "POST")).upper(),
        content_type      = str(tmpl.get("content_type", "json")),
        key_count_body    = str(tmpl.get("key_count_body", "")),
        key_name_body     = str(tmpl.get("key_name_body", "")),
        validate_endpoint = str(tmpl.get("validate_endpoint", "")),
        validate_method   = str(tmpl.get("validate_method", "GET")).upper(),
        validate_param    = str(tmpl.get("validate_param", "{{field}}")),
        validate_value    = str(tmpl.get("validate_value", "invalid_test")),
        validate_oracle   = dict(tmpl.get("validate_oracle") or {}),
        validate_status   = int(tmpl.get("validate_status", 400)),
        charset           = str(tmpl.get("charset",
                              "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_")),
        max_keys          = int(tmpl.get("max_keys", 8)),
        max_key_length    = int(tmpl.get("max_key_length", 30)),
        oracle_spec       = dict(tmpl.get("oracle") or {}),
        max_requests      = int(tmpl.get("max_requests", 400)),
        concurrency       = int(tmpl.get("concurrency", 1)),
    )


def extract_target_account(objective: str) -> str | None:
    """Parse the target account name from an investigation objective string.

    Patterns:
    - "log in as carlos"          → "carlos"
    - "log in as the X user"      → "X"
    - "extract X's password"      → "X"
    - "password for the X user"   → "X"

    Returns None if no pattern matches (caller falls back to template default).
    Case-insensitive matching. Never raises.
    """
    try:
        obj_lower = objective.lower()
        for pattern in _TARGET_PATTERNS:
            m = re.search(pattern, obj_lower)
            if m:
                return m.group(1)
        return None
    except Exception:
        return None


def render_payload(template: ExecutionTemplate, ctx: dict) -> dict:
    """Substitute {{placeholder}} values from ctx into payload_template.

    ctx keys: username, session, target, endpoint.
    Raises MissingContext if a required placeholder is absent.
    Raises NeedsSession if template.requires_session and 'session' not in ctx.
    """
    if template.requires_session and "session" not in ctx:
        raise NeedsSession(template.engine_id)

    result: dict = {}
    for key, value in template.payload_template.items():
        rendered_str = str(value)
        for m in _PLACEHOLDER_RE.finditer(rendered_str):
            placeholder = m.group(1)
            if placeholder not in ctx:
                raise MissingContext(placeholder)
        result[key] = _PLACEHOLDER_RE.sub(
            lambda m, c=ctx: str(c[m.group(1)]), rendered_str
        )
    return result
