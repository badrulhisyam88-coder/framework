"""Deterministic technique-name → engine_id resolver.

Intercepts the chat→engine routing path BEFORE the 7B model sees it.
When the operator names a technique explicitly, the router maps it directly
to an engine_id without LLM inference — the source of flaky/null results.
The AI is only involved in OPEN asks ("what can be exploited here").

Alias derivation: general security terminology + engine label equivalents +
  concept titles/when_to_use text. No lab-specific strings.
"""
from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Engine label map — mirrors _ENGINE_LABELS in exploitation-mindmap.js.
# Used by routes to build human-readable approval-card text.
# ---------------------------------------------------------------------------
ENGINE_LABELS: dict[str, str] = {
    "username_enum":      "Enumerate username via response differential",
    "credential_brute":   "Brute-force credentials",
    "sqli_auth_bypass":   "Test SQL injection auth bypass",
    "access_control":     "Test IDOR / broken access control",
    "default_creds":      "Try default credentials",
    "js_spider":          "Spider JS for hidden endpoints",
    "xss_reflected":      "Test reflected XSS",
    "cmdi_reflected":     "Test reflected command injection",
    "cmdi_blind_time":    "Test time-based blind command injection",
    "cmdi_blind_boolean": "Test boolean-blind command injection",
    "metasploit_recipe":  "Run Metasploit recipe modules",
}

# ---------------------------------------------------------------------------
# Engine descriptions for the grounded-AI system prompt (open asks).
# One line per engine, shown verbatim to the model so it reasons from reality.
# ---------------------------------------------------------------------------
ENGINE_DESCRIPTIONS: dict[str, str] = {
    "username_enum":      "enumerate valid usernames via response differential (body/length/status oracle)",
    "credential_brute":   "brute-force login credentials with a wordlist",
    "sqli_auth_bypass":   "test SQL injection for authentication bypass",
    "access_control":     "test IDOR, broken access control, BOLA, mass assignment",
    "default_creds":      "try vendor default credentials against API/login endpoints",
    "js_spider":          "authenticated crawl of JS files to discover hidden API endpoints",
    "xss_reflected":      "test reflected cross-site scripting",
    "cmdi_reflected":     "test reflected OS command injection",
    "cmdi_blind_time":    "test time-based blind OS command injection",
    "cmdi_blind_boolean": "test boolean-based blind OS command injection",
    "metasploit_recipe":  "run Metasploit module recipes against a service",
}

# ---------------------------------------------------------------------------
# Alias table: (lowercase-phrase → engine_id or None)
#
# None = technique recognised but no engine exists yet.
# Phrases are checked in order — put LONGER / MORE SPECIFIC phrases first
# within each group so the most specific match wins via early-return.
# Sources: engine IDs, SUGGESTIONS catalog labels, concept when_to_use/titles,
#   standard OWASP/PortSwigger terminology.  No lab URLs, no lab-specific names.
# ---------------------------------------------------------------------------
_ALIASES: list[tuple[str, str | None]] = [
    # ── username_enum ────────────────────────────────────────────────────────
    ("username enumeration by length",      "username_enum"),
    ("enumerate usernames by length",       "username_enum"),
    ("enumerate username by length",        "username_enum"),
    ("username enum by length",             "username_enum"),
    ("length-based username enumeration",   "username_enum"),
    ("length differential enumeration",     "username_enum"),
    ("username enumeration by status",      "username_enum"),
    ("enumerate usernames by status",       "username_enum"),
    ("status differential enumeration",     "username_enum"),
    ("username enumeration",               "username_enum"),
    ("enumerate usernames",                "username_enum"),
    ("enumerate username",                 "username_enum"),
    ("user enumeration",                   "username_enum"),
    ("username enum",                      "username_enum"),
    ("user enum",                          "username_enum"),
    # ── credential_brute ────────────────────────────────────────────────────
    ("brute force credentials",             "credential_brute"),
    ("brute-force credentials",             "credential_brute"),
    ("credential brute force",              "credential_brute"),
    ("brute force login",                   "credential_brute"),
    ("brute-force login",                   "credential_brute"),
    ("password brute force",                "credential_brute"),
    ("password brute-force",                "credential_brute"),
    ("brute force password",                "credential_brute"),
    ("credential brute",                    "credential_brute"),
    ("password brute",                      "credential_brute"),
    ("password attack",                     "credential_brute"),
    ("brute force",                         "credential_brute"),
    ("brute-force",                         "credential_brute"),
    ("bruteforce",                          "credential_brute"),
    # ── none-yet: nosql must precede sqli entries (substring conflict) ──────
    # "nosql injection" contains "sql injection" — check nosql FIRST.
    ("nosql injection",                    None),
    ("operator injection",                 None),
    ("nosql",                              None),
    # ── sqli_auth_bypass ────────────────────────────────────────────────────
    ("sql injection auth bypass",           "sqli_auth_bypass"),
    ("sql injection authentication bypass", "sqli_auth_bypass"),
    ("sqli authentication bypass",          "sqli_auth_bypass"),
    ("sqli auth bypass",                    "sqli_auth_bypass"),
    ("sql injection bypass",                "sqli_auth_bypass"),
    ("sql injection login bypass",          "sqli_auth_bypass"),
    ("sql injection",                       "sqli_auth_bypass"),
    ("sqli bypass",                         "sqli_auth_bypass"),
    ("sqli",                                "sqli_auth_bypass"),
    # ── access_control ──────────────────────────────────────────────────────
    ("insecure direct object reference",    "access_control"),
    ("broken access control",               "access_control"),
    ("access control testing",              "access_control"),
    ("horizontal privilege escalation",     "access_control"),
    ("mass assignment attack",              "access_control"),
    ("privilege escalation",               "access_control"),
    ("mass assignment",                    "access_control"),
    ("access control",                     "access_control"),
    ("idor test",                          "access_control"),
    ("idor",                               "access_control"),
    ("bola",                               "access_control"),
    # ── default_creds ───────────────────────────────────────────────────────
    ("default credentials",                "default_creds"),
    ("default credential",                 "default_creds"),
    ("default passwords",                  "default_creds"),
    ("default password",                   "default_creds"),
    ("vendor defaults",                    "default_creds"),
    ("default creds",                      "default_creds"),
    # ── js_spider ───────────────────────────────────────────────────────────
    ("javascript spider",                  "js_spider"),
    ("js endpoint discovery",              "js_spider"),
    ("endpoint discovery",                 "js_spider"),
    ("js spider",                          "js_spider"),
    ("hidden endpoints",                   "js_spider"),
    ("spider js",                          "js_spider"),
    ("spider",                             "js_spider"),
    # ── xss_reflected ───────────────────────────────────────────────────────
    ("cross-site scripting",               "xss_reflected"),
    ("cross site scripting",               "xss_reflected"),
    ("reflected xss",                      "xss_reflected"),
    ("xss injection",                      "xss_reflected"),
    ("xss",                                "xss_reflected"),
    # ── cmdi engines ─────────────────────────────────────────────────────────
    ("time-based blind command injection",  "cmdi_blind_time"),
    ("time based blind command injection",  "cmdi_blind_time"),
    ("blind time command injection",        "cmdi_blind_time"),
    ("command injection time",              "cmdi_blind_time"),
    ("boolean blind command injection",     "cmdi_blind_boolean"),
    ("boolean-based blind command injection","cmdi_blind_boolean"),
    ("command injection boolean",           "cmdi_blind_boolean"),
    ("blind command injection",             "cmdi_blind_time"),
    ("reflected command injection",         "cmdi_reflected"),
    ("os command injection",                "cmdi_reflected"),
    ("command injection",                   "cmdi_reflected"),
    ("os injection",                        "cmdi_reflected"),
    ("cmdi",                                "cmdi_reflected"),
    # ── metasploit_recipe ───────────────────────────────────────────────────
    ("metasploit recipe",                  "metasploit_recipe"),
    ("metasploit module",                  "metasploit_recipe"),
    ("metasploit",                         "metasploit_recipe"),
    ("msf module",                         "metasploit_recipe"),
    ("msf",                                "metasploit_recipe"),
    # ── none-yet techniques (remaining; nosql entries moved above sqli) ────
    # Recognised as valid technique names; no engine wired yet.
    # Caller must show "no engine yet" message, never a silent null.
    ("xml injection",                      None),
    ("xml external entity",                None),
    ("xxe",                                None),
    ("server side request forgery",        None),
    ("ssrf",                               None),
    ("server side template injection",     None),
    ("ssti",                               None),
    ("template injection",                 None),
    ("path traversal",                     None),
    ("directory traversal",               None),
    ("insecure deserialization",           None),
    ("deserialization",                    None),
]

# Oracle-strategy clue sets — only checked when matched engine is username_enum.
_LENGTH_ORACLE_CLUES: frozenset[str] = frozenset({
    "by length", "length differential", "length-based", "length outlier",
    "response length", "same message", "same text", "same body",
    "different length", "subtle difference",
})

_STATUS_ORACLE_CLUES: frozenset[str] = frozenset({
    "by status", "status code", "status differential", "status outlier",
    "different status", "response code",
})

_TIMING_ORACLE_CLUES: frozenset[str] = frozenset({
    "by timing", "response time", "timing differential", "time differential",
    "time-based", "timing oracle", "slow response", "response time outlier",
    "timing outlier", "bcrypt", "argon2", "password hash", "by time",
})


@dataclass
class RouteResult:
    """Result of technique-name resolution."""
    is_explicit:      bool       = False  # True = recognised technique in text
    engine_id:        str | None = None   # None = technique exists but no engine yet
    oracle_strategy:  str | None = None   # "length" | "status" | None (→ default "message")
    technique_phrase: str        = ""     # matched alias phrase, for display


def resolve_technique(text: str) -> RouteResult:
    """Return routing result for a user's chat message.

    Walk _ALIASES in order (longer/more-specific first within each group).
    Return on first match — is_explicit=True with the matched engine_id.
    No match → is_explicit=False (open ask, hand off to AI).

    Never raises.
    """
    try:
        low = text.lower()
        for phrase, engine in _ALIASES:
            if phrase in low:
                oracle: str | None = None
                if engine == "username_enum":
                    if any(clue in low for clue in _TIMING_ORACLE_CLUES):
                        oracle = "timing"
                    elif any(clue in low for clue in _LENGTH_ORACLE_CLUES):
                        oracle = "length"
                    elif any(clue in low for clue in _STATUS_ORACLE_CLUES):
                        oracle = "status"
                return RouteResult(
                    is_explicit=True,
                    engine_id=engine,
                    oracle_strategy=oracle,
                    technique_phrase=phrase,
                )
    except Exception:
        pass
    return RouteResult()


def build_engine_menu(engine_ids: list[str]) -> str:
    """Return a concise engine menu string for null-fallback chat messages.

    Example: "username_enum (enumerate username), credential_brute (brute-force), ..."
    """
    parts = []
    for eid in sorted(engine_ids):
        desc = ENGINE_DESCRIPTIONS.get(eid, eid)
        parts.append(f"{eid} ({desc})")
    return "; ".join(parts)
