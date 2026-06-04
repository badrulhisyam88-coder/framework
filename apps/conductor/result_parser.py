"""Phase C-3 — Engine result parser.

Translates raw artifact/exhaustion_record dicts from exploitation_branches into
structured ParsedResult objects for Zone 3 rendering.

parse_engine_result() reads the actual artifact shapes emitted by each engine
(confirmed from source — do not change this without re-reading the engine files).

Never raises — returns ParsedResult(status="fail") on any exception.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParsedResult:
    engine_id:        str
    status:           str             # "success" | "partial" | "fail" | "exhausted"
    summary:          str             # one plain-language sentence, operator-readable
    key_findings:     list[str]       # extracted facts shown as bullets
    session_captured: bool            # True when a session cookie was captured
    session_data:     dict | None     # {"username": ..., "cookies": ...} if captured


# ── Public API ─────────────────────────────────────────────────────────────────

def parse_engine_result(
    engine_id: str,
    artifact: dict | None,
    exhaustion_record: dict | None = None,
    state: str = "",
) -> ParsedResult:
    """Parse raw exploitation_branches data into a structured ParsedResult.

    Args:
        engine_id:         engine that ran (e.g. "credential_brute")
        artifact:          branch.artifact dict (None if engine exhausted or failed)
        exhaustion_record: branch.exhaustion_record dict (None if engine succeeded)
        state:             branch.state ("succeeded" | "exhausted" | "failed" | ...)

    Returns ParsedResult. Never raises.
    """
    try:
        return _parse(engine_id, artifact or {}, exhaustion_record or {}, state)
    except Exception as exc:
        return ParsedResult(
            engine_id=engine_id,
            status="fail",
            summary=f"Result received but could not be parsed ({exc})",
            key_findings=[],
            session_captured=False,
            session_data=None,
        )


# ── Internal dispatch ──────────────────────────────────────────────────────────

def _parse(engine_id: str, artifact: dict, exh: dict, state: str) -> ParsedResult:
    # The BranchRecord.artifact may be stored as {"artifact": {...inner...}} (the full
    # emit_stage payload) or as the inner dict directly.  Unwrap the outer wrapper if present.
    if "artifact" in artifact and isinstance(artifact.get("artifact"), dict):
        artifact = artifact["artifact"]
    atype = artifact.get("artifact_type", "")

    # Terminal state from branch.state
    is_exhausted = (state == "exhausted") or bool(exh)
    is_success   = (state == "succeeded") and bool(artifact)

    if not is_success and is_exhausted:
        return _parse_exhausted(engine_id, exh)

    if not is_success:
        return ParsedResult(engine_id=engine_id, status="fail",
                            summary="Engine did not find a result.", key_findings=[],
                            session_captured=False, session_data=None)

    # Route by artifact_type (confirmed from each engine source file)
    if atype == "captured_session":
        return _parse_captured_session(engine_id, artifact)
    if atype == "bookmarklet_href":
        return _parse_sqli_bypass(engine_id, artifact)
    if atype in ("mass_assignment_result", "idor_evidence", "access_control_note"):
        return _parse_access_control(engine_id, artifact, atype)
    if atype == "xss_evidence":
        return _parse_xss(engine_id, artifact)
    if atype == "cmdi_evidence":
        return _parse_cmdi(engine_id, artifact)
    if atype == "endpoint_list":
        return _parse_js_spider(engine_id, artifact)
    if atype in ("msf_session_opened", "msf_module_success", "msf_session", "msf_result"):
        return _parse_metasploit(engine_id, artifact, atype)

    # Unknown — show partial result
    findings = []
    if artifact:
        for k, v in list(artifact.items())[:4]:
            if k != "artifact_type" and isinstance(v, (str, int, float, bool)):
                findings.append(f"{k}: {str(v)[:80]}")
    return ParsedResult(engine_id=engine_id, status="partial",
                        summary="Result received.", key_findings=findings,
                        session_captured=False, session_data=None)


def _parse_exhausted(engine_id: str, exh: dict) -> ParsedResult:
    reason = exh.get("reason", "unknown")
    neg    = exh.get("negative_evidence", {})
    findings = [f"Reason: {reason}"]
    if neg:
        for k, v in list(neg.items())[:3]:
            findings.append(f"{k}: {v}")
    return ParsedResult(engine_id=engine_id, status="exhausted",
                        summary=f"{engine_id} tried all payloads — no result found.",
                        key_findings=findings, session_captured=False, session_data=None)


def _parse_captured_session(engine_id: str, art: dict) -> ParsedResult:
    # credential_brute + default_creds both emit artifact_type=captured_session
    # Fields: username, password, login_url, cookies, session_cookies, status_code
    username = art.get("username") or art.get("user") or ""
    password = art.get("password") or ""
    cookies  = art.get("session_cookies") or art.get("cookies") or {}
    url      = art.get("login_url", "")

    findings = []
    if username:
        findings.append(f"Credentials accepted: {username}:{password}" if password else f"User: {username}")
    if cookies:
        cookie_names = list(cookies.keys())[:3]
        findings.append(f"Session cookies captured: {', '.join(cookie_names)}")
    if url:
        findings.append(f"Login endpoint: {url}")

    # Surface the credential in the summary so the operator sees it in the
    # bottom progress trail without opening the artifact panel.
    if username and password:
        _cred_str = f"{username} / {password}"
    elif username:
        _cred_str = username
    else:
        _cred_str = "user"
    return ParsedResult(
        engine_id=engine_id, status="success",
        summary=f"SOLVED — credentials: {_cred_str} (session captured).",
        key_findings=findings, session_captured=True,
        session_data={"username": username, "cookies": cookies},
    )


def _parse_sqli_bypass(engine_id: str, art: dict) -> ParsedResult:
    # sqli_auth_bypass: artifact_type=bookmarklet_href
    # Fields: bookmarklet_href, login_url, payload_used, session_cookies
    payload  = art.get("payload_used") or art.get("payload") or ""
    login_url = art.get("login_url", "")
    cookies  = art.get("session_cookies") or {}
    findings = []
    if payload:
        findings.append(f"Payload: {str(payload)[:80]}")
    if login_url:
        findings.append(f"Endpoint: {login_url}")
    if cookies:
        findings.append(f"Session cookies: {', '.join(list(cookies.keys())[:3])}")
    session_captured = bool(cookies)
    return ParsedResult(
        engine_id=engine_id, status="success",
        summary="SQL injection auth bypass confirmed — session captured.",
        key_findings=findings,
        session_captured=session_captured,
        session_data={"cookies": cookies} if session_captured else None,
    )


def _parse_access_control(engine_id: str, art: dict, atype: str) -> ParsedResult:
    # access_control: mass_assignment_result, idor_evidence, access_control_note
    if atype == "access_control_note":
        note = art.get("note") or art.get("description", "Note recorded.")
        return ParsedResult(engine_id=engine_id, status="partial",
                            summary=note[:120], key_findings=[],
                            session_captured=False, session_data=None)
    findings = []
    if atype == "idor_evidence":
        endpoint = art.get("endpoint") or art.get("path", "")
        target_user = art.get("target_user") or art.get("victim", "")
        if endpoint:  findings.append(f"Endpoint: {endpoint}")
        if target_user: findings.append(f"Accessed resource for: {target_user}")
    elif atype == "mass_assignment_result":
        payload = art.get("payload") or {}
        endpoint = art.get("endpoint", "")
        if endpoint: findings.append(f"Endpoint: {endpoint}")
        if payload: findings.append(f"Injected: {str(payload)[:60]}")
        status_code = art.get("status_code")
        if status_code: findings.append(f"Response: HTTP {status_code}")
    return ParsedResult(engine_id=engine_id, status="success",
                        summary="Access control vulnerability confirmed.",
                        key_findings=findings, session_captured=False, session_data=None)


def _parse_xss(engine_id: str, art: dict) -> ParsedResult:
    # xss_exploit_engine: artifact_type=xss_evidence
    payload = art.get("payload") or art.get("payload_used") or ""
    param   = art.get("param") or art.get("parameter", "")
    url     = art.get("url") or art.get("target_url", "")
    severity = art.get("severity", "")
    findings = []
    if param:    findings.append(f"Injection parameter: {param}")
    if payload:  findings.append(f"Payload: {str(payload)[:80]}")
    if url:      findings.append(f"URL: {url[:80]}")
    if severity: findings.append(f"Severity: {severity}")
    return ParsedResult(engine_id=engine_id, status="success",
                        summary="Reflected XSS confirmed — payload executed in response.",
                        key_findings=findings, session_captured=False, session_data=None)


def _parse_cmdi(engine_id: str, art: dict) -> ParsedResult:
    # cmdi_reflected, cmdi_blind_time, cmdi_blind_boolean: artifact_type=cmdi_evidence
    path     = art.get("path") or art.get("full_url", "")
    param    = art.get("param_name") or art.get("param", "")
    excerpt  = art.get("body_excerpt") or art.get("output_excerpt", "")
    delay    = art.get("sleep_payload") or art.get("delay_confirmed", "")
    payload  = art.get("payload") or art.get("sep_template", "")
    findings = []
    if path:    findings.append(f"Endpoint: {str(path)[:80]}")
    if param:   findings.append(f"Parameter: {param}")
    if excerpt and excerpt != "(time-based blind — no body to capture; detection by elapsed time)":
        findings.append(f"Output: {str(excerpt)[:80]}")
    if delay:   findings.append(f"Trigger: {str(delay)[:60]}")
    if payload and not delay:
        findings.append(f"Payload: {str(payload)[:60]}")
    return ParsedResult(engine_id=engine_id, status="success",
                        summary="Command injection confirmed.",
                        key_findings=findings, session_captured=False, session_data=None)


def _parse_js_spider(engine_id: str, art: dict) -> ParsedResult:
    endpoints = art.get("discovered_endpoints") or []
    pages     = art.get("pages_fetched", 0)
    js_files  = art.get("js_files_parsed", 0)
    findings  = [f"{len(endpoints)} endpoint(s) discovered"]
    if pages:    findings.append(f"Pages crawled: {pages}")
    if js_files: findings.append(f"JS files parsed: {js_files}")
    for ep in endpoints[:5]:
        findings.append(f"  · {ep}")
    if len(endpoints) > 5:
        findings.append(f"  … and {len(endpoints) - 5} more")
    return ParsedResult(
        engine_id=engine_id, status="success" if endpoints else "partial",
        summary=(f"JS spider discovered {len(endpoints)} endpoint(s)."
                 if endpoints else "JS spider found no endpoints."),
        key_findings=findings, session_captured=False, session_data=None,
    )


def _parse_metasploit(engine_id: str, art: dict, atype: str) -> ParsedResult:
    module   = art.get("module_path") or art.get("module", "")
    intent   = art.get("intent", "")
    session  = art.get("session_id") or art.get("session", "")
    findings = []
    if module:  findings.append(f"Module: {module}")
    if intent:  findings.append(f"Intent: {intent}")
    if session: findings.append(f"Session ID: {session}")
    success = (atype == "msf_session_opened") or bool(session)
    return ParsedResult(
        engine_id=engine_id,
        status="success" if success else "partial",
        summary=("Metasploit session opened — RCE confirmed."
                 if success else "Metasploit module executed successfully."),
        key_findings=findings, session_captured=False, session_data=None,
    )
