"""Gate registry — feature flags for engine behaviour at runtime.

Gates are in-memory toggles. They reset to defaults on process restart.
Thread-safe: all mutations go through _LOCK.

Current gates:
  nmap_external_scan  (default=False) — allow nmap against EXTERNAL targets.
                       When False, nmap only runs against LOCAL/PRIVATE targets.
                       When True, classification is bypassed entirely; nmap runs
                       against any target the operator supplies.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class Gate:
    gate_id: str
    description: str
    default: bool
    value: bool = field(init=False)

    def __post_init__(self) -> None:
        self.value = self.default


_LOCK = threading.Lock()

_REGISTERED_GATES: dict[str, Gate] = {
    "nuclei_severity_info": Gate(
        gate_id="nuclei_severity_info",
        description=(
            "Run nuclei templates that produce info-severity findings."
            " Default ON — informational findings are low-noise and always useful."
        ),
        default=True,
    ),
    "nuclei_severity_low": Gate(
        gate_id="nuclei_severity_low",
        description=(
            "Run nuclei templates that produce low-severity findings."
            " Default ON — low findings indicate surface exposure worth tracking."
        ),
        default=True,
    ),
    "nuclei_severity_medium": Gate(
        gate_id="nuclei_severity_medium",
        description=(
            "Run nuclei templates that produce medium-severity findings."
            " Default OFF — medium findings can be noisy; enable when deeper coverage needed."
        ),
        default=False,
    ),
    "nuclei_severity_high": Gate(
        gate_id="nuclei_severity_high",
        description=(
            "Run nuclei templates that produce high-severity findings."
            " Default OFF — enable when actively hunting high-severity vulnerabilities."
        ),
        default=False,
    ),
    "nuclei_severity_critical": Gate(
        gate_id="nuclei_severity_critical",
        description=(
            "Run nuclei templates that produce critical-severity findings."
            " Default OFF — enable for targeted critical-vuln campaigns."
        ),
        default=False,
    ),
    "nmap_external_scan": Gate(
        gate_id="nmap_external_scan",
        description=(
            "Allow nmap to scan EXTERNAL targets (PortSwigger labs, internet hosts)."
            " Default OFF — nmap runs only against local/private targets."
        ),
        default=False,
    ),
    "ssh_credential_testing": Gate(
        gate_id="ssh_credential_testing",
        description=(
            "Run SSH default-credential validation against discovered SSH services."
            " Uses paramiko with the ssh_credentials_default wordlist."
        ),
        default=False,
    ),
    "telnet_credential_capture": Gate(
        gate_id="telnet_credential_capture",
        description=(
            "Run Telnet cleartext-credential capture against discovered Telnet services."
            " Proves cleartext transmission by sending a test username."
        ),
        default=False,
    ),
    "smb_null_session_enum": Gate(
        gate_id="smb_null_session_enum",
        description=(
            "Run SMB null-session enumeration against discovered SMB services."
            " Uses impacket when available; falls back to TCP+SMB2 probe."
        ),
        default=False,
    ),
    "wordpress_vuln_check": Gate(
        gate_id="wordpress_vuln_check",
        description=(
            "Run WordPress vulnerability checks against discovered HTTP services."
            " Tests SQLi, version disclosure, user enum, XML-RPC, and config exposure."
        ),
        default=False,
    ),
    "drupal_vuln_check": Gate(
        gate_id="drupal_vuln_check",
        description=(
            "Run Drupal vulnerability checks against discovered HTTP services."
            " Tests Drupalgeddon2, version disclosure, default files, admin, and API exposure."
        ),
        default=False,
    ),
    "apache_misconfig_check": Gate(
        gate_id="apache_misconfig_check",
        description=(
            "Run Apache misconfiguration checks against discovered HTTP services."
            " Tests version disclosure, sensitive paths, HTTP methods, and directory listing."
        ),
        default=False,
    ),
    "nginx_misconfig_check": Gate(
        gate_id="nginx_misconfig_check",
        description=(
            "Run Nginx misconfiguration checks against discovered HTTP services."
            " Tests version disclosure, default page, misconfig paths, and security headers."
        ),
        default=False,
    ),
    "zap_passive_scan": Gate(
        gate_id="zap_passive_scan",
        description=(
            "When ON, ZAP performs passive analysis of HTTP traffic to the target"
            " (response header checks, cookie analysis, information disclosure detection)."
            " Read-only — no payloads sent. Run after spider for best coverage."
        ),
        default=False,
    ),
    "zap_spider": Gate(
        gate_id="zap_spider",
        description=(
            "When ON, ZAP crawls the target to discover URLs, forms, and parameters."
            " Used for endpoint enumeration. Generates HTTP traffic visible in access logs."
        ),
        default=False,
    ),
}


def get_gate(gate_id: str) -> bool:
    with _LOCK:
        gate = _REGISTERED_GATES.get(gate_id)
        if gate is None:
            raise KeyError(f"Unknown gate: {gate_id!r}")
        return gate.value


def set_gate(gate_id: str, value: bool) -> None:
    with _LOCK:
        gate = _REGISTERED_GATES.get(gate_id)
        if gate is None:
            raise KeyError(f"Unknown gate: {gate_id!r}")
        gate.value = value


def list_gates() -> list[dict]:
    with _LOCK:
        return [
            {
                "gate_id": g.gate_id,
                "description": g.description,
                "default": g.default,
                "value": g.value,
            }
            for g in _REGISTERED_GATES.values()
        ]


def reset_all_gates_to_defaults() -> None:
    with _LOCK:
        for gate in _REGISTERED_GATES.values():
            gate.value = gate.default


def engine_is_visible(engine: object) -> bool:
    """Return True if *engine* should be dispatched given current gate states.

    Visibility rules:
    - gate_id (single)  : visible iff that one gate is ON.
    - gate_ids (tuple)  : visible iff ANY gate in the tuple is ON.
    - Both declared     : fail-closed (return False, log error — bad engine config).
    - Neither declared  : always visible (ungated engine).

    KeyError from get_gate means the gate_id is unknown → fail-closed.
    """
    import logging as _log

    _logger = _log.getLogger("conductor.gates")

    has_single = getattr(engine, "gate_id", None) is not None
    has_multi = bool(getattr(engine, "gate_ids", None))

    if has_single and has_multi:
        _logger.error(
            "engine %s declares both gate_id and gate_ids — fail-closed",
            getattr(engine, "engine_id", repr(engine)),
        )
        return False

    if has_single:
        gate_id = engine.gate_id  # type: ignore[attr-defined]
        try:
            return get_gate(gate_id)
        except KeyError:
            _logger.error(
                "engine %s has unknown gate_id=%r — engine BLOCKED",
                getattr(engine, "engine_id", repr(engine)), gate_id,
            )
            return False

    if has_multi:
        gate_ids: tuple[str, ...] = engine.gate_ids  # type: ignore[attr-defined]
        for gate_id in gate_ids:
            try:
                if get_gate(gate_id):
                    return True
            except KeyError:
                _logger.error(
                    "engine %s has unknown gate_id=%r in gate_ids — treating as OFF",
                    getattr(engine, "engine_id", repr(engine)), gate_id,
                )
        return False

    return True  # ungated engine
