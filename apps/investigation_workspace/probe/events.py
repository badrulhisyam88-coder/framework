"""Event vocabulary the passive probe emits.

The runtime consumes these in order. Each event becomes one or more nodes
on the topology — stage events become reasoning nodes, finding events
become real persisted findings (NormalizedFinding insert in the DB).

Kept as plain dataclasses (no LLM, no scoring) so the relationship between
"the probe saw X" and "the topology shows Y" is fully traceable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Phase = Literal["recon", "enumeration", "exploitation"]


@dataclass(frozen=True)
class StageEvent:
    """A reasoning step the probe is performing right now.

    Becomes a reasoning node on the topology with the metadata as its
    'actions / tools / detected / confidence' record.
    """
    label:      str
    actions:    tuple[str, ...] = ()
    tools:      tuple[str, ...] = ()
    detected:   tuple[str, ...] = ()
    confidence: str             = "—"


@dataclass(frozen=True)
class FindingEvent:
    """A real finding the probe discovered. Persists as NormalizedFinding.

    The probe only emits this when the underlying condition is actually
    observed in the response. Evidence is captured in raw_data so the
    operator can verify the finding against the original probe output.

    V1.6 optional fields (default None — existing probes unchanged):
      id          — stable deterministic finding ID from finding_id.generate_finding_id().
                    None means the probe didn't generate one; persistence layer
                    falls back to its own UUID.
      confidence  — how sure the probe is: "high" | "medium" | "low".
                    Distinct from severity (how bad). None means undeclared.
      next_actions — list of action descriptors this finding recommends.
                    Schema per item:
                    {
                      "probe_id":        str,        # which probe this action triggers
                      "trigger":         str,        # "operator_arm_required" |
                                                     # "operator_confirm_required" |
                                                     # "auto_fire"
                      "description":     str,        # human-readable, what the action does
                      "required_inputs": list[str],  # input field names that must be
                                                     # filled before execution ([] = none)
                      "produces":        str | None, # capability on success, e.g.
                                                     # "authenticated_session",
                                                     # "endpoint_inventory", None
                    }
                    Enforced by convention only in PR0. PR3 may add a runtime validator.
    """
    after_stage_index: int
    finding_type:      str
    title:             str
    severity:          str          # critical | high | medium | low | info
    description:       str
    endpoint:          str | None        = None
    port:              int | None        = None
    evidence:          dict              = field(default_factory=dict)
    phase:             Phase             = "recon"
    # V1.6 additive fields — default None, existing probes unaffected
    id:                str | None        = None
    confidence:        str | None        = None
    next_actions:      list[dict] | None = None
    # Producer identity — set by StorageBridge from finding["probe_id"].
    # Empty string for legacy bootstrap probes that don't set probe_id.
    source_scanner:    str               = ""


@dataclass(frozen=True)
class ResultEvent:
    """An execution probe's real outcome — becomes a result node.

    Phase 49 — suggestion-driven probes yield these when they have a
    concrete observable (a file fetched, an origin enumerated, a header
    confirmed). evidence is shown to the operator when they Expand the
    result node, so the conclusion is auditable.

    Phase 54 — structured `payload` field added. Optional: legacy
    probes keep emitting `evidence: dict` and a None payload, and the
    renderer falls back to flattening the evidence dict (legacy mode).

    Phase 56 — probe-emitted next_actions belong INSIDE the payload,
    not as a separate ResultEvent field. The Phase 55 pilot surfaced
    that resolve_next_actions() reads `payload["next_actions"]` and
    the top-level ResultEvent.next_actions was dead. Removed in 56.

    kind vocabulary (matches topology status mapping):
      detected  — concrete observation worth showing
      blocked   — the threat surface this would exploit is mitigated
      persists  — the underlying condition is still present
      note      — informational

    payload shape (all sub-fields optional except analysis):
      {
        "request":      {method, url, headers, body},
        "response":     {status, headers, body_excerpt, full_body_ref},
        "sent":         {payload_string, encoding, injection_point},
        "observed":     {reflected_at, sanitization, execution_context,
                         indicators},
        "analysis":     {confirmed: bool, severity, exploitability_notes,
                         references: [{label, url}, ...]},
        "next_actions": [{action_kind, label, reason}, ...]   # optional;
                        # when present, OVERRIDES the catalog default
                        # for the resolved exploit path. action_kinds
                        # MUST be registered in the suggestions catalog
                        # — unregistered ones produce broken ghost clicks.
      }

    Example next_actions entry:
        {
          "action_kind": "csp_xss_reflected",
          "label":       "Test reflected XSS payload",
          "reason":      "CSP gap permits inline scripts",
        }
    """
    label:    str
    kind:     str
    evidence: dict = field(default_factory=dict)
    # Phase 54 — structured exploit payload. None signals legacy.
    payload:  dict | None = None
