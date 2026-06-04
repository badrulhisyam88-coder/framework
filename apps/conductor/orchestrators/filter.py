"""FilterOrchestrator — applies V1.7 validation rules to recon findings.

Runs after recon phase completes. Reads findings from the wired
FindingsOrchestrator, applies the registered rule pipeline (first match
wins, order: drop → validate → incomplete), and persists results.

Two-pass when a reinvocation dispatcher is wired: after first pass,
reinvocation rules collect engine re-invocation requests, dispatch them
(deduped), then run a second filter pass on newly-added findings.

Findings that no rule matches remain 'pending'.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from apps.conductor.events.bus import EventBus
from apps.conductor.rules.base import ReinvocationRequest
from apps.conductor.rules.registry import REGISTERED_RULES, REINVOCATION_RULES

if TYPE_CHECKING:
    from apps.conductor.orchestrators.findings import FindingsOrchestrator

logger = logging.getLogger("conductor.orchestrators.filter")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class FilterOrchestrator:
    def __init__(
        self,
        investigation_id: str,
        bus: EventBus,
    ) -> None:
        self._investigation_id = investigation_id
        self._bus = bus
        self._findings_orch: FindingsOrchestrator | None = None
        self._update_fn = None  # optional async fn(finding_id, status, reason, gaps, validated_at)
        self._reinvoke_fn = None  # optional async fn(engine_id, config)
        self._block_reason_fn = None  # optional async fn(finding_id, reason)
        self._cancelled = False

        # Results stored keyed by finding_id
        self._results: dict[str, dict] = {}

    def wire_findings(self, findings_orch: FindingsOrchestrator) -> None:
        self._findings_orch = findings_orch

    def wire_db_writer(self, update_fn) -> None:
        """Wire an async callback for persisting validation results to DB.

        Signature: async update_fn(finding_id, status, reason, gaps_json, validated_at)
        """
        self._update_fn = update_fn

    def wire_reinvocation_dispatcher(self, fn) -> None:
        """Wire an async callback to dispatch engine re-invocations.

        Signature: async fn(engine_id: str, config: dict)
        When wired, run_filter() runs a second pass after dispatching
        re-invocations and waiting for their findings to be ingested.
        """
        self._reinvoke_fn = fn

    def wire_block_reason_writer(self, fn) -> None:
        """Wire an async callback for persisting enumeration_block_reason to DB.

        Signature: async fn(finding_id: str, reason: str)
        """
        self._block_reason_fn = fn

    async def run_filter(self) -> dict:
        """Apply rule pipeline to all recon findings. Returns summary dict."""
        if self._findings_orch is None:
            logger.warning("filter: no FindingsOrchestrator wired — nothing to filter")
            await self._emit_completed(
                {"pending": 0, "validated": 0, "dropped": 0, "incomplete": 0, "error": 0}
            )
            return {}

        all_findings = self._findings_orch.list_findings()
        pending = [f for f in all_findings if not self._results.get(f.get("id", ""))]

        counts = {"validated": 0, "dropped": 0, "incomplete": 0, "pending": 0, "error": 0}

        # ── First pass ────────────────────────────────────────────────────────
        await self._apply_rules(pending, all_findings, counts)

        # ── Re-invocation pass ────────────────────────────────────────────────
        if self._reinvoke_fn is not None and not self._cancelled:
            requests = self._collect_reinvocations(all_findings)
            unique = self._dedup_requests(requests)
            for req in unique:
                if self._cancelled:
                    break
                try:
                    await self._reinvoke_fn(req.engine_id, req.config)
                    logger.info(
                        "filter: dispatched reinvocation engine=%s rule=%s",
                        req.engine_id, req.rule_id,
                    )
                except Exception as exc:
                    logger.warning(
                        "filter: reinvoke dispatch failed engine=%s: %s",
                        req.engine_id, exc,
                    )

            # ── Second pass — filter newly-added findings ─────────────────────
            if not self._cancelled:
                refreshed = self._findings_orch.list_findings()
                new_findings = [
                    f for f in refreshed
                    if not self._results.get(f.get("id", ""))
                ]
                if new_findings:
                    await self._apply_rules(new_findings, refreshed, counts)

        if self._cancelled:
            await self._emit_cancelled()
        else:
            await self._emit_completed(counts)

        logger.info(
            "filter: investigation %s — %s",
            self._investigation_id,
            ", ".join(f"{k}={v}" for k, v in counts.items() if v),
        )
        return counts

    async def _apply_rules(
        self,
        findings: list[dict],
        all_findings: list[dict],
        counts: dict,
    ) -> None:
        """Apply the REGISTERED_RULES pipeline to *findings*, updating counts."""
        for finding in findings:
            if self._cancelled:
                break
            finding_id = finding.get("id", "")
            try:
                status, reason, gaps, block_reason = self._evaluate(finding, all_findings)
                if status is not None:
                    validated_at = _now_iso()
                    gaps_json = json.dumps(gaps) if gaps else None

                    self._results[finding_id] = {
                        "validation_status": status,
                        "validation_reason": reason,
                        "enumeration_gaps": gaps_json,
                        "validated_at": validated_at,
                        "enumeration_block_reason": block_reason,
                    }
                    counts[status] += 1

                    if self._update_fn is not None:
                        try:
                            await self._update_fn(
                                finding_id, status, reason, gaps_json, validated_at
                            )
                        except Exception as exc:
                            logger.error(
                                "filter: db_writer raised for %s: %s", finding_id, exc
                            )
                    if block_reason is not None and self._block_reason_fn is not None:
                        try:
                            await self._block_reason_fn(finding_id, block_reason)
                        except Exception as exc:
                            logger.error(
                                "filter: block_reason_fn raised for %s: %s", finding_id, exc
                            )
                else:
                    counts["pending"] += 1
                    if block_reason is not None:
                        self._results[finding_id] = {
                            "validation_status": "pending",
                            "validation_reason": None,
                            "enumeration_gaps": None,
                            "validated_at": None,
                            "enumeration_block_reason": block_reason,
                        }
                        if self._block_reason_fn is not None:
                            try:
                                await self._block_reason_fn(finding_id, block_reason)
                            except Exception as exc:
                                logger.error(
                                    "filter: block_reason_fn raised for %s: %s", finding_id, exc
                                )
            except Exception as exc:
                logger.error(
                    "filter: rule evaluation error for finding %s: %s", finding_id, exc
                )
                counts["error"] += 1
                counts["pending"] += 1

    def _evaluate(
        self, finding: dict, all_findings: list[dict]
    ) -> tuple[str | None, str | None, list | None, str | None]:
        """Run the rule pipeline.

        Returns (status, reason, gaps, block_reason). All four can be None.
        block_reason is set when any rule signals evidence_gap; the chain
        continues after an evidence_gap so a later rule may still classify.
        """
        block_reason: str | None = None
        for rule in REGISTERED_RULES:
            try:
                result = rule.evaluate(finding, all_findings)
                if result.matched:
                    if result.is_evidence_gap:
                        if block_reason is None:
                            block_reason = result.reason
                    else:
                        return result.status, result.reason, result.gaps, block_reason
            except Exception as exc:
                logger.warning("filter: rule %s raised: %s", rule.id, exc)
        return None, None, None, block_reason

    def _collect_reinvocations(
        self, all_findings: list[dict]
    ) -> list[ReinvocationRequest]:
        """Run reinvocation rules over all findings; return all requests."""
        requests: list[ReinvocationRequest] = []
        for finding in all_findings:
            for rule in REINVOCATION_RULES:
                try:
                    requests.extend(rule.evaluate(finding, all_findings))
                except Exception as exc:
                    logger.warning(
                        "filter: reinvoke rule %s raised: %s", rule.id, exc
                    )
        return requests

    @staticmethod
    def _dedup_requests(
        requests: list[ReinvocationRequest],
    ) -> list[ReinvocationRequest]:
        """Deduplicate requests by (engine_id, sorted config JSON)."""
        seen: set[str] = set()
        unique: list[ReinvocationRequest] = []
        for req in requests:
            key = f"{req.engine_id}:{json.dumps(req.config, sort_keys=True)}"
            if key not in seen:
                seen.add(key)
                unique.append(req)
        return unique

    async def _emit_completed(self, counts: dict) -> None:
        await self._bus.emit(
            orchestrator="filter",
            event_type="filter_phase_completed",
            investigation_id=self._investigation_id,
            payload={"counts": counts},
        )

    async def _emit_cancelled(self) -> None:
        await self._bus.emit(
            orchestrator="filter",
            event_type="filter_phase_cancelled",
            investigation_id=self._investigation_id,
            payload={},
        )

    def cancel(self) -> None:
        self._cancelled = True

    def get_result(self, finding_id: str) -> dict | None:
        return self._results.get(finding_id)

    def get_all_results(self) -> dict[str, dict]:
        return dict(self._results)

    def get_state(self) -> dict:
        return {
            "orchestrator": "filter",
            "investigation_id": self._investigation_id,
            "results_count": len(self._results),
            "cancelled": self._cancelled,
        }
