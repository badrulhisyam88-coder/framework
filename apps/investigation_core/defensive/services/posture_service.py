"""PostureSnapshotService — capture, list, compare investigation posture.

Capture is a deterministic aggregation over current findings + themes + evidence.
Compare is a pure-function diff between two captured snapshots.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime

import aiosqlite

from apps.investigation_core.defensive.models.posture import (
    POSTURE_KIND_LABELS,
    PostureComparison,
    PostureSnapshot,
    PostureSnapshotKind,
    ThemeDelta,
)
from apps.investigation_core.defensive.storage.posture_repo import (
    PostureRepository,
    new_snapshot_id,
)
from sdk import Logger


class PostureSnapshotService:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db
        self._repo = PostureRepository(db)

    # ── Capture ────────────────────────────────────────────────────────

    async def capture(
        self,
        investigation_id: str,
        *,
        label: str = "",
        snapshot_kind: PostureSnapshotKind = PostureSnapshotKind.BASELINE,
        campaign_id: str | None = None,
        notes: str | None = None,
        captured_by: str = "user",
    ) -> PostureSnapshot:
        """Deterministically build + persist a posture snapshot."""
        from apps.investigation_core.evidence.storage.artifact_repo import (
            ArtifactRepository,
        )
        from apps.investigation_core.intelligence.engine import themes_for_findings
        from apps.investigation_core.memory.services.quality_scorer import (
            score_investigation_evidence,
        )
        from apps.scanner_orchestration.storage.finding_repo import (
            NormalizedFindingRepository,
        )

        finding_repo = NormalizedFindingRepository(self._db)
        art_repo = ArtifactRepository(self._db)

        findings = await finding_repo.list_for_investigation(investigation_id)
        artifacts = await art_repo.list_for_investigation(investigation_id)

        sev_counts: Counter = Counter(f.severity for f in findings)
        type_counts: Counter = Counter(f.finding_type for f in findings)

        themes = themes_for_findings(findings, evidence=artifacts)
        active_themes = [
            {
                "cluster_id": t.theme_id,
                "label": t.label,
                "confidence": t.confidence,
                "finding_count": t.matching_finding_count,
                "remediation_documented": t.remediation_documented,
            }
            for t in themes
        ]
        remediation_docd = [
            t.theme_id for t in themes if t.remediation_documented
        ]

        ev_snap = score_investigation_evidence(artifacts)

        snapshot = PostureSnapshot(
            snapshot_id=new_snapshot_id(),
            investigation_id=investigation_id,
            campaign_id=campaign_id,
            label=label.strip() or POSTURE_KIND_LABELS[str(snapshot_kind)],
            snapshot_kind=snapshot_kind,
            captured_at=datetime.utcnow(),
            findings_count=len(findings),
            findings_by_severity=dict(sev_counts),
            findings_by_type=dict(type_counts),
            active_themes=active_themes,
            evidence_quality_score=ev_snap.overall_score,
            remediation_documented_themes=remediation_docd,
            captured_by=captured_by,
            notes=notes,
        )
        await self._repo.insert(snapshot)
        Logger.info(
            "posture.captured",
            extra={
                "snapshot_id": snapshot.snapshot_id,
                "investigation_id": investigation_id,
                "kind": str(snapshot_kind),
                "findings": len(findings),
            },
        )
        return snapshot

    async def list_for_investigation(
        self, investigation_id: str
    ) -> list[PostureSnapshot]:
        return await self._repo.list_for_investigation(investigation_id)

    async def list_for_campaign(self, campaign_id: str) -> list[PostureSnapshot]:
        return await self._repo.list_for_campaign(campaign_id)

    async def get(self, snapshot_id: str) -> PostureSnapshot | None:
        return await self._repo.get_by_id(snapshot_id)

    async def delete(self, snapshot_id: str) -> None:
        await self._repo.delete(snapshot_id)

    # ── Compare ────────────────────────────────────────────────────────

    async def compare(
        self, before_id: str, after_id: str
    ) -> PostureComparison | None:
        before = await self._repo.get_by_id(before_id)
        after = await self._repo.get_by_id(after_id)
        if not before or not after:
            return None
        return compare_snapshots(before, after)


# ── Pure comparison function (unit-testable) ──────────────────────────


def compare_snapshots(
    before: PostureSnapshot, after: PostureSnapshot
) -> PostureComparison:
    """Diff two snapshots into a structured comparison."""
    cmp = PostureComparison(before=before, after=after)

    # Aggregate deltas
    cmp.findings_delta = after.findings_count - before.findings_count
    sev_keys = set(before.findings_by_severity) | set(after.findings_by_severity)
    cmp.severity_delta = {
        k: after.findings_by_severity.get(k, 0) - before.findings_by_severity.get(k, 0)
        for k in sev_keys
    }
    type_keys = set(before.findings_by_type) | set(after.findings_by_type)
    cmp.finding_type_delta = {
        k: after.findings_by_type.get(k, 0) - before.findings_by_type.get(k, 0)
        for k in type_keys
    }
    cmp.evidence_quality_delta = (
        after.evidence_quality_score - before.evidence_quality_score
    )

    # Theme-level diff
    before_themes = {t["cluster_id"]: t for t in before.active_themes}
    after_themes = {t["cluster_id"]: t for t in after.active_themes}
    _conf_rank = {"emerging": 1, "established": 2, "strong": 3}

    for cid, bt in before_themes.items():
        at = after_themes.get(cid)
        if at is None:
            # Theme cleared
            cmp.themes_resolved.append(ThemeDelta(
                cluster_id=cid,
                label=bt["label"],
                state="resolved",
                before_finding_count=bt["finding_count"],
                after_finding_count=0,
                before_confidence=bt["confidence"],
            ))
        elif at["finding_count"] < bt["finding_count"]:
            # Weakened — same theme but fewer findings
            cmp.themes_resolved.append(ThemeDelta(
                cluster_id=cid,
                label=bt["label"],
                state="resolved",
                before_finding_count=bt["finding_count"],
                after_finding_count=at["finding_count"],
                before_confidence=bt["confidence"],
                after_confidence=at["confidence"],
            ))
        elif at["finding_count"] > bt["finding_count"]:
            cmp.themes_strengthened.append(ThemeDelta(
                cluster_id=cid,
                label=bt["label"],
                state="strengthened",
                before_finding_count=bt["finding_count"],
                after_finding_count=at["finding_count"],
                before_confidence=bt["confidence"],
                after_confidence=at["confidence"],
            ))
        else:
            cmp.themes_unchanged.append(ThemeDelta(
                cluster_id=cid,
                label=bt["label"],
                state="unchanged",
                before_finding_count=bt["finding_count"],
                after_finding_count=at["finding_count"],
                before_confidence=bt["confidence"],
                after_confidence=at["confidence"],
            ))

    for cid, at in after_themes.items():
        if cid not in before_themes:
            cmp.themes_emerging.append(ThemeDelta(
                cluster_id=cid,
                label=at["label"],
                state="emerging",
                before_finding_count=0,
                after_finding_count=at["finding_count"],
                after_confidence=at["confidence"],
            ))

    # Regression: themes resolved earlier, reappearing now (caller decides
    # whether "before" was a post-remediation snapshot). We mark a separate
    # regressed list when before was POST_REMEDIATION and theme reappears.
    if str(before.snapshot_kind) == "post_remediation":
        # Resolved-in-before but now present-in-after with MORE findings → regression
        for t in cmp.themes_strengthened + cmp.themes_emerging:
            if t.before_finding_count == 0 and t.after_finding_count > 0:
                cmp.themes_regressed.append(ThemeDelta(
                    cluster_id=t.cluster_id,
                    label=t.label,
                    state="regressed",
                    before_finding_count=0,
                    after_finding_count=t.after_finding_count,
                    after_confidence=t.after_confidence,
                ))

    # New remediation documentation
    cmp.new_remediation_themes = sorted(
        set(after.remediation_documented_themes)
        - set(before.remediation_documented_themes)
    )

    # Human-readable summary
    cmp.summary = _build_summary(cmp)
    cmp.why = _build_why(cmp)
    return cmp


def _build_summary(cmp: PostureComparison) -> list[str]:
    out: list[str] = []
    if cmp.themes_resolved:
        labels = ", ".join(t.label for t in cmp.themes_resolved[:3])
        out.append(f"Resolved themes: {labels}")
    if cmp.themes_regressed:
        labels = ", ".join(t.label for t in cmp.themes_regressed[:3])
        out.append(f"⚠ Regression detected: {labels}")
    if cmp.themes_emerging:
        labels = ", ".join(t.label for t in cmp.themes_emerging[:3])
        out.append(f"New themes emerged: {labels}")
    if cmp.findings_delta < 0:
        out.append(f"{abs(cmp.findings_delta)} fewer finding(s) overall")
    elif cmp.findings_delta > 0:
        out.append(f"{cmp.findings_delta} more finding(s) overall")
    if cmp.new_remediation_themes:
        out.append(
            f"{len(cmp.new_remediation_themes)} theme(s) now have documented remediation"
        )
    if cmp.evidence_quality_delta > 0:
        out.append(f"Evidence quality improved by {cmp.evidence_quality_delta} point(s)")
    return out


def _build_why(cmp: PostureComparison) -> list[str]:
    return [
        f"Before snapshot: '{cmp.before.label}' ({cmp.before.snapshot_kind}) — "
        f"{cmp.before.findings_count} finding(s) on {cmp.before.captured_at:%Y-%m-%d %H:%M}",
        f"After snapshot: '{cmp.after.label}' ({cmp.after.snapshot_kind}) — "
        f"{cmp.after.findings_count} finding(s) on {cmp.after.captured_at:%Y-%m-%d %H:%M}",
    ]
