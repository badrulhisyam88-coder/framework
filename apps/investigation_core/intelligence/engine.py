"""ClusterEngine — identify themes and cross-investigation links deterministically.

All inputs are simple lists / dicts so this module is easy to unit-test without
DB access. The async wrappers (`cross_investigation_links`, `comparison_summary`)
delegate to repositories.
"""

from __future__ import annotations

from collections import Counter, defaultdict

import aiosqlite

from apps.investigation_core.evidence.models.artifact import EvidenceArtifact
from apps.investigation_core.intelligence.clusters import (
    CLUSTERS,
    RootCauseCluster,
    clusters_for_finding_type,
    confidence_for_count,
)
from apps.investigation_core.intelligence.models import (
    ComparisonSummary,
    CrossInvestigationLink,
    InvestigationTheme,
    RemediationGap,
    ThemeRepetition,
)

# ── In-process theme identification ────────────────────────────────────────


def themes_for_findings(
    findings: list,
    *,
    evidence: list[EvidenceArtifact] | None = None,
) -> list[InvestigationTheme]:
    """Identify themes from a list of NormalizedFinding rows.

    A theme emerges when at least `cluster.emerging_threshold` distinct findings
    in the investigation belong to a cluster. Confidence grows with count.
    """
    if not findings:
        return []

    # Group findings by cluster
    by_cluster: dict[str, dict] = defaultdict(lambda: {
        "finding_ids": [],
        "finding_types": Counter(),
    })
    for f in findings:
        for cluster in clusters_for_finding_type(f.finding_type):
            entry = by_cluster[cluster.cluster_id]
            entry["finding_ids"].append(f.finding_id)
            entry["finding_types"][f.finding_type] += 1

    # Compute remediation_documented flag
    evidence = evidence or []
    documented_concept_index = _build_documented_concept_index(evidence)

    themes: list[InvestigationTheme] = []
    for cluster_id, agg in by_cluster.items():
        cluster = CLUSTERS[cluster_id]
        count = len(agg["finding_ids"])
        confidence = confidence_for_count(cluster, count)
        if confidence is None:
            continue
        types_list = sorted(agg["finding_types"].keys())
        # Did any evidence mention one of this cluster's remediation concepts?
        remediation_docd = any(
            _concept_match(c, documented_concept_index)
            for c in cluster.remediation_concepts
        )
        why = (
            f"{count} finding(s) match cluster '{cluster.cluster_id}' "
            f"({', '.join(types_list)}) — threshold "
            f"emerging≥{cluster.emerging_threshold}, "
            f"established≥{cluster.established_threshold}, "
            f"strong≥{cluster.strong_threshold}"
        )
        themes.append(InvestigationTheme(
            theme_id=cluster.cluster_id,
            label=cluster.label,
            description=cluster.description,
            confidence=confidence,
            matching_finding_count=count,
            matching_finding_types=types_list,
            matching_finding_ids=agg["finding_ids"],
            remediation_concepts=list(cluster.remediation_concepts),
            related_skill_prefixes=list(cluster.related_skill_prefixes),
            remediation_documented=remediation_docd,
            why=why,
        ))

    # Sort by confidence then count (strongest first)
    _conf_order = {"strong": 0, "established": 1, "emerging": 2}
    themes.sort(key=lambda t: (_conf_order[t.confidence], -t.matching_finding_count))
    return themes


# ── Evidence-keyword indexing for remediation_documented ──────────────────


def _build_documented_concept_index(
    evidence: list[EvidenceArtifact],
) -> set[str]:
    """Return a lower-cased token set drawn from evidence content + description.

    Used to test 'did the user describe X concept' deterministically — no NLP,
    just substring search.
    """
    tokens: set[str] = set()
    for art in evidence:
        for src in (art.description, art.content, art.title):
            if src:
                tokens.add(src.lower())
    return tokens


def _concept_match(concept: str, documented_index: set[str]) -> bool:
    """Concept appears in any evidence content/description (substring match)."""
    needle = concept.lower()
    # Split on common separators to allow partial matches like "parameterised queries"
    # if the user wrote "parameterised" alone.
    cleaned = needle.replace("/", " ").replace("(", " ").replace(")", " ")
    keywords = [w for w in cleaned.split() if len(w) > 4]
    for blob in documented_index:
        if needle in blob:
            return True
        if keywords and all(k in blob for k in keywords[:2]):
            return True
    return False


# ── Cross-investigation queries ────────────────────────────────────────────


async def cross_investigation_links(
    db: aiosqlite.Connection,
    cluster: RootCauseCluster,
    *,
    exclude_investigation_id: str,
    limit: int = 6,
) -> list[CrossInvestigationLink]:
    """Find OTHER investigations whose findings overlap with this cluster's types."""
    if not cluster.finding_types:
        return []
    placeholders = ",".join("?" * len(cluster.finding_types))
    sql = (
        "SELECT nf.investigation_id, i.title, "
        "       COUNT(nf.finding_id)  AS n,"
        "       GROUP_CONCAT(DISTINCT nf.finding_type) AS types "
        "  FROM normalized_findings nf"
        "  JOIN investigations i ON i.investigation_id = nf.investigation_id"
        f" WHERE nf.finding_type IN ({placeholders})"
        "   AND nf.investigation_id != ?"
        " GROUP BY nf.investigation_id"
        " ORDER BY n DESC LIMIT ?"
    )
    params = (*cluster.finding_types, exclude_investigation_id, limit)
    async with db.execute(sql, params) as cur:
        rows = await cur.fetchall()
    return [
        CrossInvestigationLink(
            cluster_id=cluster.cluster_id,
            investigation_id=r[0],
            title=str(r[1])[:80],
            matching_finding_count=int(r[2]),
            matching_finding_types=sorted(str(r[3] or "").split(",")) if r[3] else [],
        )
        for r in rows
    ]


async def all_themes_for_all_investigations(
    db: aiosqlite.Connection,
) -> dict[str, list[InvestigationTheme]]:
    """Return {investigation_id: [themes]} for every investigation.

    Used by the comparison summary. Reads finding rows only — no evidence per
    investigation here (remediation_documented stays False; comparison view
    doesn't need it).
    """
    from apps.scanner_orchestration.storage.finding_repo import (
        NormalizedFindingRepository,
    )

    repo = NormalizedFindingRepository(db)
    async with db.execute(
        "SELECT investigation_id FROM investigations"
    ) as cur:
        inv_ids = [r[0] for r in await cur.fetchall()]

    out: dict[str, list[InvestigationTheme]] = {}
    for inv_id in inv_ids:
        findings = await repo.list_for_investigation(inv_id)
        out[inv_id] = themes_for_findings(findings)
    return out


async def comparison_summary(
    db: aiosqlite.Connection,
) -> ComparisonSummary:
    """Compare themes across every investigation; surface repetitions + gaps."""
    by_inv = await all_themes_for_all_investigations(db)
    if not by_inv:
        return ComparisonSummary(investigations_compared=0)

    # Repetitions: count investigations per cluster
    rep_count: Counter = Counter()
    rep_findings: Counter = Counter()
    rep_invs: dict[str, list[str]] = defaultdict(list)
    rep_labels: dict[str, str] = {}
    for inv_id, themes in by_inv.items():
        for t in themes:
            rep_count[t.theme_id] += 1
            rep_findings[t.theme_id] += t.matching_finding_count
            rep_invs[t.theme_id].append(inv_id)
            rep_labels[t.theme_id] = t.label

    repeated_themes: list[ThemeRepetition] = []
    for cid, count in rep_count.most_common():
        if count >= 2:
            repeated_themes.append(ThemeRepetition(
                cluster_id=cid,
                label=rep_labels[cid],
                investigations_count=count,
                total_findings=rep_findings[cid],
                investigation_ids=rep_invs[cid][:8],
            ))

    # Remediation gaps: concepts surfaced often but rarely documented.
    # 'Rarely documented' is checked here via a separate per-investigation evidence
    # scan — call the per-investigation theme builder with evidence to mark documented.
    art_by_inv = await _artifacts_by_investigation(db)
    surfaced: Counter = Counter()
    documented: Counter = Counter()
    concept_clusters: dict[str, set[str]] = defaultdict(set)

    for inv_id, themes in by_inv.items():
        if not themes:
            continue
        evidence = art_by_inv.get(inv_id, [])
        index = _build_documented_concept_index(evidence)
        for t in themes:
            for concept in t.remediation_concepts:
                concept_clusters[concept].add(t.theme_id)
                surfaced[concept] += 1
                if _concept_match(concept, index):
                    documented[concept] += 1

    gaps: list[RemediationGap] = []
    for concept, s_count in surfaced.most_common():
        d_count = documented[concept]
        # Surfaced ≥2 investigations but documented in < half of them
        if s_count >= 2 and d_count * 2 < s_count:
            gaps.append(RemediationGap(
                concept=concept,
                surfaced_in_investigations=s_count,
                documented_in_investigations=d_count,
                cluster_ids=sorted(concept_clusters[concept]),
            ))

    return ComparisonSummary(
        investigations_compared=len(by_inv),
        repeated_themes=repeated_themes,
        common_remediation_gaps=gaps[:10],
    )


async def _artifacts_by_investigation(
    db: aiosqlite.Connection,
) -> dict[str, list[EvidenceArtifact]]:
    """Bulk-load evidence artifacts grouped by investigation_id."""
    from apps.investigation_core.evidence.storage.artifact_repo import (
        ArtifactRepository,
    )

    art_repo = ArtifactRepository(db)
    async with db.execute(
        "SELECT investigation_id FROM investigations"
    ) as cur:
        inv_ids = [r[0] for r in await cur.fetchall()]
    out: dict[str, list[EvidenceArtifact]] = {}
    for inv_id in inv_ids:
        out[inv_id] = await art_repo.list_for_investigation(inv_id)
    return out
