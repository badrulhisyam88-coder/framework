#!/usr/bin/env python3
"""CLI: back-fill evidence_refs for findings persisted before the ordering fix.

Findings created before Phase 5 were inserted before their evidence artifact was
created, leaving evidence_refs = [] in the database. This script repairs them using
deterministic title-matching: "[SCANNER] finding.title" matches artifact.title.

Usage:
    python scripts/backfill_evidence_refs.py [options]

Options:
    --dry-run              Preview repairs without writing to DB
    --investigation-id ID  Restrict to one investigation (default: all)
    --limit N              Max findings to process per investigation (default: 500)

Output:
    Per-investigation report: candidates / repaired / not_found / ambiguous

Exit codes:
    0 — success (even if some findings were skipped)
    1 — unexpected error
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Allow running from repo root without installing the package
sys.path.insert(0, str(Path(__file__).parent.parent))


async def _backfill_investigation(
    db,
    investigation_id: str,
    dry_run: bool,
    limit: int,
) -> dict:
    """Back-fill evidence_refs for one investigation. Returns per-investigation stats."""
    from apps.investigation_core.evidence.storage.artifact_repo import ArtifactRepository
    from apps.scanner_orchestration.storage.finding_repo import NormalizedFindingRepository

    finding_repo = NormalizedFindingRepository(db)
    art_repo = ArtifactRepository(db)

    findings = await finding_repo.list_with_empty_evidence_refs(investigation_id)
    findings = findings[:limit]
    if not findings:
        return {"investigation_id": investigation_id, "candidates": 0,
                "repaired": 0, "not_found": 0, "ambiguous": 0}

    artifacts = await art_repo.list_for_investigation(investigation_id)
    by_title: dict[str, list[str]] = {}
    for art in artifacts:
        by_title.setdefault(art.title, []).append(art.evidence_id)

    repaired = not_found = ambiguous = 0
    for f in findings:
        expected = f"[{f.source_scanner.upper()}] {f.title}"
        matches = by_title.get(expected, [])
        if len(matches) == 1:
            if not dry_run:
                await finding_repo.update_evidence_refs(f.finding_id, matches)
            repaired += 1
        elif len(matches) == 0:
            not_found += 1
        else:
            ambiguous += 1

    return {
        "investigation_id": investigation_id,
        "candidates": len(findings),
        "repaired": repaired,
        "not_found": not_found,
        "ambiguous": ambiguous,
    }


async def _get_all_investigation_ids(db) -> list[str]:
    async with db.execute("SELECT investigation_id FROM investigations") as cur:
        rows = await cur.fetchall()
    return [r[0] for r in rows]


async def main(dry_run: bool, investigation_id: str | None, limit: int) -> None:
    import aiosqlite
    from apps.validation.database import DB_PATH

    mode = "[DRY RUN] " if dry_run else ""
    print(f"{mode}Backfill evidence_refs — DB: {DB_PATH}")
    print("-" * 60)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        if investigation_id:
            inv_ids = [investigation_id]
        else:
            inv_ids = await _get_all_investigation_ids(db)

        total = {"candidates": 0, "repaired": 0, "not_found": 0, "ambiguous": 0}
        for inv_id in inv_ids:
            result = await _backfill_investigation(db, inv_id, dry_run, limit)
            if result["candidates"] > 0:
                print(
                    f"  {inv_id[:8]}…  "
                    f"candidates={result['candidates']}  "
                    f"repaired={result['repaired']}  "
                    f"not_found={result['not_found']}  "
                    f"ambiguous={result['ambiguous']}"
                )
            for k in total:
                total[k] += result[k]

    print("-" * 60)
    print(
        f"Total: candidates={total['candidates']}  "
        f"repaired={total['repaired']}  "
        f"not_found={total['not_found']}  "
        f"ambiguous={total['ambiguous']}"
    )
    if dry_run:
        print("\n[DRY RUN] No changes written. Re-run without --dry-run to apply.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    parser.add_argument("--investigation-id", metavar="ID", help="Restrict to one investigation")
    parser.add_argument("--limit", type=int, default=500, help="Max findings per investigation")
    args = parser.parse_args()

    try:
        asyncio.run(main(args.dry_run, args.investigation_id, args.limit))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
