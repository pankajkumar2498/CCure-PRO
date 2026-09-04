"""
Backend/scripts/cleanup_test_catalogue_residue.py
─────────────────────────────────────────────────────────────────────────────
Remove synthetic ``CVE-9999-*`` rows from ``vulnerability_definitions``.

    python -m scripts.cleanup_test_catalogue_residue            # dry run
    python -m scripts.cleanup_test_catalogue_residue --apply    # delete

Why this exists
───────────────
The test suite writes vulnerability-catalogue rows as a side effect of
exercising the scan-sync path: a scan payload carrying a ``cve_id`` makes
``scans/asset_syncer.py`` upsert a ``vulnerability_definitions`` row for it.
Those rows were never cleaned up. ``tests/conftest.py`` purges organisations,
users, frameworks, controls and roles, and the findings go with their
organisation through ``ON DELETE CASCADE`` — but the catalogue rows the
findings pointed at simply stayed, run after run.

On the live application database that left 24 rows titled "Test vulnerability",
"Test vulnerability 2", "Test vulnerability status" and "Package CVE", dated
between 2026-06-19 and 2026-08-10 — the last of them on the day of the incident
recorded in CLAUDE.md, when a full-suite run inherited the API container's
``DATABASE_URL``.

They are inert: nothing reads them, no current code path creates more against a
correctly-configured deployment, and no finding references them. They are worth
removing anyway, because **each one reads to a person, and to any tool, as a
published CVE**. ``CVE-9999-0b388ca6`` in a report or an export is a CVE
identifier that NVD has never heard of. That is exactly the confusion
``core/checks/definitions.py`` exists to prevent for identifiers this product
mints deliberately.

The recurrence guard is in ``tests/conftest.py`` — the per-test purge now
removes these rows, so a run leaves no catalogue residue on whatever database
it reaches. This script is for databases that already have some.

Safety
──────
* **Dry run is the default.** ``--apply`` is the only way into the delete.
* **The pattern cannot match a published CVE.** Year 9999 does not exist in the
  CVE numbering scheme. The script asserts this per row anyway rather than
  trusting the ``LIKE``, because the cost of being wrong is deleting real feed
  data that a finding may depend on.
* **Findings referencing the residue block the delete** unless
  ``--include-findings`` is passed. ``asset_vulnerabilities.vuln_id`` is
  ``ON DELETE RESTRICT``, so this would fail loudly anyway; refusing first
  produces an explanation instead of a foreign-key error.
* **One transaction.** Either every row goes or none does.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text
from sqlalchemy.orm import Session

#: Must match ``tests/conftest.SYNTHETIC_CVE_PREFIX``. Two spellings of one
#: convention would mean the cleanup and the guard disagree about what counts
#: as residue, and the gap between them is where rows survive.
SYNTHETIC_CVE_PREFIX = "CVE-9999-"
SYNTHETIC_CVE_LIKE = SYNTHETIC_CVE_PREFIX + "%"


def _assert_not_a_real_cve(identifiers: List[str]) -> None:
    """
    Refuse outright if anything selected could be a published CVE.

    The ``LIKE`` already cannot match one, so this never fires in practice. It
    is here because the failure it guards against — deleting real advisories
    that live findings reference — is not recoverable from a report, and a
    belt-and-braces check over a handful of rows costs nothing.
    """
    offenders = [i for i in identifiers if not i.startswith(SYNTHETIC_CVE_PREFIX)]
    if offenders:
        raise RuntimeError(
            "refusing to delete: the selection contains identifiers outside the "
            f"synthetic prefix {SYNTHETIC_CVE_PREFIX!r}: {offenders[:10]}"
        )


def find_residue(db: Session) -> List[Dict[str, Any]]:
    """Every synthetic catalogue row, with the finding count against each."""
    rows = db.execute(
        text(
            "SELECT d.id, d.title, d.source, d.created_at, "
            "       (SELECT count(*) FROM asset_vulnerabilities av "
            "         WHERE av.vuln_id = d.id) AS finding_count "
            "  FROM vulnerability_definitions d "
            " WHERE d.id LIKE :p "
            " ORDER BY d.id"
        ),
        {"p": SYNTHETIC_CVE_LIKE},
    ).fetchall()
    return [
        {
            "id": r.id,
            "title": r.title,
            "source": r.source,
            "created_at": r.created_at,
            "finding_count": r.finding_count,
        }
        for r in rows
    ]


def cleanup(
    db: Session, *, dry_run: bool = True, include_findings: bool = False
) -> Dict[str, Any]:
    """
    Remove the residue. Returns a report; writes nothing when ``dry_run``.
    """
    residue = find_residue(db)
    identifiers = [r["id"] for r in residue]
    referenced = [r for r in residue if r["finding_count"]]
    finding_total = sum(r["finding_count"] for r in residue)

    report: Dict[str, Any] = {
        "dry_run": dry_run,
        "rows": residue,
        "definitions_found": len(residue),
        "findings_referencing": finding_total,
        "definitions_deleted": 0,
        "findings_deleted": 0,
    }

    if not residue:
        return report

    _assert_not_a_real_cve(identifiers)

    if referenced and not include_findings:
        raise RuntimeError(
            f"{finding_total} finding(s) still reference "
            f"{len(referenced)} synthetic definition(s) "
            f"({[r['id'] for r in referenced][:5]}). "
            "asset_vulnerabilities.vuln_id is ON DELETE RESTRICT, so the "
            "delete would fail. Re-run with --include-findings once you have "
            "confirmed those findings are test residue too."
        )

    if dry_run:
        return report

    if include_findings and finding_total:
        result = db.execute(
            text("DELETE FROM asset_vulnerabilities WHERE vuln_id LIKE :p"),
            {"p": SYNTHETIC_CVE_LIKE},
        )
        report["findings_deleted"] = result.rowcount or 0

    result = db.execute(
        text("DELETE FROM vulnerability_definitions WHERE id LIKE :p"),
        {"p": SYNTHETIC_CVE_LIKE},
    )
    report["definitions_deleted"] = result.rowcount or 0
    db.commit()
    return report


def _render(report: Dict[str, Any]) -> None:
    rows = report["rows"]
    if not rows:
        print("No synthetic catalogue residue found. Nothing to do.")
        return

    print(f"Synthetic catalogue rows matching {SYNTHETIC_CVE_LIKE!r}: {len(rows)}")
    for row in rows:
        stamp = row["created_at"].date() if row["created_at"] else "?"
        suffix = (
            f"  [{row['finding_count']} finding(s)]" if row["finding_count"] else ""
        )
        print(f"  {row['id']:<32} {stamp}  {row['source']:<12} {row['title']}{suffix}")

    if report["dry_run"]:
        print(
            f"\nDRY RUN — nothing was deleted. Re-run with --apply to remove "
            f"{len(rows)} definition(s)."
        )
    else:
        print(
            f"\nDeleted {report['definitions_deleted']} definition(s) and "
            f"{report['findings_deleted']} finding(s)."
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Remove synthetic CVE-9999-* rows left in vulnerability_definitions "
            "by test runs. Dry run unless --apply is given."
        )
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Perform the deletion. Without this the script only reports.",
    )
    parser.add_argument(
        "--include-findings",
        action="store_true",
        help=(
            "Also delete findings that reference the synthetic definitions. "
            "Required when any exist, because the foreign key is RESTRICT."
        ),
    )
    args = parser.parse_args()

    from db.base import SessionLocal

    db = SessionLocal()
    try:
        report = cleanup(
            db, dry_run=not args.apply, include_findings=args.include_findings
        )
    except RuntimeError as exc:
        db.rollback()
        print(f"Refused: {exc}", file=sys.stderr)
        return 1
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    _render(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
