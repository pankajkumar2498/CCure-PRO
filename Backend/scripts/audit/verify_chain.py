"""
scripts/audit/verify_chain.py
─────────────────────────────────────────────────────────────────────────────
Walk every organisation's audit hash chain and report on it.

    docker exec ccure-api python scripts/audit/verify_chain.py
    docker exec ccure-api python scripts/audit/verify_chain.py --org org_default
    docker exec ccure-api python scripts/audit/verify_chain.py --status

Read-only. It never writes, and it is safe to run against production.

Three properties this tool is careful about, each of which is easy to get wrong
in a way that produces a confidently false answer:

**It recomputes through the database's own function.** `audit_record_hash_v1`
is the same function the insert trigger calls. A Python reimplementation would
be a second definition of the canonical form, and two definitions drift — at
which point the verifier reports tampering that never happened, on a trail
nobody can then trust.

**It orders the chain by `prev_hash` links, never by `created_at`.** That
column is set client-side in Python, so it can legitimately run out of order
relative to insertion — two events inside the same millisecond, or a clock
adjustment, are enough. A verifier that sorted by timestamp would manufacture
breaks.

**It never reports pre-chain history as verified.** Rows written before the
chain was installed have no hash and nothing to recompute against. They are
counted and reported separately as *unverifiable*, which is the honest answer;
folding them into a verified total, or reporting them as breaks, would both be
wrong.

Exit codes: 0 clean, 1 a break was found, 2 the chain is not installed.
"""

from __future__ import annotations

import argparse
import sys

from db.base import SessionLocal
from sqlalchemy import text


def chain_installed(db) -> bool:
    return bool(
        db.execute(text("SELECT to_regclass('public.audit_chain_heads')")).scalar()
    ) and bool(
        db.execute(
            text("SELECT 1 FROM pg_trigger WHERE tgname = 'audit_logs_chain' LIMIT 1")
        ).scalar()
    )


def verify_org(db, org_id: str) -> dict:
    """Walk one organisation's chain from genesis and check every link."""
    rows = db.execute(
        text(
            "SELECT id, prev_hash, record_hash FROM audit_logs "
            " WHERE org_id = :o AND record_hash IS NOT NULL"
        ),
        {"o": org_id},
    ).fetchall()

    legacy = db.execute(
        text(
            "SELECT count(*) FROM audit_logs WHERE org_id = :o AND record_hash IS NULL"
        ),
        {"o": org_id},
    ).scalar()

    head = db.execute(
        text(
            "SELECT event_count, last_event_id, last_record_hash, genesis_event_id, "
            "       legacy_event_count FROM audit_chain_heads WHERE org_id = :o"
        ),
        {"o": org_id},
    ).fetchone()

    report = {
        "org_id": org_id,
        "chained": len(rows),
        "legacy": legacy,
        "walked": 0,
        "breaks": [],
        "head": head,
    }

    if not rows:
        if head and head.event_count:
            report["breaks"].append(
                f"head claims {head.event_count} events but no chained rows exist"
            )
        return report

    by_prev: dict[str | None, list] = {}
    for row in rows:
        by_prev.setdefault(row.prev_hash, []).append(row)

    # A duplicate prev_hash IS a fork: two events claiming the same predecessor.
    for prev, group in by_prev.items():
        if len(group) > 1:
            report["breaks"].append(
                f"fork: {len(group)} events share prev_hash "
                f"{(prev or 'NULL')[:16]} ({', '.join(r.id for r in group)})"
            )

    genesis = by_prev.get(None, [])
    if len(genesis) != 1:
        report["breaks"].append(
            f"expected exactly one chain start, found {len(genesis)}"
        )
        return report

    seen: set[str] = set()
    current = genesis[0]
    while current is not None:
        if current.id in seen:
            report["breaks"].append(f"cycle at {current.id}")
            break
        seen.add(current.id)
        report["walked"] += 1

        expected = db.execute(
            text(
                "SELECT audit_record_hash_v1(a.prev_hash, a) FROM audit_logs a "
                " WHERE a.id = :i AND a.org_id = :o"
            ),
            {"i": current.id, "o": org_id},
        ).scalar()
        if expected != current.record_hash:
            report["breaks"].append(
                f"content altered at {current.id}: stored "
                f"{current.record_hash[:16]}, recomputed {(expected or '')[:16]}"
            )

        nxt = by_prev.get(current.record_hash, [])
        current = nxt[0] if nxt else None

    if report["walked"] != len(rows):
        report["breaks"].append(
            f"walked {report['walked']} of {len(rows)} chained rows — "
            f"{len(rows) - report['walked']} are not reachable from genesis"
        )

    # The head is maintained in the same transaction as the rows, so it can only
    # disagree through out-of-band modification. That makes it an independent
    # witness rather than a duplicate of what was just walked.
    if head is None:
        report["breaks"].append("no chain head row for an organisation with events")
    else:
        tip = seen and [r for r in rows if r.record_hash not in by_prev]
        if tip and len(tip) == 1:
            if head.last_event_id != tip[0].id:
                report["breaks"].append(
                    f"head names {head.last_event_id} as the tip, but the chain "
                    f"ends at {tip[0].id}"
                )
            if head.last_record_hash != tip[0].record_hash:
                report["breaks"].append("head's last_record_hash is not the chain tip")
        if head.event_count != len(rows):
            report["breaks"].append(
                f"head counts {head.event_count} events, {len(rows)} rows are chained"
            )
        if head.genesis_event_id and head.genesis_event_id != genesis[0].id:
            report["breaks"].append(
                f"head names {head.genesis_event_id} as genesis, chain starts at "
                f"{genesis[0].id}"
            )

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org", help="verify a single organisation")
    parser.add_argument(
        "--status", action="store_true", help="report installation state only"
    )
    args = parser.parse_args()

    db = SessionLocal()
    try:
        if not chain_installed(db):
            print("audit chain: NOT INSTALLED")
            print(
                "\nThe privileged half of phase 4 has not been applied. A database\n"
                "administrator must run, as postgres:\n"
                "    psql -v ON_ERROR_STOP=1 -f Backend/scripts/audit/bootstrap_chain.sql\n"
                "\nUntil then every audit event is unchained and NOT VERIFIABLE."
            )
            return 2

        if args.status:
            heads = db.execute(
                text(
                    "SELECT count(*), coalesce(sum(event_count),0), "
                    "       coalesce(sum(legacy_event_count),0) FROM audit_chain_heads"
                )
            ).fetchone()
            print("audit chain: INSTALLED")
            print(f"  organisations tracked : {heads[0]}")
            print(f"  chained events        : {heads[1]}")
            print(f"  legacy (unverifiable) : {heads[2]}")
            return 0

        org_ids = (
            [args.org]
            if args.org
            else [
                r[0]
                for r in db.execute(
                    text("SELECT DISTINCT org_id FROM audit_logs ORDER BY org_id")
                )
            ]
        )

        total_breaks = 0
        total_chained = total_legacy = 0
        print(f"verifying {len(org_ids)} organisation(s)\n")
        for org_id in org_ids:
            report = verify_org(db, org_id)
            total_chained += report["chained"]
            total_legacy += report["legacy"]
            total_breaks += len(report["breaks"])

            state = "BROKEN" if report["breaks"] else "verified"
            print(f"  {org_id}")
            print(
                f"    chained   : {report['chained']} "
                f"({report['walked']} walked from genesis) -> {state}"
            )
            print(
                f"    legacy    : {report['legacy']} "
                f"(pre-chain, NOT verifiable — no hash exists to check)"
            )
            for issue in report["breaks"]:
                print(f"    BREAK     : {issue}")
            print()

        print("=" * 68)
        print(f"chained events verified : {total_chained - total_breaks}")
        print(f"legacy, unverifiable    : {total_legacy}")
        print(f"breaks found            : {total_breaks}")
        if total_breaks:
            print("\nCHAIN INTEGRITY FAILED — investigate before trusting this trail.")
            return 1
        print("\nAll chained events verify. Legacy events are reported separately")
        print("above and are NOT covered by any cryptographic guarantee.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
