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


def chain_location(db) -> dict:
    """Where the chain machinery is, if anywhere.

    Delegates to `db.audit_hardening.chain_objects_installed`, which checks
    both `audit_chain` (current) and `public` (pre-isolation), so there is one
    definition of "installed" shared by the verifier, the startup check and
    the migration downgrade guard.
    """
    from db.audit_hardening import chain_objects_installed

    return chain_objects_installed(db)


def chain_installed(db) -> bool:
    return chain_location(db)["installed"]


def legacy_accounting_status(
    head_count: int, surviving: int
) -> tuple[str | None, str | None]:
    """
    Compare the chain head's pre-chain counter against the rows still present.

    Returns ``(break, note)``, at most one of which is set.

    **Directional, and the direction is the whole point.**

    ``head > surviving`` — pre-chain rows *disappeared* without the counter
    moving. That is the break. Sanctioned retention decrements the head in the
    same transaction as the deletion, so the two can only diverge this way
    through a removal outside the purge path.

    ``head < surviving`` — pre-chain rows were *inserted* without being hashed,
    which means the chain trigger was disabled for that write. It is how real
    pre-chain history and every legacy test fixture come to exist. A note, not
    a break: nothing was lost, and calling it tampering would cry wolf on the
    ordinary case.

    Pure, and separated out for that reason. The break direction is only
    reachable on a database whose counter is authoritative — seeded from a
    COUNT at chain bootstrap — which a test organisation cannot be, because the
    only function that raises it is granted to nobody and the only one that
    lowers it belongs to ``audit_maintenance``. Extracting the comparison means
    both directions are testable without a database, and without granting
    anything a privilege the design withholds.
    """
    if head_count > surviving:
        return (
            f"legacy accounting mismatch: head records {head_count} pre-chain "
            f"event(s) and only {surviving} remain. Retention decrements the "
            f"head in the same transaction as the deletion, so a shortfall "
            f"means rows were removed outside the purge path.",
            None,
        )
    if head_count < surviving:
        return (
            None,
            f"{surviving - head_count} unhashed row(s) beyond the count "
            f"recorded at chain bootstrap — written with the chain trigger "
            f"disabled. Not a loss; not verifiable either.",
        )
    return None, None


def retention_anchors(db, org_id: str) -> dict:
    """
    What retention has legitimately removed from this organisation.

    Returns zeroes when the phase-6a machinery is not installed, so a database
    without retention reads exactly as it did before.

    Phase 6a covers **legacy** rows only, and those have no hash, so an anchor
    here is an accounting record rather than continuity evidence — there was
    never a link to preserve. Phase 6b introduces ``kind='chained'``, where the
    anchor *is* continuity evidence; this function reports the counts either
    way and the caller decides what may be claimed.
    """
    if not db.execute(
        text("SELECT to_regclass('audit_retention.retention_anchors')")
    ).scalar():
        return {"installed": False, "legacy_purged": 0, "chained_purged": 0, "runs": 0}

    row = db.execute(
        text(
            "SELECT coalesce(sum(deleted_count) FILTER (WHERE kind='legacy'), 0), "
            "       coalesce(sum(deleted_count) FILTER (WHERE kind='chained'), 0), "
            "       count(*) "
            "  FROM audit_retention.retention_anchors WHERE org_id = :o"
        ),
        {"o": org_id},
    ).fetchone()
    return {
        "installed": True,
        "legacy_purged": int(row[0]),
        "chained_purged": int(row[1]),
        "runs": int(row[2]),
    }


def anchored_genesis(db, org_id: str, prev_hash: str | None) -> dict | None:
    """
    Is this non-NULL ``prev_hash`` explained by a sanctioned chained purge?

    After a chained purge the oldest surviving row no longer has
    ``prev_hash IS NULL`` -- the row it linked to is gone. That is
    indistinguishable, from the row alone, from somebody having deleted history
    and left the remainder behind.

    What distinguishes them is the anchor. A chained purge writes
    ``last_deleted_record_hash``: the hash of the newest row it removed. The
    surviving row's ``prev_hash`` must equal it. A value with no matching
    anchor is exactly the unsanctioned case, and stays a break.

    Note what this does **not** establish. It proves the surviving chain links
    back to a value committed at purge time; it says nothing about what the
    removed events contained. Deletion destroyed that. The archive artefact
    named on the anchor is where the content went, and verifying that file is a
    manual act against something this tool does not hold.
    """
    if prev_hash is None:
        return None
    if not db.execute(
        text("SELECT to_regclass('audit_retention.retention_anchors')")
    ).scalar():
        return None

    row = (
        db.execute(
            text(
                "SELECT id, deleted_count, range_from, range_to, purge_completed_at, "
                "       archive_artifact ->> 'export_event_id' AS export_event_id, "
                "       archive_artifact ->> 'sha256'          AS sha256 "
                "  FROM audit_retention.retention_anchors "
                " WHERE org_id = :o AND kind = 'chained' "
                "   AND last_deleted_record_hash = :h "
                " ORDER BY id DESC LIMIT 1"
            ),
            {"o": org_id, "h": prev_hash},
        )
        .mappings()
        .fetchone()
    )
    return dict(row) if row else None


def verify_org(db, org_id: str, schema: str = "audit_chain") -> dict:
    """Walk one organisation's chain from genesis and check every link.

    `schema` is where the chain machinery lives, resolved once by
    `chain_location()`. Every chain-object reference below is qualified
    with it — never left bare — because the application role owns `public`
    on some databases and could create a shadow `audit_chain_heads` there.
    """
    rows = db.execute(
        text(
            "SELECT id, prev_hash, record_hash FROM public.audit_logs "
            " WHERE org_id = :o AND record_hash IS NOT NULL"
        ),
        {"o": org_id},
    ).fetchall()

    legacy = db.execute(
        text(
            "SELECT count(*) FROM public.audit_logs WHERE org_id = :o AND record_hash IS NULL"
        ),
        {"o": org_id},
    ).scalar()

    head = db.execute(
        text(
            "SELECT event_count, last_event_id, last_record_hash, genesis_event_id, "
            f"       legacy_event_count FROM {schema}.audit_chain_heads WHERE org_id = :o"
        ),
        {"o": org_id},
    ).fetchone()

    anchors = retention_anchors(db, org_id)

    report = {
        "org_id": org_id,
        "chained": len(rows),
        "legacy": legacy,
        "purged": anchors,
        "walked": 0,
        "breaks": [],
        "notes": [],
        "anchored_genesis": None,
        "head": head,
    }

    # An unexplained fall in the legacy count IS a break, and phase 6a is what
    # makes it detectable. `legacy_event_count` is seeded from a COUNT at chain
    # bootstrap and afterwards only ever *decremented*, by
    # `audit_chain_note_legacy_purge_v1`, which the sanctioned purge calls in
    # the same transaction as the deletion and the anchor. Nothing else can
    # reach it: the head is owned by audit_chain_writer and the application
    # role holds SELECT only.
    #
    # So a privileged deletion performed outside the purge — as postgres, say —
    # removes rows without moving the counter, and the two stop agreeing. That
    # is exactly the difference between sanctioned retention and somebody
    # quietly removing history, and it is reported as a break rather than
    # excused.
    if head is not None:
        issue, note = legacy_accounting_status(head.legacy_event_count, legacy)
        if issue:
            report["breaks"].append(issue)
        if note:
            report["notes"].append(note)

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

    if len(genesis) > 1:
        report["breaks"].append(
            f"expected exactly one chain start, found {len(genesis)}"
        )
        return report

    if not genesis:
        # No row with a NULL prev_hash. Either a chained purge removed the
        # original genesis -- in which case an anchor explains it -- or history
        # was removed by something that left no account of itself.
        candidates = [
            row for row in rows if row.prev_hash not in {r.record_hash for r in rows}
        ]
        if len(candidates) != 1:
            report["breaks"].append(
                f"no chain start: {len(candidates)} row(s) link to a hash that "
                f"is not present, expected exactly one"
            )
            return report

        anchor_row = anchored_genesis(db, org_id, candidates[0].prev_hash)
        if anchor_row is None:
            report["breaks"].append(
                f"chain starts at {candidates[0].id}, whose prev_hash "
                f"{(candidates[0].prev_hash or '')[:16]} matches no retention "
                f"anchor. History was removed outside the purge path."
            )
            return report

        report["anchored_genesis"] = anchor_row
        report["notes"].append(
            f"chain starts above a purge boundary: anchor {anchor_row['id']} "
            f"removed {anchor_row['deleted_count']} chained event(s) under "
            f"archive {anchor_row['export_event_id']}. Continuity is provable; "
            f"the removed events are NOT preserved here."
        )
        genesis = candidates

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
                f"SELECT {schema}.audit_record_hash_v1(a.prev_hash, a) "
                "FROM public.audit_logs a WHERE a.id = :i AND a.org_id = :o"
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
        location = chain_location(db)
        if not location["installed"]:
            print("audit chain: NOT INSTALLED")
            print(
                "\nThe privileged half of phase 4 has not been applied. A database\n"
                "administrator must run, as postgres:\n"
                "    psql -v ON_ERROR_STOP=1 -f Backend/scripts/audit/bootstrap_chain.sql\n"
                "\nUntil then every audit event is unchained and NOT VERIFIABLE."
            )
            return 2

        schema = location["schema"]
        if location["needs_migration"]:
            print(
                f"WARNING: chain machinery is in `{schema}`, not `audit_chain`.\n"
                "Where the application role owns that schema it can DROP the\n"
                "chain objects, because a schema owner may drop objects it does\n"
                "not own. Re-run bootstrap_chain.sql as a superuser to move\n"
                "them; existing chain state is preserved.\n"
            )

        if args.status:
            heads = db.execute(
                text(
                    "SELECT count(*), coalesce(sum(event_count),0), "
                    "       coalesce(sum(legacy_event_count),0) "
                    f"  FROM {schema}.audit_chain_heads"
                )
            ).fetchone()
            print(f"audit chain: INSTALLED (schema: {schema})")
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
                    text(
                        "SELECT DISTINCT org_id FROM public.audit_logs ORDER BY org_id"
                    )
                )
            ]
        )

        total_breaks = 0
        total_chained = total_legacy = total_purged = 0
        print(f"verifying {len(org_ids)} organisation(s)\n")
        for org_id in org_ids:
            report = verify_org(db, org_id, schema)
            total_chained += report["chained"]
            total_legacy += report["legacy"]
            purged = report["purged"]
            total_purged += purged["legacy_purged"] + purged["chained_purged"]
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
            if purged["runs"]:
                # A distinct category, deliberately not folded into either of
                # the two above. These events are gone; what survives is an
                # accounting record of their removal, which is a different
                # claim from "verified" and from "present but unverifiable".
                print(
                    f"    purged    : {purged['legacy_purged']} legacy"
                    + (
                        f", {purged['chained_purged']} chained"
                        if purged["chained_purged"]
                        else ""
                    )
                    + f" (retention, {purged['runs']} anchored run(s)) — "
                    "removed and accounted for, NOT preserved"
                )
            for note in report["notes"]:
                print(f"    note      : {note}")
            for issue in report["breaks"]:
                print(f"    BREAK     : {issue}")
            print()

        print("=" * 68)
        print(f"chained events verified : {total_chained - total_breaks}")
        print(f"legacy, unverifiable    : {total_legacy}")
        print(f"purged under retention  : {total_purged}")
        print(f"breaks found            : {total_breaks}")
        if total_breaks:
            print("\nCHAIN INTEGRITY FAILED — investigate before trusting this trail.")
            return 1
        print("\nAll chained events verify. Legacy events are reported separately")
        print("above and are NOT covered by any cryptographic guarantee.")
        if total_purged:
            print(
                "Events removed under retention are counted separately again: "
                "an\nanchor records that they were removed and by what run. It "
                "does not\npreserve their contents, and for pre-chain rows "
                "there was never any\ncryptographic continuity to preserve."
            )
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
