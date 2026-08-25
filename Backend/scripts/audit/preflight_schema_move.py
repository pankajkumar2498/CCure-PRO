"""
scripts/audit/preflight_schema_move.py
─────────────────────────────────────────────────────────────────────────────
Capture and compare the exact state the schema move must preserve.

    # before the DBA runs bootstrap_chain.sql
    docker exec ccure-api python scripts/audit/preflight_schema_move.py --capture

    # after
    docker exec ccure-api python scripts/audit/preflight_schema_move.py --compare

Read-only in both modes. `--capture` writes a JSON snapshot beside the script's
output directory; `--compare` re-reads live state and diffs it against that
snapshot, failing on any difference.

Why a fingerprint rather than eyeballing counts
───────────────────────────────────────────────
The move must be a catalogue operation: `ALTER TABLE ... SET SCHEMA` and
`CREATE OR REPLACE`, never a drop-and-recreate, and never a rehash. "The counts
look the same" would not catch a silently recomputed `record_hash` — the count
would be identical and every value different. The two SHA-256 fingerprints
below are over the full ordered set of (event id, org, prev_hash, record_hash)
and (org, last_event_id, last_record_hash, event_count, genesis_event_id,
legacy_event_count), so any single altered byte changes them.

Exit codes: 0 identical, 1 a difference was found, 2 no snapshot to compare.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

from db.base import SessionLocal
from sqlalchemy import text

SNAPSHOT = pathlib.Path(__file__).with_name("preflight_snapshot.json")


def _chain_schema(db) -> str | None:
    return db.execute(
        text(
            "SELECT n.nspname FROM pg_class c JOIN pg_namespace n "
            " ON n.oid = c.relnamespace WHERE c.relname = 'audit_chain_heads'"
        )
    ).scalar()


def capture_state(db) -> dict:
    """Everything condition 6 names, plus the context needed to interpret it."""
    schema = _chain_schema(db)

    events = db.execute(
        text(
            "SELECT id, org_id, prev_hash, record_hash FROM public.audit_logs "
            " WHERE record_hash IS NOT NULL ORDER BY org_id, id"
        )
    ).fetchall()

    heads = []
    if schema:
        heads = db.execute(
            text(
                "SELECT org_id, last_event_id, last_record_hash, event_count, "
                "       genesis_event_id, legacy_event_count "
                f"  FROM {schema}.audit_chain_heads ORDER BY org_id"
            )
        ).fetchall()

    event_blob = "|".join(f"{r[0]}:{r[1]}:{r[2]}:{r[3]}" for r in events)
    head_blob = "|".join(f"{r[0]}:{r[1]}:{r[2]}:{r[3]}:{r[4]}:{r[5]}" for r in heads)

    return {
        "database": db.execute(text("SELECT current_database()")).scalar(),
        "alembic_revision": db.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar(),
        "chain_schema": schema,
        "trigger_points_at": db.execute(
            text(
                "SELECT n.nspname || '.' || p.proname FROM pg_trigger t "
                "  JOIN pg_proc p ON p.oid = t.tgfoid "
                "  JOIN pg_namespace n ON n.oid = p.pronamespace "
                " WHERE t.tgname = 'audit_logs_chain' LIMIT 1"
            )
        ).scalar(),
        "trigger_function_oid": db.execute(
            text(
                "SELECT tgfoid FROM pg_trigger WHERE tgname='audit_logs_chain' LIMIT 1"
            )
        ).scalar(),
        "audit_logs_owner": db.execute(
            text(
                "SELECT pg_get_userbyid(relowner) FROM pg_class "
                "WHERE oid = 'public.audit_logs'::regclass"
            )
        ).scalar(),
        "public_schema_owner": db.execute(
            text(
                "SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname='public'"
            )
        ).scalar(),
        "chain_schema_owner": (
            db.execute(
                text(
                    "SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname=:s"
                ),
                {"s": schema},
            ).scalar()
            if schema
            else None
        ),
        "append_only_triggers": db.execute(
            text(
                "SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid "
                " WHERE NOT t.tgisinternal AND c.relname LIKE 'audit_logs%' "
                "   AND t.tgname <> 'audit_logs_chain'"
            )
        ).scalar(),
        "total_events": db.execute(
            text("SELECT count(*) FROM public.audit_logs")
        ).scalar(),
        "legacy_events": db.execute(
            text("SELECT count(*) FROM public.audit_logs WHERE record_hash IS NULL")
        ).scalar(),
        "chained_events": len(events),
        "events": [list(r) for r in events],
        "heads": [list(r) for r in heads],
        "event_fingerprint": hashlib.sha256(event_blob.encode()).hexdigest(),
        "head_fingerprint": hashlib.sha256(head_blob.encode()).hexdigest(),
    }


def _print_state(state: dict) -> None:
    print(f"  database            : {state['database']}")
    print(f"  alembic revision    : {state['alembic_revision']}")
    print(f"  chain schema        : {state['chain_schema']}")
    print(f"  chain schema owner  : {state['chain_schema_owner']}")
    print(f"  public schema owner : {state['public_schema_owner']}")
    print(f"  audit_logs owner    : {state['audit_logs_owner']}")
    print(f"  trigger points at   : {state['trigger_points_at']}")
    print(f"  trigger fn OID      : {state['trigger_function_oid']}")
    print(f"  append-only triggers: {state['append_only_triggers']}")
    print(f"  total events        : {state['total_events']}")
    print(f"  legacy (unhashed)   : {state['legacy_events']}")
    print(f"  chained             : {state['chained_events']}")
    print(f"  event fingerprint   : {state['event_fingerprint']}")
    print(f"  head  fingerprint   : {state['head_fingerprint']}")
    if state["heads"]:
        print("  per-organisation:")
        for h in state["heads"]:
            print(f"    {h[0]:24s} chained={h[3]} legacy={h[5]} genesis={h[4]}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--capture", action="store_true", help="snapshot current state")
    g.add_argument("--compare", action="store_true", help="diff against the snapshot")
    args = ap.parse_args()

    db = SessionLocal()
    try:
        state = capture_state(db)

        if args.capture:
            print("PRE-MOVE STATE")
            _print_state(state)
            SNAPSHOT.write_text(
                json.dumps(state, indent=2, default=str), encoding="utf-8"
            )
            print(f"\nsnapshot written to {SNAPSHOT}")
            return 0

        if not SNAPSHOT.exists():
            print(f"NO SNAPSHOT at {SNAPSHOT} — run --capture before the move.")
            return 2

        before = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        print("POST-MOVE STATE")
        _print_state(state)

        # These are expected to change: that is the point of the move.
        #
        # `alembic_revision` is here rather than in `must_hold` because the
        # documented sequence deliberately applies the guard revision
        # (b8c9d0e1f2a3) after the move, and `start.sh` also runs
        # `alembic upgrade head` on container restart. Treating it as an
        # invariant made this tool report a violation on a database that was
        # entirely correct — a false alarm on the one report that exists to be
        # trusted. It is still printed, so an unexpected revision is visible.
        expected_to_change = {
            "chain_schema",
            "chain_schema_owner",
            "trigger_points_at",
            "alembic_revision",
        }
        # These must NOT change under any circumstances. Every one is either
        # chain data or a property whose change would mean the move was not the
        # catalogue operation it claims to be.
        must_hold = [
            "event_fingerprint",
            "head_fingerprint",
            "total_events",
            "legacy_events",
            "chained_events",
            "audit_logs_owner",
            "public_schema_owner",
            "append_only_triggers",
            # Unchanged OID is the proof the trigger binding followed the
            # function across schemas rather than being dropped and recreated.
            "trigger_function_oid",
        ]

        print("\nINVARIANTS")
        failed = []
        for key in must_hold:
            same = before.get(key) == state.get(key)
            print(
                f"  [{'OK  ' if same else 'FAIL'}] {key}: {before.get(key)!r}"
                + ("" if same else f"  ->  {state.get(key)!r}")
            )
            if not same:
                failed.append(key)

        print("\nEXPECTED CHANGES")
        for key in sorted(expected_to_change):
            print(f"  {key}: {before.get(key)!r}  ->  {state.get(key)!r}")

        if state["chain_schema"] != "audit_chain":
            print(
                "\nWARNING: chain is not in `audit_chain`; the move did not take effect."
            )
            failed.append("chain_schema")

        if failed:
            print(f"\n{len(failed)} INVARIANT(S) VIOLATED: {', '.join(failed)}")
            print("The move altered state it must have preserved. Investigate before")
            print("trusting this chain; consider the rollback procedure.")
            return 1

        print("\nAll preserved invariants hold. Chain state is byte-identical.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
