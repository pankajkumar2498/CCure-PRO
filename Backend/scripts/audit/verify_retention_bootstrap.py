"""
scripts/audit/verify_retention_bootstrap.py
─────────────────────────────────────────────────────────────────────────────
Prove that ``bootstrap_chain_retention.sql`` actually established the phase-6a
privilege boundary, rather than merely running without error.

    docker exec ccure-api python scripts/audit/verify_retention_bootstrap.py

Read-only. Every check asserts an **effect** rather than the presence of a
statement, because several of the statements in that script succeed while
doing nothing. A ``GRANT`` issued without grant option emits
``WARNING: no privileges were granted`` and returns success — the phase-4
bootstrap verifier learned that the expensive way, and the same trap applies
here.

Exit codes: 0 all checks pass, 1 a check failed, 2 retention is not installed.
"""

from __future__ import annotations

import os
import sys

BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from db.base import SessionLocal  # noqa: E402
from sqlalchemy import text  # noqa: E402

PASSED: list[str] = []
FAILED: list[str] = []

PURGE_SIG = (
    "audit_retention.purge_legacy_v1(character varying, timestamp with time zone, "
    "integer, integer, text, character varying, text)"
)
NOTE_SIG = "audit_chain.audit_chain_note_legacy_purge_v1(character varying, bigint)"
LOCK_SIG = "audit_chain.audit_chain_lock_head_v1(character varying)"
PREVIEW_SIG = "audit_retention.preview_legacy_v1(timestamp with time zone)"


def check(number: str, description: str, actual, expected, detail: str = "") -> None:
    ok = actual == expected
    line = f"  [{'PASS' if ok else 'FAIL'}] {number}. {description}"
    if detail or not ok:
        line += f"  ({detail or f'got={actual!r} want={expected!r}'})"
    print(line)
    (PASSED if ok else FAILED).append(line)


#: A tenant id no real installation uses, so the effect check below cannot
#: collide with anything. It never survives the rollback regardless.
_PROBE_ORG = "org_retention_selftest_probe"


def _effect_check(db) -> None:
    """
    Drive the **whole purge path** once, then roll it back unconditionally.

    Every check above this one reads GRANT metadata, and metadata is not the
    same thing as a working path. The first version of this verifier passed
    48/48 against a database on which no purge could execute at all: the
    EXECUTE grant on a function in ``audit_chain`` reported true while
    ``audit_maintenance`` had no USAGE on that schema, so every call failed
    with "permission denied for schema audit_chain". `has_function_privilege`
    cannot see that, and neither can any other catalogue query.

    So this creates a throwaway organisation, one chained event and one aged
    pre-chain row, purges the pre-chain row, and asserts what came back — the
    lock function, the hold check, the anchor insert, the DELETE through the
    append-only trigger, and the chain-head decrement, in one go.

    **Nothing is committed.** The transaction is rolled back in a ``finally``
    before any assertion is reported, exactly as the chain suites' probes do,
    so a failure part-way cannot leave synthetic purge state behind.

    One cost worth knowing: producing an unhashed row requires disabling the
    chain trigger, which takes a brief ACCESS EXCLUSIVE lock on ``audit_logs``.
    It is held for the few milliseconds of this transaction and released by the
    rollback. That is why this runs last.
    """
    from datetime import datetime, timedelta, timezone

    outcome: dict = {}
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=365)

        db.execute(
            text(
                "INSERT INTO organizations (id, name, slug, plan, max_assets, "
                "                           max_users, settings, is_active, created_at) "
                "VALUES (:o, 'Retention self-test', :s, 'community', 1, 1, "
                "        '{}'::jsonb, true, now())"
            ),
            {"o": _PROBE_ORG, "s": f"{_PROBE_ORG}-slug"},
        )

        # A normal insert: the chain trigger hashes it and creates the head.
        db.execute(
            text(
                "INSERT INTO audit_logs (id, org_id, action, status, severity, "
                "                        created_at) "
                "VALUES ('probe_chained', :o, 'user.login', 'success', 'info', now())"
            ),
            {"o": _PROBE_ORG},
        )

        # A pre-chain row: the only way to make one is with the trigger off,
        # which is how real legacy history came to exist.
        db.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_chain"))
        db.execute(
            text(
                "INSERT INTO audit_logs (id, org_id, action, status, severity, "
                "                        created_at) "
                "VALUES ('probe_legacy', :o, 'user.login', 'success', 'info', "
                "        now() - interval '500 days')"
            ),
            {"o": _PROBE_ORG},
        )
        db.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_chain"))

        row = db.execute(
            text(
                "SELECT deleted_count, anchor_id FROM audit_retention.purge_legacy_v1("
                "  :o, :c, 10, 90, 'verify_retention_bootstrap', NULL, 'self-test')"
            ),
            {"o": _PROBE_ORG, "c": cutoff},
        ).fetchone()

        outcome["deleted"] = int(row.deleted_count or 0)
        outcome["anchor"] = row.anchor_id
        outcome["anchor_rows"] = db.execute(
            text(
                "SELECT count(*) FROM audit_retention.retention_anchors "
                " WHERE org_id = :o AND kind = 'legacy'"
            ),
            {"o": _PROBE_ORG},
        ).scalar()
        outcome["legacy_left"] = db.execute(
            text(
                "SELECT count(*) FROM audit_logs "
                " WHERE org_id = :o AND record_hash IS NULL"
            ),
            {"o": _PROBE_ORG},
        ).scalar()
        outcome["chained_left"] = db.execute(
            text(
                "SELECT count(*) FROM audit_logs "
                " WHERE org_id = :o AND record_hash IS NOT NULL"
            ),
            {"o": _PROBE_ORG},
        ).scalar()
    except Exception as exc:  # noqa: BLE001 - the message is the evidence
        outcome["error"] = str(exc).splitlines()[0]
    finally:
        # Unconditional, and before any assertion is made.
        db.rollback()

    if "error" in outcome:
        check("12", "the purge path executes end to end", outcome["error"], "no error")
        return

    check(
        "12a",
        "the purge path executes and removes the legacy row",
        outcome["deleted"],
        1,
    )
    check("12b", "an anchor was written by that purge", outcome["anchor_rows"], 1)
    check("12c", "no pre-chain row remains", outcome["legacy_left"], 0)
    check("12d", "the chained row survived", outcome["chained_left"], 1)

    # And the rollback really did undo it.
    left = db.execute(
        text("SELECT count(*) FROM audit_logs WHERE org_id = :o"), {"o": _PROBE_ORG}
    ).scalar()
    anchors = db.execute(
        text(
            "SELECT count(*) FROM audit_retention.retention_anchors WHERE org_id = :o"
        ),
        {"o": _PROBE_ORG},
    ).scalar()
    check("12e", "the self-test left no rows behind", left, 0)
    check("12f", "the self-test left no anchor behind", anchors, 0)


def main() -> int:
    db = SessionLocal()
    app_role = db.execute(text("SELECT current_user")).scalar()
    print(f"verifying phase 6a retention bootstrap as {app_role}\n")

    try:
        installed = db.execute(
            text("SELECT 1 FROM pg_namespace WHERE nspname='audit_retention'")
        ).scalar()
        if not installed:
            print("audit retention: NOT INSTALLED")
            print(
                "\nA database administrator must run, as a superuser:\n"
                "    psql -v ON_ERROR_STOP=1 -f "
                "Backend/scripts/audit/bootstrap_chain_retention.sql\n"
                "\nUntil then no purge can run. NOT VERIFIED, not passing."
            )
            return 2

        # ── 1-3. The role exists, cannot log in, and is separate ────────────
        role = db.execute(
            text(
                "SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb "
                "  FROM pg_roles WHERE rolname='audit_maintenance'"
            )
        ).fetchone()
        check("1", "audit_maintenance exists", role is not None, True)
        if role:
            check("2a", "audit_maintenance cannot log in", role[0], False)
            check("2b", "audit_maintenance is not a superuser", role[1], False)
            check("2c", "audit_maintenance has no CREATEROLE", role[2], False)
            check("2d", "audit_maintenance has no CREATEDB", role[3], False)

        # The boundary itself. If the application role can become the
        # maintenance role, nothing below matters.
        check(
            "3a",
            "the application role is NOT a member of audit_maintenance",
            db.execute(
                text("SELECT pg_has_role(:r, 'audit_maintenance', 'MEMBER')"),
                {"r": app_role},
            ).scalar(),
            False,
        )
        check(
            "3b",
            "audit_maintenance and audit_chain_writer are separate",
            db.execute(
                text(
                    "SELECT pg_has_role('audit_maintenance','audit_chain_writer','MEMBER')"
                    "    OR pg_has_role('audit_chain_writer','audit_maintenance','MEMBER')"
                )
            ).scalar(),
            False,
        )

        # ── 4. Schema ownership ─────────────────────────────────────────────
        check(
            "4a",
            "audit_retention is owned by audit_maintenance",
            db.execute(
                text(
                    "SELECT nspowner::regrole::text FROM pg_namespace "
                    " WHERE nspname='audit_retention'"
                )
            ).scalar(),
            "audit_maintenance",
        )
        # A schema owner may drop any object in the schema regardless of who
        # owns the object. This is the phase-4 finding, and it is why the
        # application role must not own this schema.
        check(
            "4b",
            "the application role cannot CREATE in audit_retention",
            db.execute(
                text("SELECT has_schema_privilege(:r,'audit_retention','CREATE')"),
                {"r": app_role},
            ).scalar(),
            False,
        )
        check(
            "4c",
            "the application role CAN use audit_retention",
            db.execute(
                text("SELECT has_schema_privilege(:r,'audit_retention','USAGE')"),
                {"r": app_role},
            ).scalar(),
            True,
        )

        # ── 5. Table ownership and grants ───────────────────────────────────
        for table in ("retention_anchors", "retention_holds"):
            check(
                f"5a-{table}",
                f"{table} is owned by audit_maintenance",
                db.execute(
                    text(
                        "SELECT pg_get_userbyid(relowner) FROM pg_class "
                        # CAST(...) rather than `:t::regclass`: SQLAlchemy's
                        # text() reads `:t::regclass` as a bind parameter named
                        # `t:` and emits it verbatim. The same trap cost a pass
                        # in the phase-4 verifier with `:s::regprocedure`.
                        " WHERE oid = CAST(:t AS regclass)"
                    ),
                    {"t": f"audit_retention.{table}"},
                ).scalar(),
                "audit_maintenance",
            )
            for privilege, want in (
                ("SELECT", True),
                ("INSERT", False),
                ("UPDATE", False),
                ("DELETE", False),
            ):
                check(
                    f"5b-{table}-{privilege}",
                    f"app role {privilege} on {table} is {want}",
                    db.execute(
                        text("SELECT has_table_privilege(:r, :t, :p)"),
                        {
                            "r": app_role,
                            "t": f"audit_retention.{table}",
                            "p": privilege,
                        },
                    ).scalar(),
                    want,
                )

        # ── 5c. Schema reachability ─────────────────────────────────────────
        # An EXECUTE grant on a function in a schema the role cannot enter
        # reports true and does not work. This is the check whose absence let
        # the first bootstrap pass 48/48 while no purge could run at all.
        check(
            "5c-usage",
            "audit_maintenance has USAGE on audit_chain",
            db.execute(
                text(
                    "SELECT has_schema_privilege('audit_maintenance','audit_chain','USAGE')"
                )
            ).scalar(),
            True,
        )
        for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            check(
                f"5d-{privilege}",
                f"audit_maintenance has NO {privilege} on audit_chain_heads",
                db.execute(
                    text(
                        "SELECT has_table_privilege('audit_maintenance',"
                        "  'audit_chain.audit_chain_heads', :p)"
                    ),
                    {"p": privilege},
                ).scalar(),
                False,
            )

        # ── 6. audit_logs privileges for the maintenance role ───────────────
        for privilege, want in (
            ("SELECT", True),
            ("DELETE", True),
            ("UPDATE", False),
            ("INSERT", False),
            ("TRUNCATE", False),
        ):
            check(
                f"6-{privilege}",
                f"audit_maintenance {privilege} on audit_logs is {want}",
                db.execute(
                    text(
                        "SELECT has_table_privilege('audit_maintenance', "
                        "       'public.audit_logs', :p)"
                    ),
                    {"p": privilege},
                ).scalar(),
                want,
            )

        # Every leaf partition too: privileges are not inherited by partitions,
        # and a DELETE is routed to the leaf.
        missing = db.execute(
            text(
                """
                SELECT count(*) FROM pg_inherits i
                  JOIN pg_class c ON c.oid = i.inhrelid
                 WHERE i.inhparent = 'public.audit_logs'::regclass
                   AND NOT has_table_privilege('audit_maintenance',
                                               c.oid, 'DELETE')
                """
            )
        ).scalar()
        check("6-partitions", "every leaf partition grants DELETE", missing, 0)

        # ── 7. The functions ────────────────────────────────────────────────
        for number, signature, owner in (
            ("7a", PURGE_SIG, "audit_maintenance"),
            ("7b", PREVIEW_SIG, "audit_maintenance"),
            # Owned by the CHAIN role, deliberately: only a function owned by
            # the head table's owner may write to it, and granting the
            # maintenance role direct UPDATE would let retention rewrite a
            # chain tip.
            ("7c", NOTE_SIG, "audit_chain_writer"),
            # Also the chain role's: PostgreSQL requires UPDATE privilege to
            # lock a row, and audit_maintenance must never hold one on the
            # head, so the lock is taken by a function owned by the table's
            # owner.
            ("7d", LOCK_SIG, "audit_chain_writer"),
        ):
            row = db.execute(
                text(
                    "SELECT pg_get_userbyid(proowner), prosecdef, proconfig "
                    "  FROM pg_proc WHERE oid = CAST(:s AS regprocedure)"
                ),
                {"s": signature},
            ).fetchone()
            check(
                f"{number}-owner",
                f"{signature.split('(')[0]} owned by {owner}",
                row[0],
                owner,
            )
            check(
                f"{number}-secdef",
                f"{signature.split('(')[0]} is SECURITY DEFINER",
                row[1],
                True,
            )
            check(
                f"{number}-path",
                f"{signature.split('(')[0]} pins search_path",
                any(str(c).startswith("search_path=") for c in (row[2] or [])),
                True,
            )

        # ── 8. Execute privileges ───────────────────────────────────────────
        for number, signature, who, want in (
            ("8a", PURGE_SIG, "public", False),
            ("8b", PURGE_SIG, app_role, True),
            ("8c", PREVIEW_SIG, "public", False),
            ("8d", NOTE_SIG, "public", False),
            # The application role must NOT be able to adjust the chain head
            # directly: that path exists for the purge function alone.
            ("8e", NOTE_SIG, app_role, False),
            ("8f", NOTE_SIG, "audit_maintenance", True),
            ("8g", LOCK_SIG, "public", False),
            ("8h", LOCK_SIG, "audit_maintenance", True),
            # Deliberately NOT the application role: locking a tenant's chain
            # head blocks every audit write for that tenant until the
            # transaction ends, which is a denial of service nothing reachable
            # from a request may be able to cause.
            ("8i", LOCK_SIG, app_role, False),
        ):
            check(
                number,
                f"EXECUTE on {signature.split('(')[0]} for {who} is {want}",
                db.execute(
                    text(
                        "SELECT has_function_privilege(:w, CAST(:s AS regprocedure), 'EXECUTE')"
                    ),
                    {"w": who, "s": signature},
                ).scalar(),
                want,
            )

        # ── 9. The append-only trigger still refuses the application role ───
        # The escape added in 6a is `current_user = 'audit_maintenance' AND
        # OLD.record_hash IS NULL`. Read the function source and assert both
        # halves are present: a trigger that dropped the second half would let
        # a future phase-6b bug delete chained rows today.
        source = (
            db.execute(
                text(
                    "SELECT prosrc FROM pg_proc p JOIN pg_namespace n "
                    "  ON n.oid = p.pronamespace "
                    " WHERE p.proname='audit_logs_reject_mutation' AND n.nspname='public'"
                )
            ).scalar()
            or ""
        )
        check(
            "9a",
            "the trigger's retention escape requires audit_maintenance",
            "current_user = 'audit_maintenance'" in source,
            True,
        )
        check(
            "9b",
            "the trigger's retention escape requires record_hash IS NULL",
            "OLD.record_hash IS NULL" in source,
            True,
        )
        check(
            "9c",
            "the trigger still refuses UPDATE unconditionally except the FK null",
            "UPDATE is not permitted" in source,
            True,
        )

        # ── 10. Anchor table shape ──────────────────────────────────────────
        columns = {
            r[0]
            for r in db.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    " WHERE table_schema='audit_retention' "
                    "   AND table_name='retention_anchors'"
                )
            )
        }
        required = {
            "org_id",
            "kind",
            "purge_started_at",
            "purge_completed_at",
            "cutoff",
            "range_from",
            "range_to",
            "deleted_count",
            "last_deleted_event_id",
            "last_deleted_record_hash",
            "first_surviving_event_id",
            "first_surviving_record_hash",
            "head_event_count_after",
            "head_legacy_count_after",
            "head_genesis_after",
            "head_tip_after",
            "operator_db_user",
            "operator_identity",
            "audit_event_id",
            "archive_artifact",
            "backup_reference",
        }
        check(
            "10",
            "the anchor records every required fact",
            sorted(required - columns),
            [],
        )

        # ── 11. Phase 4 is untouched ────────────────────────────────────────
        check(
            "11a",
            "audit_chain_heads is still owned by audit_chain_writer",
            db.execute(
                text(
                    "SELECT pg_get_userbyid(relowner) FROM pg_class "
                    " WHERE oid='audit_chain.audit_chain_heads'::regclass"
                )
            ).scalar(),
            "audit_chain_writer",
        )
        check(
            "11b",
            "audit_maintenance cannot UPDATE the chain head directly",
            db.execute(
                text(
                    "SELECT has_table_privilege('audit_maintenance',"
                    "       'audit_chain.audit_chain_heads','UPDATE')"
                )
            ).scalar(),
            False,
        )
        check(
            "11c",
            "the chain trigger still points at audit_chain",
            db.execute(
                text(
                    "SELECT n.nspname FROM pg_trigger t "
                    "  JOIN pg_proc p ON p.oid = t.tgfoid "
                    "  JOIN pg_namespace n ON n.oid = p.pronamespace "
                    " WHERE t.tgname='audit_logs_chain' LIMIT 1"
                )
            ).scalar(),
            "audit_chain",
        )

        # ── 12. The path actually executes ──────────────────────────────────
        _effect_check(db)

        print("=" * 74)
        total = len(PASSED) + len(FAILED)
        print(f"{len(PASSED)}/{total} checks passed")
        if FAILED:
            print("\nFAILURES:")
            for line in FAILED:
                print(line)
            return 1
        print("\nPhase 6a retention boundary verified. The application role can call")
        print("the purge function and cannot do anything else it constrains.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
