"""
scripts/audit/verify_chain_bootstrap.py
─────────────────────────────────────────────────────────────────────────────
Acceptance check for `bootstrap_chain.sql`. **Run this first**, before any
other chain-dependent test, and run it as the APPLICATION role:

    docker exec ccure-api python scripts/audit/verify_chain_bootstrap.py

Why it exists
─────────────
The chain's security rests on two arrangements that cannot be prototyped
without role-creation rights:

1. A cross-role `SECURITY DEFINER` path — a trigger on a table owned by the
   application role invokes a function owned by `audit_chain_writer`, which
   writes a table the application role cannot touch.
2. Schema isolation — the machinery lives in `audit_chain`, owned by
   `audit_chain_writer`, because **a schema owner may DROP any object in that
   schema regardless of who owns the object**. Owning the objects is necessary
   but not sufficient.

Until both have actually executed, "implemented" would be a claim rather than
a fact.

Non-invasive
────────────
The end-to-end probe inserts one audit event and then **rolls back**, so the
cross-role write is proven without leaving a synthetic row in an append-only
table that could never be removed. Every refusal probe rolls back
unconditionally and never commits — a test that verifies "X is refused" must
never be the thing that performs X.

Exit code is 0 only if every check passes.
"""

from __future__ import annotations

import sys

from db.base import SessionLocal, gen_uuid
from sqlalchemy import text

#: Where the chain machinery lives. Every reference below is qualified with it
#: — never left bare — because the application role owns `public` on some
#: databases and could create a shadow `audit_chain_heads` there.
CHAIN_SCHEMA = "audit_chain"
HEADS = f"{CHAIN_SCHEMA}.audit_chain_heads"

#: (name, argument types). The `audit_logs` row type stays in `public`: only
#: the chain machinery moves.
APP_FUNCS = (
    ("_audit_field_v1", "text"),
    ("audit_canonical_payload_v1", "public.audit_logs"),
    ("audit_record_hash_v1", "text, public.audit_logs"),
    ("audit_chain_advance_v1", ""),
    ("audit_chain_seed_legacy_v1", ""),
)
#: The two that write the head table and therefore must run as the owner.
DEFINER_FUNCS = {"audit_chain_advance_v1", "audit_chain_seed_legacy_v1"}
#: The application role legitimately calls these; it must NOT be able to call
#: the legacy seeder, which is a bootstrap-only entry point.
APP_EXECUTABLE = {
    "_audit_field_v1",
    "audit_canonical_payload_v1",
    "audit_record_hash_v1",
    "audit_chain_advance_v1",
}

results: list[tuple[bool, str, str]] = []


def check(ok: bool, name: str, detail: str = "") -> None:
    results.append((bool(ok), name, detail))


def _refused(db, sql: str) -> tuple[bool, str]:
    """
    Run `sql`, expecting the database to refuse it, **without committing**.

    The rollback is unconditional and happens before anything is returned, so a
    statement that turns out to be permitted is never made durable. This
    matters: several probes below attempt destructive DDL.
    """
    try:
        db.execute(text(sql))
        return False, "ALLOWED"
    except Exception as exc:  # noqa: BLE001 - the message is the evidence
        first = str(exc).splitlines()[0]
        return ("permission denied" in first or "must be" in first), first[:110]
    finally:
        db.rollback()


def main() -> int:
    db = SessionLocal()

    def scalar(sql: str, **params):
        return db.execute(text(sql), params).scalar()

    app_role = scalar("SELECT current_user")
    print(f"connected as : {app_role}")
    print(f"database     : {scalar('SELECT current_database()')}")
    print(f"chain schema : {CHAIN_SCHEMA}\n")

    # ── Preflight ───────────────────────────────────────────────────────────
    from db.audit_hardening import chain_objects_installed

    state = chain_objects_installed(db)
    if not state["installed"]:
        print("NOT VERIFIED: the chain bootstrap has not been run on this database.")
        print("A database administrator must run, as postgres:")
        print("    psql -U postgres -d <db> -v ON_ERROR_STOP=1 \\")
        print("         -f Backend/scripts/audit/bootstrap_chain.sql")
        print("\nNothing below has been checked. This is not a pass.")
        return 2

    if state["schema"] != CHAIN_SCHEMA:
        print(
            f"NOT VERIFIED: the chain is installed in `{state['schema']}`, not "
            f"`{CHAIN_SCHEMA}`. Where the application role owns that schema it "
            f"can DROP the chain machinery. Re-run bootstrap_chain.sql as a "
            f"superuser to move it; existing chain state is preserved."
        )
        return 2

    # ── 1-3. The cross-role SECURITY DEFINER path, end to end ──────────────
    org_id = scalar(
        f"SELECT org_id FROM {HEADS} ORDER BY legacy_event_count DESC LIMIT 1"
    ) or scalar("SELECT id FROM public.organizations ORDER BY created_at LIMIT 1")

    head_sql = (
        f"SELECT event_count, last_event_id, last_record_hash FROM {HEADS} "
        "WHERE org_id = :o"
    )
    before = db.execute(text(head_sql), {"o": org_id}).fetchone()
    before_count = before[0] if before else 0

    probe_id = gen_uuid()
    try:
        db.execute(
            text(
                "INSERT INTO public.audit_logs "
                "  (id, org_id, action, resource_type, status, severity, created_at) "
                "VALUES "
                "  (:id, :org, 'audit.chain_probe', 'audit', 'success', 'info', now())"
            ),
            {"id": probe_id, "org": org_id},
        )
        row = db.execute(
            text(
                "SELECT prev_hash, record_hash FROM public.audit_logs "
                "WHERE id = :id AND org_id = :o"
            ),
            {"id": probe_id, "o": org_id},
        ).fetchone()
        after = db.execute(text(head_sql), {"o": org_id}).fetchone()

        check(
            row is not None and row[1] is not None,
            "1. app role INSERT is chained (record_hash written by trigger)",
            f"record_hash={row[1][:16] if row and row[1] else None}...",
        )
        check(
            row is not None
            and row[1]
            == scalar(
                f"SELECT {CHAIN_SCHEMA}.audit_record_hash_v1(a.prev_hash, a) "
                "FROM public.audit_logs a WHERE a.id = :id AND a.org_id = :o",
                id=probe_id,
                o=org_id,
            ),
            "2. stored hash reproduces via the shared canonical function",
        )
        check(
            after is not None
            and after[0] == before_count + 1
            and after[1] == probe_id
            and after[2] == (row[1] if row else None),
            "3. SECURITY DEFINER advanced the head across the role boundary",
            f"event_count {before_count} -> {after[0] if after else '?'}",
        )
    finally:
        # The probe never lands: an append-only table must not accumulate
        # synthetic rows that can never be removed.
        db.rollback()

    check(
        scalar("SELECT count(*) FROM public.audit_logs WHERE id = :id", id=probe_id)
        == 0,
        "3b. probe rolled back, no synthetic row persisted",
    )

    # ── 4-6. Direct writes to the head table must be denied ────────────────
    for verb, sql in (
        (
            "INSERT",
            f"INSERT INTO {HEADS} (org_id, event_count, legacy_event_count) "
            "VALUES ('org_probe_forged', 0, 0)",
        ),
        ("UPDATE", f"UPDATE {HEADS} SET last_record_hash = repeat('f', 64)"),
        ("DELETE", f"DELETE FROM {HEADS}"),
        ("TRUNCATE", f"TRUNCATE {HEADS}"),
    ):
        ok, detail = _refused(db, sql)
        check(ok, f"4-6. direct {verb} on the head table is denied", detail)

    # ── 7. The app role cannot grant itself the privilege back ─────────────
    #
    # Asserted on the EFFECT, not on an exception: PostgreSQL does not raise
    # when a role without grant option issues a GRANT — it emits
    # `WARNING: no privileges were granted` and succeeds as a no-op. An
    # exception-based assertion reports a broken boundary that is intact.
    priv = f"SELECT has_table_privilege(:r, '{HEADS}', 'UPDATE')"
    before_priv = scalar(priv, r=app_role)
    try:
        db.execute(text(f'GRANT UPDATE ON {HEADS} TO "{app_role}"'))
    except Exception:  # noqa: BLE001 - a refusal is equally acceptable
        db.rollback()
    after_priv = scalar(priv, r=app_role)
    still_denied, _ = _refused(
        db, f"UPDATE {HEADS} SET last_record_hash = repeat('f', 64)"
    )
    check(
        before_priv is False and after_priv is False and still_denied,
        "7. app role cannot GRANT itself write access",
        f"privilege before={before_priv} after={after_priv}; write denied={still_denied}",
    )
    db.rollback()

    # ── 8. No membership, and SET ROLE is closed ───────────────────────────
    check(
        scalar("SELECT pg_has_role(:r, 'audit_chain_writer', 'MEMBER')", r=app_role)
        is False,
        "8a. app role is NOT a member of audit_chain_writer",
    )
    ok, detail = _refused(db, "SET ROLE audit_chain_writer")
    check(ok, "8b. SET ROLE audit_chain_writer is refused", detail)

    # ── 9. Ownership ───────────────────────────────────────────────────────
    check(
        scalar(
            "SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname = :s",
            s=CHAIN_SCHEMA,
        )
        == "audit_chain_writer",
        f"9a. schema {CHAIN_SCHEMA} is owned by audit_chain_writer",
    )
    check(
        scalar(
            "SELECT pg_get_userbyid(relowner) FROM pg_class "
            "WHERE oid = CAST(:h AS regclass)",
            h=HEADS,
        )
        == "audit_chain_writer",
        "9b. head table is owned by audit_chain_writer",
    )
    check(
        scalar(f"SELECT has_table_privilege(:r, '{HEADS}', 'SELECT')", r=app_role)
        is True,
        "9c. app role retains SELECT on the head table",
    )

    # ── 10-13. Removal resistance — the property the schema exists for ─────
    ok, detail = _refused(db, f"DROP SCHEMA {CHAIN_SCHEMA} CASCADE")
    check(ok, f"10. app role cannot DROP SCHEMA {CHAIN_SCHEMA}", detail)

    ok, detail = _refused(db, f"DROP TABLE {HEADS}")
    check(ok, "11. app role cannot DROP the head table", detail)

    ok, detail = _refused(
        db,
        f"DROP FUNCTION {CHAIN_SCHEMA}.audit_record_hash_v1(text, public.audit_logs)",
    )
    check(ok, "12. app role cannot DROP a chain function", detail)

    ok, detail = _refused(
        db,
        f"CREATE OR REPLACE FUNCTION {CHAIN_SCHEMA}._audit_field_v1(v text) "
        "RETURNS text LANGUAGE sql IMMUTABLE AS $$ SELECT 'x' $$",
    )
    check(ok, "13. app role cannot redefine the canonical algorithm", detail)

    # ── 14-17. Per-function configuration ──────────────────────────────────
    for fname, args in APP_FUNCS:
        sig = f"{CHAIN_SCHEMA}.{fname}({args})"

        owner = scalar(
            "SELECT pg_get_userbyid(proowner) FROM pg_proc "
            "WHERE oid = CAST(:s AS regprocedure)",
            s=sig,
        )
        check(
            owner == "audit_chain_writer",
            f"14. {fname} owned by the writer role",
            f"owner={owner}",
        )

        cfg = (
            scalar(
                "SELECT array_to_string(proconfig, ',') FROM pg_proc "
                "WHERE oid = CAST(:s AS regprocedure)",
                s=sig,
            )
            or ""
        )
        check(
            f"search_path=pg_catalog, {CHAIN_SCHEMA}, public" in cfg.replace('"', ""),
            f"15a. {fname} has a pinned search_path",
            cfg,
        )
        if fname == "audit_chain_advance_v1":
            check(
                "lock_timeout=3s" in cfg, "15b. chain trigger fn pins lock_timeout", cfg
            )

        secdef = scalar(
            "SELECT prosecdef FROM pg_proc WHERE oid = CAST(:s AS regprocedure)", s=sig
        )
        check(
            secdef == (fname in DEFINER_FUNCS),
            f"16. {fname} SECURITY DEFINER is {fname in DEFINER_FUNCS}",
            f"prosecdef={secdef}",
        )

        pub = scalar("SELECT has_function_privilege('public', :s, 'EXECUTE')", s=sig)
        check(pub is False, f"17a. PUBLIC cannot EXECUTE {fname}", f"public={pub}")

        appx = scalar(
            "SELECT has_function_privilege(:r, :s, 'EXECUTE')", r=app_role, s=sig
        )
        check(
            appx is (fname in APP_EXECUTABLE),
            f"17b. app role EXECUTE on {fname} is {fname in APP_EXECUTABLE}",
            f"app={appx}",
        )

    # ── 18. Nothing left behind in public ──────────────────────────────────
    residue = db.execute(
        text(
            "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            " WHERE n.nspname = 'public' AND p.proname IN "
            "   ('_audit_field_v1','audit_canonical_payload_v1','audit_record_hash_v1',"
            "    'audit_chain_advance_v1','audit_chain_seed_legacy_v1')"
        )
    ).scalar()
    check(
        residue == 0
        and scalar("SELECT to_regclass('public.audit_chain_heads')") is None,
        "18. no chain objects remain in schema public",
        f"stale functions in public: {residue}",
    )

    # ── 19. The trigger still points where it should ───────────────────────
    check(
        state["trigger_points_at"] == f"{CHAIN_SCHEMA}.audit_chain_advance_v1",
        "19. audit_logs_chain points at the relocated function",
        f"points at {state['trigger_points_at']}",
    )

    db.close()

    print("=" * 74)
    passed = sum(1 for ok, _, _ in results if ok)
    for ok, name, detail in results:
        print(
            f"  [{'PASS' if ok else 'FAIL'}] {name}"
            + (f"  ({detail})" if detail else "")
        )
    print("=" * 74)
    print(f"{passed}/{len(results)} checks passed")
    if passed != len(results):
        print("\nThe chain boundary is NOT verified.")
        return 1
    print("\nCross-role SECURITY DEFINER path and removal resistance verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
