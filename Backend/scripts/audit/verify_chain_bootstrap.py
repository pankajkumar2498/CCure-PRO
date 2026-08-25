"""
scripts/audit/verify_chain_bootstrap.py
─────────────────────────────────────────────────────────────────────────────
Acceptance check for `bootstrap_chain.sql`. **Run this first**, before any
other chain-dependent test, and run it as the APPLICATION role:

    docker exec ccure-api python scripts/audit/verify_chain_bootstrap.py

Why it exists
─────────────
The chain's security rests on a cross-role `SECURITY DEFINER` arrangement that
cannot be prototyped without role-creation rights: a trigger on a table owned
by the application role invokes a function owned by `audit_chain_writer`, which
writes a table the application role cannot touch. Until that path has actually
executed, "implemented" would be a claim rather than a fact.

It also checks the four things that make `SECURITY DEFINER` safe rather than a
privilege-escalation gift: ownership, a pinned `search_path`, EXECUTE revoked
from PUBLIC, and no role membership that would let the caller `SET ROLE` its
way around the boundary.

Non-invasive
────────────
The end-to-end probe inserts one audit event and then **rolls back**. The head
advance is observed inside the transaction, so the cross-role write is proven
without leaving a synthetic row in an append-only table that could never be
removed afterwards.

Exit code is 0 only if every check passes.
"""

from __future__ import annotations

import sys

from db.base import SessionLocal, gen_uuid
from sqlalchemy import text

APP_FUNCS = (
    ("_audit_field_v1", "text"),
    ("audit_canonical_payload_v1", "public.audit_logs"),
    ("audit_record_hash_v1", "text, public.audit_logs"),
    ("audit_chain_advance_v1", ""),
    ("audit_chain_seed_legacy_v1", ""),
)
#: The two that write `audit_chain_heads` and therefore must run as the owner.
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


def _refused(db, sql: str, params: dict | None = None) -> tuple[bool, str]:
    """Run `sql`, expecting the database to refuse it."""
    try:
        db.execute(text(sql), params or {})
        db.rollback()
        return False, "ALLOWED"
    except Exception as exc:  # noqa: BLE001 - the message is the evidence
        db.rollback()
        first = str(exc).splitlines()[0]
        return ("permission denied" in first or "must be" in first), first[:110]


def main() -> int:
    db = SessionLocal()
    scalar = lambda sql, **p: db.execute(text(sql), p).scalar()  # noqa: E731

    app_role = scalar("SELECT current_user")
    print(f"connected as : {app_role}")
    print(f"database     : {scalar('SELECT current_database()')}\n")

    # ── Preflight: is the bootstrap even installed? ─────────────────────────
    installed = bool(scalar("SELECT to_regclass('public.audit_chain_heads')")) and bool(
        scalar("SELECT 1 FROM pg_trigger WHERE tgname='audit_logs_chain' LIMIT 1")
    )
    if not installed:
        print("NOT VERIFIED: the chain bootstrap has not been run on this database.")
        print("A database administrator must run, as postgres:")
        print("    psql -U postgres -d <db> -v ON_ERROR_STOP=1 \\")
        print("         -f Backend/scripts/audit/bootstrap_chain.sql")
        print("\nNothing below has been checked. This is not a pass.")
        return 2

    # ── 1-3. The cross-role SECURITY DEFINER path, end to end ──────────────
    org_id = scalar(
        "SELECT org_id FROM audit_chain_heads ORDER BY legacy_event_count DESC LIMIT 1"
    ) or scalar("SELECT id FROM organizations ORDER BY created_at LIMIT 1")

    before = db.execute(
        text(
            "SELECT event_count, last_event_id, last_record_hash "
            "FROM audit_chain_heads WHERE org_id = :o"
        ),
        {"o": org_id},
    ).fetchone()
    before_count = before[0] if before else 0

    probe_id = gen_uuid()
    try:
        db.execute(
            text(
                """
                INSERT INTO audit_logs
                    (id, org_id, action, resource_type, status, severity, created_at)
                VALUES
                    (:id, :org, 'audit.chain_probe', 'audit', 'success', 'info', now())
                """
            ),
            {"id": probe_id, "org": org_id},
        )
        row = db.execute(
            text(
                "SELECT prev_hash, record_hash FROM audit_logs "
                "WHERE id = :id AND org_id = :o"
            ),
            {"id": probe_id, "o": org_id},
        ).fetchone()
        after = db.execute(
            text(
                "SELECT event_count, last_event_id, last_record_hash "
                "FROM audit_chain_heads WHERE org_id = :o"
            ),
            {"o": org_id},
        ).fetchone()

        check(
            row is not None and row[1] is not None,
            "1. app role INSERT is chained (record_hash written by trigger)",
            f"record_hash={row[1][:16] if row and row[1] else None}...",
        )
        check(
            row is not None
            and row[1]
            == scalar(
                "SELECT audit_record_hash_v1(a.prev_hash, a) FROM audit_logs a "
                "WHERE a.id = :id AND a.org_id = :o",
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
            "3. SECURITY DEFINER advanced audit_chain_heads across the role boundary",
            f"event_count {before_count} -> {after[0] if after else '?'}",
        )
    finally:
        # The probe never lands: an append-only table must not accumulate
        # synthetic rows that can never be removed.
        db.rollback()

    check(
        scalar("SELECT count(*) FROM audit_logs WHERE id = :id", id=probe_id) == 0,
        "3b. probe rolled back, no synthetic row persisted",
    )

    # ── 4-6. Direct writes to the head table must be denied ────────────────
    for verb, sql in (
        (
            "INSERT",
            "INSERT INTO audit_chain_heads (org_id, event_count, legacy_event_count) "
            "VALUES ('org_probe_forged', 0, 0)",
        ),
        ("UPDATE", "UPDATE audit_chain_heads SET last_record_hash = repeat('f', 64)"),
        ("DELETE", "DELETE FROM audit_chain_heads"),
    ):
        ok, detail = _refused(db, sql)
        check(ok, f"4-6. direct {verb} on audit_chain_heads is denied", detail)

    # ── 7. The app role cannot grant itself the privilege back ─────────────
    #
    # Asserted on the EFFECT, not on an exception, because PostgreSQL does not
    # raise one here: a GRANT issued by a role holding no grant option emits
    # `WARNING: no privileges were granted` and succeeds as a no-op. An earlier
    # version of this check expected a raise and reported FAIL against a
    # boundary that was in fact intact — the failure mode being guarded against
    # everywhere else in this module, a check that answers for the wrong reason.
    #
    # What matters is that the privilege is still absent afterwards and the
    # write is still refused.
    before = scalar(
        "SELECT has_table_privilege(:r,'audit_chain_heads','UPDATE')", r=app_role
    )
    try:
        db.execute(text(f'GRANT UPDATE ON audit_chain_heads TO "{app_role}"'))
    except Exception:  # noqa: BLE001 - a refusal here is also an acceptable outcome
        db.rollback()
    after = scalar(
        "SELECT has_table_privilege(:r,'audit_chain_heads','UPDATE')", r=app_role
    )
    still_denied, denial = _refused(
        db, "UPDATE audit_chain_heads SET last_record_hash = repeat('f', 64)"
    )
    check(
        before is False and after is False and still_denied,
        "7. app role cannot GRANT itself write access",
        f"privilege before={before} after={after}; write still denied={still_denied}",
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

    # ── 9-12. Object configuration ─────────────────────────────────────────
    check(
        scalar(
            "SELECT pg_get_userbyid(relowner) FROM pg_class "
            "WHERE oid = 'public.audit_chain_heads'::regclass"
        )
        == "audit_chain_writer",
        "9a. audit_chain_heads is owned by audit_chain_writer",
    )
    check(
        scalar(
            "SELECT has_table_privilege(:r,'audit_chain_heads','SELECT')", r=app_role
        )
        is True,
        "9b. app role retains SELECT on audit_chain_heads",
    )

    for fname, args in APP_FUNCS:
        sig = f"public.{fname}({args})"
        owner = scalar(
            "SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE oid = CAST(:s AS regprocedure)",
            s=sig,
        )
        check(
            owner == "audit_chain_writer",
            f"9c. {fname} owned by audit_chain_writer",
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
            "search_path=pg_catalog, public" in cfg.replace('"', ""),
            f"10a. {fname} has a pinned search_path",
            cfg,
        )
        if fname == "audit_chain_advance_v1":
            check(
                "lock_timeout=3s" in cfg, "10b. chain trigger fn pins lock_timeout", cfg
            )

        secdef = scalar(
            "SELECT prosecdef FROM pg_proc WHERE oid = CAST(:s AS regprocedure)", s=sig
        )
        check(
            secdef == (fname in DEFINER_FUNCS),
            f"11. {fname} SECURITY DEFINER is {fname in DEFINER_FUNCS}",
            f"prosecdef={secdef}",
        )

        pub = scalar("SELECT has_function_privilege('public', :s, 'EXECUTE')", s=sig)
        check(pub is False, f"12a. PUBLIC cannot EXECUTE {fname}", f"public={pub}")

        appx = scalar(
            "SELECT has_function_privilege(:r, :s, 'EXECUTE')", r=app_role, s=sig
        )
        check(
            appx is (fname in APP_EXECUTABLE),
            f"12b. app role EXECUTE on {fname} is {fname in APP_EXECUTABLE}",
            f"app={appx}",
        )

    db.close()

    # ── Report ─────────────────────────────────────────────────────────────
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
        print("\nThe cross-role SECURITY DEFINER path is NOT verified.")
        return 1
    print("\nCross-role SECURITY DEFINER path verified end to end.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
