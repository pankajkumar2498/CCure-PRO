"""
Make an account the platform administrator — first-run bootstrap and recovery (RBAC-8).

    python -m scripts.rbac.bootstrap_admin --email you@example.com --reason "first administrator" \
        --allow-database NAME [--recover] [--allow-additional] [--production-approved REF]

There is no hidden administrator and no application back door. Establishing the first
administrator (or recovering a system that has lost its last one) is an explicit,
operator-run, audited act:

* it assigns the ``platform.superadmin`` system role — an ordinary assignment through the
  same tables the governed API uses, revocable there;
* it is **idempotent**: asking twice for the same account changes nothing the second time;
* it **refuses** when the platform already has an active administrator, unless
  ``--allow-additional`` is given (adding to a working system is the governed API's job);
* it needs ``--reason`` and records ``rbac.bootstrap.administrator`` (or
  ``rbac.recovery.administrator`` with ``--recover``), CRITICAL, attributed to the
  ``system:rbac-bootstrap`` actor and the account's own organisation;
* it refuses an account that is not active, verified and approved, and the live databases
  without ``--production-approved <reference>``.

Recovery procedure (the last administrator is gone or locked out): take a backup, run this
with ``--recover`` and the reason, sign in, then use RBAC administration to restore the
organisation's role administrators. Needs operator access to the host or database — by design.
"""

from __future__ import annotations

import argparse
import sys

LIVE_DATABASES = {"ccure_db", "ccure_test", "vuln_intel"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    who = ap.add_mutually_exclusive_group(required=True)
    who.add_argument("--email")
    who.add_argument("--user-id")
    ap.add_argument("--reason", required=True)
    ap.add_argument("--recover", action="store_true")
    ap.add_argument("--allow-additional", action="store_true")
    ap.add_argument("--allow-database", required=True, metavar="NAME")
    ap.add_argument("--production-approved", metavar="REFERENCE")
    args = ap.parse_args(argv)

    from auth.email_utils import email_matches, normalize_email
    from ccure_platform.rbac.governance import GovernanceError
    from ccure_platform.rbac.provisioning import grant_platform_administrator
    from db.base import SessionLocal
    from db.models.users import User
    from sqlalchemy import text

    db = SessionLocal()
    try:
        name = str(db.execute(text("SELECT current_database()")).scalar())
        if args.allow_database != name:
            print(f"refused: --allow-database {name!r} is required", file=sys.stderr)
            return 3
        if name in LIVE_DATABASES and not args.production_approved:
            print(
                "refused: a live database needs --production-approved <reference>",
                file=sys.stderr,
            )
            return 3
        user_id = args.user_id
        if args.email:
            row = (
                db.query(User)
                .filter(email_matches(User.email, normalize_email(args.email)))
                .first()
            )
            if row is None:
                print("refused: no such account", file=sys.stderr)
                return 2
            user_id = row.id
        try:
            _, created = grant_platform_administrator(
                db,
                user_id,
                reason=args.reason,
                recovery=args.recover,
                allow_additional=args.allow_additional,
            )
        except GovernanceError as error:
            db.rollback()
            print(
                "refused: "
                + "; ".join(f"{v.code}: {v.message}" for v in error.violations),
                file=sys.stderr,
            )
            return 2
        db.commit()
        print(
            "administrator granted"
            if created
            else "already an administrator; nothing changed"
        )
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
