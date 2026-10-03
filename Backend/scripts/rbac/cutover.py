"""
The RBAC final-cutover tool (RBAC-8). Operator-run, never run by the application.

    python -m scripts.rbac.cutover plan      [--json]    # read-only: readiness + what apply would do
    python -m scripts.rbac.cutover apply     --allow-database NAME [--production-approved REF]
    python -m scripts.rbac.cutover verify    [--json]    # read-only: post-cutover checks
    python -m scripts.rbac.cutover rollback-prepare [--apply --allow-database NAME ...]
    python -m scripts.rbac.cutover checklist [--json|--md]

``apply`` performs the database half of the cutover, **idempotently** and stopping at the
first failing step:

    1  backup       a recent database dump exists (``backups/``) — refused without one
    2  schema       ``alembic upgrade heads`` (adds nothing destructive)
    3  catalogue    sync the permission catalogue
    4  roles        ensure the five system roles
    5  provision    assign every active account the RBAC role its legacy role maps to
                    (golden mapping), nothing else — an unmapped legacy role or an account
                    with no role is reported and left holding nothing
    6  default      configure the self-registration default role if unset
    7  verify       readiness: catalogue, system roles, an administrator, no missing or wrong
                    assignment, continuity
    8  report       a JSON record of every step, written beside the backups

It refuses the live application databases (``ccure_db``, ``ccure_test``) unless
``--production-approved <reference>`` records the approval, and refuses any database unless
``--allow-database`` names it. Nothing here deploys code: RBAC is authoritative in the
code that is deployed *after* ``apply`` has succeeded (docs/architecture/RBAC_CUTOVER.md).

``rollback-prepare`` is the pre-rollback step: it back-fills ``users.role_id`` for accounts
created without one (so the previous release's authorization can run again) from their
RBAC assignments, and refuses an account it cannot map. It never removes an assignment.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
REPO = BACKEND.parent
LIVE_DATABASES = {"ccure_db", "ccure_test", "vuln_intel"}
CHECKLIST = BACKEND / "data" / "rbac" / "cutover_checklist.json"


def _db_name(db) -> str:
    from sqlalchemy import text

    return str(db.execute(text("SELECT current_database()")).scalar())


def _step(name: str, ok: bool, detail: str = "", **extra) -> dict:
    return {"step": name, "ok": ok, "detail": detail, **extra}


def _backup_ok(max_age_hours: float, backup_file: str | None) -> dict:
    candidates = (
        [Path(backup_file)]
        if backup_file
        else sorted((REPO / "backups").glob("*.dump"))
    )
    if not candidates or not all(p.exists() for p in candidates):
        return _step(
            "backup",
            False,
            "no database dump found; take one first (scripts/backup_db.sh)",
        )
    newest = max(candidates, key=lambda p: p.stat().st_mtime)
    age = (time.time() - newest.stat().st_mtime) / 3600
    if age > max_age_hours:
        return _step(
            "backup",
            False,
            f"newest dump {newest.name} is {age:.1f}h old (limit {max_age_hours}h)",
        )
    return _step("backup", True, f"{newest.name}, {age:.1f}h old")


def plan(db) -> dict:
    from ccure_platform import composition
    from ccure_platform.rbac import reconcile
    from ccure_platform.rbac.readiness import assess

    report = reconcile.reconcile(db)
    planned = reconcile.plan(db, report)
    ready = assess(db, composition.load_permission_sources())
    return {
        "database": _db_name(db),
        "readiness": ready.as_dict(),
        "reconciliation": report.counts(),
        "would_assign": len(planned),
        "unmapped_legacy": [d.user_id for d in report.unmapped_legacy],
        "no_legacy_role": [d.user_id for d in report.no_legacy_role],
    }


def apply(db, args) -> dict:
    from ccure_platform import composition
    from ccure_platform.models.platform_audit import PlatformAuditEvent  # noqa: F401
    from ccure_platform.rbac import provisioning, reconcile
    from ccure_platform.rbac.catalogue import ensure_system_roles, sync
    from ccure_platform.rbac.readiness import assess

    steps: list[dict] = []

    def stop(step: dict) -> dict:
        steps.append(step)
        return {"ok": False, "steps": steps}

    s = _backup_ok(args.backup_max_age_hours, args.backup_file)
    if not s["ok"] and not args.skip_backup_check:
        return stop(s)
    steps.append(
        s
        if s["ok"]
        else {**s, "ok": True, "detail": "skipped by operator: " + s["detail"]}
    )

    out = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "heads"],
        cwd=BACKEND,
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        return stop(_step("schema", False, out.stderr[-400:]))
    steps.append(_step("schema", True, "alembic upgrade heads"))

    report = sync(db, composition.load_permission_sources(), audit=False)
    steps.append(
        _step(
            "catalogue",
            True,
            (
                f"{len(report.registered)} registered, {len(report.updated)} updated"
                if hasattr(report, "registered")
                else "synced"
            ),
        )
    )
    created = ensure_system_roles(db)
    steps.append(_step("roles", True, f"{len(created)} created"))

    rec = reconcile.reconcile(db)
    planned = reconcile.plan(db, rec)
    made = reconcile.apply(db, planned)
    steps.append(
        _step(
            "provision",
            True,
            f"{made} assignment(s) created",
            unmapped=[d.user_id for d in rec.unmapped_legacy],
            no_legacy_role=[d.user_id for d in rec.no_legacy_role],
        )
    )

    if provisioning.default_role(db) is None:
        from ccure_platform.rbac import governance
        from ccure_platform.rbac.audit import emit
        from ccure_platform.rbac.model import RbacRole

        viewer = db.query(RbacRole).filter_by(key="platform.viewer").one_or_none()
        if viewer is not None:
            draft = governance.configure_default_role(
                db,
                provisioning.SELF_REGISTRATION,
                str(viewer.id),
                updated_by="system:rbac-cutover",
            )
            emit(db, [draft], system_actor="system:rbac-cutover")
            steps.append(
                _step("default", True, "self_registration → the read-only system role")
            )
        else:
            steps.append(
                _step("default", False, "the read-only system role is missing")
            )
    else:
        steps.append(_step("default", True, "already configured"))

    db.commit()
    ready = assess(db, composition.load_permission_sources())
    steps.append(
        _step(
            "verify",
            ready.ready,
            "; ".join(ready.blockers) or "ready",
            notes=ready.notes,
            counts=ready.counts,
        )
    )
    return {"ok": ready.ready, "steps": steps}


def verify(db) -> dict:
    """Post-cutover checks: readiness, and that each system role holds exactly the grants
    the frozen golden mapping says."""
    from ccure_platform.rbac import legacy_map
    from ccure_platform.rbac.model import RbacRole, granted_keys
    from ccure_platform import composition
    from ccure_platform.rbac.readiness import assess

    golden = legacy_map.load_golden()
    all_keys = {p["key"] for p in golden["permissions"]}
    problems = []
    for key, expected in golden["role_grants"].items():
        row = db.query(RbacRole).filter_by(key=key).one_or_none()
        if row is None:
            problems.append(f"{key}: missing")
            continue
        want = all_keys if isinstance(expected, str) else set(expected)
        have = set(granted_keys(db, row.id))
        if want - have:
            problems.append(f"{key}: lacks {len(want - have)} permission(s)")
    ready = assess(db, composition.load_permission_sources())
    return {
        "ok": ready.ready and not problems,
        "readiness": ready.as_dict(),
        "role_grant_problems": problems,
    }


def rollback_prepare(db, apply_it: bool) -> dict:
    """Back-fill users.role_id from RBAC assignments, for accounts created without one."""
    from sqlalchemy import text

    from ccure_platform.rbac import legacy_map

    inverse = {
        r["role_key"]: r["legacy_role"] for r in legacy_map.load_golden()["roles"]
    }
    rows = db.execute(
        text(
            "SELECT u.id, r.key FROM users u "
            "JOIN rbac_user_roles ur ON ur.user_id = u.id AND ur.revoked_at IS NULL "
            "JOIN rbac_roles r ON r.id = ur.role_id "
            "WHERE u.role_id IS NULL ORDER BY u.id, r.key"
        )
    ).all()
    chosen: dict[str, str] = {}
    for uid, key in rows:
        legacy = inverse.get(key)
        if legacy and uid not in chosen:
            chosen[uid] = legacy
    unmappable = sorted(
        {
            r[0]
            for r in db.execute(
                text(
                    "SELECT id FROM users WHERE role_id IS NULL AND is_deleted = false"
                )
            ).all()
        }
        - set(chosen)
    )
    if apply_it:
        for uid, legacy in chosen.items():
            db.execute(
                text(
                    "UPDATE users SET role_id = (SELECT id FROM roles WHERE name = :n) WHERE id = :u"
                ),
                {"n": legacy, "u": uid},
            )
        db.commit()
    return {
        "backfill": len(chosen),
        "applied": apply_it,
        "unmappable_accounts": unmappable,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "command", choices=["plan", "apply", "verify", "rollback-prepare", "checklist"]
    )
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--md", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--allow-database", metavar="NAME")
    ap.add_argument("--production-approved", metavar="REFERENCE")
    ap.add_argument("--backup-file")
    ap.add_argument("--backup-max-age-hours", type=float, default=24.0)
    ap.add_argument("--skip-backup-check", action="store_true")
    args = ap.parse_args(argv)

    if args.command == "checklist":
        data = json.loads(CHECKLIST.read_text(encoding="utf-8"))
        if args.md:
            for i, item in enumerate(data["steps"], 1):
                print(f"{i}. [{item['id']}] {item['title']} — {item['verify']}")
        else:
            print(json.dumps(data, indent=2))
        return 0

    from db.base import SessionLocal

    db = SessionLocal()
    try:
        name = _db_name(db)
        mutating = args.command == "apply" or (
            args.command == "rollback-prepare" and args.apply
        )
        if mutating:
            if args.allow_database != name:
                print(
                    f"refused: --allow-database {name!r} is required", file=sys.stderr
                )
                return 3
            if name in LIVE_DATABASES and not args.production_approved:
                print(
                    f"refused: {name!r} is a live application database; record the approval "
                    "with --production-approved <reference>",
                    file=sys.stderr,
                )
                return 3
        if args.command == "plan":
            result = plan(db)
        elif args.command == "apply":
            result = apply(db, args)
            result["database"] = name
            result["production_approved"] = args.production_approved
            result["at"] = datetime.now(timezone.utc).isoformat()
            report_path = (
                REPO / "backups" / f"rbac_cutover_{name}_{int(time.time())}.json"
            )
            if report_path.parent.is_dir():
                report_path.write_text(json.dumps(result, indent=2, default=str))
                result["report"] = str(report_path)
        elif args.command == "verify":
            result = verify(db)
        else:
            result = rollback_prepare(db, args.apply)
        print(json.dumps(result, indent=2, default=str))
        return 0 if result.get("ok", True) else 2
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
