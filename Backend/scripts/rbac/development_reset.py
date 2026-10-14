"""Reviewed, snapshot-backed development reset. Never run against production.

Plan is read-only. Apply requires its digest, exact database identity, stopped
services, a verified recovery dump and an explicit development confirmation.
Tenant deletion follows ownership foreign keys with every audit guard enabled.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from sqlalchemy import inspect, text
from sqlalchemy.engine import make_url

from scripts.rbac.development_artifacts import (
    artifacts,
    broker_plan,
    clean_broker,
    file_hash,
    quarantine,
    restore,
)

MANIFEST = (
    Path(__file__).resolve().parents[2] / "data/rbac/development_reset_manifest.json"
)
# Explicitly reviewed after f6a8c0e2b4d7 removed only organisation subscription
# columns, and after a7c9e1b3d5f8 (13 Oct 2026) widened only the unique key of
# asset_vulnerabilities to include component — no RBAC, identity, audit-log or
# catalogue table, and nothing this reset preserves or removes changes shape.
# Reviewed again for c4d6e8f0a2b4 (a nullable asset_vulnerabilities.fix_state)
# and d5e7f9a1b3c6 (services.scan_id ON DELETE SET NULL), 14 Oct 2026: neither
# touches an RBAC, identity, audit-log or catalogue table. The reset still
# empties `services`: it deletes `assets`, and services.asset_id remains ON
# DELETE CASCADE, so no service row survives the scans it no longer cascades
# from — and the child-table check below refuses the reset if one did.
# Never derive this allowlist from the current migration tree.
HEADS = {"d5e7f9a1b3c6", "policy_pro_0001", "rank_0001"}
SERVICES = ("ccure-api", "ccure-worker", "ccure-web-worker", "ccure-beat")
NATIVE = (
    "rbac_roles",
    "rbac_permissions",
    "rbac_role_permissions",
    "rbac_role_revisions",
    "rbac_user_roles",
    "rbac_default_roles",
    "platform_audit_events",
)


class ResetRefused(RuntimeError):
    """No reset is permitted until the stated guard is satisfied."""


def require(condition, reason):
    if not condition:
        raise ResetRefused(reason)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def identifier(value):
    require(
        bool(re.fullmatch(r"[a-z_][a-z_0-9]*(\.[a-z_][a-z_0-9]*)?", value)),
        "unsafe SQL identifier",
    )
    return ".".join('"' + p + '"' for p in value.split("."))


def development_guard(target, confirmation):
    require(
        all(
            os.environ.get(k, "").lower() in {"development", "dev", "test", "testing"}
            for k in ("APP_ENV", "ENV")
        ),
        "both ENV and APP_ENV must explicitly be development or test",
    )
    require(
        confirmation == "RESET DEVELOPMENT " + target,
        "explicit development confirmation does not match target database",
    )
    require(
        make_url(os.environ["DATABASE_URL"]).database == target,
        "DATABASE_URL does not identify the confirmed database",
    )


def protected_json(path, value):
    path = Path(path)
    require(not path.exists(), "recovery output already exists")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)


def backup_guard(path, expected):
    path = Path(path)
    require(
        path.is_file() and not path.is_symlink(),
        "recovery snapshot must be a regular file",
    )
    require(
        not stat.S_IMODE(path.stat().st_mode) & 0o077,
        "snapshot must have private permissions",
    )
    with path.open("rb") as stream:
        require(
            stream.read(5) == b"PGDMP",
            "snapshot must be a PostgreSQL custom-format dump",
        )
    require(file_hash(path) == expected, "recovery snapshot digest mismatch")
    # A successful restore is recorded separately by the operator. A TOC alone
    # is not accepted as restore verification.
    receipt = json.loads(Path(str(path) + ".verified.json").read_text())
    require(
        receipt.get("sha256") == expected and receipt.get("restore_verified") is True,
        "snapshot has no matching successful-restore receipt",
    )
    return {"path": str(path.absolute()), "sha256": expected}


def identity(conn):
    return dict(
        conn.execute(
            text(
                "SELECT current_database() AS database, d.oid::bigint AS database_oid, "
                "current_user AS database_user, inet_server_addr()::text AS server_address, "
                "inet_server_port() AS server_port FROM pg_database d WHERE datname=current_database()"
            )
        )
        .mappings()
        .one()
    )


def quiescence(conn, target):
    require(
        not conn.execute(
            text(
                "SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()"
            )
        ).first(),
        "target database has another connected session; quiesce all consumers",
    )
    result = subprocess.run(
        ["docker", "inspect", *SERVICES], capture_output=True, text=True
    )
    require(result.returncode == 0, "cannot verify local API/worker/beat service state")
    for container in json.loads(result.stdout):
        env = dict(p.split("=", 1) for p in container["Config"]["Env"] if "=" in p)
        url = make_url(env["DATABASE_URL"])
        if url.database == target:
            require(
                not container["State"]["Running"],
                "a target API, worker or beat is running",
            )


def fingerprint(conn, table, predicate=None):
    name = identifier(table)
    where = " WHERE " + predicate if predicate else ""
    row = (
        conn.execute(
            text(
                f"SELECT count(*) AS count, md5(coalesce(string_agg(h, '' ORDER BY h), '')) AS digest "
                f"FROM (SELECT md5(row_to_json(t)::text) h FROM {name} t{where}) hashes"
            )
        )
        .mappings()
        .one()
    )
    return dict(row)


def infrastructure(conn, manifest):
    """Owners, ACLs, functions and trigger definitions (including partitions)."""
    schemas = tuple(manifest["preserve_schemas"])
    rows = conn.execute(
        text(
            "SELECT n.nspname, n.nspowner::regrole::text, n.nspacl::text "
            "FROM pg_namespace n WHERE n.nspname = ANY(:schemas) ORDER BY 1"
        ),
        {"schemas": list(schemas)},
    ).all()
    functions = conn.execute(
        text(
            "SELECT p.oid::regprocedure::text, p.proowner::regrole::text, p.proacl::text, pg_get_functiondef(p.oid) "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname=ANY(:schemas) ORDER BY 1"
        ),
        {"schemas": list(schemas)},
    ).all()
    objects = conn.execute(
        text(
            "SELECT n.nspname,c.relname,c.relkind,c.relowner::regrole::text,c.relacl::text "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname=ANY(:schemas) ORDER BY 1,2"
        ),
        {"schemas": list(schemas)},
    ).all()
    triggers = conn.execute(
        text(
            "SELECT t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid) "
            "FROM pg_trigger t WHERE NOT t.tgisinternal AND "
            "(t.tgname LIKE 'audit_%' OR t.tgname LIKE 'rbac_%' OR t.tgname LIKE 'platform_audit%') ORDER BY 1,2"
        )
    ).all()
    require(
        any(r[0] == "audit_chain" and r[1] == "audit_chain_writer" for r in rows),
        "privileged audit-chain bootstrap is missing",
    )
    require(
        any(r[0] == "audit_retention" and r[1] == "audit_maintenance" for r in rows),
        "privileged audit-retention bootstrap is missing",
    )
    require(
        all(r[2] == "O" for r in triggers),
        "an audit or RBAC protection trigger is disabled",
    )
    return digest(
        [list(r) for group in (rows, functions, objects, triggers) for r in group]
    )


def foreign_keys(conn):
    """Check existing FK rows, including constraints marked NOT VALID."""
    rows = conn.execute(
        text(
            "SELECT c.conrelid::regclass::text child,c.confrelid::regclass::text parent,c.conname,"
            "array_agg(ca.attname ORDER BY k.i) children,array_agg(pa.attname ORDER BY k.i) parents "
            "FROM pg_constraint c JOIN LATERAL generate_subscripts(c.conkey,1) k(i) ON true "
            "JOIN pg_attribute ca ON ca.attrelid=c.conrelid AND ca.attnum=c.conkey[k.i] "
            "JOIN pg_attribute pa ON pa.attrelid=c.confrelid AND pa.attnum=c.confkey[k.i] "
            "WHERE c.contype='f' AND c.conparentid=0 GROUP BY c.oid ORDER BY 1,3"
        )
    ).mappings()
    for row in rows:
        conditions = " AND ".join(
            f"a.{identifier(a)}=b.{identifier(b)}"
            for a, b in zip(row["children"], row["parents"])
        )
        nonnull = " AND ".join(
            f"a.{identifier(a)} IS NOT NULL" for a in row["children"]
        )
        require(
            not conn.execute(
                text(
                    f"SELECT 1 FROM {identifier(row['child'])} a WHERE {nonnull} AND NOT EXISTS (SELECT 1 FROM {identifier(row['parent'])} b WHERE {conditions}) LIMIT 1"
                )
            ).first(),
            "broken foreign key: " + row["conname"],
        )


def preserved(conn, manifest):
    result = {
        t: fingerprint(conn, t, p) for t, p in manifest["preserve_tables"].items()
    }
    for schema in ("policy_pro", "rank", "ir"):
        for table in inspect(conn).get_table_names(schema=schema):
            result[schema + "." + table] = fingerprint(conn, schema + "." + table)
    return {"tables": result, "infrastructure": infrastructure(conn, manifest)}


def require_reviewed_migration_heads(conn):
    """Read-only, exact-set gate; new migrations require an ownership review."""
    require(
        set(conn.execute(text("SELECT version_num FROM alembic_version")).scalars())
        == HEADS,
        "migration heads do not match",
    )


def inventory(conn, manifest):
    tables = set(inspect(conn).get_table_names(schema="public"))
    import yaml

    registry_path = MANIFEST.parents[2] / "scripts/architecture/table_ownership.yaml"
    registry = yaml.safe_load(registry_path.read_text())["tables"]
    classified = (
        set(manifest["tenant_tables"])
        | set(manifest["child_tables"])
        | set(manifest["user_tables"])
        | set(NATIVE)
        | {"organizations", "users", "audit_logs", "scan_reports"}
        | {
            t.split(".")[1]
            for t in manifest["preserve_tables"]
            if t.startswith("public.")
        }
    )
    require(set(registry) <= classified, "ownership registry has an unclassified table")
    require(
        not tables
        - classified
        - {"alembic_version"}
        - {"audit_logs_p" + str(i) for i in range(8)},
        "database contains unreviewed tables",
    )
    require(
        not tables & {"roles", "permissions", "role_permissions", "rbac_legacy_map"},
        "legacy migration has not completed",
    )
    require(
        "role_id"
        not in {c["name"] for c in inspect(conn).get_columns("users", schema="public")},
        "users.role_id still exists",
    )
    require(set(NATIVE) <= tables, "native RBAC schema is incomplete")
    require_reviewed_migration_heads(conn)
    require(
        not conn.execute(
            text(
                "SELECT 1 FROM rbac_roles WHERE kind<>'system' OR managed_by<>'code' LIMIT 1"
            )
        ).first(),
        "unexpected custom RBAC roles require an explicit ownership review",
    )
    require(
        not conn.execute(
            text(
                "SELECT 1 FROM audit_retention.retention_holds WHERE released_at IS NULL LIMIT 1"
            )
        ).first(),
        "active retention hold blocks reset",
    )
    orgs = sorted(conn.execute(text("SELECT id FROM organizations")).scalars())
    users = sorted(conn.execute(text("SELECT id FROM users")).scalars())
    owners = sorted(set(orgs) | set(manifest["known_orphan_organizations"]))
    counts = {}
    for table, column in manifest["tenant_tables"].items():
        unknown = (
            conn.execute(
                text(
                    f"SELECT DISTINCT {identifier(column)} FROM {identifier(table)} WHERE {identifier(column)} IS NOT NULL AND {identifier(column)}<>ALL(:owners)"
                ),
                {"owners": owners},
            )
            .scalars()
            .all()
        )
        require(not unknown, "unreviewed orphan ownership in " + table)
        counts[table] = conn.execute(
            text(
                f"SELECT count(*) FROM {identifier(table)} WHERE {identifier(column)}=ANY(:owners)"
            ),
            {"owners": owners},
        ).scalar_one()
    for table in (
        *manifest["child_tables"],
        *manifest["user_tables"],
        "audit_logs",
        "scan_reports",
        "rbac_user_roles",
    ):
        counts[table] = conn.execute(
            text(f"SELECT count(*) FROM {identifier(table)}")
        ).scalar_one()
    scans, tasks = [], []
    for table in ("scans", "web_scans"):
        scans += list(conn.execute(text(f"SELECT id FROM {table}")).scalars())
        columns = {c["name"] for c in inspect(conn).get_columns(table)}
        for column in ("current_task_id", "celery_task_id", "task_id"):
            if column in columns:
                tasks += list(
                    conn.execute(
                        text(f"SELECT {column} FROM {table} WHERE {column} IS NOT NULL")
                    ).scalars()
                )
    foreign_keys(conn)
    return {
        "organizations": orgs,
        "users": users,
        "owners": owners,
        "scans": sorted(scans),
        "tasks": sorted(tasks),
        "counts": counts,
        "reports": sorted(conn.execute(text("SELECT id FROM scan_reports")).scalars()),
    }


def make_plan(conn, redis, args, manifest):
    require(
        identity(conn)["database"] == args.target_database,
        "connected target identity mismatch",
    )
    quiescence(conn, args.target_database)
    scope = inventory(conn, manifest)
    return {
        "identity": identity(conn),
        "manifest_sha256": digest(manifest),
        "ownership_registry_sha256": file_hash(
            MANIFEST.parents[2] / "scripts/architecture/table_ownership.yaml"
        ),
        "snapshot": backup_guard(args.snapshot, args.snapshot_sha256),
        "scope": scope,
        "preserved": preserved(conn, manifest),
        "artifacts": artifacts(
            args.reports_root, args.evidence_root, manifest, disposable=args.disposable
        ),
        "broker": broker_plan(
            redis,
            manifest,
            set(scope["owners"] + scope["users"] + scope["scans"]),
            scope["tasks"],
        ),
        "bootstrap": {
            "email": args.admin_email,
            "username": args.admin_username,
            "org_name": os.environ.get("DEFAULT_ORG_NAME"),
            "org_slug": os.environ.get("DEFAULT_ORG_SLUG"),
        },
    }


def bootstrap(db, email, username, password):
    from ccure_platform import composition
    from ccure_platform.models.users import User
    from ccure_platform.identity.jwt_handler import (
        hash_password,
        validate_password_strength,
    )
    from ccure_platform.rbac.catalogue import (
        ensure_system_roles,
        ensure_default_roles,
        sync,
    )
    from ccure_platform.rbac.provisioning import grant_platform_administrator
    from db.base import utcnow
    from db.email_canonical import canonicalize_email
    from db.migrate_production_schema import seed_default_org

    ensure_system_roles(db)
    sync(db, composition.load_permission_sources())
    ensure_default_roles(db, updated_by="system:development-reset")
    org_id = seed_default_org(db.connection())
    validate_password_strength(password)
    user = User(
        org_id=org_id,
        email=email,
        email_canonical=canonicalize_email(email),
        username=username,
        full_name="Development Administrator",
        password_hash=hash_password(password),
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="system:development-reset",
    )
    db.add(user)
    db.flush()
    grant_platform_administrator(
        db, user.id, reason="Approved clean development bootstrap"
    )
    return user


def verify_native(db, user):
    from ccure_platform import composition
    from ccure_platform.rbac import contract as c
    from ccure_platform.rbac.model import RbacRole, granted_keys
    from ccure_platform.rbac.resolver import resolve_grants, principal_for_user

    declarations = [
        d for s in composition.load_permission_sources() for d in s.permissions
    ]
    expected = {d.key for d in declarations}
    actual = set(
        db.execute(
            text("SELECT key FROM rbac_permissions WHERE status='active'")
        ).scalars()
    )
    require(
        len(expected) == 69 and actual == expected,
        "native permission catalogue differs from the frozen 69 permissions",
    )
    roles = db.query(RbacRole).all()
    require(
        {r.key for r in roles} == {r.key for r in c.SYSTEM_ROLE_SEEDS},
        "system roles differ from the frozen five",
    )
    for role in roles:
        grants = (
            expected
            if role.auto_grant_new_permissions
            else {d.key for d in declarations if role.key in d.default_grants}
        )
        require(
            granted_keys(db, str(role.id)) == grants,
            "frozen grants differ for " + role.key,
        )
    effective = {g.permission_key for g in resolve_grants(db, principal_for_user(user))}
    require(
        effective == expected,
        "administrator effective permissions do not match catalogue",
    )
    require(
        db.execute(
            text(
                "SELECT r.key FROM rbac_default_roles d JOIN rbac_roles r ON r.id=d.role_id WHERE purpose='self_registration'"
            )
        ).scalar_one()
        == "platform.viewer",
        "default role is not Viewer",
    )
    return {
        "organization": user.org_id,
        "administrator": user.id,
        "permissions": len(actual),
        "system_roles": len(roles),
        "effective_permissions": len(effective),
    }


def reset_database(db, plan, manifest, password):
    # Import actual module offboarding hooks; no authorization fallback or bypass.
    import ccure_audit.offboarding  # noqa: F401
    import ccure_platform.rbac.offboarding  # noqa: F401
    from ccure_platform.offboarding import run_user_purge_hooks
    from ccure_platform.rbac.audit import EventDraft, emit

    conn = db.connection()
    owners = plan["scope"]["owners"]
    for table, column in manifest["tenant_tables"].items():
        conn.execute(
            text(
                f"DELETE FROM {identifier(table)} WHERE {identifier(column)}=ANY(:owners)"
            ),
            {"owners": owners},
        )
    conn.execute(
        text("DELETE FROM scan_reports WHERE id=ANY(:ids)"),
        {"ids": plan["scope"]["reports"]},
    )
    for user_id in plan["scope"]["users"]:
        run_user_purge_hooks(db, user_id)
    conn.execute(
        text("DELETE FROM users WHERE id=ANY(:ids)"), {"ids": plan["scope"]["users"]}
    )
    # Existing FK ownership cascades permit this with audit protections enabled.
    conn.execute(
        text("DELETE FROM organizations WHERE id=ANY(:ids)"),
        {"ids": plan["scope"]["organizations"]},
    )
    require(
        preserved(conn, manifest) == plan["preserved"],
        "catalogue or audit infrastructure changed; reset rolled back",
    )
    for table, column in manifest["tenant_tables"].items():
        require(
            not conn.execute(
                text(
                    f"SELECT 1 FROM {identifier(table)} WHERE {identifier(column)} IS NOT NULL LIMIT 1"
                )
            ).first(),
            "tenant rows remain in " + table,
        )
    for table in (
        *manifest["child_tables"],
        *manifest["user_tables"],
        "scan_reports",
        "audit_logs",
        "rbac_user_roles",
    ):
        require(
            conn.execute(text(f"SELECT count(*) FROM {identifier(table)}")).scalar_one()
            == 0,
            "owned child rows remain in " + table,
        )
    require(
        conn.execute(text("SELECT count(*) FROM users")).scalar_one() == 0
        and conn.execute(text("SELECT count(*) FROM organizations")).scalar_one() == 0,
        "old development identities remain",
    )
    user = bootstrap(
        db, plan["bootstrap"]["email"], plan["bootstrap"]["username"], password
    )
    result = verify_native(db, user)
    foreign_keys(conn)
    require(
        preserved(conn, manifest) == plan["preserved"],
        "bootstrap changed protected catalogue or infrastructure",
    )
    emit(
        db,
        [
            EventDraft(
                action="rbac.development_reset.applied",
                resource_type="database",
                resource_id=plan["identity"]["database"],
                changes={
                    "plan_sha256": digest(plan),
                    "removed": plan["scope"]["counts"],
                    "snapshot_sha256": plan["snapshot"]["sha256"],
                    "bootstrap": result,
                },
            )
        ],
        system_actor="system:development-reset",
    )
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("operation", choices=("plan", "apply"))
    for flag in (
        "target-database",
        "confirm-development",
        "snapshot",
        "snapshot-sha256",
        "reports-root",
        "evidence-root",
        "broker-url",
        "admin-email",
        "admin-username",
        "plan",
    ):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--disposable", action="store_true")
    parser.add_argument("--plan-sha256")
    parser.add_argument("--password-file")
    parser.add_argument("--recovery-directory")
    args = parser.parse_args(argv)
    development_guard(args.target_database, args.confirm_development)
    require(
        os.environ.get("DEFAULT_ORG_NAME") == "CCure Development"
        and os.environ.get("DEFAULT_ORG_SLUG") == "development",
        "development bootstrap organization configuration is required",
    )
    if args.disposable:
        require(
            args.target_database.startswith("ccure_dev_rehearsal_"),
            "disposable database must have the rehearsal prefix",
        )
    from db.base import engine
    from sqlalchemy.orm import Session
    from redis import Redis

    manifest = json.loads(MANIFEST.read_text())
    redis = Redis.from_url(args.broker_url)
    require(
        args.broker_url == os.environ.get("CELERY_BROKER_URL"),
        "broker identity differs from the explicit development target",
    )
    moved = []
    committed = False
    with Session(engine) as db:
        try:
            conn = db.connection()
            conn.execute(text("SET LOCAL lock_timeout='5s'"))
            conn.execute(text("SELECT pg_advisory_xact_lock(828143820)"))
            if args.operation == "apply":
                lock_tables = sorted(
                    set(manifest["tenant_tables"])
                    | set(manifest["child_tables"])
                    | set(manifest["user_tables"])
                    | {"users", "organizations", "scan_reports", "rbac_user_roles"}
                )
                conn.execute(
                    text(
                        "LOCK TABLE "
                        + ",".join(identifier(t) for t in lock_tables)
                        + " IN ACCESS EXCLUSIVE MODE"
                    )
                )
                conn.execute(
                    text(
                        "LOCK TABLE "
                        + ",".join(
                            identifier(t)
                            for t in manifest["preserve_tables"]
                            if t.startswith("public.")
                        )
                        + " IN SHARE MODE"
                    )
                )
            current = make_plan(conn, redis, args, manifest)
            if args.operation == "plan":
                protected_json(args.plan, current)
                print(
                    json.dumps(
                        {
                            "plan_sha256": digest(current),
                            "identity": current["identity"],
                            "counts": current["scope"]["counts"],
                            "artifacts": len(current["artifacts"]),
                            "broker": {k: len(v) for k, v in current["broker"].items()},
                        }
                    )
                )
                return 0
            reviewed = json.loads(Path(args.plan).read_text())
            require(
                args.plan_sha256 == digest(reviewed), "reviewed plan digest mismatch"
            )
            require(current == reviewed, "target state changed since the reviewed plan")
            require(
                args.password_file and args.recovery_directory,
                "apply requires protected credentials and a recovery directory",
            )
            credential = Path(args.password_file)
            require(
                credential.is_file()
                and not credential.is_symlink()
                and not stat.S_IMODE(credential.stat().st_mode) & 0o077,
                "password file must be private",
            )
            password = credential.read_text().strip()
            require(
                len(password) >= 12,
                "administrator password does not meet minimum length",
            )
            recovery = Path(args.recovery_directory).absolute()
            require(
                not recovery.exists() and recovery.resolve() == recovery,
                "recovery directory must be new, real and absolute",
            )
            if args.disposable:
                require(
                    recovery.is_relative_to(Path("/tmp")),
                    "rehearsal recovery must be under /tmp",
                )
            recovery.mkdir(mode=0o700)
            protected_json(recovery / "plan.json", reviewed)
            # Redis DUMP is the exact recovery representation, retaining type and TTL.
            keys = set(current["broker"]["keys"]) | {
                i["queue"] for i in current["broker"]["queued"]
            }
            if current["broker"]["unacked"]:
                keys |= {"unacked", "unacked_index"}
            protected_json(
                recovery / "broker.json",
                {
                    k: {
                        "dump_hex": redis.dump(k).hex() if redis.dump(k) else None,
                        "ttl_ms": redis.pttl(k),
                    }
                    for k in sorted(keys)
                },
            )
            moved = quarantine(current["artifacts"], recovery / "artifacts")
            result = reset_database(db, current, manifest, password)
            db.commit()
            committed = True
            clean_broker(redis, current["broker"])
            protected_json(
                recovery / "result.json",
                {**result, "database_committed": True, "broker_cleaned": True},
            )
            print(json.dumps(result))
            return 0
        except Exception:
            db.rollback()
            if not committed:
                restore(moved)
            else:
                print(
                    "Database committed; broker cleanup needs recovery review. Keep services stopped."
                )
            raise


if __name__ == "__main__":
    raise SystemExit(main())
