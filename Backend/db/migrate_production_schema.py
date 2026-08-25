"""
db/migrate_production_schema.py
──────────────────────────────────────────────────────────────────────────────
Schema initialization and RBAC seeding script.

This script:
  1. Runs Alembic migrations to create/update all database schema
  2. Seeds the 5 built-in RBAC roles and permission atoms
  3. Seeds a default 'default' Organization
  4. Prints a final summary of what was created

IMPORTANT: Alembic handles all schema creation. This script only handles data initialization.

Usage
─────
  # From the Backend directory:
  python -m db.migrate_production_schema

  # OR run standalone:
  python Backend/db/migrate_production_schema.py
"""

import io
import os
import subprocess
import sys

# Force UTF-8 output on Windows (cp1252 terminal cannot handle checkmarks/arrows) when run directly
if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Allow running from repo root: python Backend/db/migrate_production_schema.py
_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_HERE)
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

# Import all models to register them in Base.metadata for bootstrapping
import db.models
from db.base import Base, engine, gen_org_id
from sqlalchemy import text

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def is_database_empty(conn) -> bool:
    result = conn.execute(
        text(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'"
        )
    )
    return result.scalar() == 0


def create_partitions(conn):
    print("\n  Creating table partitions (Enterprise Mode)...")
    partition_targets = ["audit_logs", "asset_vulnerabilities"]

    for table in partition_targets:
        is_partitioned = conn.execute(
            text(
                """
            SELECT COUNT(*)
            FROM pg_partitioned_table pt
            JOIN pg_class c ON c.oid = pt.partrelid
            WHERE c.relname = :table_name
        """
            ),
            {"table_name": table},
        ).scalar()

        if not is_partitioned:
            print(
                f"    ⚠ Skipping partitions for '{table}' — table exists as a regular (non-partitioned) table."
            )
            continue

        created = 0
        for i in range(8):
            partition_name = f"{table}_p{i}"
            already_exists = conn.execute(
                text("SELECT COUNT(*) FROM pg_class WHERE relname = :pname"),
                {"pname": partition_name},
            ).scalar()
            if not already_exists:
                conn.execute(
                    text(
                        f"CREATE TABLE {partition_name} PARTITION OF {table} FOR VALUES WITH (MODULUS 8, REMAINDER {i})"
                    )
                )
                created += 1

        if created > 0:
            print(f"    ✓ {created} new partitions created for '{table}'")
        else:
            print(f"    ✓ All partitions already exist for '{table}'")


def _print_header(title: str):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print("=" * 60)


def _table_exists(conn, table_name: str) -> bool:
    result = conn.execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
            "WHERE table_schema='public' AND table_name=:t)"
        ),
        {"t": table_name},
    )
    return result.scalar()


def _row_count(conn, table_name: str) -> int:
    try:
        from sqlalchemy import func, select, table

        stmt = select(func.count()).select_from(table(table_name))
        return conn.execute(stmt).scalar()
    except Exception:
        return -1


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Run Alembic Migrations
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_ROLES = [
    {
        "name": "superadmin",
        "description": "Full platform access — not bound to any specific organization.",
        "is_system_role": True,
    },
    {
        "name": "org_admin",
        "description": "Full access within their Organization: manage users, assets, scans, and reports.",
        "is_system_role": True,
    },
    {
        "name": "analyst",
        "description": "Can run scans, view all results within their org, and generate reports.",
        "is_system_role": True,
    },
    {
        "name": "viewer",
        "description": "Read-only access: view dashboards and existing scan history. Cannot run scans.",
        "is_system_role": True,
    },
    {
        "name": "scanner",
        "description": "API service account: can submit scan jobs and read back results programmatically.",
        "is_system_role": True,
    },
]

# resource × action permission atoms
PERMISSIONS = [
    # Scans
    ("scans", "create", "Create and start new scan sessions"),
    ("scans", "read", "View your own scan history and results"),
    ("scans", "read_all", "View all scan history within the organization"),
    ("scans", "update", "Modify scan configuration"),
    ("scans", "archive", "Move scans to the archived area"),
    ("scans", "restore", "Restore archived or recycled scans"),
    ("scans", "recycle", "Move scans to the recycle bin"),
    ("scans", "purge", "Permanently delete recycled scans"),
    ("scans", "execute", "Trigger scan execution via API"),
    ("scans", "cancel", "Cancel an in-progress scan"),
    # Assets
    ("assets", "create", "Manually add assets to the registry"),
    ("assets", "read", "View asset inventory and details"),
    ("assets", "update", "Edit asset metadata, tags, and notes"),
    ("assets", "delete", "Remove assets from the registry"),
    ("assets", "export", "Export asset list to CSV/JSON"),
    # Vulnerabilities / Findings
    ("findings", "read", "View vulnerability findings"),
    ("findings", "update", "Update finding status (accept, suppress, remediate)"),
    ("findings", "export", "Export findings to CSV/JSON/PDF"),
    # Reports
    ("reports", "create", "Generate reports"),
    ("reports", "read", "View and download reports"),
    ("reports", "delete", "Delete generated reports"),
    # Users
    ("users", "create", "Invite and create user accounts"),
    ("users", "read", "List and view user accounts"),
    ("users", "update", "Edit user details and roles"),
    ("users", "delete", "Deactivate or delete user accounts"),
    # Credentials
    ("credentials", "create", "Store scan credentials"),
    ("credentials", "read", "List stored credential profiles (not the secrets)"),
    ("credentials", "delete", "Remove stored credential profiles"),
    # Settings / Org
    ("settings", "read", "View organization settings"),
    ("settings", "update", "Change organization settings and feature flags"),
    # Dashboard
    ("dashboard", "read", "View the security analytics dashboard"),
    # Roles & Permissions
    ("roles", "read", "View system roles and permissions"),
    ("roles", "create", "Create custom roles"),
    ("roles", "update", "Modify role permissions"),
    ("roles", "delete", "Delete custom roles"),
    # Organizations (multi-tenant)
    ("organizations", "read", "View organizations"),
    ("organizations", "create", "Create new organizations"),
    ("organizations", "update", "Update organization settings"),
    ("organizations", "delete", "Delete organizations"),
    # Audit Logs
    ("audit", "read", "View the immutable audit log"),
    # Taking a copy of the trail off the platform is a distinct act from
    # reading it on screen, and is audited as one. It is a permission rather
    # than a role check because the export is tenant-scoped -- unlike the
    # platform-wide email-domain rules, which are superadmin-only for exactly
    # the opposite reason.
    ("audit", "export", "Export the audit log as CSV or PDF"),
    # Compliance
    ("compliance", "read", "View compliance dashboards and findings"),
    ("compliance", "scan", "Trigger manual compliance scans"),
    ("compliance", "manage_schedules", "Manage recurring compliance scan schedules"),
    ("compliance", "attest", "Record manual control attestation and evidence"),
    ("compliance", "remediate", "Apply remediation scripts and status updates"),
    ("compliance", "manage_rules", "Create and edit compliance policies and rules"),
    ("compliance", "manage_frameworks", "Install and configure compliance frameworks"),
    (
        "compliance",
        "manage_retention",
        "Configure compliance evidence retention policies",
    ),
    (
        "compliance",
        "manage_integrations",
        "Configure compliance notifications and integrations",
    ),
    (
        "compliance",
        "approve_exception",
        "Approve or reject compliance exception waivers",
    ),
    (
        "compliance",
        "export_report",
        "Export Statement of Applicability and executive reports",
    ),
]

# Which permissions are granted to each role
# superadmin gets everything; others get a subset
ROLE_PERMISSIONS = {
    "superadmin": "*",  # all permissions
    "org_admin": [
        "scans:create",
        "scans:read",
        "scans:read_all",
        "scans:update",
        "scans:archive",
        "scans:restore",
        "scans:recycle",
        "scans:purge",
        "scans:execute",
        "scans:cancel",
        "assets:create",
        "assets:read",
        "assets:update",
        "assets:delete",
        "assets:export",
        "findings:read",
        "findings:update",
        "findings:export",
        "reports:create",
        "reports:read",
        "reports:delete",
        "users:create",
        "users:read",
        "users:update",
        "users:delete",
        "roles:read",
        "credentials:create",
        "credentials:read",
        "credentials:delete",
        "settings:read",
        "settings:update",
        "dashboard:read",
        "audit:read",
        "audit:export",
        "compliance:read",
        "compliance:scan",
        "compliance:manage_schedules",
        "compliance:attest",
        "compliance:remediate",
        "compliance:manage_rules",
        "compliance:manage_frameworks",
        "compliance:manage_retention",
        "compliance:manage_integrations",
        "compliance:approve_exception",
        "compliance:export_report",
    ],
    "analyst": [
        "scans:create",
        "scans:read",
        "scans:read_all",
        "scans:execute",
        "scans:cancel",
        "assets:read",
        "assets:update",
        "assets:export",
        "findings:read",
        "findings:update",
        "findings:export",
        "reports:create",
        "reports:read",
        "credentials:read",
        "settings:read",
        "dashboard:read",
        "compliance:read",
        "compliance:scan",
        "compliance:manage_schedules",
        "compliance:attest",
        "compliance:remediate",
        "compliance:export_report",
    ],
    "viewer": [
        "scans:read",
        "scans:read_all",
        "assets:read",
        "findings:read",
        "reports:read",
        "settings:read",
        "dashboard:read",
        "compliance:read",
    ],
    "scanner": [
        "scans:create",
        "scans:read",
        "scans:execute",
        "credentials:read",
    ],
}

DEFAULT_ORG_NAME = "superadmin"
DEFAULT_ORG_SLUG = "KING"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _print_header(title: str):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print("=" * 60)


def _table_exists(conn, table_name: str) -> bool:
    result = conn.execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
            "WHERE table_schema='public' AND table_name=:t)"
        ),
        {"t": table_name},
    )
    return result.scalar()


def _row_count(conn, table_name: str) -> int:
    try:
        from sqlalchemy import func, select, table

        stmt = select(func.count()).select_from(table(table_name))
        return conn.execute(stmt).scalar()
    except Exception:
        return -1


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Run Alembic Migrations
# ─────────────────────────────────────────────────────────────────────────────


def run_alembic_migrations():
    _print_header("Step 1: Running Alembic Schema Migrations")

    with engine.begin() as conn:
        empty = is_database_empty(conn)

    if empty:
        print(
            "  ✓ No public tables found; bootstrapping schema from SQLAlchemy metadata."
        )
        Base.metadata.create_all(bind=engine)
        with engine.begin() as conn:
            create_partitions(conn)

        # Triggers and grants cannot be expressed in SQLAlchemy metadata, so
        # `create_all` does not produce them and the migration that would has
        # just been skipped by the `stamp head` below. Without this call a
        # fresh install would come up with `audit_logs` fully mutable while an
        # upgraded install was append-only — the fresh-vs-migrated divergence
        # `tests/repo/test_schema_drift.py` exists to catch, except that test
        # only compares columns and would not see a missing trigger.
        with engine.begin() as conn:
            from db.audit_hardening import apply_audit_immutability

            result = apply_audit_immutability(conn)
            print(
                f"  ✓ audit_logs append-only enforcement applied "
                f"({result['partitions']} partitions)."
            )

        # The tamper-evidence chain is deliberately NOT installed here, and it
        # cannot be: it needs a dedicated `audit_chain_writer` role that owns
        # the chain-head table and the SECURITY DEFINER hash functions, and this
        # process connects as the application role, which holds neither
        # SUPERUSER nor CREATEROLE. Measured on this deployment:
        #
        #     CREATE ROLE ...          -> permission denied to create role
        #     ALTER TABLE ... OWNER TO -> must be able to SET ROLE
        #
        # Granting the application role CREATEROLE to close that gap would
        # defeat the control it exists to build, since from PostgreSQL 16 a
        # CREATEROLE role becomes admin of the roles it creates and could
        # SET ROLE into the writer.
        #
        # So a fresh install comes up append-only but unchained, and says so
        # here as well as on every subsequent boot via `log_audit_chain_state()`
        # in main.py's lifespan. Silence would be the dangerous option: the
        # deployment behaves normally while writing unverifiable events.
        print(
            "  ! audit tamper-evidence chain NOT installed — this requires a\n"
            "    database administrator to run, as a superuser:\n"
            "        psql -v ON_ERROR_STOP=1 -f "
            "Backend/scripts/audit/bootstrap_chain.sql\n"
            "    Until then audit events are append-only but carry no hash and\n"
            "    cannot be cryptographically verified."
        )

        print("  ✓ Schema bootstrap complete; stamping Alembic head.")
        command = [sys.executable, "-m", "alembic", "stamp", "head"]
    else:
        command = [sys.executable, "-m", "alembic", "upgrade", "head"]

    try:
        result = subprocess.run(
            command, cwd=_BACKEND, capture_output=True, text=True, timeout=120
        )

        if result.returncode == 0:
            print("  ✓ Alembic command completed successfully")
            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        print(f"    {line}")
        else:
            print("  ✗ Alembic command failed:")
            print(result.stderr)
            sys.exit(1)
    except subprocess.TimeoutExpired:
        print("  ✗ Alembic command timed out")
        sys.exit(1)
    except Exception as e:
        print(f"  ✗ Error running Alembic: {e}")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Seed RBAC
# ─────────────────────────────────────────────────────────────────────────────


def seed_rbac(conn):
    _print_header("Step 2: Seeding RBAC Roles & Permissions")

    # ── Roles ─────────────────────────────────────────────────────────────────
    role_ids = {}
    for role_data in SYSTEM_ROLES:
        existing = conn.execute(
            text("SELECT id FROM roles WHERE name = :name"), {"name": role_data["name"]}
        ).fetchone()
        if existing:
            role_ids[role_data["name"]] = existing[0]
            print(f"  ✓ role '{role_data['name']}' already exists (id={existing[0]})")
        else:
            result = conn.execute(
                text(
                    """
                    INSERT INTO roles (name, description, is_system_role, created_at)
                    VALUES (:name, :description, :is_system_role, NOW())
                    RETURNING id
                """
                ),
                role_data,
            )
            new_id = result.fetchone()[0]
            role_ids[role_data["name"]] = new_id
            print(f"  + Created role '{role_data['name']}' (id={new_id})")

    # ── Permissions ───────────────────────────────────────────────────────────
    perm_ids = {}
    for resource, action, description in PERMISSIONS:
        key = f"{resource}:{action}"
        existing = conn.execute(
            text("SELECT id FROM permissions WHERE resource=:r AND action=:a"),
            {"r": resource, "a": action},
        ).fetchone()
        if existing:
            perm_ids[key] = existing[0]
        else:
            result = conn.execute(
                text(
                    """
                    INSERT INTO permissions (resource, action, description)
                    VALUES (:resource, :action, :description)
                    RETURNING id
                """
                ),
                {"resource": resource, "action": action, "description": description},
            )
            perm_ids[key] = result.fetchone()[0]
            print(f"  + Permission: {key}")

    print(f"\n  Total permissions: {len(perm_ids)}")

    legacy_scan_delete_ids = [
        row[0]
        for row in conn.execute(
            text(
                "SELECT id FROM permissions WHERE resource='scans' AND action='delete'"
            )
        ).fetchall()
    ]
    if legacy_scan_delete_ids:
        conn.execute(
            text(
                """
                DELETE FROM role_permissions
                WHERE permission_id IN (
                    SELECT id FROM permissions
                    WHERE resource='scans' AND action='delete'
                )
            """
            )
        )
        conn.execute(
            text("DELETE FROM permissions WHERE resource='scans' AND action='delete'")
        )
        print("  - Removed legacy permission: scans:delete")

    # ── Role ↔ Permission assignments ─────────────────────────────────────────
    print("\n  Assigning permissions to roles...")
    all_perm_ids = list(perm_ids.values())

    for role_name, perms in ROLE_PERMISSIONS.items():
        role_id = role_ids.get(role_name)
        if not role_id:
            continue

        target_perm_ids = (
            all_perm_ids
            if perms == "*"
            else [perm_ids[p] for p in perms if p in perm_ids]
        )

        for perm_id in target_perm_ids:
            conn.execute(
                text(
                    """
                    INSERT INTO role_permissions (role_id, permission_id)
                    VALUES (:role_id, :perm_id)
                    ON CONFLICT DO NOTHING
                """
                ),
                {"role_id": role_id, "perm_id": perm_id},
            )

        count = conn.execute(
            text("SELECT COUNT(*) FROM role_permissions WHERE role_id=:r"),
            {"r": role_id},
        ).scalar()
        print(f"  ✓ {role_name:12s} → {count} permissions")


# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — Default Organization
# ─────────────────────────────────────────────────────────────────────────────


def seed_default_org(conn):
    _print_header("Step 3: Seeding Default Organization (Stripe-Style ID)")
    org_id = gen_org_id(DEFAULT_ORG_SLUG)

    existing = conn.execute(
        text("SELECT id, name FROM organizations WHERE slug = :slug OR id = :id"),
        {"slug": DEFAULT_ORG_SLUG, "id": org_id},
    ).fetchone()

    if existing:
        print(
            f"  ✓ Default organization already exists: '{existing[1]}' (id={existing[0]})"
        )
        return existing[0]

    result = conn.execute(
        text(
            """
            INSERT INTO organizations
                (id, name, slug, plan, max_assets, max_users, is_active, settings, created_at, updated_at)
            VALUES
                (:id, :name, :slug, 'pro', 10000, 100, true, '{}', NOW(), NOW())
            RETURNING id, name
        """
        ),
        {"id": org_id, "name": DEFAULT_ORG_NAME, "slug": DEFAULT_ORG_SLUG},
    )
    row = result.fetchone()
    print(f"  + Created default organization: '{row[1]}' (id={row[0]})")
    print(f"  ✔ ID is human-readable: {row[0]!r} (not a UUID!)")
    return row[0]


# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — Summary
# ─────────────────────────────────────────────────────────────────────────────


def print_summary(conn):
    _print_header("Database Initialization Complete")

    tables = [
        ("organizations", "Tenant organizations"),
        ("roles", "RBAC roles"),
        ("permissions", "Permission atoms"),
        ("role_permissions", "Role ↔ Permission assignments"),
        ("users", "User accounts"),
        ("refresh_token_sessions", "Active JWT sessions"),
        ("audit_logs", "Immutable audit trail"),
        ("assets", "Asset registry (persistent host inventory)"),
        ("asset_tags", "Asset labels"),
        ("asset_notes", "Analyst notes"),
        ("asset_change_log", "Differential scan change history"),
        ("scans", "Scan sessions"),
        ("scan_phases", "Per-phase execution tracking"),
        ("services", "Discovered services (normalized ports)"),
        ("tls_details", "TLS/SSL assessment per service"),
        ("http_security_details", "HTTP security header assessment"),
        ("vulnerability_definitions", "CVE/vuln catalog"),
        ("asset_vulnerabilities", "Findings (asset × cve per scan)"),
        ("mac_vendor_cache", "MAC address OUI vendor cache"),
        ("notifications", "User notification inbox"),
    ]

    print(f"\n  {'Table':<30} {'Rows':>8}   {'Purpose'}")
    print(f"  {'-'*30} {'-'*8}   {'-'*40}")
    for table, purpose in tables:
        count = _row_count(conn, table)
        count_str = str(count) if count >= 0 else "ERR"
        print(f"  {table:<30} {count_str:>8}   {purpose}")

    print("\n  ✅ Database is initialized and ready.")
    print()
    print("  ✨ Stripe-Style ID Examples (what you'll see in your DB now):")
    print("     org_default              → Default Organization")
    print("     usr_def_pankaj_x9v1      → User 'pankaj' in default org")
    print("     scn_def_07may25_x9v1     → Scan run on May 7 2025 in default org")
    print("     ast_def_192.168.1.5      → Host 192.168.1.5 in default org")
    print("     svc_192.168.1.5_22_tcp   → TCP/22 service on that host")
    print("     fnd_ast_def_...CVE-2024  → Finding: CVE on that host")
    print()
    print("  Next steps:")
    print("    1. Create your first admin user via the /auth/register endpoint")
    print("    2. The user ID will look like: usr_def_[username]_[4rand]")
    print("    3. Run scans — scan IDs will look like: scn_def_[ddmonyy]_[4rand]")


# ─────────────────────────────────────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────────────────────────────────────


def run_migration():
    print("\n" + "=" * 60)
    print("  CCure Audit PRO -- Database Initialization")
    print("=" * 60)
    print(f"\n  Database: {engine.url}")

    # Validate connection
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print("  ✓ Database connection verified")
    except Exception as e:
        print(f"\n  ✗ Cannot connect to database: {e}")
        sys.exit(1)

    # Step 1: Run Alembic migrations
    run_alembic_migrations()

    # Step 1.5: Run additive migrations
    # 1. Users schema
    try:
        from db.models.users import ensure_user_schema

        ensure_user_schema()
        print("  ✓ User schema verified and migrated")
    except Exception as e:
        print(f"  ✗ Failed to run additive User schema updates: {e}")

    # 2. Assets (OUI Cache) schema
    try:
        from db.models.assets import ensure_mac_vendor_schema

        ensure_mac_vendor_schema()
        print("  ✓ MAC OUI cache schema verified and migrated")
    except Exception as e:
        print(f"  ✗ Failed to run additive MAC OUI cache schema updates: {e}")

    # 3. Scans schema (might fail on Windows permission issues with scapy)
    try:
        from scans.schema_bootstrap import ensure_scan_schema

        ensure_scan_schema()
        print("  ✓ Scan schema verified and migrated")
    except Exception as e:
        print(f"  ✗ Failed to run additive Scan schema updates: {e}")

    # 4. Network Topology schema
    try:
        from db.models.topology import ensure_topology_schema

        ensure_topology_schema()
        print("  ✓ Network Topology schema verified and migrated")
    except Exception as e:
        print(f"  ✗ Failed to run additive Topology schema updates: {e}")

    # Step 2 & 3: Seed RBAC and default org in a transaction
    with engine.begin() as conn:
        seed_rbac(conn)
        seed_default_org(conn)

    # Step 4: Print summary
    with engine.connect() as conn:
        print_summary(conn)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    run_migration()
