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

import sys
import os
import io
import subprocess

# Force UTF-8 output on Windows (cp1252 terminal cannot handle checkmarks/arrows)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Allow running from repo root: python Backend/db/migrate_production_schema.py
_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_HERE)
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from sqlalchemy import text, inspect
from db.base import engine, Base, gen_org_id

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def is_database_empty(conn) -> bool:
    result = conn.execute(
        text("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'")
    )
    return result.scalar() == 0


def create_partitions(conn):
    print(f"\n  Creating table partitions (Enterprise Mode)...")
    partition_targets = ["audit_logs", "asset_vulnerabilities"]

    for table in partition_targets:
        is_partitioned = conn.execute(text("""
            SELECT COUNT(*)
            FROM pg_partitioned_table pt
            JOIN pg_class c ON c.oid = pt.partrelid
            WHERE c.relname = :table_name
        """), {"table_name": table}).scalar()

        if not is_partitioned:
            print(f"    ⚠ Skipping partitions for '{table}' — table exists as a regular (non-partitioned) table.")
            continue

        created = 0
        for i in range(8):
            partition_name = f"{table}_p{i}"
            already_exists = conn.execute(
                text("SELECT COUNT(*) FROM pg_class WHERE relname = :pname"),
                {"pname": partition_name}
            ).scalar()
            if not already_exists:
                conn.execute(text(f"CREATE TABLE {partition_name} PARTITION OF {table} FOR VALUES WITH (MODULUS 8, REMAINDER {i})"))
                created += 1

        if created > 0:
            print(f"    ✓ {created} new partitions created for '{table}'")
        else:
            print(f"    ✓ All partitions already exist for '{table}'")


def _print_header(title: str):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print('=' * 60)


def _table_exists(conn, table_name: str) -> bool:
    result = conn.execute(
        text("SELECT EXISTS (SELECT 1 FROM information_schema.tables "
             "WHERE table_schema='public' AND table_name=:t)"),
        {"t": table_name}
    )
    return result.scalar()


def _row_count(conn, table_name: str) -> int:
    try:
        return conn.execute(text(f"SELECT COUNT(*) FROM {table_name}")).scalar()
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
    ("scans",       "create",  "Create and start new scan sessions"),
    ("scans",       "read",    "View your own scan history and results"),
    ("scans",       "read_all", "View all scan history within the organization"),
    ("scans",       "update",  "Modify scan configuration"),
    ("scans",       "delete",  "Delete or archive scans"),
    ("scans",       "execute", "Trigger scan execution via API"),
    ("scans",       "cancel",  "Cancel an in-progress scan"),
    # Assets
    ("assets",      "create",  "Manually add assets to the registry"),
    ("assets",      "read",    "View asset inventory and details"),
    ("assets",      "update",  "Edit asset metadata, tags, and notes"),
    ("assets",      "delete",  "Remove assets from the registry"),
    ("assets",      "export",  "Export asset list to CSV/JSON"),
    # Vulnerabilities / Findings
    ("findings",    "read",    "View vulnerability findings"),
    ("findings",    "update",  "Update finding status (accept, suppress, remediate)"),
    ("findings",    "export",  "Export findings to CSV/JSON/PDF"),
    # Reports
    ("reports",     "create",  "Generate reports"),
    ("reports",     "read",    "View and download reports"),
    ("reports",     "delete",  "Delete generated reports"),
    # Users
    ("users",       "create",  "Invite and create user accounts"),
    ("users",       "read",    "List and view user accounts"),
    ("users",       "update",  "Edit user details and roles"),
    ("users",       "delete",  "Deactivate or delete user accounts"),
    # Credentials
    ("credentials", "create",  "Store scan credentials"),
    ("credentials", "read",    "List stored credential profiles (not the secrets)"),
    ("credentials", "delete",  "Remove stored credential profiles"),
    # Settings / Org
    ("settings",    "read",    "View organization settings"),
    ("settings",    "update",  "Change organization settings and feature flags"),
    # Roles & Permissions
    ("roles",       "read",    "View system roles and permissions"),
    ("roles",       "create",  "Create custom roles"),
    ("roles",       "update",  "Modify role permissions"),
    ("roles",       "delete",  "Delete custom roles"),
    # Organizations (multi-tenant)
    ("organizations", "read",    "View organizations"),
    ("organizations", "create",  "Create new organizations"),
    ("organizations", "update",  "Update organization settings"),
    ("organizations", "delete",  "Delete organizations"),
    # Audit Logs
    ("audit",       "read",    "View the immutable audit log"),
]

# Which permissions are granted to each role
# superadmin gets everything; others get a subset
ROLE_PERMISSIONS = {
    "superadmin": "*",      # all permissions
    "org_admin":  [
        "scans:create", "scans:read", "scans:read_all", "scans:update", "scans:delete",
        "scans:execute", "scans:cancel",
        "assets:create", "assets:read", "assets:update", "assets:delete", "assets:export",
        "findings:read", "findings:update", "findings:export",
        "reports:create", "reports:read", "reports:delete",
        "users:create", "users:read", "users:update", "users:delete",
        "roles:read",
        "credentials:create", "credentials:read", "credentials:delete",
        "settings:read", "settings:update",
        "audit:read",
    ],
    "analyst": [
        "scans:create", "scans:read", "scans:read_all", "scans:execute", "scans:cancel",
        "assets:read", "assets:update", "assets:export",
        "findings:read", "findings:update", "findings:export",
        "reports:create", "reports:read",
        "credentials:read",
        "settings:read",
    ],
    "viewer": [
        "scans:read",
        "assets:read",
        "findings:read",
        "reports:read",
        "settings:read",
    ],
    "scanner": [
        "scans:create", "scans:read", "scans:execute",
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
    print('=' * 60)


def _table_exists(conn, table_name: str) -> bool:
    result = conn.execute(
        text("SELECT EXISTS (SELECT 1 FROM information_schema.tables "
             "WHERE table_schema='public' AND table_name=:t)"),
        {"t": table_name}
    )
    return result.scalar()


def _row_count(conn, table_name: str) -> int:
    try:
        return conn.execute(text(f"SELECT COUNT(*) FROM {table_name}")).scalar()
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
        print("  ✓ No public tables found; bootstrapping schema from SQLAlchemy metadata.")
        Base.metadata.create_all(bind=engine)
        with engine.begin() as conn:
            create_partitions(conn)

        print("  ✓ Schema bootstrap complete; stamping Alembic head.")
        command = [sys.executable, "-m", "alembic", "stamp", "head"]
    else:
        command = [sys.executable, "-m", "alembic", "upgrade", "head"]

    try:
        result = subprocess.run(
            command,
            cwd=_BACKEND,
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode == 0:
            print("  ✓ Alembic command completed successfully")
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
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
            text("SELECT id FROM roles WHERE name = :name"),
            {"name": role_data["name"]}
        ).fetchone()
        if existing:
            role_ids[role_data["name"]] = existing[0]
            print(f"  ✓ role '{role_data['name']}' already exists (id={existing[0]})")
        else:
            result = conn.execute(
                text("""
                    INSERT INTO roles (name, description, is_system_role, created_at)
                    VALUES (:name, :description, :is_system_role, NOW())
                    RETURNING id
                """),
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
            {"r": resource, "a": action}
        ).fetchone()
        if existing:
            perm_ids[key] = existing[0]
        else:
            result = conn.execute(
                text("""
                    INSERT INTO permissions (resource, action, description)
                    VALUES (:resource, :action, :description)
                    RETURNING id
                """),
                {"resource": resource, "action": action, "description": description},
            )
            perm_ids[key] = result.fetchone()[0]
            print(f"  + Permission: {key}")

    print(f"\n  Total permissions: {len(perm_ids)}")

    # ── Role ↔ Permission assignments ─────────────────────────────────────────
    print("\n  Assigning permissions to roles...")
    all_perm_ids = list(perm_ids.values())

    for role_name, perms in ROLE_PERMISSIONS.items():
        role_id = role_ids.get(role_name)
        if not role_id:
            continue

        target_perm_ids = all_perm_ids if perms == "*" else [
            perm_ids[p] for p in perms if p in perm_ids
        ]

        for perm_id in target_perm_ids:
            conn.execute(
                text("""
                    INSERT INTO role_permissions (role_id, permission_id)
                    VALUES (:role_id, :perm_id)
                    ON CONFLICT DO NOTHING
                """),
                {"role_id": role_id, "perm_id": perm_id},
            )

        count = conn.execute(
            text("SELECT COUNT(*) FROM role_permissions WHERE role_id=:r"),
            {"r": role_id}
        ).scalar()
        print(f"  ✓ {role_name:12s} → {count} permissions")


# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — Default Organization
# ─────────────────────────────────────────────────────────────────────────────

def seed_default_org(conn):
    _print_header("Step 3: Seeding Default Organization (Stripe-Style ID)")

    existing = conn.execute(
        text("SELECT id, name FROM organizations WHERE slug = :slug"),
        {"slug": DEFAULT_ORG_SLUG}
    ).fetchone()

    if existing:
        print(f"  ✓ Default organization already exists: '{existing[1]}' (id={existing[0]})")
        return existing[0]

    # Stripe-style readable ID: "org_default"
    org_id = gen_org_id(DEFAULT_ORG_SLUG)

    result = conn.execute(
        text("""
            INSERT INTO organizations
                (id, name, slug, plan, max_assets, max_users, is_active, settings, created_at, updated_at)
            VALUES
                (:id, :name, :slug, 'pro', 10000, 100, true, '{}', NOW(), NOW())
            RETURNING id, name
        """),
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
        ("organizations",          "Tenant organizations"),
        ("roles",                  "RBAC roles"),
        ("permissions",            "Permission atoms"),
        ("role_permissions",       "Role ↔ Permission assignments"),
        ("users",                  "User accounts"),
        ("refresh_token_sessions", "Active JWT sessions"),
        ("audit_logs",             "Immutable audit trail"),
        ("assets",                 "Asset registry (persistent host inventory)"),
        ("asset_tags",             "Asset labels"),
        ("asset_notes",            "Analyst notes"),
        ("asset_change_log",       "Differential scan change history"),
        ("scans",                  "Scan sessions"),
        ("scan_phases",            "Per-phase execution tracking"),
        ("services",               "Discovered services (normalized ports)"),
        ("tls_details",            "TLS/SSL assessment per service"),
        ("http_security_details",  "HTTP security header assessment"),
        ("vulnerability_definitions", "CVE/vuln catalog"),
        ("asset_vulnerabilities",  "Findings (asset × cve per scan)"),
        ("notifications",          "User notification inbox"),
    ]

    print(f"\n  {'Table':<30} {'Rows':>8}   {'Purpose'}")
    print(f"  {'-'*30} {'-'*8}   {'-'*40}")
    for table, purpose in tables:
        count = _row_count(conn, table)
        count_str = str(count) if count >= 0 else "ERR"
        print(f"  {table:<30} {count_str:>8}   {purpose}")

    print(f"\n  ✅ Database is initialized and ready.")
    print(f"")
    print(f"  ✨ Stripe-Style ID Examples (what you'll see in your DB now):")
    print(f"     org_default              → Default Organization")
    print(f"     usr_def_pankaj_x9v1      → User 'pankaj' in default org")
    print(f"     scn_def_07may25_x9v1     → Scan run on May 7 2025 in default org")
    print(f"     ast_def_192.168.1.5      → Host 192.168.1.5 in default org")
    print(f"     svc_192.168.1.5_22_tcp   → TCP/22 service on that host")
    print(f"     fnd_ast_def_...CVE-2024  → Finding: CVE on that host")
    print(f"")
    print(f"  Next steps:")
    print(f"    1. Create your first admin user via the /auth/register endpoint")
    print(f"    2. The user ID will look like: usr_def_[username]_[4rand]")
    print(f"    3. Run scans — scan IDs will look like: scn_def_[ddmonyy]_[4rand]")


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
