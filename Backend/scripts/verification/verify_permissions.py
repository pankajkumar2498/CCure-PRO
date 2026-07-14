import os
import sys

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

os.environ["DATABASE_URL"] = (
    "postgresql://ccure_user:ccure_admin_2026@localhost:5432/ccure_test"
)

from sqlalchemy import text, create_engine

print("=" * 70)
print("Verifying Permission Setup for Admin Routes")
print("=" * 70)

try:
    engine = create_engine(
        "postgresql://ccure_user:ccure_admin_2026@localhost:5432/ccure_db"
    )
    with engine.connect() as conn:
        print("\n✓ Connected to PostgreSQL\n")

        # Check superadmin role
        admin_role = conn.execute(
            text("SELECT id FROM roles WHERE name = 'superadmin'")
        ).scalar()
        print(f"Superadmin role ID: {admin_role}")

        # Check if admin user exists
        admin_user = conn.execute(
            text(
                """
            SELECT id, username, role_id, org_id FROM users WHERE username = 'admin'
        """
            )
        ).fetchone()
        print(f"Admin user: {admin_user}\n")

        # Check if admin user is superadmin
        if admin_user and admin_user[2] == admin_role:
            print("✓ Admin user is superadmin\n")
        elif admin_user:
            print(
                f"✗ Admin user role_id={admin_user[2]} doesn't match superadmin={admin_role}\n"
            )

        # Check permissions linked to superadmin
        perms = conn.execute(
            text(
                """
            SELECT p.resource, p.action
            FROM role_permissions rp
            JOIN permissions p ON p.id = rp.permission_id
            WHERE rp.role_id = :role_id
            ORDER BY p.resource, p.action
        """
            ),
            {"role_id": admin_role},
        ).fetchall()

        print(f"Permissions assigned to superadmin ({len(perms)} total):")
        print("=" * 70)

        # Check specifically for admin route permissions
        admin_perms = {
            ("users", "read"): False,
            ("roles", "read"): False,
            ("organizations", "read"): False,
            ("audit", "read"): False,
        }

        for resource, action in perms:
            if (resource, action) in admin_perms:
                admin_perms[(resource, action)] = True
            print(f"  {resource:15s} : {action}")

        print("\n" + "=" * 70)
        print("Admin Route Permission Status:")
        print("=" * 70)

        for (resource, action), exists in admin_perms.items():
            status = "✓ OK" if exists else "✗ MISSING"
            print(f"  {status:10s} {resource}:{action}")

        if all(admin_perms.values()):
            print("\n✅ All admin route permissions are properly configured!")
        else:
            print("\n❌ Some permissions are MISSING from superadmin role!")

except Exception as e:
    print(f"\n❌ Error: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)
