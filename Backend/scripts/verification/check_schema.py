import os
import sys

# Add Backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Backend'))

os.environ["DATABASE_URL"] = "postgresql://ccure_user:ccure_admin_2026@localhost:5432/ccure_test"

from sqlalchemy import text, create_engine

print("=" * 60)
print("Checking PostgreSQL Database Schema")
print("=" * 60)

try:
    engine = create_engine("postgresql://ccure_user:ccure_admin_2026@localhost:5432/ccure_db")
    with engine.connect() as conn:
        print("\n✓ Connected to PostgreSQL")
        
        # Check if new permissions exist
        result = conn.execute(text("""
            SELECT COUNT(*) FROM permissions 
            WHERE resource IN ('roles', 'organizations', 'audit')
        """))
        count = result.scalar()
        
        print(f"\nNew permissions found: {count}")
        
        if count > 0:
            result = conn.execute(text("""
                SELECT resource, action FROM permissions 
                WHERE resource IN ('roles', 'organizations', 'audit')
                ORDER BY resource, action
            """))
            print("\n✓ Existing new permissions:")
            for row in result:
                print(f"    - {row[0]}:{row[1]}")
            print("\n✅ Database already has the new schema!")
            sys.exit(0)
        else:
            print("\n❌ New permissions NOT found in database")
            print("    Database has OLD schema without roles/organizations/audit permissions")
            sys.exit(1)
            
except Exception as e:
    print(f"\n❌ Error: {e}")
    print("Make sure PostgreSQL is running on localhost:5432")
    sys.exit(1)
