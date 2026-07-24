import os
import sys

# Add Backend to path
sys.path.append(os.path.abspath("Backend"))

try:
    from db.base import SessionLocal
    from sqlalchemy import inspect

    db = SessionLocal()
    inspector = inspect(db.bind)
    tables = inspector.get_table_names()

    print(f"Current Tables: {', '.join(tables)}")

    if "web_scans" in tables:
        print(
            "\n✅ Web Scan tables ALREADY EXIST in the database. Migration was successful."
        )
    else:
        print("\n❌ Web Scan tables MISSING. Migration has NOT been applied yet.")

    db.close()
except Exception as e:
    print(f"Error checking DB: {e}")
