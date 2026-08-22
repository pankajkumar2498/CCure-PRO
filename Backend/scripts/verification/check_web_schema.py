"""
Backend/scripts/verification/check_web_schema.py
──────────────────────────────────────────────────────────────────────────────
Report which tables the configured database holds, and whether the web-scanning
migration has been applied.

Was tests/check_web_db.py. It was never a test — it has no assertions and
pytest never collected it — and its `sys.path.append("Backend")` was relative to
the caller's working directory, so it only resolved when run from the repo root
and silently failed to import from the Backend directory itself. The path is
anchored to __file__ here, like its siblings.

Usage
─────
  # From the Backend directory:
  python scripts/verification/check_web_schema.py
"""

import os
import sys

# Ensure the root of the project is in python path
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from db.base import SessionLocal
from sqlalchemy import inspect


def check_web_schema():
    db = SessionLocal()
    try:
        inspector = inspect(db.bind)
        tables = inspector.get_table_names()

        print(f"Current Tables ({len(tables)}): {', '.join(sorted(tables))}")

        if "web_scans" in tables:
            print("\nWeb scan tables exist. The migration has been applied.")
        else:
            print("\nWeb scan tables are MISSING. The migration has not been applied.")

    except Exception as e:
        print(f"Error checking DB: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    check_web_schema()
