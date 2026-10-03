"""
Backend/tests/test_docs_integrity.py
───────────────────────────────────────────────────────────────────────────────
Automated "Drift Guard" test suite asserting that:
1. Every registered FastAPI route is documented in docs/BACKEND_API_REFERENCE.md.
2. Every active SQLAlchemy database table is documented in docs/DATABASE_SCHEMA.md.
3. Every registered RBAC permission is documented in docs/RBAC_Management_Permissions.md.
"""

from testpaths import BACKEND_ROOT, REPO_ROOT

import os
import sys

# Ensure Backend directory is in path
sys.path.insert(0, str(BACKEND_ROOT))

from main import app
from db.base import Base
from ccure_platform import composition


REPO_ROOT = str(REPO_ROOT)
DOCS_DIR = os.path.join(REPO_ROOT, "docs")


def read_doc_file(filename: str) -> str:
    filepath = os.path.join(DOCS_DIR, filename)
    assert os.path.isfile(filepath), f"Documentation file missing: {filepath}"
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def test_api_routes_documented():
    """Verify that all non-utility FastAPI endpoints are mentioned in BACKEND_API_REFERENCE.md."""
    doc_content = read_doc_file("BACKEND_API_REFERENCE.md")

    # Extract registered paths
    registered_paths = set()
    for route in app.routes:
        path = getattr(route, "path", "")
        # Filter out system Swagger/OpenAPI docs utility endpoints
        if path and not path.startswith(("/docs", "/redoc", "/openapi.json")):
            registered_paths.add(path)

    missing_paths = []
    for path in sorted(registered_paths):
        clean_path = path.rstrip("/")
        if clean_path and clean_path not in doc_content and path not in doc_content:
            missing_paths.append(path)

    assert (
        not missing_paths
    ), f"Found {len(missing_paths)} API endpoints missing in BACKEND_API_REFERENCE.md: {missing_paths[:10]}"


def test_database_tables_documented():
    """Verify that all SQLAlchemy tables are described in DATABASE_SCHEMA.md."""
    doc_content = read_doc_file("DATABASE_SCHEMA.md")

    tables = Base.metadata.tables.keys()
    missing_tables = [table for table in sorted(tables) if table not in doc_content]

    assert (
        not missing_tables
    ), f"Found {len(missing_tables)} database tables missing in DATABASE_SCHEMA.md: {missing_tables}"


def test_rbac_permissions_documented():
    """Verify that all RBAC permissions are documented in RBAC_Management_Permissions.md."""
    doc_content = read_doc_file("architecture/RBAC_PERMISSION_CATALOG.md")

    all_perms = {
        p.key for s in composition.load_permission_sources() for p in s.permissions
    }

    missing_perms = [p for p in sorted(all_perms) if p not in doc_content]
    assert (
        not missing_perms
    ), f"Found {len(missing_perms)} permissions missing in RBAC_Management_Permissions.md: {missing_perms}"
