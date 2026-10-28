"""
Who still imports a legacy alias (backend alignment, follow-up 7).

``ccure_platform/_legacy.py`` keeps every moved module importable under its old
name, as an alias of the same module object. The aliases are for what has not
moved on yet — tests, patch targets, operator scripts, old migrations — not for
new code. This ratchet counts the importers in **module code** (the application
packages, ``main.py`` and ``db/``; not tests, ``scripts/`` or ``alembic/``):
the 20 aliases of the audit-log, notification, administration and profile moves
have none, and the ones with an importer are listed with who and why. A new
importer of a legacy path in module code fails here; so does removing one
without lowering the list.
"""

from __future__ import annotations

import re

from ccure_platform._legacy import MOVED_MODULES
from testpaths import BACKEND_ROOT

MODULE_CODE_DIRS = (
    "routers",
    "scans",
    "core",
    "engines",
    "orchestrator",
    "reporting",
    "ccure_audit",
    "ccure_platform",
    "db",
)
MODULE_CODE_FILES = ("main.py", "scan_helpers.py", "config.py")

#: legacy path -> the module-code files that still import it, and why.
ALLOWED: dict[str, set[str]] = {
    # the composition root mounts the auth router and seeds the first admin
    "auth.router": {"main.py"},
    "auth.email_utils": {"main.py"},
    "db.models.users": {"main.py", "db/migrate_production_schema.py"},
    "db.models.rbac": {"main.py"},
    # the composition root creates the email-screening tables at start-up;
    # the module moved into ccure_platform.models in B8
    "db.models.email_security": {"main.py"},
    # the two WebSocket ticket logins decode a token (identity_boundary
    # KNOWN_IDENTITY_IMPORTS, Phase 10) and the root decodes the same way
    "auth.jwt_handler": {"main.py", "routers/scan_history.py", "routers/web_scans.py"},
    # the scan tasks' compatibility facade re-exports the mail tasks so
    # `core.tasks.send_*` resolves
    "auth.mail_tasks": {"core/tasks.py"},
}


def _importers(legacy: str) -> set[str]:
    pattern = re.compile(r"(from|import) " + re.escape(legacy) + r"\b")
    own = legacy.replace(".", "/") + ".py"
    found = set()
    candidates = [BACKEND_ROOT / f for f in MODULE_CODE_FILES]
    for d in MODULE_CODE_DIRS:
        candidates += list((BACKEND_ROOT / d).rglob("*.py"))
    for path in candidates:
        rel = str(path.relative_to(BACKEND_ROOT))
        if rel == own or not path.is_file():
            continue
        if pattern.search(path.read_text(encoding="utf-8")):
            found.add(rel)
    return found


def test_module_code_imports_a_legacy_alias_only_where_listed():
    problems = []
    for legacy in MOVED_MODULES:
        current = _importers(legacy)
        allowed = ALLOWED.get(legacy, set())
        if current - allowed:
            problems.append(f"{legacy}: new importer(s) {sorted(current - allowed)}")
        if allowed - current:
            problems.append(
                f"{legacy}: listed importer(s) gone {sorted(allowed - current)}; "
                "lower ALLOWED"
            )
    assert not problems, "\n".join(problems)


def test_the_extracted_modules_have_no_importer_in_module_code():
    for legacy in (
        "core.audit",
        "core.audit_taxonomy",
        "core.audit_retention",
        "reporting.audit_export",
        "routers.audit",
        "core.notifications",
        "routers.notifications",
        "routers.admin_users",
        "routers.admin_orgs",
        "routers.admin_email_domains",
        "routers.user_profile",
    ):
        assert legacy not in ALLOWED and not _importers(legacy), legacy
