"""
Phase 8.2: identity's code and models moved into ``ccure_platform``.

The move must be invisible. These tests pin the properties that make it so:

* every legacy path (``auth.*``, ``db.models.users``, ``db.models.rbac``) is the
  **same module object** as its new home, whichever name is imported first, and
  every model class is the same class through every path;
* no identity table is mapped or defined twice;
* each moved module keeps its legacy ``__name__``, so the limiter's route keys,
  logger names and the Celery task registry are unchanged;
* the legacy files are stubs and nothing else — no code was left behind.

``ccure_platform._legacy.MOVED_MODULES`` is the record of what moved, and it is
checked in both directions.
"""

from __future__ import annotations

import ast
import importlib
import subprocess
import sys
import textwrap

import pytest

from ccure_platform._legacy import MOVED_MODULES
from testpaths import BACKEND_ROOT

IDENTITY_TABLES = {
    "users": "User",
    "refresh_token_sessions": "RefreshTokenSession",
    "password_reset_tokens": "PasswordResetToken",
    "email_verification_tokens": "EmailVerificationToken",
    "audit_logs": "AuditLog",
    "organizations": "Organization",
    "roles": "Role",
    "permissions": "Permission",
    "role_permissions": "RolePermission",
}


def _file(dotted: str):
    return BACKEND_ROOT / (dotted.replace(".", "/") + ".py")


# ── same module, same class ──────────────────────────────────────────────────


@pytest.mark.parametrize("legacy, new", sorted(MOVED_MODULES.items()))
def test_the_legacy_path_is_the_same_module_object(legacy, new):
    old_module = importlib.import_module(legacy)
    new_module = importlib.import_module(new)
    assert old_module is new_module
    assert sys.modules[legacy] is sys.modules[new]
    parent, _, child = legacy.rpartition(".")
    assert getattr(importlib.import_module(parent), child) is new_module
    # It keeps the name everything observable was derived from …
    assert new_module.__name__ == legacy
    # … and says where it really lives.
    assert new_module.__spec__.name == new
    assert _file(new).samefile(new_module.__file__)


def test_every_model_class_is_one_class_through_every_path():
    import ccure_platform.models.rbac as platform_rbac
    import ccure_platform.models.users as platform_users
    import db.models as registry
    import db.models.rbac as legacy_rbac
    import db.models.users as legacy_users

    for name in IDENTITY_TABLES.values():
        new = getattr(platform_users, name, None) or getattr(platform_rbac, name)
        assert getattr(registry, name) is new, name
        legacy = legacy_users if hasattr(platform_users, name) else legacy_rbac
        assert getattr(legacy, name) is new, name


def test_no_identity_table_is_mapped_twice():
    import db.models as registry
    from db.base import Base

    mapped = {}
    for mapper in Base.registry.mappers:
        table = getattr(mapper.persist_selectable, "name", None)
        mapped.setdefault(table, []).append(mapper.class_)
    for table, class_name in IDENTITY_TABLES.items():
        assert mapped[table] == [getattr(registry, class_name)], table
        assert Base.metadata.tables[table] is getattr(registry, class_name).__table__
    names = [m.class_.__name__ for m in Base.registry.mappers]
    assert len(names) == len(set(names)), "a mapped class name is registered twice"


def test_each_identity_table_is_defined_in_exactly_one_source_file():
    """A copy left behind would define the table a second time the day it is imported."""
    found: dict[str, list[str]] = {t: [] for t in IDENTITY_TABLES}
    for path in BACKEND_ROOT.rglob("*.py"):
        rel = path.relative_to(BACKEND_ROOT)
        if rel.parts[0] in {"tests", "alembic", "scripts"} or any(
            p.startswith(".") for p in rel.parts
        ):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "__tablename__"
                for t in node.targets
            ):
                value = getattr(node.value, "value", None)
                if value in found:
                    found[value].append(str(rel))
    for table, files in found.items():
        assert len(files) == 1 and files[0].startswith("ccure_platform/models/"), (
            table,
            files,
        )


@pytest.mark.parametrize(
    "first",
    ["new", "legacy", "registry"],
)
def test_the_aliases_hold_whichever_name_is_imported_first(first):
    """Import order is where a sys.modules alias breaks, so each order runs fresh."""
    program = textwrap.dedent(
        f"""
        import importlib, sys
        from ccure_platform._legacy import MOVED_MODULES
        first = {first!r}
        if first == "new":
            for n in MOVED_MODULES.values():
                importlib.import_module(n)
        elif first == "legacy":
            for n in MOVED_MODULES:
                importlib.import_module(n)
        else:
            import db.models  # noqa: F401
        import db.models
        from db.base import Base
        from sqlalchemy.orm import configure_mappers
        for old, new in MOVED_MODULES.items():
            a, b = importlib.import_module(old), importlib.import_module(new)
            assert a is b, (old, new)
            parent, _, child = old.rpartition(".")
            assert getattr(importlib.import_module(parent), child) is a, (old, "parent attribute")
        configure_mappers()
        names = [m.class_.__name__ for m in Base.registry.mappers]
        assert len(names) == len(set(names)), "duplicate mapper"
        print("ok", len(names))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.startswith("ok ")


# ── what the legacy name preserves ───────────────────────────────────────────


def test_limiter_route_keys_are_unchanged():
    import ccure_platform.identity.router  # noqa: F401  (registers the limits)
    from core.rate_limiter import limiter

    for endpoint in ("login", "register", "forgot_password", "reset_password_endpoint"):
        assert limiter._route_limits.get(f"auth.router.{endpoint}"), endpoint
    assert not any(k.startswith("ccure_platform.") for k in limiter._route_limits)


@pytest.mark.parametrize(
    "module, attribute, logger_name",
    [
        ("ccure_platform.identity.router", "logger", "auth.router"),
        ("ccure_platform.identity.jwt_handler", "logger", "auth.jwt_handler"),
        (
            "ccure_platform.identity.registration_limits",
            "logger",
            "auth.registration_limits",
        ),
        (
            "ccure_platform.identity.email_domain_guard",
            "logger",
            "auth.email_domain_guard",
        ),
        ("ccure_platform.identity.mail_service", "logger", "auth.mail_service"),
        ("ccure_platform.rbac.dependencies", "logger", "auth.rbac"),
        # these two were already named explicitly and must stay so
        ("ccure_platform.identity.mail_dispatch", "log", "ccure.mail"),
        ("ccure_platform.identity.mail_tasks", "log", "ccure.tasks"),
        (
            "ccure_platform.identity.email_security_tasks",
            "log",
            "core.email_security_tasks",
        ),
    ],
)
def test_logger_names_are_unchanged(module, attribute, logger_name):
    assert getattr(importlib.import_module(module), attribute).name == logger_name


def test_celery_task_names_and_include_are_unchanged():
    import ccure_platform.identity.mail_tasks as mail_tasks
    from core.celery_app import celery_app

    names = {
        "ccure.tasks.send_password_reset_email",
        "ccure.tasks.send_mfa_otp",
        "ccure.tasks.send_verification_email",
        "ccure.tasks.send_password_changed_email",
        "ccure.tasks.send_account_approved_email",
    }
    assert names <= set(celery_app.tasks)
    for name in names:
        assert celery_app.tasks[name].__module__ == "auth.mail_tasks"
    # The worker still loads the mail tasks by their legacy path.
    assert "auth.mail_tasks" in celery_app.conf.include
    assert sys.modules["auth.mail_tasks"] is mail_tasks


def test_account_screening_tasks_keep_their_names_queue_and_include():
    """core.email_security_tasks moved into the platform in step 8.3."""
    import ccure_platform.identity.email_security_tasks as screening
    from core.celery_app import celery_app

    for name in (
        "ccure.tasks.enrich_email_risk",
        "ccure.tasks.retro_scan_email_risk",
        "ccure.tasks.purge_stale_unapproved_accounts",
        "ccure.tasks.sync_disposable_domains",
    ):
        task = celery_app.tasks[name]
        assert task.__module__ == "core.email_security_tasks", name
        assert task.queue == "default", name
    assert "core.email_security_tasks" in celery_app.conf.include
    assert sys.modules["core.email_security_tasks"] is screening


def test_no_openapi_name_mentions_the_new_location():
    """
    FastAPI names a colliding component after its class's module, so a class
    that lost its legacy ``__module__`` could surface as ``ccure_platform__…``.
    The byte-for-byte comparison is done against the previous commit at review;
    this holds the property afterwards.
    """
    import json

    from main import app

    assert "ccure_platform" not in json.dumps(app.openapi())


# ── nothing was left behind ──────────────────────────────────────────────────


@pytest.mark.parametrize("legacy, new", sorted(MOVED_MODULES.items()))
def test_the_legacy_file_is_only_a_stub(legacy, new):
    tree = ast.parse(_file(legacy).read_text(encoding="utf-8"))
    body = [
        node
        for node in tree.body
        if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))
    ]
    imported = {
        alias.name
        for node in body
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert imported == {new, "sys"}, imported
    assert all(isinstance(n, (ast.Import, ast.Assign)) for n in body), legacy
    assert sum(isinstance(n, ast.Assign) for n in body) == 1


def test_every_file_left_in_auth_is_a_recorded_stub():
    left = {
        f"auth.{p.stem}"
        for p in (BACKEND_ROOT / "auth").glob("*.py")
        if p.name != "__init__.py"
    }
    assert left == {k for k in MOVED_MODULES if k.startswith("auth.")}


@pytest.mark.parametrize("legacy, new", sorted(MOVED_MODULES.items()))
def test_each_moved_module_adopts_its_legacy_name_first(legacy, new):
    """Before anything reads ``__name__`` — a logger, a decorator, a class body."""
    tree = ast.parse(_file(new).read_text(encoding="utf-8"))
    statements = [
        node
        for node in tree.body
        if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))
        and not (isinstance(node, ast.ImportFrom) and node.module == "__future__")
    ]
    first_import, call = statements[0], statements[1]
    assert isinstance(first_import, ast.ImportFrom)
    assert first_import.module == "ccure_platform._legacy"
    assert isinstance(call, ast.Expr) and isinstance(call.value, ast.Call)
    assert call.value.func.id == "adopt_legacy_name"
    assert call.value.args[1].value == legacy
