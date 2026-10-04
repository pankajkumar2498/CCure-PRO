"""Development reset safety boundaries and dependency-ordered migration."""

import base64
import importlib.util
import json

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import inspect, text
from rbac_testing import rbac_db_fixture  # noqa: F401

from scripts.rbac.development_artifacts import artifacts, message_owner, quarantine
from scripts.rbac.development_reset import (
    ResetRefused,
    development_guard,
    digest,
    identifier,
)
from testpaths import BACKEND_ROOT


@pytest.mark.parametrize(
    "env,app",
    [("production", "development"), ("development", "production"), ("", "development")],
)
def test_reset_refuses_production_and_implicit_environment(monkeypatch, env, app):
    monkeypatch.setenv("ENV", env)
    monkeypatch.setenv("APP_ENV", app)
    with pytest.raises(ResetRefused):
        development_guard("test_reset", "RESET DEVELOPMENT test_reset")


def test_reset_confirmation_and_database_identity_are_both_required(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/test_reset")
    development_guard("test_reset", "RESET DEVELOPMENT test_reset")
    with pytest.raises(ResetRefused):
        development_guard("test_reset", "yes")
    with pytest.raises(ResetRefused):
        development_guard("another_db", "RESET DEVELOPMENT another_db")


def test_review_digest_is_order_independent_and_binds_every_field():
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})
    assert digest({"a": 1}) != digest({"a": 2})
    with pytest.raises(ResetRefused):
        identifier("users; DROP SCHEMA public")


def test_review_and_recovery_outputs_are_private_and_never_overwritten(tmp_path):
    from scripts.rbac.development_reset import protected_json

    path = tmp_path / "review.json"
    protected_json(path, {"review": "approved"})
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ResetRefused, match="already exists"):
        protected_json(path, {"review": "changed"})
    assert json.loads(path.read_text()) == {"review": "approved"}


def test_artifact_inventory_preserves_unknown_files_and_refuses_symlinks(tmp_path):
    reports, evidence = tmp_path / "reports", tmp_path / "evidence"
    reports.mkdir()
    evidence.mkdir()
    (reports / "scan_owned.pdf").write_bytes(b"report")
    (reports / "operator-notes.pdf").write_bytes(b"preserve")
    manifest = {
        "artifact_report_prefixes": ["scan_"],
        "artifact_report_extensions": [".pdf"],
    }
    files = artifacts(reports, evidence, manifest, disposable=True)
    assert [f["relative"] for f in files] == ["scan_owned.pdf"]
    (reports / "symlink.pdf").symlink_to(reports / "scan_owned.pdf")
    with pytest.raises(ValueError, match="symlink"):
        artifacts(reports, evidence, manifest, disposable=True)


def test_artifact_change_restores_already_quarantined_files(tmp_path):
    reports, evidence = tmp_path / "reports", tmp_path / "evidence"
    reports.mkdir()
    evidence.mkdir()
    for name in ("scan_a.pdf", "scan_b.pdf"):
        (reports / name).write_bytes(b"original")
    manifest = {
        "artifact_report_prefixes": ["scan_"],
        "artifact_report_extensions": [".pdf"],
    }
    files = artifacts(reports, evidence, manifest, disposable=True)
    (reports / "scan_b.pdf").write_bytes(b"changed")
    with pytest.raises(ValueError, match="changed"):
        quarantine(files, tmp_path / "recovery")
    assert (reports / "scan_a.pdf").read_bytes() == b"original"
    assert (reports / "scan_b.pdf").read_bytes() == b"changed"
    with pytest.raises(ValueError, match="escapes"):
        quarantine([{**files[0], "relative": "../escape"}], tmp_path / "other")


@pytest.mark.parametrize("raw", [b"not json", b"[]", b"null", b"42", b'{"body":"%%%"}'])
def test_unrecognized_broker_entries_are_preserved(raw):
    assert message_owner(raw, {"org_reset"}) is None


def test_broker_ownership_requires_exact_task_arguments():
    def message(owner):
        return json.dumps(
            {
                "headers": {"id": "task"},
                "body": base64.b64encode(
                    json.dumps([[owner], {}, {}]).encode()
                ).decode(),
            }
        )

    assert message_owner(message("org_reset"), {"org_reset"}) == "task"
    assert message_owner(message("org_reset_suffix"), {"org_reset"}) is None
    assert (
        message_owner(
            json.dumps([json.loads(message("org_reset")), "", "scanner"]), {"org_reset"}
        )
        == "task"
    )


def test_forward_migration_removes_only_legacy_objects(rbac_db):
    from rbac_testing import make_org, make_user

    make_user(rbac_db, make_org(rbac_db))
    conn = rbac_db.connection()
    names = (
        "rbac_roles",
        "rbac_permissions",
        "rbac_role_permissions",
        "rbac_role_revisions",
        "rbac_user_roles",
        "rbac_default_roles",
        "platform_audit_events",
    )
    from scripts.rbac.development_reset import fingerprint

    before = {name: fingerprint(conn, name) for name in names}
    ddl = json.dumps(
        {name: inspect(conn).get_columns(name) for name in names},
        default=str,
        sort_keys=True,
    )
    for sql in (
        "CREATE TABLE roles (id text PRIMARY KEY)",
        "CREATE TABLE permissions (id text PRIMARY KEY)",
        "CREATE TABLE role_permissions (role_id text REFERENCES roles(id), permission_id text REFERENCES permissions(id))",
        "CREATE TABLE rbac_legacy_map (role_id text REFERENCES roles(id))",
        "ALTER TABLE users ADD COLUMN role_id text REFERENCES roles(id)",
        "CREATE INDEX ix_users_role_id ON users(role_id)",
    ):
        conn.execute(text(sql))
    path = next((BACKEND_ROOT / "alembic/versions").glob("d4f8b2c6e0a1_*.py"))
    spec = importlib.util.spec_from_file_location("development_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with Operations.context(MigrationContext.configure(conn)):
        migration.upgrade()
        migration.upgrade()  # Metadata-created installations have no legacy tables.
    assert not {"roles", "permissions", "role_permissions", "rbac_legacy_map"} & set(
        inspect(conn).get_table_names()
    )
    assert "role_id" not in {c["name"] for c in inspect(conn).get_columns("users")}
    assert {name: fingerprint(conn, name) for name in names} == before
    assert (
        json.dumps(
            {name: inspect(conn).get_columns(name) for name in names},
            default=str,
            sort_keys=True,
        )
        == ddl
    )
    with pytest.raises(RuntimeError, match="(?i)restore"):
        migration.downgrade()


def test_reset_bootstraps_native_administrator_without_touching_catalogues(
    rbac_db, monkeypatch
):
    from scripts.rbac import development_reset as reset
    from rbac_testing import make_org, make_user
    from db import migrate_production_schema as initializer
    from ccure_platform.rbac.provisioning import assign_default_role
    from ccure_platform.rbac.catalogue import ensure_system_roles, ensure_default_roles

    monkeypatch.setattr(initializer, "DEFAULT_ORG_NAME", "CCure Development")
    monkeypatch.setattr(initializer, "DEFAULT_ORG_SLUG", "development")
    manifest = json.loads(reset.MANIFEST.read_text())
    org = make_org(rbac_db)
    old_user = make_user(rbac_db, org)
    ensure_system_roles(rbac_db)
    ensure_default_roles(rbac_db)
    assign_default_role(rbac_db, old_user)
    conn = rbac_db.connection()
    # The suite's out-of-metadata sentinel is intentionally unreviewed by the
    # operator tool. Drop it only within this rolled-back pytest transaction.
    with pytest.raises(ResetRefused, match="unreviewed tables"):
        reset.inventory(conn, manifest)
    conn.execute(text("DROP TABLE _pytest_scratch_marker"))
    # The session-scoped test application runs its NVD updater. Keep that
    # unrelated writer out of this transactional reset verification.
    conn.execute(
        text(
            "LOCK TABLE "
            + ",".join(
                reset.identifier(t)
                for t in manifest["preserve_tables"]
                if t.startswith("public.")
            )
            + " IN SHARE MODE"
        )
    )
    plan = {
        "scope": reset.inventory(conn, manifest),
        "preserved": reset.preserved(conn, manifest),
        "bootstrap": {"email": "bootstrap@example.test", "username": "bootstrap"},
        "identity": {"database": "pytest_development_reset"},
        "snapshot": {"sha256": "test-only"},
    }
    result = reset.reset_database(rbac_db, plan, manifest, "Testing_Reset_123!")
    assert result["permissions"] == result["effective_permissions"] == 67
    assert result["system_roles"] == 5
    assert result["organization"] == "org_development"
    assert conn.execute(text("SELECT count(*) FROM users")).scalar_one() == 1
    assert conn.execute(text("SELECT count(*) FROM organizations")).scalar_one() == 1
    assert conn.execute(text("SELECT count(*) FROM rbac_user_roles")).scalar_one() == 1
    assert (
        conn.execute(
            text(
                "SELECT count(*) FROM platform_audit_events WHERE action='rbac.development_reset.applied'"
            )
        ).scalar_one()
        == 1
    )
    assert reset.preserved(conn, manifest) == plan["preserved"]


def test_percent_encoded_migration_url_is_preserved(monkeypatch):
    from alembic.config import Config
    from alembic import command
    from sqlalchemy.engine import make_url
    import os

    url = make_url(os.environ["DATABASE_URL"]).set(
        query={"application_name": "reset%verification"}
    )
    rendered = url.render_as_string(hide_password=False)
    encoded = "%25" in rendered
    assert encoded
    monkeypatch.setenv("DATABASE_URL", rendered)
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    command.current(config)
    assert digest(config.get_main_option("sqlalchemy.url")) == digest(rendered)
