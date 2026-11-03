"""
The default organisation is configured, never assumed (db/migrate_production_schema.py).

start.sh runs the initializer on every API start. It used to fall back to a
"superadmin"/"KING" organisation, so a start without DEFAULT_ORG_* on an
existing installation created a second organisation beside the real one. Now
the organisation is found by its slug or by its id (org_<slug>), created only
on a database with no organisation at all, and everything else is refused.
"""

import pytest
from sqlalchemy import text

from db import migrate_production_schema as initializer
from db.migrate_production_schema import DefaultOrganisationError, plan_default_org

# The live installation's shape: its slug was edited to "cdac.in" after it was
# created as "development", so only its id still matches the configured slug.
LIVE = [
    ("org_development", "CCure Development", "cdac.in"),
    ("org_self-service", "Self-Service Users", "self-service"),
]


def test_an_existing_organisation_is_found_by_its_id():
    plan = plan_default_org(LIVE, "CCure Development", "development")
    assert (plan.action, plan.org_id) == ("use", "org_development")


def test_an_existing_organisation_is_found_by_its_slug():
    plan = plan_default_org(LIVE, "Anything", "self-service")
    assert (plan.action, plan.org_id) == ("use", "org_self-service")


def test_a_different_configured_name_does_not_rename_the_organisation():
    plan = plan_default_org(LIVE, "Renamed", "development")
    assert plan.action == "use" and "does not rename" in plan.message


def test_missing_configuration_on_an_existing_installation_creates_nothing():
    plan = plan_default_org(LIVE, None, None)
    assert (plan.action, plan.org_id) == ("skip", None)


def test_missing_configuration_on_an_empty_database_is_refused():
    with pytest.raises(
        DefaultOrganisationError, match="DEFAULT_ORG_NAME and DEFAULT_ORG_SLUG"
    ):
        plan_default_org([], None, None)


def test_a_missing_name_is_refused_where_one_must_be_created():
    with pytest.raises(DefaultOrganisationError, match="DEFAULT_ORG_NAME must be set"):
        plan_default_org([], "", "acme")


def test_the_old_fallback_slug_is_not_valid():
    with pytest.raises(DefaultOrganisationError, match="not a valid slug"):
        plan_default_org([], "superadmin", "KING")


def test_a_slug_matching_nothing_on_an_existing_installation_is_refused():
    with pytest.raises(
        DefaultOrganisationError, match="matches no organisation"
    ) as err:
        plan_default_org(LIVE, "Example Organisation", "example")
    assert "org_development" in str(err.value)  # names what exists


def test_a_slug_and_an_id_naming_different_organisations_is_ambiguous():
    rows = [("org_alpha", "Alpha", "beta"), ("org_beta", "Beta", "gamma")]
    with pytest.raises(DefaultOrganisationError, match="ambiguous"):
        plan_default_org(rows, "Beta", "beta")


def test_a_fresh_installation_creates_the_configured_organisation():
    plan = plan_default_org([], "Example Organisation", "example")
    assert (plan.action, plan.org_id) == ("create", "org_example")


def _count(conn):
    return conn.execute(text("SELECT count(*) FROM organizations")).scalar()


def _add_org(conn, org_id, name, slug):
    conn.execute(
        text(
            "INSERT INTO organizations (id, name, slug, is_active, settings, created_at, updated_at)"
            " VALUES (:id, :name, :slug, true, '{}', NOW(), NOW())"
        ),
        {"id": org_id, "name": name, "slug": slug},
    )


def test_seeding_an_existing_installation_reuses_its_organisation(
    db_session, monkeypatch
):
    conn = db_session.connection()
    _add_org(conn, "org_pytest_default", "Pytest Default Org", "edited-slug")
    before = _count(conn)
    monkeypatch.setattr(initializer, "DEFAULT_ORG_NAME", "Pytest Default Org")
    monkeypatch.setattr(initializer, "DEFAULT_ORG_SLUG", "pytest_default")
    try:
        assert initializer.seed_default_org(conn) == "org_pytest_default"
        assert _count(conn) == before
    finally:
        db_session.rollback()


def test_seeding_with_a_slug_matching_nothing_inserts_nothing(db_session, monkeypatch):
    conn = db_session.connection()
    _add_org(conn, "org_pytest_default", "Pytest Default Org", "pytest-default")
    before = _count(conn)
    monkeypatch.setattr(initializer, "DEFAULT_ORG_NAME", "superadmin")
    monkeypatch.setattr(initializer, "DEFAULT_ORG_SLUG", "king")
    try:
        with pytest.raises(DefaultOrganisationError):
            initializer.seed_default_org(conn)
        assert _count(conn) == before
    finally:
        db_session.rollback()


def test_the_initializer_has_no_fallback_organisation():
    import re

    source = open(initializer.__file__, encoding="utf-8").read()
    assert not re.search(r'getenv\(\s*"DEFAULT_ORG_(NAME|SLUG)"\s*,', source)
    assert initializer.DEFAULT_ORG_SLUG is None or initializer.DEFAULT_ORG_SLUG.strip()
