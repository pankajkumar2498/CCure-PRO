"""
tests/audit/test_audit_retention_holds.py
─────────────────────────────────────────────────────────────────────────────
Phase 6a: an organisation under hold is never purged, and the skip is visible.

A hold is the mechanism by which a legal, contractual or investigative
obligation outranks a retention policy. Two properties make it worth having:

* **It cannot be removed.** A hold is released by setting ``released_at``,
  never by DELETE — the record that a hold existed is why a purge did not
  happen, and is itself evidence. The application role holds SELECT on the
  table and writes it only through functions that cannot delete.

* **The skip is reported, never silent.** "Nothing was deleted for this
  tenant" and "this tenant is under hold" are different facts, and an operator
  reading a purge report has to be able to tell them apart.
"""

import pytest
from audit_retention_support import (
    counts,
    expect_refused,
    require_retention,
    seed_legacy,
)
from config import AppConfig
from core.audit_retention import active_holds, preview, resolve_cutoff, run_retention
from sqlalchemy import text


@pytest.fixture(autouse=True)
def require_bootstrap(db_session):
    require_retention(db_session)


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(AppConfig, "AUDIT_LOG_RETENTION_DAYS", 180)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_MIN_DAYS", 90)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_REQUIRE_BACKUP_HOURS", 0)


@pytest.fixture
def held(db_session, test_user):
    """The caller's tenant, with aged rows and a hold in place."""
    org = test_user.org_id
    seed_legacy(db_session, org, 5, age_days=400)
    db_session.execute(
        text("SELECT audit_retention.place_hold_v1(:o, :r, :b)"),
        {"o": org, "r": "regulatory investigation REF-2026-11", "b": "tests"},
    )
    db_session.commit()
    yield org
    db_session.execute(
        text("SELECT audit_retention.release_hold_v1(:o, :b)"),
        {"o": org, "b": "tests"},
    )
    db_session.commit()


def test_a_held_organisation_is_never_purged(db_session, held, enabled):
    before = counts(db_session, held)
    report = run_retention(db_session, dry_run=False)

    assert report["deleted_total"] == 0
    assert counts(db_session, held) == before
    assert held in report["held_orgs"]


def test_the_database_refuses_even_a_direct_call(db_session, held, enabled):
    """
    The hold is checked inside the SECURITY DEFINER function, not only in the
    orchestration above it. A caller that reached the function directly — a
    future task, a console session — must still be refused.
    """
    cutoff = resolve_cutoff()
    with pytest.raises(Exception) as raised:
        db_session.execute(
            text(
                "SELECT * FROM audit_retention.purge_legacy_v1("
                "  :org, :cutoff, 100, 90, 'test', NULL, 'test')"
            ),
            {"org": held, "cutoff": cutoff},
        )
    assert "hold" in str(raised.value).lower()
    db_session.rollback()


def test_the_skip_is_reported_not_silent(db_session, held, enabled):
    report = run_retention(db_session, dry_run=False)
    assert held in report["held_orgs"]
    assert report["held_orgs"][held]["on_hold"] is True
    assert held not in report["eligible_orgs"]


def test_the_preview_shows_the_hold(db_session, held, enabled):
    rows = preview(db_session, resolve_cutoff())
    entry = next(row for row in rows if row["org_id"] == held)
    assert entry["on_hold"] is True
    # The count of *eligible* rows is still reported: an operator needs to see
    # what the hold is protecting, not a zero that hides it.
    assert entry["eligible_count"] >= 5


def test_a_hold_cannot_be_deleted_by_the_application(db_session, held):
    """
    Deleting a hold would erase the reason a purge did not happen. It is
    released, never removed — and the application role cannot do either
    directly.
    """
    message = expect_refused(db_session, "DELETE FROM audit_retention.retention_holds")
    assert "denied" in message.lower()


def test_a_hold_cannot_be_forged_or_edited_by_the_application(db_session, held):
    for statement in (
        (
            "INSERT INTO audit_retention.retention_holds "
            "  (org_id, reason, placed_by) VALUES ('org_x', 'fake', 'nobody')"
        ),
        "UPDATE audit_retention.retention_holds SET released_at = now()",
    ):
        message = expect_refused(db_session, statement)
        assert "denied" in message.lower(), message


def test_releasing_a_hold_permits_the_next_run(db_session, test_user, enabled):
    org = test_user.org_id
    seed_legacy(db_session, org, 4, age_days=400)

    db_session.execute(
        text("SELECT audit_retention.place_hold_v1(:o, :r, :b)"),
        {"o": org, "r": "temporary", "b": "tests"},
    )
    db_session.commit()
    assert run_retention(db_session, dry_run=False)["deleted_total"] == 0

    db_session.execute(
        text("SELECT audit_retention.release_hold_v1(:o, :b)"),
        {"o": org, "b": "tests"},
    )
    db_session.commit()

    report = run_retention(db_session, dry_run=False)
    assert report["deleted_total"] == 4
    assert counts(db_session, org)["legacy"] == 0


def test_a_released_hold_is_kept_as_a_record(db_session, test_user):
    org = test_user.org_id
    db_session.execute(
        text("SELECT audit_retention.place_hold_v1(:o, :r, :b)"),
        {"o": org, "r": "kept for the record", "b": "tests"},
    )
    db_session.commit()
    db_session.execute(
        text("SELECT audit_retention.release_hold_v1(:o, :b)"),
        {"o": org, "b": "tests"},
    )
    db_session.commit()

    row = db_session.execute(
        text(
            "SELECT reason, placed_by, released_by, released_at "
            "  FROM audit_retention.retention_holds WHERE org_id = :o "
            " ORDER BY id DESC LIMIT 1"
        ),
        {"o": org},
    ).fetchone()
    assert row.reason == "kept for the record"
    assert row.released_at is not None
    assert row.released_by == "tests"
    assert org not in active_holds(db_session)


def test_a_hold_requires_a_reason(db_session, test_user):
    """An unexplained hold is indistinguishable from a mistake later on."""
    with pytest.raises(Exception) as raised:
        db_session.execute(
            text("SELECT audit_retention.place_hold_v1(:o, '', :b)"),
            {"o": test_user.org_id, "b": "tests"},
        )
    assert "reason" in str(raised.value).lower()
    db_session.rollback()


def test_only_one_active_hold_per_organisation(db_session, test_user):
    org = test_user.org_id
    first = db_session.execute(
        text("SELECT audit_retention.place_hold_v1(:o, 'one', :b)"),
        {"o": org, "b": "tests"},
    ).scalar()
    second = db_session.execute(
        text("SELECT audit_retention.place_hold_v1(:o, 'two', :b)"),
        {"o": org, "b": "tests"},
    ).scalar()
    db_session.commit()
    assert first == second

    db_session.execute(
        text("SELECT audit_retention.release_hold_v1(:o, :b)"),
        {"o": org, "b": "tests"},
    )
    db_session.commit()
