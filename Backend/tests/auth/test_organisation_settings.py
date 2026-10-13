"""
Organisation settings through ``ccure_platform.api``.

Each function is tested against the behaviour of the code it replaced — the
scope read from ``core.scan_scope`` and the settings read from
``core.remediation.sla`` — including the edge cases those
functions were written to tolerate.
"""

from __future__ import annotations

import json
import logging

import pytest

from ccure_platform import api


# ── scan scope ────────────────────────────────────────────────────────────────


def test_scope_of_an_unknown_organisation_is_none(db_session):
    assert api.scan_scope(db_session, "org_does_not_exist") is None
    assert api.scan_scope(db_session, None) is None


@pytest.mark.parametrize(
    "stored, configured, cidrs",
    [
        (None, False, ()),
        ([], True, ()),
        (["10.0.0.0/8", "192.168.1.0/24"], True, ("10.0.0.0/8", "192.168.1.0/24")),
        (["not-a-cidr"], True, ("not-a-cidr",)),  # parsed and dropped by Audit
    ],
)
def test_scope_is_reported_as_stored(db_session, test_org, stored, configured, cidrs):
    test_org.scan_scope_cidrs = stored
    db_session.commit()
    view = api.scan_scope(db_session, test_org.id)
    assert (view.org_id, view.configured, view.cidrs) == (
        test_org.id,
        configured,
        cidrs,
    )


def test_a_scope_that_is_not_a_list_denies_everything(db_session, test_org, caplog):
    test_org.scan_scope_cidrs = "10.0.0.0/8"
    db_session.commit()
    with caplog.at_level(logging.WARNING, logger="ccure.scan_scope"):
        view = api.scan_scope(db_session, test_org.id)
    assert view.configured and view.cidrs == ()
    assert "expected a list; treating as deny-all" in caplog.text


# ── remediation SLA setting ───────────────────────────────────────────────────


def test_sla_setting_of_an_unknown_organisation_is_none(db_session):
    assert api.remediation_sla_setting(db_session, "org_does_not_exist") is None


def test_an_organisation_without_a_setting_reports_none_stored(db_session, test_org):
    view = api.remediation_sla_setting(db_session, test_org.id)
    assert view.org_id == test_org.id and view.stored is None


@pytest.mark.parametrize(
    "value",
    [
        {"days_by_severity": {"critical": 3}},
        {"due_soon_window_days": "seven", "days_by_severity": {"Critical": -1}},
        ["not", "a", "mapping"],
        None,
    ],
)
def test_the_stored_setting_passes_through_uninterpreted(db_session, test_org, value):
    test_org.settings = {"description": "kept", "remediation_sla": value}
    db_session.commit()
    view = api.remediation_sla_setting(db_session, test_org.id)
    assert json.loads(view.stored) == value


def test_storing_replaces_only_the_sla_key_and_does_not_commit(db_session, test_org):
    test_org.settings = {"description": "kept"}
    db_session.commit()

    api.store_remediation_sla_setting(
        db_session, test_org.id, {"days_by_severity": {"high": 10}}
    )
    assert test_org.settings == {
        "description": "kept",
        "remediation_sla": {"days_by_severity": {"high": 10}},
    }
    db_session.rollback()  # nothing was committed on the caller's behalf
    db_session.refresh(test_org)
    assert test_org.settings == {"description": "kept"}


def test_storing_for_an_unknown_organisation_refuses(db_session):
    with pytest.raises(LookupError):
        api.store_remediation_sla_setting(db_session, "org_does_not_exist", {})
