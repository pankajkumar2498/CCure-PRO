"""
tests/scans/test_database_content.py
─────────────────────────────────────────────────────────────────────────────
The shipped database rules, the coverage denominator, and the credential and
dispatch wiring. Phase 7 (GAP-10).

These are invariants over the *content*, not over the engine. They exist
because a database rule is three things at once — a SQL statement, a targeting
declaration and a coverage claim — and each can be wrong independently while
the other two look right. The engine cannot catch any of them: a rule that
targets no engine runs nowhere and reports nothing, which is
indistinguishable from a clean estate.

Every ``gap10_area`` named here must appear in the frozen denominator in
``scripts/measure_database_coverage.py``. That is what stops coverage being
raised by inventing an area, which is the failure mode a percentage invites.
"""

import pytest

from core.checks.definitions import (
    DEFINITION_TYPE_CONFIG_CHECK,
    DEFINITION_TYPE_CVE,
    definition_id_for_check,
    definition_type_for_id,
)
from core.config_audit.builtin import BUILTIN_CHECKS, DATABASE_CHECKS
from core.config_audit.engine import select_checks
from core.config_audit.spec import AbsencePolicy
from engines.credentialed.database_executor import (
    SUPPORTED_ENGINES,
    DatabaseConfigurationError,
    assert_read_only,
    normalize_engine,
)
from scripts.measure_database_coverage import NOT_PLANNED, SCOPE

SCOPE_AREAS = {area for area, _theme, _description in SCOPE}


# ── The rules are read-only, and that is checked rather than trusted ─────────


@pytest.mark.parametrize("check", DATABASE_CHECKS, ids=lambda c: c.check_id)
def test_every_shipped_rule_is_a_read_only_statement(check):
    """
    The strongest invariant in the phase. Rules are administrator-editable, so
    the guard exists at runtime — but nothing shipped should ever need it, and
    a rule that would be refused at scan time is a rule that reports ERROR
    against every instance it is dispatched at.
    """
    assert_read_only(check.collect["sql"])


def test_the_read_only_guard_would_actually_refuse_a_write():
    """
    Mutation check on the test above: if the guard stopped refusing writes,
    the per-rule assertions would pass vacuously.
    """
    with pytest.raises(DatabaseConfigurationError):
        assert_read_only("DROP TABLE pg_authid")


# ── Shape ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("check", DATABASE_CHECKS, ids=lambda c: c.check_id)
def test_every_database_rule_declares_the_database_platform(check):
    assert check.check_type == "database_query"
    assert check.platforms == ("database",)
    assert check.requires_credentials is True


@pytest.mark.parametrize("check", DATABASE_CHECKS, ids=lambda c: c.check_id)
def test_every_database_rule_targets_a_supported_engine(check):
    """
    Two declarations, both required. ``os_match`` is what the engine applies;
    ``collect['engine']`` is the collector's backstop for a rule that forgot.
    A rule with neither runs against every database product and reports the
    absence of a PostgreSQL view as a verdict about MySQL.
    """
    assert check.os_match.get("os_name_contains"), (
        f"{check.check_id} names no engine in os_match, so it would be "
        f"dispatched at every database product"
    )
    engine = check.collect.get("engine")
    assert engine, f"{check.check_id} does not name its engine in collect"
    names = engine if isinstance(engine, (list, tuple)) else [engine]
    for name in names:
        assert normalize_engine(name) in SUPPORTED_ENGINES


@pytest.mark.parametrize("check", DATABASE_CHECKS, ids=lambda c: c.check_id)
def test_offender_list_rules_treat_absence_as_a_pass(check):
    """
    A ``rows`` rule asks which items are offending, so no rows is a real result
    and a clean instance must pass on it. MANUAL_REVIEW there would leave every
    correctly configured database with an unassessed control.
    """
    if check.collect.get("result") == "rows":
        assert check.absent is AbsencePolicy.PASS, (
            f"{check.check_id} enumerates offenders; an empty result is a "
            f"clean instance, not an unanswerable question"
        )


@pytest.mark.parametrize("check", DATABASE_CHECKS, ids=lambda c: c.check_id)
def test_no_database_rule_is_filed_as_a_cve(check):
    """
    A configuration deviation is not a published vulnerability. Filing one as
    ``cve`` inherits KEV lookups, EPSS scores and an NVD link resolving to
    nothing.
    """
    assert check.finding_type == DEFINITION_TYPE_CONFIG_CHECK
    assert check.finding_type != DEFINITION_TYPE_CVE


@pytest.mark.parametrize("check", DATABASE_CHECKS, ids=lambda c: c.check_id)
def test_every_rule_mints_a_usable_ccure_identifier(check):
    minted = definition_id_for_check(check.check_id, check.finding_type)
    assert minted.startswith("CCURE-CFG-")
    assert len(minted) <= 120
    assert definition_type_for_id(minted) == DEFINITION_TYPE_CONFIG_CHECK


@pytest.mark.parametrize("check", DATABASE_CHECKS, ids=lambda c: c.check_id)
def test_every_rule_carries_remediation_and_a_rationale(check):
    """
    A finding a reader cannot act on is noise. Severity without a reason and a
    fix is what makes a configuration report get ignored wholesale.
    """
    assert check.remediation.strip(), f"{check.check_id} has no remediation"
    assert check.rationale.strip(), f"{check.check_id} has no rationale"
    assert check.description.strip(), f"{check.check_id} has no description"


def test_check_ids_are_unique_across_every_builtin():
    ids = [c.check_id for c in BUILTIN_CHECKS]
    assert len(ids) == len(set(ids))


def test_minted_identifiers_are_unique_across_every_builtin():
    """
    ``definition_id_for_check`` folds dots and underscores to one spelling, so
    two check ids differing only in punctuation would collide into one
    catalogue row — and the second rule's verdict would silently overwrite the
    first's.
    """
    minted = [
        definition_id_for_check(c.check_id, c.finding_type) for c in BUILTIN_CHECKS
    ]
    assert len(minted) == len(set(minted))


# ── Coverage claims ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("check", DATABASE_CHECKS, ids=lambda c: c.check_id)
def test_every_rule_claims_an_area_inside_the_frozen_denominator(check):
    area = check.metadata.get("gap10_area")
    assert area, f"{check.check_id} claims no gap10_area"
    assert area in SCOPE_AREAS, (
        f"{check.check_id} claims area {area!r}, which is not in the frozen "
        f"GAP-10 denominator. The denominator is fixed; an area outside it "
        f"counts for nothing and adding one would be inflating coverage."
    )


@pytest.mark.parametrize("check", DATABASE_CHECKS, ids=lambda c: c.check_id)
def test_every_rule_names_the_engine_it_was_measured_on(check):
    engine = check.metadata.get("db_engine")
    assert engine in SUPPORTED_ENGINES


def test_areas_recorded_as_not_planned_have_no_implementation():
    """
    A stale reason is worse than none: it tells a reader an area was skipped
    for a reason that no longer applies.
    """
    implemented = {c.metadata.get("gap10_area") for c in DATABASE_CHECKS}
    overlap = implemented & set(NOT_PLANNED)
    assert not overlap, (
        f"areas {sorted(overlap)} are implemented but still listed in "
        f"NOT_PLANNED with a reason for not implementing them"
    )


def test_every_supported_engine_actually_ships_rules():
    """
    An engine named as supported with no content is a capability claim with
    nothing behind it.
    """
    covered = {c.metadata.get("db_engine") for c in DATABASE_CHECKS}
    assert covered == set(SUPPORTED_ENGINES)


# ── Platform isolation ───────────────────────────────────────────────────────


def test_database_rules_are_never_selected_for_a_host_scan():
    """
    The credentialed host audit selects on platform. A database rule reaching a
    Linux host would run a PostgreSQL catalogue query through a shell.
    """
    for platform in ("windows", "linux"):
        selected = select_checks(BUILTIN_CHECKS, platform=platform)
        assert selected
        assert not [c for c in selected if c.check_type == "database_query"]


def test_host_rules_are_never_selected_for_a_database_scan():
    selected = select_checks(BUILTIN_CHECKS, platform="database")
    assert selected
    assert all(c.check_type == "database_query" for c in selected)
    assert len(selected) == len(DATABASE_CHECKS)


# ── Credential wiring ────────────────────────────────────────────────────────


def test_the_database_credential_type_is_usable():
    from db.models.compliance import (
        CREDENTIAL_TYPE_DATABASE,
        CREDENTIAL_TYPES,
        USABLE_CREDENTIAL_TYPES,
    )

    assert CREDENTIAL_TYPE_DATABASE in CREDENTIAL_TYPES
    assert CREDENTIAL_TYPE_DATABASE in USABLE_CREDENTIAL_TYPES


def test_every_database_transport_matches_a_supported_engine():
    from db.models.compliance import DATABASE_TRANSPORTS, TRANSPORTS

    assert set(DATABASE_TRANSPORTS) == set(SUPPORTED_ENGINES)
    assert set(DATABASE_TRANSPORTS) <= set(TRANSPORTS)


def test_reserved_transports_are_admitted_by_the_column_but_not_offered():
    """
    The same reservation that let this phase add a credential type without a
    migration on live encrypted credentials. The column is permissive so the
    next phase adds a collector; the API is not, so nobody can save a
    credential nothing would use.
    """
    from db.models.compliance import TRANSPORTS, USABLE_TRANSPORTS

    assert "oracle" in TRANSPORTS and "mongodb" in TRANSPORTS
    assert "oracle" not in USABLE_TRANSPORTS
    assert "mongodb" not in USABLE_TRANSPORTS


def test_the_transport_check_constraint_matches_the_model():
    """
    A migration renders the vocabulary by hand. A model that gains a value the
    migration does not have produces a schema an upgraded database rejects and a
    bootstrapped one accepts.

    **The exact-equality assertion belongs to the newest migration**, and moves
    when another one adds a value — d2e3f4a5b6c7 added ``smb`` for the Windows
    SMB transport. Pinning it to a historical migration would make every future
    transport a failing test in a phase that has nothing to do with it, which is
    the trap the check-type constraint tests fell into twice.
    """
    # Loaded by path: `alembic` on sys.path is the installed library, so
    # `alembic.versions` resolves to it and not to this repository's migrations.
    import importlib.util
    from pathlib import Path

    from db.models.compliance import TRANSPORTS as MODEL_TRANSPORTS

    path = (
        Path(__file__).resolve().parents[2]
        / "alembic"
        / "versions"
        / "d2e3f4a5b6c7_smb_transport.py"
    )
    spec = importlib.util.spec_from_file_location("_newest_transport_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert tuple(module.TRANSPORTS) == tuple(MODEL_TRANSPORTS)
    # Its own predecessor set: everything except the value it adds.
    assert tuple(module.OLD_TRANSPORTS) == tuple(
        t for t in MODEL_TRANSPORTS if t != "smb"
    )


@pytest.mark.parametrize(
    "transport,expected_port",
    [("postgresql", 5432), ("mysql", 3306), ("mssql", 1433)],
)
def test_the_default_port_follows_the_engine_not_the_type(transport, expected_port):
    """
    Defaulting a MySQL credential to PostgreSQL's 5432 stores something that
    cannot connect, and it surfaces as an unreachable instance at scan time
    rather than as a mistake at the moment somebody saved it.
    """
    from routers.credentials import _apply_type_rules

    resolved_transport, port = _apply_type_rules(
        "database", "password", transport, None
    )
    assert resolved_transport == transport
    assert port == expected_port


def test_a_database_credential_cannot_take_a_shell_transport():
    from fastapi import HTTPException

    from routers.credentials import _apply_type_rules

    with pytest.raises(HTTPException):
        _apply_type_rules("database", "password", "winrm", None)


def test_a_windows_credential_cannot_take_a_database_transport():
    """
    Transport was previously defaulted per type but never validated. With
    database engines in the vocabulary that stops being cosmetic — a Windows
    credential carrying ``postgresql`` would be dispatched at a database
    session.
    """
    from fastapi import HTTPException

    from routers.credentials import _apply_type_rules

    with pytest.raises(HTTPException):
        _apply_type_rules("windows", "password", "postgresql", None)


def test_a_database_credential_cannot_use_key_authentication():
    from fastapi import HTTPException

    from routers.credentials import _apply_type_rules

    with pytest.raises(HTTPException):
        _apply_type_rules("database", "key", "postgresql", None)


# ── Dispatch wiring ──────────────────────────────────────────────────────────


def test_the_scan_task_has_a_database_branch():
    """
    A database credential must not reach the host auditor, which would open an
    SSH connection to a database port and report the instance as unreachable.
    """
    import inspect

    from scans.tasks.credentialed import run_credentialed_scan_task

    source = inspect.getsource(run_credentialed_scan_task)
    assert "CREDENTIAL_TYPE_DATABASE" in source
    assert "audit_database_target" in source


def test_database_targets_are_excluded_from_host_asset_sync():
    """
    Both sync helpers are host-shaped. Letting a database audit through would
    overwrite the asset record of the machine hosting it with an audit that
    never looked at the machine.
    """
    import inspect

    from scans.tasks.credentialed import run_credentialed_scan_task

    source = inspect.getsource(run_credentialed_scan_task)
    assert 'if os_type == "database":' in source


def test_the_database_auditor_reports_its_own_scope():
    """
    A database audit says nothing about the operating system underneath it. A
    report that does not say so reads as a complete audit of the machine.
    """
    import inspect

    from scans.tasks.credentialed import audit_database_target

    source = inspect.getsource(audit_database_target)
    assert '"packages_assessed": False' in source
    assert '"network_scanned": False' in source
