"""
Topology authorization — native RBAC and platform scope, nothing else.

``routers/topology.py`` used to decide by ``user.role.name`` ("superadmin", and the set
``{"superadmin", "org_admin"}``). A native account has no ``role`` relationship (revision
d4f8b2c6e0a1), so the helper read ``""``: a superadmin's organisation switch was ignored
and every account but a scan's creator was refused — and the organisation-wide map,
which never reached ``_authorize_scan``, was open to anyone holding ``audit.scan.read``.

These call the route functions directly against a rolled-back database (the same seam
``test_rbac_scope`` uses), so they exercise the real engine, the real scope resolver and
the real handlers rather than a mock of either.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

from ccure_platform.rbac import scope
from ccure_platform.rbac.catalogue import sync
from ccure_platform import composition
from db.models import Scan
from rbac_testing import (
    assign,
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401
    role,
)
from routers import topology


@pytest.fixture
def w(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    w = type("W", (), {})()
    w.db = rbac_db
    w.a, w.b = make_org(rbac_db), make_org(rbac_db)
    rbac_db.flush()

    def person(org, role_key):
        user = make_user(rbac_db, org)
        rbac_db.flush()
        rbac_db.refresh(user)
        assign(rbac_db, user, role(rbac_db, role_key))
        return user

    def scan_of(org, owner):
        row = Scan(
            id=f"scan-{uuid.uuid4().hex[:8]}",
            org_id=org.id,
            created_by=owner.id,
            status="completed",
            target_str="10.0.0.0/24",
        )
        rbac_db.add(row)
        rbac_db.flush()
        return row

    w.person, w.scan_of = person, scan_of
    # scanner: may read its own scans, holds no audit.scan.read_all
    w.owner = person(w.a, "platform.scanner")
    w.colleague = person(w.a, "platform.scanner")
    w.analyst = person(w.a, "platform.analyst")  # holds read_all
    w.superadmin = person(w.a, "platform.superadmin")
    w.admin_b = person(w.b, "platform.org_admin")
    w.scan = w.scan_of(w.a, w.owner)
    return w


def _by_scan(w, user, scan_id, org_id=None):
    with scope.use_audit_session(w.db):
        return topology.get_topology_map_by_scan(
            scan_id=scan_id,
            org_id=org_id,
            subnet_mask=24,
            active_within_days=None,
            db=w.db,
            user=user,
        )


def _map(w, user, **kw):
    with scope.use_audit_session(w.db):
        return topology.get_topology_map(
            org_id=kw.get("org_id"),
            scan_id=kw.get("scan_id"),
            subnet_mask=24,
            active_within_days=None,
            db=w.db,
            user=user,
        )


def _status(call):
    try:
        call()
    except HTTPException as exc:
        return exc.status_code
    return 200


# ── the creator ──────────────────────────────────────────────────────────────


def test_the_creator_reads_their_own_scan_without_read_all(w):
    assert _status(lambda: _by_scan(w, w.owner, w.scan.id)) == 200
    assert _status(lambda: _map(w, w.owner, scan_id=w.scan.id)) == 200


# ── non-creator: read_all decides, not a role's name ─────────────────────────


def test_a_colleague_without_read_all_is_refused_the_scan(w):
    assert _status(lambda: _by_scan(w, w.colleague, w.scan.id)) == 403
    assert _status(lambda: _map(w, w.colleague, scan_id=w.scan.id)) == 403


def test_a_non_creator_holding_read_all_reads_the_scan(w):
    assert _status(lambda: _by_scan(w, w.analyst, w.scan.id)) == 200
    assert _status(lambda: _map(w, w.analyst, scan_id=w.scan.id)) == 200


def test_read_all_is_per_organisation_not_cross_organisation(w):
    # org B's administrator holds read_all in org B — and no reach into org A
    assert _status(lambda: _by_scan(w, w.admin_b, w.scan.id)) == 403
    assert _status(lambda: _by_scan(w, w.admin_b, w.scan.id, org_id=w.a.id)) == 403


def test_an_unknown_scan_is_404(w):
    assert _status(lambda: _by_scan(w, w.owner, "does-not-exist")) == 404


# ── organisation-wide map: it reads every user's scans ───────────────────────


def test_the_organisation_wide_map_needs_read_all(w):
    assert _status(lambda: _map(w, w.colleague)) == 403
    assert _status(lambda: _map(w, w.owner)) == 403  # owning a scan is not enough
    assert _status(lambda: _map(w, w.analyst)) == 200


def test_naming_another_organisation_does_not_widen_the_map(w):
    # without the switch grant the request is ignored and the home org is used
    assert _status(lambda: _map(w, w.colleague, org_id=w.b.id)) == 403
    assert _status(lambda: _map(w, w.admin_b, org_id=w.a.id)) == 200  # → its own org B
    with scope.use_audit_session(w.db):
        assert topology._resolve_org(w.admin_b, w.a.id) == w.b.id


# ── organisation switching ───────────────────────────────────────────────────


def test_a_superadmin_who_switched_organisation_reads_that_organisations_scans(w):
    foreign = w.scan_of(w.b, w.admin_b)
    # not the creator, and the scan is in another organisation: only the platform
    # switch grant plus read_all in the target organisation lets this through
    assert _status(lambda: _by_scan(w, w.superadmin, foreign.id, org_id=w.b.id)) == 200
    assert (
        _status(lambda: _map(w, w.superadmin, org_id=w.b.id, scan_id=foreign.id)) == 200
    )
    assert _status(lambda: _map(w, w.superadmin, org_id=w.b.id)) == 200


def test_without_naming_the_organisation_a_foreign_scan_is_refused_even_to_superadmin(
    w,
):
    foreign = w.scan_of(w.b, w.admin_b)
    assert _status(lambda: _by_scan(w, w.superadmin, foreign.id)) == 403
    assert _status(lambda: _map(w, w.superadmin, scan_id=foreign.id)) == 403


def test_a_missing_or_inactive_target_organisation_fails_closed(w):
    assert _status(lambda: _map(w, w.superadmin, org_id="org_nope")) == 404
    w.b.is_active = False
    w.db.flush()
    assert _status(lambda: _map(w, w.superadmin, org_id=w.b.id)) == 403


# ── no role identity anywhere in the router ──────────────────────────────────


def test_the_router_names_no_role_and_reads_no_legacy_relationship():
    import inspect

    from scripts.architecture import rbac_guardrails as rg

    source = inspect.getsource(topology)
    assert rg.scan_legacy_source("routers/topology.py", source) == []
    for forbidden in ("superadmin", "org_admin", "_role_name", ".role"):
        assert forbidden not in source, forbidden
