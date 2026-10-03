"""
RBAC-5 — the scope seam inside the real scan-lookup code: IDOR and cross-organisation
reads through ``get_scan_or_404`` and the report export's ``_scan_for_user``. A scan's
organisation is read from the stored row; a client-supplied organisation id and
forged headers or bodies never decide access.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

from ccure_platform import composition
from ccure_platform.rbac import scope
from ccure_platform.rbac.catalogue import sync
from db.models.scans import Scan
from rbac_testing import (
    assign,
    custom_org_role,
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401
    role,
)
from routers import reports
from scans import scan_access


@pytest.fixture
def w(rbac_db, monkeypatch):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    w = type("W", (), {})()
    w.db, w.a, w.b = rbac_db, make_org(rbac_db), make_org(rbac_db)

    def person(org, rbac_role=None):
        u = make_user(rbac_db, org)
        rbac_db.flush()
        rbac_db.refresh(u)
        if rbac_role:
            assign(rbac_db, u, role(rbac_db, rbac_role))
        return u

    def make_scan(org, owner):
        s = Scan(
            id=f"scan_{uuid.uuid4().hex[:10]}",
            org_id=org.id,
            created_by=owner.id,
            target_str="10.0.0.1",
            scan_type="basic",
            status="completed",
        )
        rbac_db.add(s)
        rbac_db.flush()
        return s

    w.person, w.make_scan = person, make_scan
    w.admin_a = person(w.a, "platform.org_admin")
    w.analyst_a = person(w.a, "platform.analyst")
    w.superadmin = person(w.a, "platform.superadmin")
    w.admin_b = person(w.b, "platform.org_admin")
    w.scan_a = make_scan(w.a, w.analyst_a)
    w.scan_b = make_scan(w.b, w.admin_b)
    yield w


def get(w, user, scan, org=None):
    with scope.use_audit_session(w.db):
        return scan_access.get_scan_or_404(scan.id, user, w.db, org)


def test_same_organisation_read_all_sees_the_scan(w):
    assert get(w, w.admin_a, w.scan_a).id == w.scan_a.id


def test_idor_another_organisations_scan_is_a_404_even_when_the_id_is_known(w):
    with pytest.raises(HTTPException) as e:
        get(w, w.admin_a, w.scan_b)
    assert e.value.status_code == 404


def test_idor_a_forged_organisation_id_does_not_open_it(w):
    with pytest.raises(HTTPException) as e:
        get(w, w.admin_a, w.scan_b, org=w.b.id)
    assert e.value.status_code == 404


def test_a_superadmin_reads_across_organisations_only_by_naming_one(w):
    assert get(w, w.superadmin, w.scan_b, org=w.b.id).id == w.scan_b.id
    with pytest.raises(HTTPException):
        get(w, w.superadmin, w.scan_b)  # no organisation named: it acts at home


def test_a_user_without_read_all_sees_only_their_own_scans(w):
    scanner = w.person(w.a, "platform.scanner")
    mine = w.make_scan(w.a, scanner)
    assert get(w, scanner, mine).id == mine.id
    with pytest.raises(HTTPException):
        get(w, scanner, w.scan_a)
    # a custom role granting read_all lifts that limit inside its organisation
    assign(w.db, scanner, custom_org_role(w.db, w.a, "ra", "RA", "audit.scan.read_all"))
    assert get(w, scanner, w.scan_a).id == w.scan_a.id


def test_a_scan_in_an_inactive_organisation_cannot_be_reached(w):
    w.b.is_active = False
    w.db.flush()
    with pytest.raises(HTTPException) as e:
        get(w, w.superadmin, w.scan_b, org=w.b.id)
    assert e.value.status_code == 403


def test_export_lookup_resolves_the_scan_organisation_server_side(w):
    with scope.use_audit_session(w.db):
        assert reports._scan_for_user(w.db, w.admin_a, w.scan_a.id).id == w.scan_a.id
        with pytest.raises(HTTPException) as other:
            reports._scan_for_user(w.db, w.admin_a, w.scan_b.id)
        assert other.value.status_code == 404
        # a superadmin finds it by id alone: the row's own organisation is then verified
        assert reports._scan_for_user(w.db, w.superadmin, w.scan_b.id).id == w.scan_b.id
        w.b.is_active = False
        w.db.flush()
        with pytest.raises(HTTPException):
            reports._scan_for_user(w.db, w.superadmin, w.scan_b.id)


def test_export_lookup_applies_read_all_per_scans_own_organisation(w):
    scanner = w.person(w.a, "platform.scanner")
    with scope.use_audit_session(w.db):
        with pytest.raises(HTTPException):
            reports._scan_for_user(w.db, scanner, w.scan_a.id)


def test_progress_visibility_is_organisation_wide_only_inside_the_organisation(w):
    from scans.progress import _can_read_scan

    assert _can_read_scan(w.db, w.scan_a, w.admin_a.id) is True
    assert _can_read_scan(w.db, w.scan_b, w.admin_a.id) is False
