"""
RBAC-1 — the shadow foundation.

The new decision must never control a request, and observing must never break
one. RBAC-1 builds the comparison and wires it to nothing; these tests hold both
properties and assert the second one (nothing calls it).
"""

from __future__ import annotations

import ast
import dataclasses
import logging

import pytest
from sqlalchemy import text

from ccure_platform.rbac import contract as c
from ccure_platform.rbac import shadow
from ccure_platform.rbac.catalogue import sync
from ccure_platform.rbac.model import RbacLegacyMap
from rbac_testing import (
    assign,
    decl,
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401  (registers the rbac_db fixture)
    role,
    source,
)
from testpaths import BACKEND_ROOT


@pytest.fixture
def mapped(rbac_db):
    sync(
        rbac_db,
        [
            source(
                "example",
                decl(
                    "example.scan.read",
                    default_grants=("platform.viewer", "platform.analyst"),
                ),
                decl("example.scan.run", default_grants=("platform.analyst",)),
                decl("example.scan.audit", default_grants=("platform.analyst",)),
            )
        ],
    )
    rbac_db.query(RbacLegacyMap).delete()
    rbac_db.flush()
    for resource, action, key in (
        ("scans", "read", "example.scan.read"),
        ("scans", "execute", "example.scan.run"),
        ("scans", "create", "example.scan.run"),  # a merge
        ("scans", "split", "example.scan.read"),  # a split into two keys
        ("scans", "split", "example.scan.audit"),
    ):
        rbac_db.add(
            RbacLegacyMap(
                kind="permission",
                legacy_resource=resource,
                legacy_action=action,
                permission_key=key,
            )
        )
    rbac_db.flush()
    org = make_org(rbac_db)
    viewer, analyst = make_user(rbac_db, org), make_user(rbac_db, org)
    assign(rbac_db, viewer, role(rbac_db, "platform.viewer"))
    assign(rbac_db, analyst, role(rbac_db, "platform.analyst"))
    return rbac_db, viewer, analyst


def test_agreement_is_a_match(mapped):
    db, viewer, analyst = mapped
    assert shadow.shadow_compare(db, viewer, "scans", "read", True).kind == shadow.MATCH
    assert (
        shadow.shadow_compare(db, viewer, "scans", "execute", False).kind
        == shadow.MATCH
    )
    assert (
        shadow.shadow_compare(db, analyst, "scans", "execute", True).kind
        == shadow.MATCH
    )


def test_disagreement_is_a_mismatch_in_both_directions_and_is_logged(mapped, caplog):
    db, viewer, analyst = mapped
    with caplog.at_level(logging.WARNING, logger="ccure.rbac.shadow"):
        legacy_says_yes = shadow.shadow_compare(db, viewer, "scans", "execute", True)
        legacy_says_no = shadow.shadow_compare(db, analyst, "scans", "read", False)
    assert (
        legacy_says_yes.kind == shadow.MISMATCH and legacy_says_yes.new_allowed is False
    )
    assert legacy_says_no.kind == shadow.MISMATCH and legacy_says_no.new_allowed is True
    assert "RBAC shadow mismatch scans:execute" in caplog.text


def test_a_split_atom_is_allowed_only_if_every_mapped_key_is(mapped):
    db, viewer, analyst = mapped
    assert (
        shadow.shadow_compare(db, analyst, "scans", "split", True).new_allowed is True
    )
    out = shadow.shadow_compare(db, viewer, "scans", "split", True)
    assert out.new_allowed is False and out.kind == shadow.MISMATCH
    assert out.permission_keys == ("example.scan.audit", "example.scan.read")


def test_an_unmapped_atom_is_neither_a_match_nor_a_mismatch(mapped):
    db, viewer, _ = mapped
    out = shadow.shadow_compare(db, viewer, "findings", "read", True)
    assert out.kind == shadow.NOT_MAPPED and out.new_allowed is None


def test_the_outcome_is_only_a_comparison_it_cannot_be_mistaken_for_the_answer(mapped):
    db, viewer, _ = mapped
    out = shadow.shadow_compare(db, viewer, "scans", "execute", True)
    assert dataclasses.is_dataclass(out)
    assert not isinstance(out, bool) and not hasattr(out, "allowed")
    # the legacy verdict is carried through untouched
    assert out.legacy_allowed is True


def test_a_recorder_counts_and_keeps_disagreements(mapped):
    db, viewer, analyst = mapped
    rec = shadow.ShadowRecorder(limit=1)
    shadow.shadow_compare(db, viewer, "scans", "read", True, recorder=rec)
    shadow.shadow_compare(db, viewer, "scans", "execute", True, recorder=rec)
    shadow.shadow_compare(db, analyst, "scans", "read", False, recorder=rec)
    shadow.shadow_compare(db, viewer, "findings", "read", True, recorder=rec)
    assert rec.counts == {"match": 1, "mismatch": 2, "not_mapped": 1}
    assert len(rec.mismatches) == 1  # bounded


def test_a_failing_evaluation_becomes_an_error_outcome_and_never_raises(
    mapped, monkeypatch
):
    db, viewer, _ = mapped

    def boom(*a, **k):
        raise RuntimeError("shadow bug")

    monkeypatch.setattr(shadow, "mapped_keys", boom)
    out = shadow.shadow_compare(db, viewer, "scans", "read", True)
    assert out.kind == shadow.ERROR and out.legacy_allowed is True


def test_a_failed_query_inside_shadow_does_not_poison_the_callers_transaction(
    mapped, monkeypatch
):
    """The savepoint is the point: a database error during shadowing must roll back
    only itself, or the request being observed would fail with it."""
    db, viewer, _ = mapped

    def bad_query(session, resource, action):
        session.execute(text("SELECT * FROM table_that_does_not_exist"))

    monkeypatch.setattr(shadow, "mapped_keys", bad_query)
    out = shadow.shadow_compare(db, viewer, "scans", "read", True)
    assert out.kind == shadow.ERROR
    # the caller's session is still usable and still holds what it wrote
    assert db.execute(text("SELECT 1")).scalar() == 1
    assert db.query(RbacLegacyMap).count() == 5


def test_shadow_changes_nothing_in_the_database(mapped):
    db, viewer, analyst = mapped
    before = {
        t: db.execute(text(f"SELECT count(*) FROM {t}")).scalar()
        for t in (
            "rbac_roles",
            "rbac_user_roles",
            "rbac_role_permissions",
            "rbac_role_revisions",
            "audit_logs",
        )
    }
    for user in (viewer, analyst):
        for action in ("read", "execute", "split", "nothing"):
            shadow.shadow_compare(db, user, "scans", action, True)
    after = {t: db.execute(text(f"SELECT count(*) FROM {t}")).scalar() for t in before}
    assert after == before


def test_nothing_in_the_application_calls_shadow_yet():
    """RBAC-1 builds the comparison; enabling it is RBAC-3. A call from anywhere
    but its own module and its tests means shadow was switched on."""
    offenders = []
    for path in BACKEND_ROOT.rglob("*.py"):
        parts = path.relative_to(BACKEND_ROOT).parts
        if parts[0] in {"tests", ".venv", "venv", "alembic", "__pycache__"}:
            continue
        if parts[:3] == ("ccure_platform", "rbac", "shadow.py"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] + [
                    getattr(node, "module", "") or ""
                ]
                if any("rbac.shadow" in n or n == "shadow_compare" for n in names):
                    offenders.append(str(path.relative_to(BACKEND_ROOT)))
            if isinstance(node, ast.Name) and node.id == "shadow_compare":
                offenders.append(str(path.relative_to(BACKEND_ROOT)))
    assert not offenders, offenders
