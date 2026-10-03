"""
RBAC-3 — the shadow comparison.

``shadow.py`` compares the new RBAC decision with the legacy one and returns a
``ShadowResult`` of one of four kinds: MATCH, MISMATCH, NOT_COMPARABLE, ERROR. It is
the comparison only — whether and how it runs beside a legacy check is
``shadow_runtime`` (``test_rbac_shadow_runtime.py``) and the hook in the legacy guards
(``test_rbac_shadow_hook.py``).

**RBAC-3 = SHADOW ONLY. LEGACY AUTHORIZATION = AUTHORITATIVE.** The first half is a
truth table over pure inputs; the second runs the real catalogue, the real golden
mapping and real role assignments in a rolled-back transaction.
"""

from __future__ import annotations

import json
import logging

import pytest

from ccure_platform import composition
from ccure_platform.rbac import contract as c
from ccure_platform.rbac import resolver
from ccure_platform.rbac import shadow as sh
from ccure_platform.rbac.catalogue import sync
from rbac_testing import (
    assign,
    custom_org_role,
    force_state,
    make_org,
    make_user,
    platform_custom_role,
    rbac_db_fixture,  # noqa: F401
    role,
)

A, B = "org_a", "org_b"

# ── the pure truth table ─────────────────────────────────────────────────────


def perm(key, scope_kind="organization", status="active"):
    module, resource, action = key.split(".")
    return c.Permission(
        key=key,
        module=module,
        resource=resource,
        action=action,
        description="d",
        scope_kind=scope_kind,
        sensitivity="normal",
        delegable_to_org_roles=scope_kind == "organization",
        continuity=False,
        status=status,
    )


CAT = {
    p.key: p
    for p in (
        perm("t.scan.read"),
        perm("t.scan.run"),
        perm("t.org.manage", scope_kind="platform"),
        perm(c.ORG_SWITCH_KEY, scope_kind="platform"),
    )
}
ENTRIES = {
    "things:read": sh.MappingEntry("things:read", "mapped", ("t.scan.read",)),
    "things:run": sh.MappingEntry("things:run", "mapped", ("t.scan.run",)),
    "things:both": sh.MappingEntry(
        "things:both", "replaced", ("t.scan.read", "t.scan.run")
    ),
    "things:admin": sh.MappingEntry("things:admin", "mapped", ("t.org.manage",)),
    "things:old": sh.MappingEntry("things:old", "retired", ()),
    "things:drift": sh.MappingEntry("things:drift", "mapped", ("t.not.there",)),
}
ROLES = (sh.RoleInfo("platform.viewer", "active", "organization", A, True),)


def human(home=A):
    return c.Principal(kind="human", principal_id="u1", home_org_id=home)


def og(key, org=A):
    return c.Grant(
        assignment_scope="organization", scope_org_id=org, permission_key=key
    )


def pg(key):
    return c.Grant(assignment_scope="platform", permission_key=key)


def cmp(
    atom,
    legacy,
    grants=(),
    *,
    scope=None,
    assignments=ROLES,
    catalogue=CAT,
    principal=None,
):
    return sh.compare_decision(
        principal or human(),
        grants,
        catalogue,
        assignments,
        ENTRIES.get(atom),
        legacy_atom=atom,
        legacy_allowed=legacy,
        scope=scope,
        operation="GET /things",
        legacy_role="viewer",
    )


def test_both_allow_is_a_match():
    r = cmp("things:read", True, [og("t.scan.read")])
    assert (r.kind, r.classification) == (sh.MATCH, sh.ALLOW_BOTH)
    assert r.legacy_decision is True and r.new_decision is True


def test_both_deny_is_a_match():
    r = cmp("things:read", False, [])
    assert (r.kind, r.classification) == (sh.MATCH, sh.DENY_BOTH)


def test_a_missing_grant_when_legacy_allows_is_a_mismatch_with_the_cause():
    r = cmp("things:read", True, [])
    assert (r.kind, r.classification) == (sh.MISMATCH, sh.NEW_DENIES)
    assert "t.scan.read:missing_permission" in r.reason
    assert r.legacy_decision is True and r.new_decision is False


def test_a_grant_when_legacy_denies_is_a_mismatch_in_the_other_direction():
    r = cmp("things:read", False, [og("t.scan.read")])
    assert (r.kind, r.classification) == (sh.MISMATCH, sh.NEW_ALLOWS)
    assert "t.scan.read" in r.reason


def test_a_split_atom_is_allowed_only_if_every_mapped_key_is():
    both = cmp("things:both", True, [og("t.scan.read"), og("t.scan.run")])
    assert both.kind == sh.MATCH and [d.allowed for d in both.key_decisions] == [
        True,
        True,
    ]
    half = cmp("things:both", True, [og("t.scan.read")])
    assert half.kind == sh.MISMATCH and half.new_decision is False
    assert [(d.key, d.allowed) for d in half.key_decisions] == [
        ("t.scan.read", True),
        ("t.scan.run", False),
    ]


def test_a_retired_atom_is_not_comparable_whatever_the_grants():
    for legacy in (True, False):
        for grants in ([], [og("t.scan.read")]):
            r = cmp("things:old", legacy, grants)
            assert (r.kind, r.classification) == (sh.NOT_COMPARABLE, sh.RETIRED_ATOM)
            assert r.new_decision is None and r.mapping_status == "retired"


def test_an_unknown_atom_is_not_comparable():
    r = cmp("things:nope", True, [og("t.scan.read")])
    assert (r.kind, r.classification) == (sh.NOT_COMPARABLE, sh.UNMAPPED_ATOM)
    assert r.new_decision is None and r.mapping_status is None


def test_an_unprovisioned_principal_is_not_comparable_never_a_mismatch():
    r = cmp("things:read", True, [], assignments=())
    assert (r.kind, r.classification) == (
        sh.NOT_COMPARABLE,
        sh.PRINCIPAL_NOT_PROVISIONED,
    )


def test_an_unpopulated_catalogue_is_not_comparable():
    r = cmp("things:read", True, [], catalogue={})
    assert (r.kind, r.classification) == (sh.NOT_COMPARABLE, sh.CATALOGUE_NOT_POPULATED)


def test_a_mapping_that_names_a_key_the_catalogue_lacks_is_an_error():
    r = cmp("things:drift", True, [])
    assert (r.kind, r.classification) == (sh.ERROR, sh.MAPPING_DRIFT)
    assert "t.not.there" in r.reason


def test_same_organisation_scope_is_compared():
    r = cmp(
        "things:read",
        True,
        [og("t.scan.read")],
        scope=c.ScopeContext(resource_org_id=A),
    )
    assert r.kind == sh.MATCH


def test_a_resource_in_another_organisation_is_the_deferred_scope_model():
    r = cmp(
        "things:read",
        True,
        [og("t.scan.read")],
        scope=c.ScopeContext(resource_org_id=B),
    )
    assert (r.kind, r.classification) == (sh.NOT_COMPARABLE, sh.SCOPE_DEFERRED)
    assert (
        r.new_decision is False
    )  # recorded for diagnosis, never forced into a verdict
    assert r.scope_resource_org == B and "RBAC-5" in r.reason


def test_a_scope_driven_denial_is_deferred_not_a_mismatch():
    # a platform grant reaches another organisation only through the switch
    r = cmp(
        "things:read",
        True,
        [pg("t.scan.read")],
        scope=c.ScopeContext(requested_org_id=B),
    )
    assert (r.kind, r.classification) == (sh.NOT_COMPARABLE, sh.SCOPE_DEFERRED)
    assert any(d.reason == c.ORG_SWITCH_REQUIRED for d in r.key_decisions)
    r = cmp("things:read", True, [og("t.scan.read")], principal=human(home=None))
    assert r.classification == sh.SCOPE_DEFERRED


def test_a_platform_scope_permission_is_compared_at_platform_scope():
    assert cmp("things:admin", True, [pg("t.org.manage")]).kind == sh.MATCH
    miss = cmp("things:admin", True, [og("t.org.manage")])
    assert (miss.kind, miss.classification) == (sh.MISMATCH, sh.NEW_DENIES)
    assert "platform_scope_required" in miss.reason


def test_the_legacy_role_label_is_diagnostic_only_it_never_changes_the_new_decision():
    grants = [og("t.scan.read")]
    labels = ["viewer", "superadmin", "org_admin", "CISO", None]
    results = [
        sh.compare_decision(
            human(),
            grants,
            CAT,
            ROLES,
            ENTRIES["things:read"],
            legacy_atom="things:read",
            legacy_allowed=True,
            legacy_role=label,
        )
        for label in labels
    ]
    assert {(r.kind, r.classification, r.new_decision) for r in results} == {
        (sh.MATCH, sh.ALLOW_BOTH, True)
    }


def test_a_role_name_check_has_no_permission_to_compare():
    class U:
        id, org_id = "u9", A

        class role:  # noqa: N801
            name = "org_admin"

    r = sh.role_name_check_result(
        U, ["superadmin", "org_admin"], False, operation="GET /x"
    )
    assert (r.kind, r.classification) == (sh.NOT_COMPARABLE, sh.ROLE_NAME_CHECK)
    assert (
        r.required_roles == ("org_admin", "superadmin") and r.legacy_decision is False
    )
    assert (
        r.mapped_keys == () and r.new_decision is None and r.legacy_role == "org_admin"
    )


# ── a result is enough to diagnose a mismatch, and safe to log ───────────────


def test_a_mismatch_carries_everything_needed_to_diagnose_it():
    r = cmp(
        "things:both",
        True,
        [og("t.scan.read")],
        scope=c.ScopeContext(requested_org_id=A),
    )
    assert r.kind == sh.MISMATCH
    assert r.principal_id == "u1" and r.principal_kind == "human" and r.org_id == A
    assert r.legacy_atom == "things:both" and r.mapping_status == "replaced"
    assert r.mapped_keys == ("t.scan.read", "t.scan.run")
    assert (r.legacy_decision, r.new_decision) == (True, False)
    assert [(k.key, k.allowed, k.reason) for k in r.key_decisions] == [
        ("t.scan.read", True, c.ALLOWED),
        ("t.scan.run", False, c.MISSING_PERMISSION),
    ]
    assert r.new_roles == ROLES and r.legacy_role == "viewer"
    assert r.scope_requested_org == A and r.operation == "GET /things" and r.reason


def test_the_result_has_no_field_for_a_secret():
    forbidden = (
        "password",
        "token",
        "cookie",
        "secret",
        "mfa",
        "header",
        "body",
        "query",
        "email",
        "authorization",
        "jwt",
    )
    names = " ".join(sh.ShadowResult.__slots__).lower()
    assert not [f for f in forbidden if f in names], names
    rendered = json.dumps(cmp("things:read", True, []).to_dict()).lower()
    assert not [f for f in forbidden if f in rendered]


def test_a_result_serialises_to_json():
    r = cmp("things:both", True, [og("t.scan.read")])
    assert json.loads(json.dumps(r.to_dict()))["classification"] == sh.NEW_DENIES


def test_log_fields_are_scalar_single_line_and_capped():
    r = sh.ShadowResult(
        kind=sh.MISMATCH,
        classification=sh.NEW_DENIES,
        reason="line one\nline two\r\nINJECTED kind=match " + "x" * 500,
        principal_id="u1\nforged=1",
        legacy_atom="a:b",
    )
    fields = r.log_fields()
    assert all(
        isinstance(v, str) and "\n" not in v and "\r" not in v and len(v) <= 160
        for v in fields.values()
    )
    assert " " not in fields["reason"] and fields["principal"] == "u1_forged=1"


def test_every_classification_belongs_to_exactly_one_kind():
    flat = [cl for kinds in sh.CLASSIFICATIONS.values() for cl in kinds]
    assert len(flat) == len(set(flat))
    assert (
        set(sh.CLASSIFICATIONS)
        == set(sh.KINDS)
        == {"match", "mismatch", "not_comparable", "error"}
    )


def test_every_result_the_truth_table_produces_uses_a_known_pair():
    cases = [
        cmp("things:read", True, [og("t.scan.read")]),
        cmp("things:read", False, []),
        cmp("things:read", True, []),
        cmp("things:read", False, [og("t.scan.read")]),
        cmp("things:old", True),
        cmp("things:nope", True),
        cmp("things:read", True, [], assignments=()),
        cmp("things:read", True, [], catalogue={}),
        cmp("things:drift", True),
        cmp(
            "things:read",
            True,
            [og("t.scan.read")],
            scope=c.ScopeContext(resource_org_id=B),
        ),
    ]
    for r in cases:
        assert r.classification in sh.CLASSIFICATIONS[r.kind], (
            r.kind,
            r.classification,
        )


# ── against the real catalogue, golden mapping and role assignments ──────────


@pytest.fixture
def world(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    w = type("World", (), {})()
    w.db, w.a, w.b = rbac_db, make_org(rbac_db), make_org(rbac_db)
    w.root = make_user(rbac_db, w.a)
    assign(rbac_db, w.root, role(rbac_db, "platform.superadmin"))
    for name, key in (
        ("oa", "platform.org_admin"),
        ("an", "platform.analyst"),
        ("vw", "platform.viewer"),
        ("sc", "platform.scanner"),
    ):
        user = make_user(rbac_db, w.a)
        assign(rbac_db, user, role(rbac_db, key))
        setattr(w, name, user)
    return w


def run(world, user, atom, legacy, **kw):
    resource, action = atom.split(":")
    return sh.shadow_compare(world.db, user, resource, action, legacy, **kw)


def test_an_allowed_permission_matches(world):
    r = run(world, world.sc, "scans:execute", True)
    assert (r.kind, r.classification) == (sh.MATCH, sh.ALLOW_BOTH)
    assert r.mapped_keys == ("audit.scan.run",) and r.duration_ms is not None


def test_a_denied_permission_matches(world):
    assert run(world, world.vw, "scans:execute", False).classification == sh.DENY_BOTH


def test_a_missing_grant_when_legacy_allows_is_a_diagnosable_mismatch(world):
    r = run(world, world.vw, "scans:execute", True)  # the viewer holds no scan.run
    assert (r.kind, r.classification) == (sh.MISMATCH, sh.NEW_DENIES)
    assert r.new_roles == (
        sh.RoleInfo("platform.viewer", "active", "organization", world.a.id, True),
    )
    assert r.org_id == world.a.id and "audit.scan.run:missing_permission" in r.reason


def test_retired_and_unknown_atoms_are_not_comparable_and_make_no_query(
    world, monkeypatch
):
    def boom(*a, **k):
        raise AssertionError("the database was touched")

    monkeypatch.setattr(resolver, "load_catalogue", boom)
    assert run(world, world.oa, "scans:cancel", True).classification == sh.RETIRED_ATOM
    assert run(world, world.oa, "widgets:frob", True).classification == sh.UNMAPPED_ATOM


def test_same_organisation_and_different_organisation_scope(world):
    own = c.ScopeContext(resource_org_id=world.a.id)
    other = c.ScopeContext(resource_org_id=world.b.id)
    assert run(world, world.an, "assets:read", True, scope=own).kind == sh.MATCH
    r = run(world, world.an, "assets:read", True, scope=other)
    assert (r.kind, r.classification) == (sh.NOT_COMPARABLE, sh.SCOPE_DEFERRED)


def test_platform_scope_the_superadmin_holds_it_and_an_organisation_role_does_not(
    world,
):
    assert run(world, world.root, "organizations:read", True).kind == sh.MATCH
    assert (
        run(world, world.oa, "organizations:read", False).classification == sh.DENY_BOTH
    )


def test_the_superadmin_matches_every_mapped_atom_through_grants_alone(world):
    for atom in (
        "scans:execute",
        "users:update",
        "roles:read",
        "compliance:approve_exception",
        "audit:export",
    ):
        r = run(world, world.root, atom, True)
        assert (r.kind, r.classification) == (sh.MATCH, sh.ALLOW_BOTH), atom


def test_a_user_with_no_rbac_assignment_is_not_provisioned(world):
    stranger = make_user(world.db, world.a)
    r = run(world, stranger, "scans:execute", True)
    assert (r.kind, r.classification) == (
        sh.NOT_COMPARABLE,
        sh.PRINCIPAL_NOT_PROVISIONED,
    )


def test_renaming_a_role_display_name_does_not_change_the_comparison(world):
    before = [
        run(world, world.vw, a, v).to_dict()
        for a, v in (
            ("scans:read", True),
            ("scans:execute", False),
            ("users:read", False),
        )
    ]
    # (display names are unique among live roles: free "Superadmin" first)
    role(world.db, "platform.superadmin").display_name = "Chief"
    world.db.flush()
    role(world.db, "platform.viewer").display_name = "Superadmin"
    world.db.flush()
    after = [
        run(world, world.vw, a, v).to_dict()
        for a, v in (
            ("scans:read", True),
            ("scans:execute", False),
            ("users:read", False),
        )
    ]

    def strip(rs):
        return [
            {k: v for k, v in r.items() if k not in ("at", "duration_ms")} for r in rs
        ]

    assert strip(before) == strip(after)


def test_a_retiring_role_still_compares_as_a_match(world):
    force_state(world.db, role(world.db, "platform.scanner"), "retiring")
    r = run(world, world.sc, "scans:execute", True)
    assert r.kind == sh.MATCH and r.new_roles[0].role_state == "retiring"


def test_a_retired_role_whose_assignment_was_revoked_is_a_real_divergence(world):
    from datetime import datetime, timezone

    from ccure_platform.rbac.model import RbacUserRole

    row = world.db.query(RbacUserRole).filter_by(user_id=world.sc.id).one()
    row.revoked_at, row.revoke_reason = datetime.now(timezone.utc), "role_retired"
    force_state(world.db, role(world.db, "platform.scanner"), "retiring")
    force_state(world.db, role(world.db, "platform.scanner"), "retired")
    r = run(
        world, world.sc, "scans:execute", True
    )  # legacy still lets the scanner scan
    assert (r.kind, r.classification) == (sh.MISMATCH, sh.NEW_DENIES)
    assert (
        r.new_roles
        and not r.new_roles[0].live
        and r.new_roles[0].role_state == "retired"
    )


def test_a_revoked_assignment_is_a_mismatch_not_unprovisioned(world):
    from datetime import datetime, timezone

    from ccure_platform.rbac.model import RbacUserRole

    row = world.db.query(RbacUserRole).filter_by(user_id=world.an.id).one()
    row.revoked_at, row.revoke_reason = datetime.now(timezone.utc), "manual"
    world.db.flush()
    r = run(world, world.an, "scans:execute", True)
    assert (r.kind, r.classification) == (sh.MISMATCH, sh.NEW_DENIES)
    assert [i.live for i in r.new_roles] == [
        False
    ]  # had a role, lost it: not "never provisioned"


def test_a_custom_organisation_role_is_compared_through_its_grants(world):
    custom = custom_org_role(world.db, world.a, "soc", "SOC", "audit.scan.run")
    user = make_user(world.db, world.a)
    assign(world.db, user, custom)
    assert run(world, user, "scans:execute", True).kind == sh.MATCH
    assert run(world, user, "scans:purge", False).classification == sh.DENY_BOTH


def test_multiple_role_assignments_union_their_grants(world):
    user = make_user(world.db, world.a)
    assign(world.db, user, role(world.db, "platform.viewer"))
    assign(world.db, user, role(world.db, "platform.scanner"))
    r = run(world, user, "scans:execute", True)
    assert r.kind == sh.MATCH and {i.role_key for i in r.new_roles} == {
        "platform.viewer",
        "platform.scanner",
    }


def test_a_platform_custom_role_without_the_switch_is_deferred_for_another_organisation(
    world,
):
    ops = platform_custom_role(world.db, "ops", "Ops", "audit.scan.read")
    user = make_user(world.db, world.a)
    assign(world.db, user, ops)
    r = run(
        world,
        user,
        "scans:read",
        True,
        scope=c.ScopeContext(requested_org_id=world.b.id),
    )
    assert r.classification == sh.SCOPE_DEFERRED


# ── failure containment ──────────────────────────────────────────────────────


def test_an_evaluator_failure_is_an_error_result_not_an_exception(world, monkeypatch):
    def boom(db):
        raise RuntimeError("catalogue exploded")

    monkeypatch.setattr(resolver, "load_catalogue", boom)
    r = run(world, world.sc, "scans:execute", True)
    assert (r.kind, r.classification) == (sh.ERROR, sh.EVALUATOR_ERROR)
    assert (
        r.reason == "RuntimeError" and "exploded" not in r.reason
    )  # a class name, never a message
    assert r.legacy_decision is True and r.new_decision is None


def test_an_unreadable_golden_mapping_is_an_error_result(world):
    sh.set_golden_index(None)

    def broken():
        raise sh.MappingUnavailable("golden mapping is gone")

    import ccure_platform.rbac.shadow as module

    original = module.golden_index
    module.golden_index = broken
    try:
        r = run(world, world.sc, "scans:execute", True)
    finally:
        module.golden_index = original
    assert (r.kind, r.classification) == (sh.ERROR, sh.MAPPING_UNAVAILABLE)


def test_a_failed_shadow_query_does_not_poison_the_callers_transaction(
    world, monkeypatch
):
    from sqlalchemy import text

    def bad_query(db):
        db.execute(text("SELECT * FROM table_that_does_not_exist"))

    monkeypatch.setattr(resolver, "load_catalogue", bad_query)
    r = run(world, world.sc, "scans:execute", True)
    assert r.kind == sh.ERROR
    assert world.db.execute(text("SELECT 1")).scalar() == 1  # still usable
    assert (
        world.db.query(type(role(world.db, "platform.viewer"))).count() >= 5
    )  # and still holds its data


def test_the_comparison_writes_nothing(world):
    from sqlalchemy import text

    tables = (
        "rbac_roles",
        "rbac_user_roles",
        "rbac_role_permissions",
        "rbac_permissions",
        "rbac_legacy_map",
        "rbac_role_revisions",
        "audit_logs",
        "platform_audit_events",
    )
    before = {
        t: world.db.execute(text(f"SELECT count(*) FROM {t}")).scalar() for t in tables
    }
    for user in (world.root, world.oa, world.an, world.vw, world.sc):
        for atom in (
            "scans:execute",
            "users:update",
            "scans:cancel",
            "widgets:frob",
            "organizations:read",
        ):
            run(world, user, atom, True)
    assert {
        t: world.db.execute(text(f"SELECT count(*) FROM {t}")).scalar() for t in tables
    } == before


# ── the golden mapping is the only mapping ───────────────────────────────────


def test_the_comparison_reads_the_rbac_2_golden_mapping_and_no_other(world):
    from ccure_platform.rbac import legacy_map

    golden = legacy_map.load_golden()
    index = sh.golden_index()
    assert set(index) == {a["atom"] for a in golden["atoms"]} and len(index) == 66
    for a in golden["atoms"]:
        assert (index[a["atom"]].status, index[a["atom"]].keys) == (
            a["status"],
            tuple(a["new_keys"]),
        )
    import inspect

    assert "rbac_legacy_map" not in inspect.getsource(
        sh
    ) and "RbacLegacyMap" not in inspect.getsource(sh)


def test_mapped_replaced_retired_and_unmapped_are_each_handled(world):
    seen = {
        run(world, world.oa, atom, True).classification: atom
        for atom in ("scans:read", "settings:update", "scans:cancel", "widgets:frob")
    }
    assert set(seen) >= {sh.ALLOW_BOTH, sh.RETIRED_ATOM, sh.UNMAPPED_ATOM}
    assert run(world, world.oa, "settings:update", True).mapping_status == "replaced"
    assert run(world, world.oa, "scans:read", True).mapping_status == "mapped"


# ── recording ────────────────────────────────────────────────────────────────


def test_the_recorder_counts_every_kind_and_keeps_a_bounded_buffer():
    rec = sh.ShadowRecorder(buffer=2)
    for _ in range(5):
        rec.record(cmp("things:read", True, []))  # mismatch
    rec.record(cmp("things:read", True, [og("t.scan.read")]))
    rec.record(cmp("things:old", True))
    rec.record(cmp("things:drift", True))
    snap = rec.snapshot()
    assert snap["by_kind"] == {
        "mismatch": 5,
        "match": 1,
        "not_comparable": 1,
        "error": 1,
    }
    assert len(snap["mismatches"]) == 2 and len(snap["errors"]) == 1
    assert rec.total() == 8 and rec.total(sh.MISMATCH) == 5
    rec.reset()
    assert rec.total() == 0


def test_mismatches_and_errors_log_at_warning_matches_do_not(caplog):
    rec = sh.ShadowRecorder()
    with caplog.at_level(logging.INFO, logger="ccure.rbac.shadow"):
        rec.record(cmp("things:read", True, []))
        rec.record(cmp("things:drift", True))
        rec.record(cmp("things:read", True, [og("t.scan.read")]))
    levels = [(r.levelno, r.getMessage().split(" ")[2]) for r in caplog.records]
    assert levels == [(logging.WARNING, "mismatch"), (logging.WARNING, "error")]
    assert (
        "principal=u1" in caplog.records[0].getMessage()
        and "atom=things:read" in caplog.records[0].getMessage()
    )


def test_not_comparable_is_logged_once_per_atom_and_classification(caplog):
    rec = sh.ShadowRecorder()
    with caplog.at_level(logging.INFO, logger="ccure.rbac.shadow"):
        for _ in range(4):
            rec.record(cmp("things:old", True))
        rec.record(cmp("things:nope", True))
    assert len(caplog.records) == 2 and rec.total(sh.NOT_COMPARABLE) == 5


def test_log_matches_is_opt_in(caplog):
    rec = sh.ShadowRecorder(log_matches=True)
    with caplog.at_level(logging.INFO, logger="ccure.rbac.shadow"):
        rec.record(cmp("things:read", True, [og("t.scan.read")]))
    assert len(caplog.records) == 1


def test_no_log_line_carries_a_secret(caplog):
    rec = sh.ShadowRecorder(log_matches=True)
    with caplog.at_level(logging.DEBUG, logger="ccure.rbac.shadow"):
        for r in (
            cmp("things:read", True, []),
            cmp("things:old", True),
            cmp("things:drift", True),
        ):
            rec.record(r)
    text = " ".join(r.getMessage() for r in caplog.records).lower()
    for word in (
        "password",
        "token",
        "cookie",
        "secret",
        "bearer",
        "authorization",
        "set-cookie",
    ):
        assert word not in text
