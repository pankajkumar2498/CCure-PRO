"""
RBAC-1 — the schema: tables, constraints, foreign keys, and the triggers that
hold the invariants even if governance is bypassed.

Every negative case runs inside a savepoint (``begin_nested``) so a refused
statement rolls back only itself, and nothing here is ever committed
(``rbac_testing.rbac_db``).
"""

from __future__ import annotations

import importlib.util
import re
from datetime import datetime, timedelta, timezone

import pytest
import yaml
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from ccure_platform.models import rbac_tables
from ccure_platform.rbac import contract as c
from ccure_platform.rbac.catalogue import (
    ensure_default_roles,
    ensure_system_roles,
    sync,
)
from ccure_platform.rbac.model import (
    RbacDefaultRole,
    RbacLegacyMap,
    RbacPermission,
    RbacRole,
    RbacRolePermission,
    RbacRoleRevision,
    RbacUserRole,
    append_revision,
)
from rbac_testing import (
    assign,
    custom_org_role,
    decl,
    grant,
    make_org,
    make_user,
    platform_custom_role,
    rbac_db_fixture,  # noqa: F401  (registers the rbac_db fixture)
    role,
    source,
)
from testpaths import BACKEND_ROOT

TABLES = (
    "rbac_permissions",
    "rbac_roles",
    "rbac_role_revisions",
    "rbac_role_permissions",
    "rbac_user_roles",
    "rbac_default_roles",
    "rbac_legacy_map",
)
NOW = lambda: datetime.now(timezone.utc)  # noqa: E731


def refused(db, fn, fragment=None):
    """Run ``fn`` in a savepoint; it must be refused by the database."""
    with pytest.raises(DBAPIError) as err:
        with db.begin_nested():
            fn()
            db.flush()
    if fragment:
        assert fragment in str(err.value.orig), str(err.value.orig)


def new_role(db, **kw):
    row = RbacRole(
        **{
            "key": "custom.platform.t" + __import__("uuid").uuid4().hex[:6],
            "display_name": "R" + __import__("uuid").uuid4().hex[:6],
            "kind": "custom",
            "assignable_scope": "platform",
            "managed_by": "admin",
            **kw,
        }
    )
    db.add(row)
    db.flush()
    return row


def set_state(row, state):
    row.state = state
    row.retired_at = NOW() if state == "retired" else None


# ── the tables ───────────────────────────────────────────────────────────────


def test_all_seven_tables_exist(rbac_db):
    present = set(
        rbac_db.execute(
            text(
                "SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'rbac_%'"
            )
        ).scalars()
    )
    assert set(TABLES) <= present


def test_every_rbac_table_is_platform_owned():
    data = yaml.safe_load(
        (BACKEND_ROOT / "scripts" / "architecture" / "table_ownership.yaml").read_text()
    )
    for table in TABLES:
        assert data["tables"][table]["owner"] == "platform", table
        assert data["tables"][table]["capability"] == "rbac"


def test_every_foreign_key_is_on_delete_restrict(rbac_db):
    rows = rbac_db.execute(
        text(
            "SELECT conrelid::regclass::text, conname, confdeltype FROM pg_constraint "
            "WHERE contype = 'f' AND conrelid::regclass::text LIKE 'rbac_%'"
        )
    ).all()
    assert len(rows) >= 12
    assert {r[2] for r in rows} == {"r"}, rows


def test_the_legacy_tables_are_not_touched_by_the_new_ones(rbac_db):
    """The new tables reference organisations and users only — never the legacy
    roles / permissions / role_permissions."""
    refs = set(
        rbac_db.execute(
            text(
                "SELECT confrelid::regclass::text FROM pg_constraint "
                "WHERE contype = 'f' AND conrelid::regclass::text LIKE 'rbac_%'"
            )
        ).scalars()
    )
    assert not refs & {"roles", "permissions", "role_permissions"}
    assert refs <= {"organizations", "users"} | set(TABLES)


# ── role identity and constraints ────────────────────────────────────────────


@pytest.mark.parametrize(
    "kw",
    [
        dict(key="superadmin"),  # no namespace
        dict(key="Platform.x"),
        dict(key="custom.acme.x"),  # org segment must start org_
        dict(kind="galaxy"),
        dict(managed_by="robot"),
        dict(state="gone"),
        dict(assignable_scope="planet"),
        dict(kind="system", key="platform.t1", managed_by="admin"),  # system ⇒ code
        dict(kind="custom", key="platform.t2"),  # platform.* is system only
        dict(key="custom.platform.t3", assignable_scope="organization"),  # key/scope
        dict(
            auto_grant_new_permissions=True,
            kind="custom",
            key="custom.org_zz.t4",
            assignable_scope="organization",
        ),
        dict(display_name=""),
        dict(display_name=" padded"),
        dict(display_name="has\x01control"),
        dict(display_name="x" * 101),
    ],
)
def test_role_constraints_refuse_what_the_model_forbids(rbac_db, kw):
    refused(rbac_db, lambda: new_role(rbac_db, **kw))


def test_an_org_custom_role_must_carry_its_org_id_and_nothing_else_may(rbac_db):
    org = make_org(rbac_db)
    refused(
        rbac_db,
        lambda: new_role(
            rbac_db,
            key=f"custom.{org.id}.a",
            assignable_scope="organization",
            org_id=None,
        ),
    )
    refused(
        rbac_db, lambda: new_role(rbac_db, org_id=org.id)
    )  # platform-scope role with an org
    ok = new_role(
        rbac_db,
        key=f"custom.{org.id}.b",
        assignable_scope="organization",
        org_id=org.id,
    )
    assert ok.org_id == org.id


def test_auto_grant_is_a_platform_scope_idea(rbac_db):
    ok = new_role(rbac_db, auto_grant_new_permissions=True)
    assert ok.auto_grant_new_permissions


def test_display_names_are_unique_among_live_roles_case_insensitively(rbac_db):
    new_role(rbac_db, display_name="Security Lead")
    refused(rbac_db, lambda: new_role(rbac_db, display_name="security LEAD"))


def test_a_retired_role_frees_its_display_name(rbac_db):
    first = new_role(rbac_db, display_name="Security Lead")
    set_state(first, "retiring")
    rbac_db.flush()
    set_state(first, "retired")
    rbac_db.flush()
    assert new_role(rbac_db, display_name="Security Lead")


def test_display_names_are_per_organisation_namespace(rbac_db):
    a, b = make_org(rbac_db), make_org(rbac_db)
    custom_org_role(rbac_db, a, "lead", "Lead")
    assert custom_org_role(rbac_db, b, "lead", "Lead")
    refused(rbac_db, lambda: custom_org_role(rbac_db, a, "lead2", "LEAD"))


# ── immutability ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "column,value",
    [
        ("id", "00000000-0000-0000-0000-000000000001"),
        ("key", "custom.platform.renamed"),
        ("kind", "system"),
        ("assignable_scope", "organization"),
        ("managed_by", "code"),
        ("created_at", datetime(2020, 1, 1, tzinfo=timezone.utc)),
    ],
)
def test_role_identity_columns_are_immutable(rbac_db, column, value):
    row = new_role(rbac_db)

    def mutate():
        setattr(row, column, value)

    refused(rbac_db, mutate)


def test_org_id_is_immutable(rbac_db):
    a, b = make_org(rbac_db), make_org(rbac_db)
    row = custom_org_role(rbac_db, a, "x", "X")

    def mutate():
        row.org_id = b.id

    refused(rbac_db, mutate)


def test_display_name_and_description_are_mutable_and_key_is_unchanged(rbac_db):
    row = role(rbac_db, "platform.superadmin")
    key, rid = row.key, row.id
    row.display_name = "CISO"
    row.description = "Chief Information Security Officer"
    rbac_db.flush()
    rbac_db.refresh(row)
    assert (row.key, row.id, row.display_name) == (key, rid, "CISO")


def test_a_role_row_is_never_deleted(rbac_db):
    row = new_role(rbac_db)
    refused(
        rbac_db,
        lambda: rbac_db.execute(
            text("DELETE FROM rbac_roles WHERE id = :i"), {"i": row.id}
        ),
        "never deleted",
    )


def test_revision_cannot_decrease(rbac_db):
    row = new_role(rbac_db)
    row.revision = 5
    rbac_db.flush()
    row.revision = 2
    refused(rbac_db, lambda: None)  # flush happens inside refused()


# ── lifecycle (the database enforces the same table the governance code uses) ─

_TRANSITIONS = [
    ("active", "retiring", True),
    ("active", "retired", False),
    ("retiring", "retired", True),
    ("retiring", "active", True),
    ("retired", "active", True),
    ("retired", "retiring", False),
]


@pytest.mark.parametrize("start,target,ok", _TRANSITIONS)
def test_role_state_transitions(rbac_db, start, target, ok):
    row = new_role(rbac_db)
    path = {"active": [], "retiring": ["retiring"], "retired": ["retiring", "retired"]}[
        start
    ]
    for step in path:
        set_state(row, step)
        rbac_db.flush()
    if ok:
        set_state(row, target)
        rbac_db.flush()
        assert row.state == target
    else:
        refused(rbac_db, lambda: set_state(row, target), "state transition")


def test_the_python_and_database_transition_tables_agree(rbac_db):
    from ccure_platform.rbac.governance import validate_transition

    for start in c.ROLE_STATES:
        for target in c.ROLE_STATES:
            if start == target:
                continue
            assert (validate_transition(start, target) is None) == (
                target in c.ROLE_TRANSITIONS[start]
            )
    assert {(a, b, True) for a, ts in c.ROLE_TRANSITIONS.items() for b in ts} == {
        t for t in _TRANSITIONS if t[2]
    }


def test_retired_requires_retirement_metadata_and_only_retired_has_it(rbac_db):
    row = new_role(rbac_db)
    set_state(row, "retiring")
    rbac_db.flush()

    def retire_without_timestamp():
        row.state = "retired"

    refused(rbac_db, retire_without_timestamp)


def test_retirement_metadata_and_replacement_are_recorded(rbac_db):
    old = new_role(rbac_db)
    new = new_role(rbac_db)
    set_state(old, "retiring")
    rbac_db.flush()
    set_state(old, "retired")
    old.retired_by = "u1"
    old.retirement_reason = "replaced"
    old.replaced_by_role_id = new.id
    rbac_db.flush()
    assert old.replaced_by_role_id == new.id
    refused(rbac_db, lambda: setattr(new, "replaced_by_role_id", new.id))


# ── revision history ─────────────────────────────────────────────────────────


def test_revisions_are_append_only(rbac_db):
    row = role(rbac_db, "platform.viewer")
    rev = rbac_db.query(RbacRoleRevision).filter_by(role_id=row.id).first()
    refused(rbac_db, lambda: setattr(rev, "display_name", "Tampered"), "append-only")
    refused(
        rbac_db,
        lambda: rbac_db.execute(
            text("DELETE FROM rbac_role_revisions WHERE id = :i"), {"i": rev.id}
        ),
        "append-only",
    )


def test_a_revision_records_everything_the_design_names(rbac_db):
    row = role(rbac_db, "platform.viewer")
    row.display_name = "Read Only"
    rbac_db.flush()
    rev = append_revision(rbac_db, row, "renamed", changed_by="u9")
    assert rev.role_id == row.id and rev.revision == row.revision >= 2
    assert (rev.display_name, rev.state, rev.change_kind, rev.changed_by) == (
        "Read Only",
        "active",
        "renamed",
        "u9",
    )
    assert len(rev.permission_set_hash) == 64 and rev.changed_at is not None
    assert rev.description == row.description


def test_two_revisions_cannot_share_a_number(rbac_db):
    row = role(rbac_db, "platform.viewer")
    refused(
        rbac_db,
        lambda: rbac_db.add(
            RbacRoleRevision(
                role_id=row.id,
                revision=1,
                display_name="x",
                permission_set_hash="0" * 64,
                state="active",
                change_kind="created",
            )
        ),
    )


def test_revision_kind_and_hash_are_constrained(rbac_db):
    row = role(rbac_db, "platform.viewer")
    for kw in (
        dict(change_kind="vibes"),
        dict(permission_set_hash="short"),
        dict(state="x"),
    ):
        base = dict(
            role_id=row.id,
            revision=99,
            display_name="x",
            permission_set_hash="0" * 64,
            state="active",
            change_kind="synced",
        )
        refused(
            rbac_db,
            lambda kw=kw, base=base: rbac_db.add(RbacRoleRevision(**{**base, **kw})),
        )


# ── permissions ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "kw",
    [
        dict(key="a.b"),
        dict(key="A.b.c", module="A"),
        dict(scope_kind="galaxy"),
        dict(sensitivity="secret"),
        dict(status="gone"),
        dict(status="retired"),  # retired needs retired_at
        dict(scope_kind="platform", delegable_to_org_roles=True),
        dict(description=""),
        dict(replaced_by="t.a.b"),  # self
        dict(module="other"),  # key must equal module.resource.action
    ],
)
def test_permission_constraints(rbac_db, kw):
    base = dict(
        key="t.a.b",
        module="t",
        resource="a",
        action="b",
        description="d",
        scope_kind="organization",
        sensitivity="normal",
        delegable_to_org_roles=True,
        continuity=False,
        status="active",
    )
    refused(rbac_db, lambda: rbac_db.add(RbacPermission(**{**base, **kw})))


def test_a_permission_key_is_not_changeable_once_referenced(rbac_db):
    sync(
        rbac_db,
        [
            source(
                "example", decl("example.a.read", default_grants=("platform.viewer",))
            )
        ],
    )
    refused(
        rbac_db,
        lambda: rbac_db.execute(
            text(
                "UPDATE rbac_permissions SET key = 'example.a.write', action = 'write' WHERE key = 'example.a.read'"
            )
        ),
    )


# ── grants ───────────────────────────────────────────────────────────────────


def test_an_organisation_role_cannot_hold_a_platform_scope_or_non_delegable_permission(
    rbac_db,
):
    sync(
        rbac_db,
        [
            source(
                "example",
                decl("example.a.read"),
                decl("example.b.admin", scope_kind="platform"),
                decl("example.c.danger", delegable_to_org_roles=False),
            )
        ],
    )
    viewer = role(rbac_db, "platform.viewer")
    grant(rbac_db, viewer, "example.a.read")
    refused(
        rbac_db,
        lambda: grant(rbac_db, viewer, "example.b.admin"),
        "organisation-scope role",
    )
    refused(
        rbac_db,
        lambda: grant(rbac_db, viewer, "example.c.danger"),
        "organisation-scope role",
    )
    # a platform-scope role may hold them: sync already materialised both for it
    held = {
        r.permission_key
        for r in rbac_db.query(RbacRolePermission).filter_by(
            role_id=role(rbac_db, "platform.superadmin").id
        )
    }
    assert {"example.b.admin", "example.c.danger"} <= held


def test_a_retired_permission_cannot_be_granted(rbac_db):
    sync(rbac_db, [source("example", decl("example.a.read"))])
    row = rbac_db.get(RbacPermission, "example.a.read")
    row.status = "retired"
    row.retired_at = NOW()
    rbac_db.flush()
    refused(
        rbac_db,
        lambda: grant(rbac_db, role(rbac_db, "platform.viewer"), "example.a.read"),
        "retired",
    )


# ── assignments ──────────────────────────────────────────────────────────────


def test_an_assignment_is_history_it_is_revoked_never_rewritten_or_restored(rbac_db):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    row = assign(rbac_db, user, role(rbac_db, "platform.viewer"))
    assert row.revoked_at is None
    row.revoked_at, row.revoked_by, row.revoke_reason = NOW(), "admin", "manual"
    rbac_db.flush()
    # the row is still there: the table is the history
    assert rbac_db.query(RbacUserRole).filter_by(user_id=user.id).count() == 1

    def restore():
        row.revoked_at, row.revoke_reason = None, None

    refused(rbac_db, restore)
    rbac_db.refresh(row)  # the refused restore left the row revoked
    assert row.revoked_at is not None

    def change_reason():
        row.revoke_reason = "migrated"

    refused(rbac_db, change_reason, "revoked assignment")


@pytest.mark.parametrize(
    "column,value",
    [
        ("user_id", "someone-else"),
        ("scope_type", "platform"),
        ("granted_by", "forged"),
        ("expires_at", NOW() + timedelta(days=9)),
        ("granted_at", datetime(2020, 1, 1, tzinfo=timezone.utc)),
    ],
)
def test_an_assignments_identity_columns_cannot_change(rbac_db, column, value):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    row = assign(rbac_db, user, role(rbac_db, "platform.viewer"))
    refused(rbac_db, lambda: setattr(row, column, value))


def test_a_revocation_needs_a_reason_and_a_reason_needs_a_revocation(rbac_db):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    row = assign(rbac_db, user, role(rbac_db, "platform.viewer"))
    refused(rbac_db, lambda: setattr(row, "revoked_at", NOW()))
    refused(rbac_db, lambda: setattr(row, "revoke_reason", "manual"))
    refused(
        rbac_db,
        lambda: (
            setattr(row, "revoked_at", NOW()),
            setattr(row, "revoke_reason", "whim"),
        ),
    )


def test_a_user_can_hold_several_roles(rbac_db):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    for key in ("platform.viewer", "platform.analyst", "platform.scanner"):
        assign(rbac_db, user, role(rbac_db, key))
    extra = custom_org_role(rbac_db, org, "extra", "Extra")
    assign(rbac_db, user, extra)
    live = (
        rbac_db.query(RbacUserRole).filter_by(user_id=user.id, revoked_at=None).count()
    )
    assert live == 4


def test_one_live_assignment_per_user_role_and_scope_but_history_may_repeat(rbac_db):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    viewer = role(rbac_db, "platform.viewer")
    first = assign(rbac_db, user, viewer)
    refused(rbac_db, lambda: assign(rbac_db, user, viewer))
    first.revoked_at, first.revoke_reason = NOW(), "manual"
    rbac_db.flush()
    assert assign(rbac_db, user, viewer)
    assert rbac_db.query(RbacUserRole).filter_by(user_id=user.id).count() == 2


def test_a_role_must_be_assigned_at_the_scope_it_declares(rbac_db):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    refused(
        rbac_db,
        lambda: assign(rbac_db, user, role(rbac_db, "platform.viewer"), "platform"),
        "assignable at organization scope",
    )
    refused(
        rbac_db,
        lambda: assign(
            rbac_db, user, role(rbac_db, "platform.superadmin"), "organization", org.id
        ),
        "assignable at platform scope",
    )


def test_a_platform_assignment_names_no_organisation(rbac_db):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    refused(
        rbac_db,
        lambda: assign(
            rbac_db, user, role(rbac_db, "platform.superadmin"), "platform", org.id
        ),
    )
    assert assign(rbac_db, user, role(rbac_db, "platform.superadmin"))


def test_an_organisation_assignment_must_be_in_the_users_own_organisation(rbac_db):
    a, b = make_org(rbac_db), make_org(rbac_db)
    user = make_user(rbac_db, a)
    refused(
        rbac_db,
        lambda: assign(
            rbac_db, user, role(rbac_db, "platform.viewer"), "organization", b.id
        ),
        "user's own organisation",
    )


def test_an_organisation_custom_role_cannot_be_assigned_outside_its_organisation(
    rbac_db,
):
    a, b = make_org(rbac_db), make_org(rbac_db)
    custom = custom_org_role(rbac_db, a, "lead", "Lead")
    user_b = make_user(rbac_db, b)
    refused(
        rbac_db,
        lambda: assign(rbac_db, user_b, custom, "organization", b.id),
        "outside its organisation",
    )
    assert assign(rbac_db, make_user(rbac_db, a), custom)


@pytest.mark.parametrize("state", ["retiring", "retired"])
def test_a_retiring_or_retired_role_cannot_be_assigned(rbac_db, state):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    custom = custom_org_role(rbac_db, org, "lead", "Lead")
    for step in ("retiring", "retired")[: 1 if state == "retiring" else 2]:
        set_state(custom, step)
        rbac_db.flush()
    refused(rbac_db, lambda: assign(rbac_db, user, custom), "cannot be assigned")


def test_assignments_survive_their_roles_retirement_as_history(rbac_db):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    custom = custom_org_role(rbac_db, org, "lead", "Lead")
    row = assign(rbac_db, user, custom)
    set_state(custom, "retiring")
    rbac_db.flush()
    row.revoked_at, row.revoked_by, row.revoke_reason = NOW(), "admin", "role_retired"
    rbac_db.flush()
    set_state(custom, "retired")
    rbac_db.flush()
    kept = rbac_db.query(RbacUserRole).filter_by(user_id=user.id).one()
    assert kept.revoke_reason == "role_retired" and kept.role_id == custom.id


def test_the_users_and_organisations_an_assignment_references_cannot_be_deleted(
    rbac_db,
):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    assign(rbac_db, user, role(rbac_db, "platform.viewer"))
    refused(
        rbac_db,
        lambda: rbac_db.execute(
            text("DELETE FROM users WHERE id = :i"), {"i": user.id}
        ),
    )
    refused(
        rbac_db,
        lambda: rbac_db.execute(
            text("DELETE FROM organizations WHERE id = :i"), {"i": org.id}
        ),
    )


def test_an_assignment_expiry_must_be_after_the_grant(rbac_db):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    row = RbacUserRole(
        user_id=user.id,
        role_id=role(rbac_db, "platform.viewer").id,
        scope_type="organization",
        scope_org_id=org.id,
        granted_at=NOW(),
        expires_at=NOW() - timedelta(days=1),
    )
    refused(rbac_db, lambda: rbac_db.add(row))


# ── default roles ────────────────────────────────────────────────────────────


def test_default_role_rejects_inactive_and_platform_scope_roles(rbac_db):
    ensure_system_roles(rbac_db)
    rbac_db.query(RbacDefaultRole).delete()
    rbac_db.flush()
    refused(
        rbac_db,
        lambda: rbac_db.add(
            RbacDefaultRole(
                purpose="self_registration",
                role_id=role(rbac_db, "platform.superadmin").id,
            )
        ),
        "within an organisation",
    )
    custom = custom_org_role(rbac_db, make_org(rbac_db), "d", "D")
    set_state(custom, "retiring")
    rbac_db.flush()
    refused(
        rbac_db,
        lambda: rbac_db.add(
            RbacDefaultRole(purpose="self_registration", role_id=custom.id)
        ),
        "must be active",
    )


def test_default_role_rejects_a_role_holding_a_continuity_or_non_delegable_permission(
    rbac_db,
):
    sync(
        rbac_db,
        [
            source(
                "platform",
                c.PermissionDecl(
                    key=c.ASSIGN_ROLE_KEY,
                    description="d",
                    scope_kind="organization",
                    continuity=True,
                    default_grants=("platform.org_admin",),
                ),
            ),
            source(
                "example",
                decl("example.a.read", default_grants=("platform.viewer",)),
                decl("example.b.risky", delegable_to_org_roles=False),
            ),
        ],
    )
    rbac_db.query(RbacDefaultRole).delete()
    rbac_db.flush()
    refused(
        rbac_db,
        lambda: rbac_db.add(
            RbacDefaultRole(
                purpose="self_registration",
                role_id=role(rbac_db, "platform.org_admin").id,
            )
        ),
        "continuity",
    )
    ok = RbacDefaultRole(
        purpose="self_registration", role_id=role(rbac_db, "platform.viewer").id
    )
    rbac_db.add(ok)
    rbac_db.flush()
    # and once a role is the default, a continuity permission cannot be added to it
    refused(
        rbac_db,
        lambda: grant(rbac_db, role(rbac_db, "platform.viewer"), c.ASSIGN_ROLE_KEY),
        "default role",
    )


def test_only_a_known_purpose_can_be_configured(rbac_db):
    refused(
        rbac_db,
        lambda: rbac_db.add(
            RbacDefaultRole(
                purpose="sso_jit", role_id=role(rbac_db, "platform.viewer").id
            )
        ),
    )


# ── the temporary legacy map ─────────────────────────────────────────────────


def test_legacy_map_shapes_are_enforced(rbac_db):
    role(rbac_db, "platform.viewer")
    sync(rbac_db, [source("example", decl("example.a.read"))])
    rbac_db.query(RbacLegacyMap).delete()
    rbac_db.flush()
    rbac_db.add(
        RbacLegacyMap(
            kind="role", legacy_role_name="viewer", role_key="platform.viewer"
        )
    )
    rbac_db.add(
        RbacLegacyMap(
            kind="permission",
            legacy_resource="scans",
            legacy_action="read",
            permission_key="example.a.read",
            behaviour_change="none",
        )
    )
    rbac_db.flush()
    refused(
        rbac_db,
        lambda: rbac_db.add(RbacLegacyMap(kind="role", legacy_role_name="viewer")),
    )
    refused(
        rbac_db,
        lambda: rbac_db.add(
            RbacLegacyMap(
                kind="permission", legacy_resource="scans", legacy_action="read"
            )
        ),
    )
    refused(
        rbac_db,
        lambda: rbac_db.add(
            RbacLegacyMap(
                kind="role",
                legacy_role_name="x",
                role_key="platform.viewer",
                permission_key="example.a.read",
            )
        ),
    )
    refused(
        rbac_db,
        lambda: rbac_db.add(
            RbacLegacyMap(
                kind="role", legacy_role_name="viewer", role_key="platform.viewer"
            )
        ),
    )
    refused(
        rbac_db,
        lambda: rbac_db.add(
            RbacLegacyMap(
                kind="role", legacy_role_name="q", role_key="platform.missing"
            )
        ),
    )


def test_one_legacy_atom_may_map_to_several_keys_and_several_atoms_to_one(rbac_db):
    sync(rbac_db, [source("example", decl("example.a.read"), decl("example.a.write"))])
    rbac_db.query(RbacLegacyMap).delete()
    rbac_db.flush()
    for key in ("example.a.read", "example.a.write"):
        rbac_db.add(
            RbacLegacyMap(
                kind="permission",
                legacy_resource="x",
                legacy_action="split",
                permission_key=key,
            )
        )
    for action in ("create", "execute"):
        rbac_db.add(
            RbacLegacyMap(
                kind="permission",
                legacy_resource="y",
                legacy_action=action,
                permission_key="example.a.read",
            )
        )
    rbac_db.flush()
    assert rbac_db.query(RbacLegacyMap).count() == 4


# ── the migration describes the same schema as the models ────────────────────


def _migration():
    path = BACKEND_ROOT / "alembic" / "versions" / "a7c1e5b3d9f2_rbac_foundation.py"
    spec = importlib.util.spec_from_file_location("rbac_foundation_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _norm(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip()


def test_the_migration_trigger_sql_equals_the_models(rbac_db):
    migration = _migration()
    assert set(migration.TRIGGER_SQL) == set(rbac_tables.TRIGGER_SQL)
    for table, statements in rbac_tables.TRIGGER_SQL.items():
        assert [_norm(s) for s in migration.TRIGGER_SQL[table]] == [
            _norm(s) for s in statements
        ], table
    assert tuple(migration.TRIGGER_FUNCTIONS) == tuple(rbac_tables.TRIGGER_FUNCTIONS)


def test_the_migration_table_sql_equals_what_the_models_compile_to():
    from db.base import Base
    from sqlalchemy.dialects import postgresql
    from sqlalchemy.schema import CreateIndex, CreateTable

    migration = _migration()
    expected = []
    for name in migration.TABLES:
        table = Base.metadata.tables[name]
        expected.append(
            _norm(
                str(
                    CreateTable(table, if_not_exists=True).compile(
                        dialect=postgresql.dialect()
                    )
                )
            )
        )
        for idx in sorted(table.indexes, key=lambda i: i.name):
            expected.append(
                _norm(
                    str(
                        CreateIndex(idx, if_not_exists=True).compile(
                            dialect=postgresql.dialect()
                        )
                    )
                )
            )
    assert [_norm(s) for s in migration.TABLE_SQL] == expected


def test_the_migration_seeds_match_the_contract():
    migration = _migration()
    assert [(k, d, s, a) for k, d, _, s, a in migration.SYSTEM_ROLES] == [
        (s.key, s.display_name, s.assignable_scope, s.auto_grant_new_permissions)
        for s in c.SYSTEM_ROLE_SEEDS
    ]
    assert dict(migration.LEGACY_ROLE_NAMES) == dict(c.LEGACY_ROLE_NAMES)
    assert migration.EMPTY_SET_HASH == __import__("hashlib").sha256(b"").hexdigest()


def test_the_migration_is_audits_head_and_follows_the_previous_one():
    migration = _migration()
    assert migration.revision == "a7c1e5b3d9f2"
    assert migration.down_revision == "f3b5d7e9a1c4"
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config(str(BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    heads = set(ScriptDirectory.from_config(cfg).get_heads())
    assert "a7c1e5b3d9f2" in heads
    assert len(heads) == 3  # Audit's, policy_pro, rank — still exactly three


def test_downgrade_refuses_while_assignments_exist():
    migration = _migration()
    import inspect

    source_code = inspect.getsource(migration.downgrade)
    assert "rbac_user_roles" in source_code and "RuntimeError" in source_code
