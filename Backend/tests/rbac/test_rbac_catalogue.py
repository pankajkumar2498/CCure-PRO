"""
RBAC-1 — the permission catalogue: generic validation, the sync, and the seed.

RBAC validates generic rules only. None of these tests names a real product's
permission: the point is that the machinery is module-agnostic, so it is
exercised with throwaway namespaces.
"""

from __future__ import annotations

import ast
import inspect

import pytest

from ccure_platform.rbac import catalogue, contract as c
from ccure_platform.rbac.catalogue import (
    CatalogueError,
    declaration_problems,
    ensure_default_roles,
    ensure_system_roles,
    sync,
    validate_declarations,
)
from ccure_platform.rbac.model import (
    RbacDefaultRole,
    RbacPermission,
    RbacRole,
    RbacRolePermission,
    RbacRoleRevision,
)
from rbac_testing import (
    decl,
    permission_rows,
    rbac_db_fixture,
    role,
    source,
)  # noqa: F401

KNOWN = {s.key: s.assignable_scope for s in c.SYSTEM_ROLE_SEEDS}


# ── grammar ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "key", ["audit.scan.read", "x.y.z", "policy.control.manage", "a1.b_2.c3"]
)
def test_valid_three_segment_keys(key):
    assert c.PERMISSION_KEY.match(key)
    assert declaration_problems(key.split(".")[0], decl(key), KNOWN) == []


@pytest.mark.parametrize(
    "key",
    [
        "audit.read",  # two segments
        "audit.scan.run.now",  # four
        "Audit.scan.read",  # case
        "audit.scan.*",  # wildcard
        "*.*.*",
        "audit..read",
        "1audit.scan.read",
        "audit.scan-x.read",
        "audit.scan.",
        "",
    ],
)
def test_invalid_keys_are_refused(key):
    problems = declaration_problems("audit", decl(key), KNOWN)
    assert problems and "three-segment" in problems[0]


@pytest.mark.parametrize(
    "key,kind",
    [
        ("platform.superadmin", "system"),
        ("custom.platform.ciso", "platform_custom"),
        ("custom.org_acme.soc_lead", "org_custom"),
        ("custom.org_a-b_c.x1", "org_custom"),
        ("superadmin", None),
        ("platform.", None),
        ("custom.acme.x", None),
        ("custom.platform", None),
        ("Platform.superadmin", None),
    ],
)
def test_role_key_grammar(key, kind):
    assert c.role_key_kind(key) == kind


def test_the_sql_grammar_matches_the_python_grammar():
    from ccure_platform.models import rbac_tables

    assert rbac_tables._PERMISSION_KEY_RE == (
        "^" + r"[a-z][a-z0-9_]*[.][a-z][a-z0-9_]*[.][a-z][a-z0-9_]*" + "$"
    )
    assert (
        c.PERMISSION_KEY.pattern
        == r"^([a-z][a-z0-9_]*)\.([a-z][a-z0-9_]*)\.([a-z][a-z0-9_]*)$"
    )


# ── declaration validation (pure) ────────────────────────────────────────────


def problems(*sources, known=KNOWN):
    return validate_declarations(list(sources), known_roles=known)


def test_a_valid_declaration_has_no_problems():
    assert not problems(source("example", decl("example.widget.read")))


def test_the_key_prefix_must_be_the_declaring_namespace():
    out = problems(source("example", decl("other.widget.read")))
    assert any("first segment must be the declaring namespace" in p for p in out)


def test_a_duplicate_key_across_sources_is_refused():
    out = problems(
        source("example", decl("example.widget.read"), decl("example.widget.read")),
    )
    assert any("declared by both" in p for p in out)


def test_two_sources_cannot_own_one_namespace():
    out = problems(
        source("example", decl("example.a.read"), module_key="m1"),
        source("example", decl("example.b.read"), module_key="m2"),
    )
    assert any("both own namespace" in p for p in out)


@pytest.mark.parametrize(
    "kwargs,fragment",
    [
        (dict(scope_kind="galaxy"), "scope_kind"),
        (dict(sensitivity="secret"), "sensitivity"),
        (dict(description=" "), "no description"),
        (dict(description="x" * 501), "longer than"),
        (dict(delegable_to_org_roles="yes"), "boolean"),
        (dict(continuity=True), "not a frozen continuity key"),
    ],
)
def test_invalid_metadata_is_refused(kwargs, fragment):
    d = c.PermissionDecl(
        key="example.widget.read",
        **{"description": "d", "scope_kind": "organization", **kwargs},
    )
    out = declaration_problems("example", d, KNOWN)
    assert any(fragment in p for p in out), out


def test_a_platform_scope_permission_cannot_be_delegable():
    d = c.PermissionDecl(
        key="example.widget.admin",
        description="d",
        scope_kind="platform",
        delegable_to_org_roles=True,
    )
    assert any(
        "cannot be delegable" in p for p in declaration_problems("example", d, KNOWN)
    )


def test_a_frozen_continuity_key_must_be_flagged():
    d = c.PermissionDecl(
        key=c.ASSIGN_ROLE_KEY,
        description="d",
        scope_kind="organization",
        continuity=False,
    )
    assert any(
        "must be flagged continuity" in p
        for p in declaration_problems("platform", d, KNOWN)
    )
    ok = c.PermissionDecl(
        key=c.ASSIGN_ROLE_KEY,
        description="d",
        scope_kind="organization",
        continuity=True,
    )
    assert declaration_problems("platform", ok, KNOWN) == []


@pytest.mark.parametrize(
    "grants,fragment",
    [
        (("not.a.role",), "not a code-managed system role key"),
        (("custom.platform.ciso",), "not a code-managed system role key"),
        (("platform.nonexistent",), "does not exist"),
        (("platform.viewer", "platform.viewer"), "twice"),
    ],
)
def test_default_grants_must_name_real_system_roles(grants, fragment):
    out = declaration_problems(
        "example", decl("example.widget.read", default_grants=grants), KNOWN
    )
    assert any(fragment in p for p in out), out


def test_a_platform_scope_permission_cannot_be_granted_to_an_organisation_role():
    d = decl(
        "example.widget.admin",
        scope_kind="platform",
        default_grants=("platform.viewer",),
    )
    assert any(
        "organisation-scope role" in p
        for p in declaration_problems("example", d, KNOWN)
    )
    ok = decl(
        "example.widget.admin",
        scope_kind="platform",
        default_grants=("platform.superadmin",),
    )
    assert declaration_problems("example", ok, KNOWN) == []


def test_a_non_decl_in_a_source_is_refused():
    out = problems(
        c.ModuleDeclarations(module_key="m", namespace="example", permissions=("nope",))
    )
    assert any("not a PermissionDecl" in p for p in out)


def test_the_catalogue_module_names_no_product():
    tree = ast.parse(inspect.getsource(catalogue))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            name = getattr(node, "module", "") or ""
            assert not name.startswith(
                ("ccure_audit", "ccure_policy", "ccure_rank", "ccure_example")
            )
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and len(node.value) < 60
        ):
            assert node.value not in {"audit", "policy", "rank", "ir"}, node.value


# ── sync ─────────────────────────────────────────────────────────────────────


def test_sync_registers_permissions_with_their_parts(rbac_db):
    report = sync(
        rbac_db,
        [source("example", decl("example.widget.read", sensitivity="privileged"))],
    )
    assert report.registered == ("example.widget.read",)
    row = permission_rows(rbac_db)["example.widget.read"]
    assert (row.module, row.resource, row.action) == ("example", "widget", "read")
    assert row.sensitivity == "privileged" and row.status == "active"
    assert report.changed


def test_sync_is_idempotent(rbac_db):
    srcs = [
        source(
            "example", decl("example.widget.read", default_grants=("platform.viewer",))
        )
    ]
    sync(rbac_db, srcs)
    again = sync(rbac_db, srcs)
    assert not again.changed
    assert again.registered == again.updated == again.deprecated == ()


def test_sync_updates_changed_metadata(rbac_db):
    sync(rbac_db, [source("example", decl("example.widget.read"))])
    report = sync(
        rbac_db,
        [
            source(
                "example",
                decl(
                    "example.widget.read",
                    description="Changed",
                    sensitivity="privileged",
                ),
            )
        ],
    )
    assert report.updated == ("example.widget.read",)
    row = permission_rows(rbac_db)["example.widget.read"]
    assert row.description == "Changed" and row.sensitivity == "privileged"


def test_an_undeclared_permission_is_deprecated_never_deleted(rbac_db):
    sync(rbac_db, [source("example", decl("example.a.read"), decl("example.b.read"))])
    report = sync(rbac_db, [source("example", decl("example.a.read"))])
    assert report.deprecated == ("example.b.read",)
    rows = permission_rows(rbac_db)
    assert rows["example.b.read"].status == "deprecated"
    # and declaring it again restores it
    sync(rbac_db, [source("example", decl("example.a.read"), decl("example.b.read"))])
    assert permission_rows(rbac_db)["example.b.read"].status == "active"


def test_a_namespace_not_in_the_sync_is_left_alone(rbac_db):
    sync(
        rbac_db, [source("one", decl("one.a.read")), source("two", decl("two.a.read"))]
    )
    sync(rbac_db, [source("one", decl("one.a.read"))])
    assert permission_rows(rbac_db)["two.a.read"].status == "active"


def test_a_retired_permission_cannot_be_declared_again(rbac_db):
    sync(rbac_db, [source("example", decl("example.a.read"))])
    row = permission_rows(rbac_db)["example.a.read"]
    row.status = "retired"
    row.retired_at = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    )
    rbac_db.flush()
    with pytest.raises(CatalogueError, match="retired"):
        sync(rbac_db, [source("example", decl("example.a.read"))])


def test_an_invalid_declaration_writes_nothing(rbac_db):
    before = rbac_db.query(RbacPermission).count()
    with pytest.raises(CatalogueError) as err:
        sync(
            rbac_db,
            [
                source(
                    "example",
                    decl("example.ok.read"),
                    decl("example.bad.read", scope_kind="galaxy"),
                )
            ],
        )
    assert "scope_kind" in str(err.value)
    assert rbac_db.query(RbacPermission).count() == before


def test_every_problem_is_listed_not_just_the_first(rbac_db):
    with pytest.raises(CatalogueError) as err:
        sync(
            rbac_db,
            [
                source(
                    "example",
                    decl("other.a.read"),
                    decl("example.b.read", sensitivity="x"),
                )
            ],
        )
    assert len(err.value.problems) >= 2


def test_default_grants_are_materialised_as_rows(rbac_db):
    sync(
        rbac_db,
        [
            source(
                "example",
                decl(
                    "example.widget.read",
                    default_grants=("platform.viewer", "platform.analyst"),
                ),
                decl("example.widget.write", default_grants=("platform.analyst",)),
            )
        ],
    )

    def held(key):
        return {
            r.permission_key
            for r in rbac_db.query(RbacRolePermission).filter(
                RbacRolePermission.role_id == role(rbac_db, key).id
            )
        }

    assert held("platform.viewer") == {"example.widget.read"}
    assert held("platform.analyst") == {"example.widget.read", "example.widget.write"}
    assert held("platform.scanner") == set()


def test_a_dropped_default_grant_is_removed_from_the_code_managed_role(rbac_db):
    sync(
        rbac_db,
        [
            source(
                "example", decl("example.a.read", default_grants=("platform.viewer",))
            )
        ],
    )
    report = sync(rbac_db, [source("example", decl("example.a.read"))])
    assert report.grants_removed == {"platform.viewer": ("example.a.read",)}
    assert (
        not rbac_db.query(RbacRolePermission)
        .filter(
            RbacRolePermission.role_id == role(rbac_db, "platform.viewer").id,
            RbacRolePermission.permission_key == "example.a.read",
        )
        .count()
    )


def test_auto_grant_materialises_every_active_permission_as_rows(rbac_db):
    """The flag is read by sync, never by the engine: the result is rows."""
    report = sync(
        rbac_db,
        [
            source(
                "example",
                decl("example.a.read"),
                decl("example.b.admin", scope_kind="platform"),
            )
        ],
    )
    sa_role = role(rbac_db, "platform.superadmin")
    assert sa_role.auto_grant_new_permissions is True
    keys = {
        r.permission_key
        for r in rbac_db.query(RbacRolePermission).filter(
            RbacRolePermission.role_id == sa_role.id
        )
    }
    assert {"example.a.read", "example.b.admin"} <= keys
    assert "platform.superadmin" in report.grants_added
    # nothing else got them
    assert (
        not rbac_db.query(RbacRolePermission)
        .filter(RbacRolePermission.role_id == role(rbac_db, "platform.viewer").id)
        .count()
    )


def test_a_changed_role_gets_a_revision_with_the_new_permission_set(rbac_db):
    viewer = role(rbac_db, "platform.viewer")
    before = rbac_db.query(RbacRoleRevision).filter_by(role_id=viewer.id).count()
    sync(
        rbac_db,
        [
            source(
                "example", decl("example.a.read", default_grants=("platform.viewer",))
            )
        ],
    )
    revs = (
        rbac_db.query(RbacRoleRevision)
        .filter_by(role_id=viewer.id)
        .order_by(RbacRoleRevision.revision)
        .all()
    )
    assert len(revs) == before + 1
    assert revs[-1].change_kind == "synced"
    from ccure_platform.rbac.model import permission_set_hash

    assert revs[-1].permission_set_hash == permission_set_hash(["example.a.read"])
    assert viewer.revision == revs[-1].revision


def test_a_retired_system_role_is_skipped_reported_and_not_resurrected(rbac_db):
    viewer = role(rbac_db, "platform.viewer")
    viewer.state = "retiring"
    rbac_db.flush()
    viewer.state = "retired"
    viewer.retired_at = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    )
    rbac_db.flush()
    report = sync(
        rbac_db,
        [
            source(
                "example", decl("example.a.read", default_grants=("platform.viewer",))
            )
        ],
    )
    assert report.skipped_retired_roles == ("platform.viewer",)
    assert viewer.state == "retired"
    assert not rbac_db.query(RbacRolePermission).filter_by(role_id=viewer.id).count()
    assert any(
        e.action == "rbac.system_role.sync_skipped_retired" for e in report.events
    )
    # a fresh ensure does not recreate it either
    assert ensure_system_roles(rbac_db) == ()


def test_events_are_returned_and_only_written_when_an_organisation_is_given(rbac_db):
    srcs = [source("example", decl("example.a.read"))]
    report = sync(rbac_db, srcs)
    assert report.events and report.events_written == 0
    assert report.events[0].action == "rbac.catalogue.permission_registered"


# ── seed ─────────────────────────────────────────────────────────────────────


def test_ensure_system_roles_creates_the_five_and_never_overwrites(rbac_db):
    ensure_system_roles(rbac_db)
    keys = {r.key for r in rbac_db.query(RbacRole).filter(RbacRole.kind == "system")}
    assert keys == {s.key for s in c.SYSTEM_ROLE_SEEDS}
    sa_role = role(rbac_db, "platform.superadmin")
    sa_role.display_name = "CISO"
    rbac_db.flush()
    assert ensure_system_roles(rbac_db) == ()
    assert role(rbac_db, "platform.superadmin").display_name == "CISO"


def test_every_system_role_has_a_created_revision(rbac_db):
    ensure_system_roles(rbac_db)
    for seed in c.SYSTEM_ROLE_SEEDS:
        r = role(rbac_db, seed.key)
        rev = (
            rbac_db.query(RbacRoleRevision)
            .filter_by(role_id=r.id)
            .order_by(RbacRoleRevision.revision)
            .first()
        )
        assert rev.change_kind == "created" and rev.revision == 1


def test_the_default_role_is_configured_to_viewer_so_behaviour_is_preserved(rbac_db):
    ensure_system_roles(rbac_db)
    rbac_db.query(RbacDefaultRole).delete()
    rbac_db.flush()
    assert ensure_default_roles(rbac_db) == ("self_registration",)
    row = rbac_db.query(RbacDefaultRole).one()
    assert row.purpose == "self_registration"
    assert str(row.role_id) == str(role(rbac_db, "platform.viewer").id)
    assert ensure_default_roles(rbac_db) == ()


def test_a_continuity_permission_cannot_be_granted_to_the_default_role(rbac_db):
    ensure_system_roles(rbac_db)
    ensure_default_roles(rbac_db)
    with pytest.raises(CatalogueError, match="configured default role"):
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
                        default_grants=("platform.viewer",),
                    ),
                )
            ],
        )
