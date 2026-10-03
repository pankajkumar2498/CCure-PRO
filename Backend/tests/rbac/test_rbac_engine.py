"""
RBAC-1 — the decision engine: a pure function over a principal, its grants, the
catalogue and a scope. No database. The properties that matter are structural —
the engine cannot see a role — and the truth table.
"""

from __future__ import annotations

import inspect
import itertools

import pytest

from ccure_platform.rbac import contract as c
from ccure_platform.rbac import engine, resolver
from ccure_platform.rbac.engine import decide, held_keys, platform_held_keys

ORG_A, ORG_B = "org_a", "org_b"


def perm(key, scope_kind="organization", status="active", **kw):
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
        **kw,
    )


CAT = {
    p.key: p
    for p in (
        perm("t.scan.read"),
        perm("t.scan.run"),
        perm("t.org.manage", scope_kind="platform"),
        perm("t.old.read", status="deprecated"),
        perm("t.gone.read", status="retired"),
        perm(c.ORG_SWITCH_KEY, scope_kind="platform"),
    )
}


def human(home=ORG_A, active=True):
    return c.Principal(kind="human", principal_id="u1", home_org_id=home, active=active)


def org_grant(key, org=ORG_A):
    return c.Grant(
        assignment_scope="organization", scope_org_id=org, permission_key=key
    )


def plat_grant(key):
    return c.Grant(assignment_scope="platform", permission_key=key)


def d(grants, key="t.scan.read", scope=None, principal=None):
    return decide(principal or human(), grants, CAT, key, scope)


# ── the engine cannot see a role ─────────────────────────────────────────────


def test_a_grant_carries_no_role_identity():
    assert {f for f in c.Grant.__slots__} == {
        "permission_key",
        "assignment_scope",
        "scope_org_id",
    }


def test_decide_takes_no_role_argument():
    params = set(inspect.signature(decide).parameters)
    assert params == {"principal", "grants", "catalogue", "permission_key", "scope"}
    assert not any("role" in p for p in params)


def test_the_engine_module_imports_no_database_and_names_no_role():
    import ast

    tree = ast.parse(inspect.getsource(engine))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
    assert imported <= {
        "__future__",
        "typing",
        "ccure_platform.rbac",
        "ccure_platform.rbac.contract",
    }, imported
    strings = {
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant)
        and isinstance(n.value, str)
        and len(n.value) < 40
    }
    from scripts.architecture.rbac_guardrails import FORBIDDEN_LITERALS

    assert not {s.lower() for s in strings} & FORBIDDEN_LITERALS
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not attrs & {"display_name", "role_key", "role_name"}


def test_there_is_no_superadmin_shortcut_a_grant_for_one_key_allows_only_that_key():
    grants = [plat_grant("t.org.manage")]
    assert d(grants, "t.org.manage").allowed
    assert not d(grants, "t.scan.read").allowed
    assert d(grants, "t.scan.read").reason == c.MISSING_PERMISSION


# ── truth table ──────────────────────────────────────────────────────────────


def test_org_grant_allows_in_its_own_organisation():
    out = d([org_grant("t.scan.read")])
    assert out.allowed and out.reason == c.ALLOWED and out.target_org_id == ORG_A


def test_nothing_granted_is_default_deny():
    out = d([])
    assert not out.allowed and out.reason == c.MISSING_PERMISSION


def test_a_grant_in_another_organisation_is_cross_org_not_missing():
    out = d([org_grant("t.scan.read", ORG_B)])
    assert not out.allowed and out.reason == c.CROSS_ORG


def test_naming_an_organisation_the_grant_does_not_cover_is_denied():
    out = d([org_grant("t.scan.read")], scope=c.ScopeContext(requested_org_id=ORG_B))
    assert not out.allowed and out.reason == c.CROSS_ORG
    assert out.target_org_id == ORG_B


def test_a_resource_in_another_organisation_is_denied_even_with_the_permission_at_home():
    out = d([org_grant("t.scan.read")], scope=c.ScopeContext(resource_org_id=ORG_B))
    assert not out.allowed and out.reason == c.CROSS_ORG


def test_requested_and_resource_organisations_that_differ_are_denied():
    out = d(
        [org_grant("t.scan.read"), org_grant("t.scan.read", ORG_B)],
        scope=c.ScopeContext(requested_org_id=ORG_A, resource_org_id=ORG_B),
    )
    assert not out.allowed and out.reason == c.CROSS_ORG


def test_no_target_organisation_is_denied_not_guessed():
    out = d([org_grant("t.scan.read")], principal=human(home=None))
    assert not out.allowed and out.reason == c.NO_TARGET_ORG


def test_platform_scope_permission_needs_a_platform_grant():
    assert d([plat_grant("t.org.manage")], "t.org.manage").allowed
    out = d([org_grant("t.org.manage")], "t.org.manage")
    assert not out.allowed and out.reason == c.PLATFORM_SCOPE_REQUIRED


def test_platform_grant_works_in_the_home_organisation_without_a_switch():
    out = d([plat_grant("t.scan.read")])
    assert out.allowed and out.target_org_id == ORG_A


def test_platform_grant_does_not_reach_another_organisation_without_the_switch():
    out = d([plat_grant("t.scan.read")], scope=c.ScopeContext(requested_org_id=ORG_B))
    assert not out.allowed and out.reason == c.ORG_SWITCH_REQUIRED


def test_platform_grant_reaches_another_organisation_with_the_switch():
    out = d(
        [plat_grant("t.scan.read"), plat_grant(c.ORG_SWITCH_KEY)],
        scope=c.ScopeContext(requested_org_id=ORG_B),
    )
    assert out.allowed and out.target_org_id == ORG_B


def test_the_switch_only_counts_at_platform_scope():
    out = d(
        [plat_grant("t.scan.read"), org_grant(c.ORG_SWITCH_KEY)],
        scope=c.ScopeContext(requested_org_id=ORG_B),
    )
    assert not out.allowed and out.reason == c.ORG_SWITCH_REQUIRED


def test_holding_a_permission_never_reaches_another_tenant_by_itself():
    """Principle 18: a permission existing is not access to another organisation."""
    for grants in ([org_grant("t.scan.read")], [plat_grant("t.scan.read")]):
        assert not d(grants, scope=c.ScopeContext(resource_org_id=ORG_B)).allowed


def test_unknown_permission_is_denied():
    out = d([org_grant("t.nope.read")], "t.nope.read")
    assert not out.allowed and out.reason == c.UNKNOWN_PERMISSION


def test_retired_permission_is_denied_even_if_granted():
    out = d([org_grant("t.gone.read")], "t.gone.read")
    assert not out.allowed and out.reason == c.RETIRED_PERMISSION


def test_deprecated_permission_is_honoured_and_flagged():
    out = d([org_grant("t.old.read")], "t.old.read")
    assert out.allowed and out.deprecated


def test_inactive_principal_is_denied_whatever_it_holds():
    out = d([org_grant("t.scan.read")], principal=human(active=False))
    assert not out.allowed and out.reason == c.PRINCIPAL_INACTIVE


def test_decision_reports_who_and_what():
    out = d([org_grant("t.scan.read")])
    assert (out.principal_id, out.principal_kind, out.permission_key) == (
        "u1",
        "human",
        "t.scan.read",
    )


# ── held_keys is decide, summarised ──────────────────────────────────────────

_GRANT_SETS = {
    "none": [],
    "org_a": [org_grant("t.scan.read"), org_grant("t.scan.run")],
    "org_b": [org_grant("t.scan.read", ORG_B)],
    "platform": [plat_grant("t.scan.read"), plat_grant("t.org.manage")],
    "platform+switch": [plat_grant("t.scan.read"), plat_grant(c.ORG_SWITCH_KEY)],
}


@pytest.mark.parametrize("name,org", itertools.product(_GRANT_SETS, [ORG_A, ORG_B]))
def test_held_keys_agrees_with_decide_for_every_key(name, org):
    grants = _GRANT_SETS[name]
    held = held_keys(human(), grants, CAT, org)
    for key in CAT:
        allowed = decide(
            human(), grants, CAT, key, c.ScopeContext(requested_org_id=org)
        ).allowed
        in_scope = key in {g.permission_key for g in grants}
        assert (key in held) == (allowed and in_scope), (name, org, key)


def test_platform_held_keys_is_the_platform_reach():
    assert platform_held_keys(human(), _GRANT_SETS["platform"], CAT) == {
        "t.scan.read",
        "t.org.manage",
    }
    assert platform_held_keys(human(), _GRANT_SETS["org_a"], CAT) == frozenset()
    assert (
        platform_held_keys(human(active=False), _GRANT_SETS["platform"], CAT)
        == frozenset()
    )


# ── a service principal goes through the same engine ─────────────────────────


def test_service_scopes_become_grants_in_the_one_tenant_and_nothing_else():
    svc = c.Principal(kind="service", principal_id="svc:ir", home_org_id=ORG_A)
    grants = resolver.service_grants(
        svc, ["t.scan.read", "t.unknown.read", "t.gone.read", "t.org.manage"], CAT
    )
    assert [g.permission_key for g in grants] == ["t.scan.read"]
    assert d(grants, principal=svc).allowed
    assert not d(
        grants, scope=c.ScopeContext(resource_org_id=ORG_B), principal=svc
    ).allowed
    assert not d(grants, "t.scan.run", principal=svc).allowed


def test_a_human_principal_gets_no_service_grants():
    assert resolver.service_grants(human(), ["t.scan.read"], CAT) == ()
