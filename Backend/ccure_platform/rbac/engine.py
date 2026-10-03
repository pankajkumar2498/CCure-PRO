"""
ccure_platform/rbac/engine.py — the authorization decision, as a pure function.

``decide`` takes a principal, the grants that principal holds, the permission
catalogue and a scope, and answers ALLOW or DENY with a reason. It touches no
database and no request. Everything it needs arrives as an argument, which is
what makes it testable as a truth table and usable by any module or service.

**The engine never receives a role.** ``Grant`` has no role field, so no code
here can branch on a role's id, key or display name — a role is only a join path
the resolver walks to *find* grants. That is the property that lets a role be
renamed, retired or replaced without touching this file.

**There is no superadmin shortcut.** A principal holding every permission holds
a grant for each one; this function checks grants and nothing else.

Rules, in order (RBAC-0 §5, steps 4–8):

1. an inactive principal is denied;
2. an unknown permission key is denied, and so is a retired one; a deprecated
   one is honoured where granted and flagged;
3. a **platform-scope** permission needs a platform-scope grant;
4. an **organisation-scope** permission is checked against one *target
   organisation* — the explicitly requested one, else the resource's, else the
   principal's own (and naming two different ones is denied as ``cross_org``):

   * an organisation-scope grant applies only to its own organisation;
   * a platform-scope grant applies in the principal's own organisation, and in
     any other only with a platform-scope grant of ``ORG_SWITCH_KEY`` — holding
     a permission never reaches another tenant by itself.

Clarification of RBAC-0 §5 step 5, recorded as an RBAC-1 decision: a platform
grant works in the principal's *home* organisation without an explicit switch,
because that is what a platform administrator does every day; the switch is for
every other organisation.
"""

from __future__ import annotations

from typing import Iterable, Mapping

from ccure_platform.rbac import contract as c

Catalogue = Mapping[str, c.Permission]


def _grant_index(grants: Iterable[c.Grant]) -> dict[str, list[c.Grant]]:
    index: dict[str, list[c.Grant]] = {}
    for g in grants:
        index.setdefault(g.permission_key, []).append(g)
    return index


def _holds_platform(index: dict[str, list[c.Grant]], key: str) -> bool:
    return any(g.assignment_scope == "platform" for g in index.get(key, ()))


def _check(
    principal: c.Principal,
    index: dict[str, list[c.Grant]],
    catalogue: Catalogue,
    key: str,
    scope: c.ScopeContext,
) -> tuple[str, str | None, bool]:
    """``(reason, target_org_id, deprecated)``; reason ``allowed`` means ALLOW."""
    if not principal.active:
        return c.PRINCIPAL_INACTIVE, None, False

    perm = catalogue.get(key)
    if perm is None:
        return c.UNKNOWN_PERMISSION, None, False
    if perm.status == "retired":
        return c.RETIRED_PERMISSION, None, False
    deprecated = perm.status == "deprecated"

    held = index.get(key, ())

    if perm.scope_kind == "platform":
        if _holds_platform(index, key):
            return c.ALLOWED, None, deprecated
        reason = c.PLATFORM_SCOPE_REQUIRED if held else c.MISSING_PERMISSION
        return reason, None, deprecated

    # organisation-scope permission
    requested, resource = scope.requested_org_id, scope.resource_org_id
    if requested and resource and requested != resource:
        return c.CROSS_ORG, requested, deprecated
    target = requested or resource or principal.home_org_id
    if not target:
        return c.NO_TARGET_ORG, None, deprecated

    for g in held:
        if g.assignment_scope == "organization" and g.scope_org_id == target:
            return c.ALLOWED, target, deprecated

    if _holds_platform(index, key):
        if target == principal.home_org_id:
            return c.ALLOWED, target, deprecated
        switch = catalogue.get(c.ORG_SWITCH_KEY)
        if (
            switch is not None
            and switch.status != "retired"
            and _holds_platform(index, c.ORG_SWITCH_KEY)
        ):
            return c.ALLOWED, target, deprecated
        return c.ORG_SWITCH_REQUIRED, target, deprecated

    if held:
        # Held, but for a different organisation: say so, because it is a
        # different fact from never having been granted it.
        return c.CROSS_ORG, target, deprecated
    return c.MISSING_PERMISSION, target, deprecated


def decide(
    principal: c.Principal,
    grants: Iterable[c.Grant],
    catalogue: Catalogue,
    permission_key: str,
    scope: c.ScopeContext | None = None,
) -> c.AuthorizationDecision:
    """ALLOW or DENY ``principal`` the permission, with a reason."""
    index = _grant_index(grants)
    reason, target, deprecated = _check(
        principal, index, catalogue, permission_key, scope or c.ScopeContext()
    )
    return c.AuthorizationDecision(
        allowed=reason == c.ALLOWED,
        reason=reason,
        permission_key=permission_key,
        principal_id=principal.principal_id,
        principal_kind=principal.kind,
        target_org_id=target,
        deprecated=deprecated,
    )


def held_keys(
    principal: c.Principal,
    grants: Iterable[c.Grant],
    catalogue: Catalogue,
    org_id: str | None,
) -> frozenset[str]:
    """
    Every permission the principal is allowed in ``org_id``, using exactly the
    rules ``decide`` applies. With ``org_id`` None, the platform-scope
    permissions held. The escalation ceiling is computed from this, so a
    ceiling and a decision can never disagree.
    """
    grants = tuple(grants)
    index = _grant_index(grants)
    scope = c.ScopeContext(requested_org_id=org_id) if org_id else c.ScopeContext()
    out = set()
    for key in index:
        perm = catalogue.get(key)
        if perm is None:
            continue
        if org_id is None and perm.scope_kind != "platform":
            continue
        reason, _, _ = _check(principal, index, catalogue, key, scope)
        if reason == c.ALLOWED:
            out.add(key)
    return frozenset(out)


def platform_held_keys(
    principal: c.Principal,
    grants: Iterable[c.Grant],
    catalogue: Catalogue,
) -> frozenset[str]:
    """
    Every active permission the principal holds through a **platform-scope**
    assignment, whatever its own scope kind. This is the reach that bounds what
    a platform-scope role may be given: an actor cannot hand out a permission
    they do not hold platform-wide. (``held_keys(..., None)`` is narrower — the
    platform-scope permissions only.)
    """
    if not principal.active:
        return frozenset()
    out = set()
    for g in grants:
        perm = catalogue.get(g.permission_key)
        if (
            g.assignment_scope == "platform"
            and perm is not None
            and perm.status != "retired"
        ):
            out.add(g.permission_key)
    return frozenset(out)
