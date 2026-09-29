"""
Module: Backend/tests/test_rbac_routes
Purpose: Programmatically walks all FastAPI routes to verify RBAC protection.
Author:  pair/Senior Full-Stack Engineer
"""

from fastapi.routing import APIRoute
from main import app

# Whitelist of routes that are allowed to bypass standard login or RBAC requirements
PUBLIC_ROUTE_WHITELIST = {
    "/",
    "/auth/login",
    "/auth/register",
    "/auth/logout",
    "/auth/refresh",
    "/auth/forgot-password",
    "/auth/check-username",
    "/auth/check-email",
    "/auth/reset-password-request",
    "/auth/reset-password",
    # Necessarily unauthenticated: the caller is proving control of a mailbox
    # precisely because it cannot yet authenticate. Both are rate-limited and
    # neither discloses whether an account exists.
    #
    # That rate-limiting claim was prose here and false in the code for a long
    # time: /auth/reset-password carried no limit at all. It is asserted for
    # real in tests/security/test_rate_limiting.py now. Do not restate a
    # control in a comment without a test that fails when it goes away.
    "/auth/verify-email",
    "/auth/resend-verification",
    # The token-verification public keys (Phase 9.3). Public by design: a
    # verifier must be able to fetch them before it can check any token. It
    # serves public key material only, which tests/auth/test_token_keys.py
    # asserts, and its rate limit is asserted there too.
    "/auth/jwks.json",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/health",
    "/scan/documentation",
    "/api/health",
    "/api/version",
    "/api/pipeline-modes",
    "/api/workflow-example",
}


def _get_all_callables(dependant) -> list:
    """
    Recursively extract every dependency callable reachable from `dependant`.

    Accepts either a FastAPI ``Dependant`` or a bare callable, because the two
    callers below supply different things: ``route.dependant`` is a Dependant,
    while ``dep.dependency`` (from ``route.dependencies``) is the raw function.

    That second case used to raise ``AttributeError: 'function' object has no
    attribute 'call'``. It went unnoticed because no *non-whitelisted* route had
    ever used router- or route-level ``dependencies=[Depends(...)]`` — the only
    route that did, ``/auth/register``, is in PUBLIC_ROUTE_WHITELIST and is
    skipped before reaching here. The first route to protect itself that way
    crashed the scan instead of being checked, which is the worst outcome for a
    test whose whole job is to notice unprotected routes.
    """
    if not dependant:
        return []
    if not hasattr(dependant, "dependencies"):
        # A bare callable, e.g. Depends(require_role("superadmin")).dependency
        return [dependant]
    callables = [dependant.call] if dependant.call else []
    for sub in dependant.dependencies:
        callables.extend(_get_all_callables(sub))
    return callables


def test_rbac_routes_security():
    """
    Scans all registered FastAPI routes and asserts that each non-whitelisted route
    has at least one authentication or RBAC guard dependency.
    """
    unprotected_routes = []

    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue

        # Skip whitelisted paths
        path = route.path
        if any(path == p or path.startswith(p + "/") for p in PUBLIC_ROUTE_WHITELIST):
            continue

        # Collect all dependencies (both route-level and parameter-level)
        callables = []
        for dep in route.dependencies:
            # dep is a Depends object
            callables.extend(
                _get_all_callables(
                    dep.dependency if hasattr(dep, "dependency") else dep
                )
            )

        if route.dependant:
            callables.extend(_get_all_callables(route.dependant))

        # Check if any dependency is an auth/rbac guard
        is_protected = False
        for func in callables:
            func_name = getattr(func, "__name__", "")
            # closures from require_permission or require_role are named '_guard'
            # standard authentication dependencies are get_current_user or get_current_active_user or get_current_user_flexible
            if func_name in (
                "_guard",
                "get_current_user",
                "get_current_active_user",
                "get_current_user_flexible",
            ):
                is_protected = True
                break

        if not is_protected:
            unprotected_routes.append(f"{route.methods} {route.path}")

    # Assert that all endpoints are protected
    assert (
        not unprotected_routes
    ), f"Security Gap: Found endpoints lacking authentication/RBAC protection: {unprotected_routes}"
