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
    """Recursively extracts all dependency callable functions from a FastAPI Dependant object."""
    if not dependant:
        return []
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
