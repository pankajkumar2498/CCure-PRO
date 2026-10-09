"""
The proof module's permission catalogue (RBAC-1).

A module declares what its own capability needs as **data**, with the one
platform type — ``PermissionDecl``, from ``ccure_platform.api``. It names no RBAC
table, no RBAC engine and no role check. The platform's composition root loads
this module by the dotted name its manifest declares and hands the declarations
to RBAC; RBAC never imports this package.

``default_grants`` names code-managed system roles as seed-time data.
"""

from ccure_platform.api import PermissionDecl

PERMISSIONS = (
    PermissionDecl(
        key="example.widget.read",
        description="See the example module's widgets.",
        scope_kind="organization",
        default_grants=("platform.viewer", "platform.analyst"),
    ),
    PermissionDecl(
        key="example.widget.write",
        description="Create and change the example module's widgets.",
        scope_kind="organization",
        default_grants=("platform.analyst",),
    ),
    PermissionDecl(
        key="example.widget.purge",
        description="Permanently remove widgets.",
        scope_kind="organization",
        sensitivity="privileged",
    ),
)
