"""
The platform's models, registered without any module's (B8).

Identity, tenancy, native RBAC, the platform audit ledger, the registration
policy, email-domain screening and notifications. The files here import nothing
from the application but the database layer and the legacy-name helper (layer
rule ``models-are-leaves``), and no model here has a relationship into a
module's tables (``tests/repo/test_platform_model_registry.py``).

Platform code imports its models from here, never from ``db.models``: that
registry is Audit's too, and importing it loads every Audit model with it. It
re-exports these, so module code's ``from db.models import User`` is unchanged.

Organization and User keep their established import aliases
(``db.models.rbac``, ``db.models.users``), as do notifications and email
screening (``ccure_platform/_legacy.py``). Native RBAC has six tables in
rbac_tables; platform_audit records platform-owned governance events.
"""

from .email_security import (
    DisposableDomain,
    EmailDomainRule,
    ensure_email_security_schema,
)
from .notifications import Notification
from .platform_audit import PlatformAuditEvent
from .rbac import Organization
from .rbac_tables import (
    RbacDefaultRole,
    RbacPermission,
    RbacRole,
    RbacRolePermission,
    RbacRoleRevision,
    RbacUserRole,
)
from .registration_policy import RegistrationPolicy
from .users import (
    AuditLog,
    EmailVerificationToken,
    PasswordResetToken,
    RefreshTokenSession,
    User,
)

__all__ = [
    # Tenancy
    "Organization",
    # Native RBAC
    "RbacPermission",
    "RbacRole",
    "RbacRoleRevision",
    "RbacRolePermission",
    "RbacUserRole",
    "RbacDefaultRole",
    "PlatformAuditEvent",
    "RegistrationPolicy",
    # Users and sessions
    "User",
    "RefreshTokenSession",
    "AuditLog",
    "PasswordResetToken",
    "EmailVerificationToken",
    # Email domain screening
    "EmailDomainRule",
    "DisposableDomain",
    "ensure_email_security_schema",
    # Notifications
    "Notification",
]
