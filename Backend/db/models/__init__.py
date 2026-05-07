"""
db/models/__init__.py
─────────────────────
Exports all production-grade ORM models in dependency order.
"""

from .rbac       import Organization, Role, Permission, RolePermission
from .users      import User, RefreshTokenSession, AuditLog
from .assets     import Asset, AssetTag, AssetNote, AssetChangeLog
from .scans      import Scan, ScanPhase
from .findings   import (
    Service, TLSDetail, HttpSecurityDetail,
    VulnerabilityDefinition, AssetVulnerability,
)
from .notifications import Notification

__all__ = [
    # RBAC
    "Organization",
    "Role",
    "Permission",
    "RolePermission",
    # Users & Auth
    "User",
    "RefreshTokenSession",
    "AuditLog",
    # Assets
    "Asset",
    "AssetTag",
    "AssetNote",
    "AssetChangeLog",
    # Scans
    "Scan",
    "ScanPhase",
    # Findings
    "Service",
    "TLSDetail",
    "HttpSecurityDetail",
    "VulnerabilityDefinition",
    "AssetVulnerability",
    # Notifications
    "Notification",
]
