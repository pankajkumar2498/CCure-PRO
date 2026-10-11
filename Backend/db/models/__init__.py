"""
db/models/__init__.py
─────────────────────
Exports all production-grade ORM models in dependency order.
"""

from .amt import AMTInventoryRecord
from .assets import (
    Asset,
    AssetChangeLog,
    AssetNote,
    AssetTag,
    MacVendorCache,
    ensure_mac_vendor_schema,
)
from .compliance import (
    ComplianceControl,
    ComplianceCredential,
    ComplianceEvidenceFile,
    ComplianceEvidenceRetentionPolicy,
    ComplianceException,
    ComplianceFinding,
    ComplianceFindingHistory,
    ComplianceFramework,
    ComplianceIntegrationConnector,
    ComplianceNotificationRule,
    CompliancePolicy,
    CompliancePolicyRule,
    ComplianceRemediation,
    ComplianceRemediationRequest,
    ComplianceRule,
    ComplianceRuleControl,
    ComplianceRuleDependency,
    ComplianceScanRun,
    ComplianceScanSchedule,
    ComplianceScore,
    ComplianceTenantFramework,
)
from .email_security import (
    DisposableDomain,
    EmailDomainRule,
    ensure_email_security_schema,
)
from .findings import (
    AssetVulnerability,
    HttpSecurityDetail,
    Service,
    TLSDetail,
    VulnerabilityDefinition,
)
from .notifications import Notification
from .rbac import Organization

# The new RBAC capability's tables (native authorization): defined in the platform's
# models and registered here so every process that builds metadata sees them.
from ccure_platform.models.platform_audit import PlatformAuditEvent  # noqa: E402
from ccure_platform.models.registration_policy import RegistrationPolicy  # noqa: E402
from ccure_platform.models.rbac_tables import (  # noqa: E402
    RbacDefaultRole,
    RbacPermission,
    RbacRole,
    RbacRolePermission,
    RbacRoleRevision,
    RbacUserRole,
)
from .scans import Scan, ScanPhase
from .scan_reports import ScanReport
from .scan_policies import ScanPolicy
from .scan_schedules import ScanSchedule, ScanScheduleRun
from .topology import NetworkLink, ensure_topology_schema
from .users import (
    AuditLog,
    EmailVerificationToken,
    PasswordResetToken,
    RefreshTokenSession,
    User,
)
from .web_scans import WebAsset, WebFinding, WebScan

__all__ = [
    # RBAC
    "Organization",
    # RBAC capability tables (native authorization)
    "RbacPermission",
    "RbacRole",
    "RbacRoleRevision",
    "RbacRolePermission",
    "RbacUserRole",
    "RbacDefaultRole",
    "PlatformAuditEvent",
    "RegistrationPolicy",
    # Users & Auth
    "User",
    "RefreshTokenSession",
    "AuditLog",
    "PasswordResetToken",
    "EmailVerificationToken",
    # Email domain screening
    "EmailDomainRule",
    "DisposableDomain",
    "ensure_email_security_schema",
    # Assets
    "Asset",
    "AssetTag",
    "AssetNote",
    "AssetChangeLog",
    "MacVendorCache",
    "ensure_mac_vendor_schema",
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
    # Web Application Scanning (DAST)
    "WebScan",
    "WebAsset",
    "WebFinding",
    # AMT Inventory
    "AMTInventoryRecord",
    # Network Topology
    "NetworkLink",
    "ensure_topology_schema",
    # Compliance Engine
    "ComplianceFramework",
    "ComplianceTenantFramework",
    "ComplianceControl",
    "ComplianceRule",
    "ComplianceRuleDependency",
    "ComplianceRuleControl",
    "ComplianceRemediation",
    "CompliancePolicy",
    "CompliancePolicyRule",
    "ComplianceScanSchedule",
    "ComplianceScanRun",
    "ComplianceFinding",
    "ComplianceFindingHistory",
    "ComplianceException",
    "ComplianceScore",
    "ComplianceEvidenceFile",
    "ComplianceEvidenceRetentionPolicy",
    "ComplianceNotificationRule",
    "ComplianceIntegrationConnector",
    "ComplianceCredential",
    "ComplianceRemediationRequest",
    # Scan scheduling (Phase 1 — gap closure)
    "ScanPolicy",
    "ScanSchedule",
    "ScanScheduleRun",
]


def __getattr__(name):
    """A submodule moved to ``ccure_platform`` and imported under its new name
    first is in ``sys.modules`` but not yet an attribute here (Phase 8.2)."""
    import sys

    module = sys.modules.get(f"{__name__}.{name}")
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return module
