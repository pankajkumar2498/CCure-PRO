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
from .rbac import Organization, Permission, Role, RolePermission
from .scans import Scan, ScanPhase
from .scan_reports import ScanReport
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
    "Role",
    "Permission",
    "RolePermission",
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
]
