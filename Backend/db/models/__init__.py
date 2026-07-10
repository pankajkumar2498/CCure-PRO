"""
db/models/__init__.py
─────────────────────
Exports all production-grade ORM models in dependency order.
"""

from .rbac       import Organization, Role, Permission, RolePermission
from .users      import User, RefreshTokenSession, AuditLog, PasswordResetToken
from .assets     import Asset, AssetTag, AssetNote, AssetChangeLog, MacVendorCache, ensure_mac_vendor_schema
from .scans      import Scan, ScanPhase
from .findings   import (
    Service, TLSDetail, HttpSecurityDetail,
    VulnerabilityDefinition, AssetVulnerability,
)
from .notifications import Notification
from .web_scans  import WebScan, WebAsset, WebFinding
from .amt        import AMTInventoryRecord
from .topology   import NetworkLink, ensure_topology_schema
from .compliance import (
    ComplianceFramework, ComplianceTenantFramework, ComplianceControl,
    ComplianceRule, ComplianceRuleDependency, ComplianceRuleControl,
    ComplianceRemediation, CompliancePolicy, CompliancePolicyRule,
    ComplianceScanSchedule, ComplianceScanRun, ComplianceFinding,
    ComplianceFindingHistory, ComplianceException, ComplianceScore,
    ComplianceEvidenceRetentionPolicy, ComplianceNotificationRule,
    ComplianceIntegrationConnector, ComplianceCredential,
    ComplianceRemediationRequest
)

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
    "ComplianceEvidenceRetentionPolicy",
    "ComplianceNotificationRule",
    "ComplianceIntegrationConnector",
    "ComplianceCredential",
    "ComplianceRemediationRequest",
]
