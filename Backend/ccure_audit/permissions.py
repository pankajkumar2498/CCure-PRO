"""Native permission declarations and frozen code-managed system grants."""

from ccure_platform.api import PermissionDecl

PERMISSIONS = (
    PermissionDecl(
        key="audit.dashboard.read",
        description="View the security dashboards.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
            "platform.viewer",
        ),
    ),
    PermissionDecl(
        key="audit.scan.read",
        description="View scans, their progress and results, and the topology map.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
            "platform.viewer",
            "platform.scanner",
        ),
    ),
    PermissionDecl(
        key="audit.scan.read_all",
        description="View every user's scans in the organisation.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
            "platform.viewer",
        ),
    ),
    PermissionDecl(
        key="audit.scan.run",
        description="Start and stop scans of every kind.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
            "platform.scanner",
        ),
    ),
    PermissionDecl(
        key="audit.scan.lifecycle",
        description="Archive, recycle and restore scans.",
        scope_kind="organization",
        default_grants=("platform.org_admin",),
    ),
    PermissionDecl(
        key="audit.scan.purge",
        description="Permanently delete recycled scans.",
        scope_kind="organization",
        sensitivity="privileged",
        default_grants=("platform.org_admin",),
    ),
    PermissionDecl(
        key="audit.scan_schedule.read",
        description="View scan schedules and their runs.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
            "platform.viewer",
        ),
    ),
    PermissionDecl(
        key="audit.scan_schedule.manage",
        description="Create, edit, enable and run scan schedules.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
        ),
    ),
    PermissionDecl(
        key="audit.scan_schedule.delete",
        description="Delete scan schedules.",
        scope_kind="organization",
        default_grants=("platform.org_admin",),
    ),
    PermissionDecl(
        key="audit.scan_policy.read",
        description="View scan policies.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
            "platform.viewer",
            "platform.scanner",
        ),
    ),
    PermissionDecl(
        key="audit.scan_policy.manage",
        description="Create, edit and version scan policies.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
        ),
    ),
    PermissionDecl(
        key="audit.scan_policy.delete",
        description="Delete scan policies.",
        scope_kind="organization",
        default_grants=("platform.org_admin",),
    ),
    PermissionDecl(
        key="audit.credential.read",
        description="View stored credential profiles (never the secrets).",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
            "platform.scanner",
        ),
    ),
    PermissionDecl(
        key="audit.credential.manage",
        description="Store and edit credential profiles.",
        scope_kind="organization",
        sensitivity="privileged",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
        ),
    ),
    PermissionDecl(
        key="audit.credential.validate",
        description="Test a stored credential against a host.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
        ),
    ),
    PermissionDecl(
        key="audit.credential.delete",
        description="Delete credential profiles.",
        scope_kind="organization",
        sensitivity="privileged",
        default_grants=("platform.org_admin",),
    ),
    PermissionDecl(
        key="audit.asset.read",
        description="View the asset inventory and its details.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
            "platform.viewer",
        ),
    ),
    PermissionDecl(
        key="audit.asset.update",
        description="Edit asset metadata, tags and notes.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
        ),
    ),
    PermissionDecl(
        key="audit.asset.import_amt",
        description="Replace the organisation's AMT inventory from a file.",
        scope_kind="organization",
        default_grants=("platform.org_admin",),
    ),
    PermissionDecl(
        key="audit.finding.read",
        description="View findings and their remediation records.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
            "platform.viewer",
        ),
    ),
    PermissionDecl(
        key="audit.finding.update",
        description="Triage findings and assign or advance their remediation.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
        ),
    ),
    PermissionDecl(
        key="audit.finding.accept_risk",
        description="Accept the risk on a finding, or withdraw an acceptance.",
        scope_kind="organization",
        sensitivity="privileged",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
        ),
    ),
    PermissionDecl(
        key="audit.report.read",
        description="View and download scan reports.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
            "platform.viewer",
        ),
    ),
    PermissionDecl(
        key="audit.report.delete",
        description="Delete generated reports.",
        scope_kind="organization",
        default_grants=("platform.org_admin",),
    ),
    PermissionDecl(
        key="audit.remediation.manage_sla",
        description="Set the organisation's remediation deadlines.",
        scope_kind="organization",
        sensitivity="privileged",
        default_grants=("platform.org_admin",),
    ),
    PermissionDecl(
        key="audit.compliance.read",
        description="View compliance dashboards, frameworks and findings.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
            "platform.viewer",
        ),
    ),
    PermissionDecl(
        key="audit.compliance.scan",
        description="Run a compliance scan.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
        ),
    ),
    PermissionDecl(
        key="audit.compliance.manage_schedules",
        description="Manage recurring compliance scans.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
        ),
    ),
    PermissionDecl(
        key="audit.compliance.attest",
        description="Record manual control attestations and evidence.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
        ),
    ),
    PermissionDecl(
        key="audit.compliance.remediate",
        description="Apply or roll back remediation on compliance findings.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
        ),
    ),
    PermissionDecl(
        key="audit.compliance.manage_rules",
        description="Create and edit compliance policies.",
        scope_kind="organization",
        sensitivity="privileged",
        default_grants=("platform.org_admin",),
    ),
    PermissionDecl(
        key="audit.compliance.manage_frameworks",
        description="Install and remove compliance frameworks.",
        scope_kind="organization",
        sensitivity="privileged",
        default_grants=("platform.org_admin",),
    ),
    PermissionDecl(
        key="audit.compliance.manage_integrations",
        description="Store and delete compliance credentials.",
        scope_kind="organization",
        sensitivity="privileged",
        default_grants=("platform.org_admin",),
    ),
    PermissionDecl(
        key="audit.compliance.approve_exception",
        description="Approve or reject compliance exceptions and remediation requests.",
        scope_kind="organization",
        sensitivity="privileged",
        default_grants=("platform.org_admin",),
    ),
    PermissionDecl(
        key="audit.compliance.export_report",
        description="Export compliance reports.",
        scope_kind="organization",
        default_grants=(
            "platform.org_admin",
            "platform.analyst",
        ),
    ),
    PermissionDecl(
        key="audit.compliance.manage_shared_rules",
        description="Edit the shared compliance rule catalogue.",
        scope_kind="platform",
        delegable_to_org_roles=False,
        sensitivity="privileged",
    ),
    PermissionDecl(
        key="audit.vuln_feed.manage",
        description="Start and monitor the vulnerability-feed synchronisation.",
        scope_kind="platform",
        delegable_to_org_roles=False,
        sensitivity="privileged",
    ),
)
