"""
Module: db.models.compliance
Purpose: SQLAlchemy ORM models for the Policy Compliance Engine.
Author:  Compliance Dev Team
"""

from db.base import TIMESTAMPTZ, Base, utcnow
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

# ─────────────────────────────────────────────────────────────────────────────
# 1. Framework Catalog & Multi-Tenancy
# ─────────────────────────────────────────────────────────────────────────────


class ComplianceFramework(Base):
    """Global security frameworks/standards catalog (e.g. ISO 27001)."""

    __tablename__ = "compliance_frameworks"
    __table_args__ = (
        UniqueConstraint(
            "code", "tenant_id", name="uq_compliance_framework_code_tenant"
        ),
    )

    id = Column(String(100), primary_key=True)  # e.g. "cfw_iso27001_2022"
    tenant_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    code = Column(String(50), nullable=False)  # e.g. "ISO27001_2022"
    name = Column(String(255), nullable=False)  # e.g. "ISO/IEC 27001:2022"
    version = Column(String(50), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    # Relationships
    tenant_frameworks = relationship(
        "ComplianceTenantFramework",
        back_populates="framework",
        cascade="all, delete-orphan",
    )
    controls = relationship(
        "ComplianceControl", back_populates="framework", cascade="all, delete-orphan"
    )
    policies = relationship(
        "CompliancePolicy", back_populates="framework", cascade="all, delete-orphan"
    )
    scan_runs = relationship(
        "ComplianceScanRun", back_populates="framework", cascade="all, delete-orphan"
    )
    scores = relationship(
        "ComplianceScore", back_populates="framework", cascade="all, delete-orphan"
    )


class ComplianceTenantFramework(Base):
    """Tenant framework installations (Marketplace states)."""

    __tablename__ = "compliance_tenant_frameworks"
    __table_args__ = (
        UniqueConstraint("tenant_id", "framework_id", name="uq_tenant_framework"),
    )

    id = Column(String(100), primary_key=True)
    tenant_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    framework_id = Column(
        String(100),
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    is_enabled = Column(Boolean, nullable=False, default=True)
    enabled_by = Column(
        String(150), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    enabled_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    # Relationships
    framework = relationship("ComplianceFramework", back_populates="tenant_frameworks")


# ─────────────────────────────────────────────────────────────────────────────
# 2. Controls, Policies & Rule Versioning
# ─────────────────────────────────────────────────────────────────────────────


class ComplianceControl(Base):
    """Granular security controls within a framework."""

    __tablename__ = "compliance_controls"
    __table_args__ = (
        UniqueConstraint(
            "framework_id", "control_number", name="uq_framework_control_number"
        ),
        CheckConstraint(
            "theme IN ('ORG', 'PPL', 'PHY', 'TECH', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC', 'CIS_01', 'CIS_02', 'CIS_03', 'CIS_04', 'CIS_05', 'CIS_06', 'CIS_07', 'CIS_08', 'CIS_09', 'CIS_10', 'CIS_11', 'CIS_12', 'CIS_13', 'CIS_14', 'CIS_15', 'CIS_16', 'CIS_17', 'CIS_18', 'SOC2_CC', 'SOC2_A', 'SOC2_PI', 'SOC2_C', 'SOC2_P', 'CERT_IR', 'CERT_LOG', 'CERT_AM', 'CERT_VM', 'CERT_AC', 'CERT_DP', 'PCI_01', 'PCI_02', 'PCI_03', 'PCI_04', 'PCI_05', 'PCI_06', 'PCI_07', 'PCI_08', 'PCI_09', 'PCI_10', 'PCI_11', 'PCI_12', 'DPDP_CN', 'DPDP_PL', 'DPDP_DR', 'DPDP_BN', 'DPDP_PS', 'DPDP_GV', 'GDPR_LT', 'GDPR_PL', 'GDPR_DM', 'GDPR_AY', 'GDPR_SL', 'GDPR_IC', 'GDPR_AC', 'SP53_AC', 'SP53_AT', 'SP53_AU', 'SP53_CA', 'SP53_CM', 'SP53_CP', 'SP53_IA', 'SP53_IR', 'SP53_MA', 'SP53_MP', 'SP53_PE', 'SP53_PL', 'SP53_PM', 'SP53_PS', 'SP53_PT', 'SP53_RA', 'SP53_SA', 'SP53_SC', 'SP53_SI', 'SP53_SR', 'IEC_2_1', 'IEC_2_3', 'IEC_2_4', 'FR1_IAC', 'FR2_UC', 'FR3_SI', 'FR4_DC', 'FR5_RDF', 'FR6_TRE', 'FR7_RA', 'SP82_AC', 'SP82_AU', 'SP82_CM', 'SP82_IA', 'SP82_IR', 'SP82_SC', 'SP82_SI', 'SP82_RA', 'SP82_SA', 'CIP_002', 'CIP_003', 'CIP_004', 'CIP_005', 'CIP_006', 'CIP_007', 'CIP_008', 'CIP_009', 'CIP_010', 'CIP_011', 'CIP_012', 'CIP_013', 'CIP_014', 'NIS2_GOV', 'NIS2_INC', 'NIS2_BC', 'NIS2_SUPPLY', 'NIS2_SEC', 'NIS2_AUDIT', 'NIS2_HYGIENE', 'NIS2_CRYPTO', 'NIS2_IAM', 'NIS2_MFA')",
            name="ck_control_theme",
        ),
        CheckConstraint(
            "scannability IN ('auto', 'semi_auto', 'manual')",
            name="ck_control_scannability",
        ),
    )

    id = Column(String(100), primary_key=True)  # e.g. "cct_iso27001_2022_8_24"
    framework_id = Column(
        String(100),
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    control_number = Column(String(50), nullable=False)  # e.g. "8.24"
    theme = Column(
        String(20), nullable=False
    )  # ORG, PPL, PHY, TECH, GV, ID, PR, DE, RS, RC, CIS_01..18, PCI_01..12, DPDP_*, GDPR_*
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    scannability = Column(String(20), nullable=False)  # auto, semi_auto, manual
    scan_module_hint = Column(String(100), nullable=True)
    crosswalk = Column(JSONB, nullable=True, default=list)
    evidence_checklist = Column(JSONB, nullable=True, default=list)
    tags = Column(JSONB, nullable=False, default=list)
    saq_profiles = Column(
        JSONB, nullable=True, default=list
    )  # PCI-DSS SAQ profile tags
    sdf_scope = Column(String(50), nullable=True)  # DPDP Act 2023 SDF scoping filter
    privacy_role = Column(
        String(50), nullable=True
    )  # GDPR Data Controller / Data Processor scoping filter

    # Relationships
    framework = relationship("ComplianceFramework", back_populates="controls")
    rule_links = relationship(
        "ComplianceRuleControl", back_populates="control", cascade="all, delete-orphan"
    )


class ComplianceRule(Base):
    """Technical checks supporting auto/semi-auto controls (Versioned & Immutable)."""

    __tablename__ = "compliance_rules"
    __table_args__ = (
        UniqueConstraint(
            "rule_family_code", "version_number", name="uq_rule_family_version"
        ),
        CheckConstraint(
            "check_type IN ('registry', 'file_content', 'port_state', 'tls_config', 'service_status', 'api_response', 'command_output')",
            name="ck_rule_check_type",
        ),
        CheckConstraint(
            "target_platform IN ('windows', 'linux', 'network_device', 'cloud', 'any')",
            name="ck_rule_target_platform",
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_rule_severity",
        ),
        CheckConstraint(
            "status IN ('draft', 'active', 'archived')", name="ck_rule_status"
        ),
    )

    id = Column(String(100), primary_key=True)
    rule_family_code = Column(String(100), nullable=False, index=True)
    version_number = Column(Integer, nullable=False, default=1)
    check_type = Column(String(50), nullable=False)
    evidence_source = Column(String(50), nullable=True)
    target_platform = Column(String(50), nullable=False)
    check_definition = Column(JSONB, nullable=False)
    severity = Column(String(20), nullable=False, default="medium")
    severity_weight = Column(Integer, nullable=False, default=5)
    tags = Column(JSONB, nullable=False, default=list)
    status = Column(String(20), nullable=False, default="draft")
    superseded_by_rule_id = Column(
        String(100),
        ForeignKey("compliance_rules.id", ondelete="SET NULL"),
        nullable=True,
    )
    remediation_id = Column(
        String(100),
        ForeignKey(
            "compliance_remediations.id",
            ondelete="SET NULL",
            use_alter=True,
            name="fk_rules_remediation",
        ),
        nullable=True,
    )

    # Relationships
    control_links = relationship(
        "ComplianceRuleControl", back_populates="rule", cascade="all, delete-orphan"
    )
    policy_links = relationship(
        "CompliancePolicyRule", back_populates="rule", cascade="all, delete-orphan"
    )
    dependencies = relationship(
        "ComplianceRuleDependency",
        foreign_keys="[ComplianceRuleDependency.rule_id]",
        back_populates="rule",
        cascade="all, delete-orphan",
    )
    remediation = relationship(
        "ComplianceRemediation", foreign_keys=[remediation_id], post_update=True
    )


class ComplianceRuleDependency(Base):
    """Check sequence constraints mapping."""

    __tablename__ = "compliance_rule_dependencies"

    rule_id = Column(
        String(100),
        ForeignKey("compliance_rules.id", ondelete="CASCADE"),
        primary_key=True,
    )
    depends_on_rule_id = Column(
        String(100),
        ForeignKey("compliance_rules.id", ondelete="CASCADE"),
        primary_key=True,
    )
    dependency_type = Column(String(50), nullable=False, default="prerequisite")

    # Relationships
    rule = relationship(
        "ComplianceRule", foreign_keys=[rule_id], back_populates="dependencies"
    )


class ComplianceRuleControl(Base):
    """Junction mapping rules to controls across frameworks."""

    __tablename__ = "compliance_rule_controls"

    rule_id = Column(
        String(100),
        ForeignKey("compliance_rules.id", ondelete="CASCADE"),
        primary_key=True,
    )
    control_id = Column(
        String(100),
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        primary_key=True,
    )

    # Relationships
    rule = relationship("ComplianceRule", back_populates="control_links")
    control = relationship("ComplianceControl", back_populates="rule_links")


class ComplianceRemediation(Base):
    """Actionable recommendations corresponding to failed checks."""

    __tablename__ = "compliance_remediations"
    __table_args__ = (
        CheckConstraint(
            "fix_type IN ('manual', 'script', 'config_template')",
            name="ck_remediation_fix_type",
        ),
    )

    id = Column(String(100), primary_key=True)
    rule_id = Column(
        String(100),
        ForeignKey("compliance_rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    recommendation_text = Column(Text, nullable=False)
    fix_type = Column(String(50), nullable=False)
    fix_command = Column(Text, nullable=True)
    fix_target_path = Column(String(512), nullable=True)
    documentation_url = Column(String(512), nullable=True)
    estimated_score_impact_pct = Column(Numeric(5, 2), nullable=True)
    requires_reboot = Column(Boolean, nullable=False, default=False)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Policies & Sub-Baselines
# ─────────────────────────────────────────────────────────────────────────────


class CompliancePolicy(Base):
    """User-defined or global baseline template baselines."""

    __tablename__ = "compliance_policies"
    __table_args__ = (
        UniqueConstraint(
            "policy_family_code", "version_number", name="uq_policy_family_version"
        ),
        CheckConstraint(
            "target_platform IN ('windows', 'linux', 'network_device', 'cloud', 'database', 'any')",
            name="ck_policy_target_platform",
        ),
        CheckConstraint(
            "status IN ('draft', 'active', 'archived')", name="ck_policy_status"
        ),
    )

    id = Column(String(100), primary_key=True)
    framework_id = Column(
        String(100),
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    policy_family_code = Column(String(100), nullable=False)
    version_number = Column(Integer, nullable=False, default=1)
    name = Column(String(255), nullable=False)
    target_platform = Column(String(50), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="draft")
    superseded_by_policy_id = Column(
        String(100),
        ForeignKey("compliance_policies.id", ondelete="SET NULL"),
        nullable=True,
    )
    tags = Column(JSONB, nullable=False, default=list)
    is_active = Column(Boolean, nullable=False, default=True)
    created_by = Column(
        String(150), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    # Relationships
    framework = relationship("ComplianceFramework", back_populates="policies")
    rule_links = relationship(
        "CompliancePolicyRule", back_populates="policy", cascade="all, delete-orphan"
    )


class CompliancePolicyRule(Base):
    """Policy mapping bridge for rule versions."""

    __tablename__ = "compliance_policy_rules"

    policy_id = Column(
        String(100),
        ForeignKey("compliance_policies.id", ondelete="CASCADE"),
        primary_key=True,
    )
    rule_id = Column(
        String(100),
        ForeignKey("compliance_rules.id", ondelete="CASCADE"),
        primary_key=True,
    )

    # Relationships
    policy = relationship("CompliancePolicy", back_populates="rule_links")
    rule = relationship("ComplianceRule", back_populates="policy_links")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Scan Scheduling & Run Audits
# ─────────────────────────────────────────────────────────────────────────────


class ComplianceScanSchedule(Base):
    """Active compliance scan scheduling configurations."""

    __tablename__ = "compliance_scan_schedules"
    __table_args__ = (
        CheckConstraint(
            "frequency IN ('daily', 'weekly', 'monthly', 'quarterly', 'continuous')",
            name="ck_schedule_frequency",
        ),
        CheckConstraint(
            "notify_on IN ('always', 'on_failure_only', 'on_score_drop')",
            name="ck_schedule_notify_on",
        ),
    )

    id = Column(String(100), primary_key=True)
    tenant_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    framework_id = Column(
        String(100),
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    policy_id = Column(
        String(100),
        ForeignKey("compliance_policies.id", ondelete="SET NULL"),
        nullable=True,
    )
    scope = Column(JSONB, nullable=False)
    frequency = Column(String(50), nullable=False)
    cron_expression = Column(String(100), nullable=True)
    notify_on = Column(String(50), nullable=False, default="always")
    notify_channels = Column(JSONB, nullable=False, default=list)
    is_active = Column(Boolean, nullable=False, default=True)
    next_run_at = Column(TIMESTAMPTZ, nullable=True)
    last_run_at = Column(TIMESTAMPTZ, nullable=True)


class ComplianceScanRun(Base):
    """Immutable audit records representing compliance execution runs."""

    __tablename__ = "compliance_scan_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')",
            name="ck_run_status",
        ),
    )

    id = Column(String(100), primary_key=True)
    tenant_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    framework_id = Column(
        String(100),
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    policy_id = Column(
        String(100),
        ForeignKey("compliance_policies.id", ondelete="SET NULL"),
        nullable=True,
    )
    schedule_id = Column(
        String(100),
        ForeignKey("compliance_scan_schedules.id", ondelete="SET NULL"),
        nullable=True,
    )
    initiated_by = Column(
        String(150), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    scope = Column(JSONB, nullable=False)
    status = Column(String(50), nullable=False, default="queued")
    started_at = Column(TIMESTAMPTZ, nullable=True)
    finished_at = Column(TIMESTAMPTZ, nullable=True)
    is_finalized = Column(Boolean, nullable=False, default=False)
    cde_scope = Column(String(50), nullable=True)  # PCI-DSS CDE scoping filter
    sdf_scope = Column(String(50), nullable=True)  # DPDP Act 2023 SDF scoping filter
    privacy_role = Column(
        String(50), nullable=True
    )  # GDPR Data Controller / Data Processor scoping filter

    # Relationships
    framework = relationship("ComplianceFramework", back_populates="scan_runs")
    findings = relationship(
        "ComplianceFinding", back_populates="scan_run", cascade="all, delete-orphan"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 5. Findings & Timeline History Log
# ─────────────────────────────────────────────────────────────────────────────


class ComplianceFinding(Base):
    """Verdict records representing current control states."""

    __tablename__ = "compliance_findings"
    __table_args__ = (
        CheckConstraint(
            "source IN ('auto_scan', 'manual_attestation')", name="ck_finding_source"
        ),
        CheckConstraint(
            "status IN ('pass', 'fail', 'not_applicable', 'manual_review', 'exception', 'remediation_applied', 'pending_reverify')",
            name="ck_finding_status",
        ),
        # Composite indexes migration k2l3m4n5o6p7 creates. Declared here too
        # because a fresh install never runs that migration — it builds from
        # Base.metadata and stamps head — so an index only the migration knows
        # about is absent on every fresh install and present on every upgraded
        # one. The single-column indexes that migration also creates are left
        # out on purpose: `index=True` on the columns below already produces an
        # equivalent index under SQLAlchemy's own name.
        Index("ix_compliance_findings_asset", "asset_id", "control_id"),
        Index("ix_compliance_findings_tenant_status", "tenant_id", "status"),
        Index("ix_compliance_findings_rule", "rule_id"),
    )

    id = Column(String(250), primary_key=True)
    scan_run_id = Column(
        String(100),
        ForeignKey("compliance_scan_runs.id", ondelete="SET NULL"),
        nullable=True,
    )
    tenant_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id = Column(
        String(200),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    control_id = Column(
        String(100),
        ForeignKey("compliance_controls.id", ondelete="RESTRICT"),
        nullable=False,
    )
    rule_id = Column(
        String(100),
        ForeignKey("compliance_rules.id", ondelete="RESTRICT"),
        nullable=True,
    )
    source = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False)
    evidence = Column(JSONB, nullable=False, default=dict)
    evidence_file_ids = Column(JSONB, nullable=False, default=list)
    attested_by = Column(
        String(150), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    remediation_applied_by = Column(
        String(150), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    remediation_applied_at = Column(TIMESTAMPTZ, nullable=True)
    first_seen = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    last_seen = Column(TIMESTAMPTZ, nullable=False, default=utcnow, index=True)
    reviewed_at = Column(TIMESTAMPTZ, nullable=True)
    cde_scope = Column(String(50), nullable=True)  # PCI-DSS CDE scoping filter
    sdf_scope = Column(String(50), nullable=True)  # DPDP Act 2023 SDF scoping filter
    privacy_role = Column(
        String(50), nullable=True
    )  # GDPR Data Controller / Data Processor scoping filter

    # Relationships
    scan_run = relationship("ComplianceScanRun", back_populates="findings")
    history = relationship(
        "ComplianceFindingHistory",
        back_populates="finding",
        cascade="all, delete-orphan",
    )


class ComplianceFindingHistory(Base):
    """Timeline history logging of control state transitions."""

    __tablename__ = "compliance_finding_history"
    __table_args__ = (
        CheckConstraint(
            "source IN ('auto_scan', 'manual_attestation', 'remediation', 'exception_granted', 'exception_expired')",
            name="ck_history_source",
        ),
    )

    id = Column(String(100), primary_key=True)
    finding_id = Column(
        String(250),
        ForeignKey("compliance_findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status = Column(String(50), nullable=False)
    changed_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    changed_by = Column(
        String(150), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    source = Column(String(50), nullable=False)
    note = Column(Text, nullable=True)

    # Relationships
    finding = relationship("ComplianceFinding", back_populates="history")


# ─────────────────────────────────────────────────────────────────────────────
# 6. Exemptions, Scores & Operations Configuration
# ─────────────────────────────────────────────────────────────────────────────


class ComplianceException(Base):
    """Tenant configuration waivers/exemptions."""

    __tablename__ = "compliance_exceptions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired')",
            name="ck_exception_status",
        ),
    )

    id = Column(String(100), primary_key=True)
    tenant_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    control_id = Column(
        String(100),
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    finding_id = Column(
        String(250),
        ForeignKey("compliance_findings.id", ondelete="SET NULL"),
        nullable=True,
    )
    reason = Column(Text, nullable=False)
    compensating_control = Column(Text, nullable=True)
    requested_by = Column(
        String(150), ForeignKey("users.id", ondelete="SET NULL"), nullable=False
    )
    approved_by = Column(
        String(150), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    status = Column(String(50), nullable=False, default="pending")
    expires_at = Column(TIMESTAMPTZ, nullable=False)


class ComplianceScore(Base):
    """Calculated compliance baseline score caching."""

    __tablename__ = "compliance_scores"
    __table_args__ = (
        CheckConstraint(
            "theme IN ('ORG', 'PPL', 'PHY', 'TECH', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC', 'CIS_01', 'CIS_02', 'CIS_03', 'CIS_04', 'CIS_05', 'CIS_06', 'CIS_07', 'CIS_08', 'CIS_09', 'CIS_10', 'CIS_11', 'CIS_12', 'CIS_13', 'CIS_14', 'CIS_15', 'CIS_16', 'CIS_17', 'CIS_18', 'SOC2_CC', 'SOC2_A', 'SOC2_PI', 'SOC2_C', 'SOC2_P', 'CERT_IR', 'CERT_LOG', 'CERT_AM', 'CERT_VM', 'CERT_AC', 'CERT_DP', 'PCI_01', 'PCI_02', 'PCI_03', 'PCI_04', 'PCI_05', 'PCI_06', 'PCI_07', 'PCI_08', 'PCI_09', 'PCI_10', 'PCI_11', 'PCI_12', 'DPDP_CN', 'DPDP_PL', 'DPDP_DR', 'DPDP_BN', 'DPDP_PS', 'DPDP_GV', 'GDPR_LT', 'GDPR_PL', 'GDPR_DM', 'GDPR_AY', 'GDPR_SL', 'GDPR_IC', 'GDPR_AC', 'SP53_AC', 'SP53_AT', 'SP53_AU', 'SP53_CA', 'SP53_CM', 'SP53_CP', 'SP53_IA', 'SP53_IR', 'SP53_MA', 'SP53_MP', 'SP53_PE', 'SP53_PL', 'SP53_PM', 'SP53_PS', 'SP53_PT', 'SP53_RA', 'SP53_SA', 'SP53_SC', 'SP53_SI', 'SP53_SR', 'IEC_2_1', 'IEC_2_3', 'IEC_2_4', 'FR1_IAC', 'FR2_UC', 'FR3_SI', 'FR4_DC', 'FR5_RDF', 'FR6_TRE', 'FR7_RA', 'SP82_AC', 'SP82_AU', 'SP82_CM', 'SP82_IA', 'SP82_IR', 'SP82_SC', 'SP82_SI', 'SP82_RA', 'SP82_SA', 'CIP_002', 'CIP_003', 'CIP_004', 'CIP_005', 'CIP_006', 'CIP_007', 'CIP_008', 'CIP_009', 'CIP_010', 'CIP_011', 'CIP_012', 'CIP_013', 'CIP_014', 'NIS2_GOV', 'NIS2_INC', 'NIS2_BC', 'NIS2_SUPPLY', 'NIS2_SEC', 'NIS2_AUDIT', 'NIS2_HYGIENE', 'NIS2_CRYPTO', 'NIS2_IAM', 'NIS2_MFA')",
            name="ck_score_theme",
        ),
        # See the note on ComplianceFinding — migration k2l3m4n5o6p7 creates
        # this composite index and nothing in the models did.
        Index("ix_compliance_scores_lookup", "tenant_id", "framework_id", "asset_id"),
    )

    id = Column(String(100), primary_key=True)
    tenant_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    framework_id = Column(
        String(100),
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_run_id = Column(
        String(100),
        ForeignKey("compliance_scan_runs.id", ondelete="SET NULL"),
        nullable=True,
    )
    asset_id = Column(
        String(200),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    theme = Column(String(30), nullable=True)
    total_controls = Column(Integer, nullable=False, default=0)
    applicable_controls = Column(Integer, nullable=False, default=0)
    pass_count = Column(Integer, nullable=False, default=0)
    fail_count = Column(Integer, nullable=False, default=0)
    na_count = Column(Integer, nullable=False, default=0)
    pending_count = Column(Integer, nullable=False, default=0)
    score_pct = Column(Numeric(5, 2), nullable=False, default=0.00)
    weighted_score_pct = Column(Numeric(5, 2), nullable=False, default=0.00)

    # Relationships
    framework = relationship("ComplianceFramework", back_populates="scores")


class ComplianceEvidenceRetentionPolicy(Base):
    """Metadata configurations checking evidence retention timelines."""

    __tablename__ = "compliance_evidence_retention_policies"

    id = Column(String(100), primary_key=True)
    tenant_id = Column(
        String(100), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True
    )
    framework_id = Column(
        String(100),
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=True,
    )
    retain_years = Column(Integer, nullable=False, default=7)
    archive_after_years = Column(Integer, nullable=True)
    encrypt_at_rest = Column(Boolean, nullable=False, default=True)
    immutable_storage = Column(Boolean, nullable=False, default=False)
    updated_by = Column(
        String(150), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)


# ─────────────────────────────────────────────────────────────────────────────
# 7. Notifications & Integrations
# ─────────────────────────────────────────────────────────────────────────────


class ComplianceIntegrationConnector(Base):
    """External notification endpoints registration."""

    __tablename__ = "compliance_integration_connectors"
    __table_args__ = (
        CheckConstraint(
            "connector_type IN ('jira', 'servicenow', 'splunk', 'webhook', 'active_directory', 'entra_id', 'edr_generic')",
            name="ck_connector_type",
        ),
    )

    id = Column(String(100), primary_key=True)
    tenant_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    connector_type = Column(String(50), nullable=False)
    config = Column(JSONB, nullable=False, default=dict)
    is_active = Column(Boolean, nullable=False, default=True)
    created_by = Column(
        String(150), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    # Relationships
    notification_rules = relationship(
        "ComplianceNotificationRule",
        back_populates="connector",
        cascade="all, delete-orphan",
    )


class ComplianceNotificationRule(Base):
    """Automated trigger configurations mapping checks to alerts."""

    __tablename__ = "compliance_notification_rules"
    __table_args__ = (
        CheckConstraint(
            "trigger_type IN ('score_below_threshold', 'control_failed', 'exception_expiring', 'schedule_failed')",
            name="ck_notif_trigger_type",
        ),
        CheckConstraint(
            "action_type IN ('notify', 'create_incident', 'create_ticket')",
            name="ck_notif_action_type",
        ),
    )

    id = Column(String(100), primary_key=True)
    tenant_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    framework_id = Column(
        String(100),
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=True,
    )
    trigger_type = Column(String(50), nullable=False)
    threshold_value = Column(Numeric(5, 2), nullable=True)
    notify_channels = Column(JSONB, nullable=False, default=list)
    action_type = Column(String(50), nullable=False, default="notify")
    integration_connector_id = Column(
        String(100),
        ForeignKey("compliance_integration_connectors.id", ondelete="SET NULL"),
        nullable=True,
    )
    is_active = Column(Boolean, nullable=False, default=True)

    # Relationships
    connector = relationship(
        "ComplianceIntegrationConnector", back_populates="notification_rules"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 8. Automated Remediation & Credentials Management
# ─────────────────────────────────────────────────────────────────────────────


class ComplianceCredential(Base):
    """Secure multi-tenant credential storage for automated scans/remediations."""

    __tablename__ = "compliance_credentials"
    __table_args__ = (
        UniqueConstraint(
            "name", "tenant_id", name="uq_compliance_credentials_name_tenant"
        ),
        CheckConstraint(
            "(auth_method = 'password' AND encrypted_password IS NOT NULL) OR "
            "(auth_method = 'key' AND encrypted_key_content IS NOT NULL)",
            name="ck_compliance_credential_auth",
        ),
        CheckConstraint(
            "auth_method IN ('password', 'key')",
            name="ck_compliance_credential_auth_method",
        ),
    )

    id = Column(String(100), primary_key=True)
    tenant_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(255), nullable=False)
    username = Column(String(150), nullable=False)
    encrypted_password = Column(Text, nullable=True)
    encrypted_key_content = Column(Text, nullable=True)
    port = Column(Integer, nullable=False, default=22)
    auth_method = Column(String(50), nullable=False, default="password")
    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)


class ComplianceRemediationRequest(Base):
    """Maker-Checker authorization queue records for script executions."""

    __tablename__ = "compliance_remediation_requests"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending_approval', 'approved', 'rejected', 'executed', 'failed')",
            name="ck_remediation_request_status",
        ),
    )

    id = Column(String(100), primary_key=True)
    tenant_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding_id = Column(
        String(250),
        ForeignKey("compliance_findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    remediation_id = Column(
        String(100),
        ForeignKey("compliance_remediations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    credential_id = Column(
        String(100),
        ForeignKey("compliance_credentials.id", ondelete="SET NULL"),
        nullable=True,
    )
    requested_by = Column(
        String(150), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_by = Column(
        String(150), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    status = Column(String(50), nullable=False, default="pending_approval")
    emergency_bypass = Column(Boolean, nullable=False, default=False)
    execution_log = Column(Text, nullable=True)
    # Temporary JIT credentials storage (encrypted, wiped on execution/rejection)
    username = Column(String(150), nullable=True)
    encrypted_password = Column(Text, nullable=True)
    encrypted_key_content = Column(Text, nullable=True)
    port = Column(Integer, nullable=True)
    auth_method = Column(String(50), nullable=True)
    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    reviewed_at = Column(TIMESTAMPTZ, nullable=True)
