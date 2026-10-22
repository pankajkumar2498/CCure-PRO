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


# Rendering a tuple as a SQL IN list, for the CHECK constraints below. Shared
# with the credential vault's model since G2 (db/constraint_sql.py says why).
from db.constraint_sql import sql_in_list as _sql_in_list  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# compliance_rules vocabularies
#
# Widened by migration b4c5d6e7f8a9 (Phase 3). These must render
# byte-identically to the tuples in that migration: a fresh install builds the
# constraint from here and stamps head, an existing install runs the ALTER, and
# a textual difference between the two makes autogenerate report a diff that
# can never be resolved.
# ─────────────────────────────────────────────────────────────────────────────

#: The first seven are the pre-existing evidence-key rule types and are kept
#: verbatim. The rest are the Phase 3 configuration-audit vocabulary, mirroring
#: ``core.config_audit.spec.CHECK_TYPES``. The two rule kinds share several
#: names and are told apart by ``check_definition.config_check``, not by type.
RULE_CHECK_TYPES = (
    "registry",
    "file_content",
    "port_state",
    "tls_config",
    "service_status",
    "api_response",
    "command_output",
    "file",
    "directory",
    "permission",
    "service",
    "process",
    "package",
    "port",
    "config_file",
    "command",
    "security_policy",
    "privilege",
    "structured_config",
    "container",
    "scap_rule",
    "api",
    "database_query",
)

#: ``database`` and ``container`` are reserved ahead of Phases 10, 11 and 17,
#: so those need no CHECK migration on a table holding customer rules.
RULE_TARGET_PLATFORMS = (
    "windows",
    "linux",
    "network_device",
    "database",
    "container",
    "cloud",
    "any",
)

RULE_CHECK_TYPE_SQL = "check_type IN %s" % _sql_in_list(RULE_CHECK_TYPES)

#: Every theme any seeded framework uses. Extracted from the inline CHECK
#: constraint by Phase 4 so that adding one is a tuple entry rather than a
#: hand-retyped 126-value SQL string — the previous shape had every framework
#: migration rewrite the whole list, which is a transcription error waiting to
#: happen on a constraint that silently rejects a control if it loses a value.
#:
#: ``BENCHMARK`` is the generic one, added by migration c5d6e7f8a9b0. A
#: hardening benchmark has its own section numbering ("1 Account Policies",
#: "2 Local Policies") which differs per benchmark and per platform; minting a
#: theme per section would add roughly eighty values for four platforms alone
#: and more for every benchmark after them. The section travels in ``tags``.
CONTROL_THEMES = (
    "ORG",
    "PPL",
    "PHY",
    "TECH",
    "GV",
    "ID",
    "PR",
    "DE",
    "RS",
    "RC",
    "CIS_01",
    "CIS_02",
    "CIS_03",
    "CIS_04",
    "CIS_05",
    "CIS_06",
    "CIS_07",
    "CIS_08",
    "CIS_09",
    "CIS_10",
    "CIS_11",
    "CIS_12",
    "CIS_13",
    "CIS_14",
    "CIS_15",
    "CIS_16",
    "CIS_17",
    "CIS_18",
    "SOC2_CC",
    "SOC2_A",
    "SOC2_PI",
    "SOC2_C",
    "SOC2_P",
    "CERT_IR",
    "CERT_LOG",
    "CERT_AM",
    "CERT_VM",
    "CERT_AC",
    "CERT_DP",
    "PCI_01",
    "PCI_02",
    "PCI_03",
    "PCI_04",
    "PCI_05",
    "PCI_06",
    "PCI_07",
    "PCI_08",
    "PCI_09",
    "PCI_10",
    "PCI_11",
    "PCI_12",
    "DPDP_CN",
    "DPDP_PL",
    "DPDP_DR",
    "DPDP_BN",
    "DPDP_PS",
    "DPDP_GV",
    "GDPR_LT",
    "GDPR_PL",
    "GDPR_DM",
    "GDPR_AY",
    "GDPR_SL",
    "GDPR_IC",
    "GDPR_AC",
    "SP53_AC",
    "SP53_AT",
    "SP53_AU",
    "SP53_CA",
    "SP53_CM",
    "SP53_CP",
    "SP53_IA",
    "SP53_IR",
    "SP53_MA",
    "SP53_MP",
    "SP53_PE",
    "SP53_PL",
    "SP53_PM",
    "SP53_PS",
    "SP53_PT",
    "SP53_RA",
    "SP53_SA",
    "SP53_SC",
    "SP53_SI",
    "SP53_SR",
    "IEC_2_1",
    "IEC_2_3",
    "IEC_2_4",
    "FR1_IAC",
    "FR2_UC",
    "FR3_SI",
    "FR4_DC",
    "FR5_RDF",
    "FR6_TRE",
    "FR7_RA",
    "SP82_AC",
    "SP82_AU",
    "SP82_CM",
    "SP82_IA",
    "SP82_IR",
    "SP82_SC",
    "SP82_SI",
    "SP82_RA",
    "SP82_SA",
    "CIP_002",
    "CIP_003",
    "CIP_004",
    "CIP_005",
    "CIP_006",
    "CIP_007",
    "CIP_008",
    "CIP_009",
    "CIP_010",
    "CIP_011",
    "CIP_012",
    "CIP_013",
    "CIP_014",
    "NIS2_GOV",
    "NIS2_INC",
    "NIS2_BC",
    "NIS2_SUPPLY",
    "NIS2_SEC",
    "NIS2_AUDIT",
    "NIS2_HYGIENE",
    "NIS2_CRYPTO",
    "NIS2_IAM",
    "NIS2_MFA",
    "BENCHMARK",
    # ISO/IEC 27001:2022 clauses 4–10, the management-system requirements
    # (migration e9a1c3d5f7b2). A theme of their own because they are not
    # Annex A controls: they are mandatory for conformity, never selected or
    # excluded through the Statement of Applicability, and must not be scored
    # or reported as one of Annex A's four themes.
    "ISMS",
    # HIPAA Security Rule, one per section of 45 CFR Part 164 Subpart C
    # (migration f3b5d7e9a1c4): 164.308 administrative, 164.310 physical,
    # 164.312 technical, 164.314 organizational, 164.316 documentation.
    "HIPAA_ADM",
    "HIPAA_PHY",
    "HIPAA_TEC",
    "HIPAA_ORG",
    "HIPAA_DOC",
)

CONTROL_THEME_SQL = "theme IN %s" % _sql_in_list(CONTROL_THEMES)
RULE_TARGET_PLATFORM_SQL = "target_platform IN %s" % _sql_in_list(RULE_TARGET_PLATFORMS)


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
        CheckConstraint(CONTROL_THEME_SQL, name="ck_control_theme"),
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
    # 100, not 50. A shipped catalogue *numbers* its controls ("8.24"); a
    # benchmark *names* its recommendations, and SSG STIG rule ids reach 62
    # characters. Truncating to fit is not an option —
    # uq_framework_control_number is UNIQUE, so two siblings sharing a
    # 50-character prefix would collide into one row standing for two
    # different requirements. Note `id` below is also 100 and is built from
    # this value as `cct_<code>_<slug>`, so a control_number near this
    # ceiling can still overflow it; that fails loudly and rolls back the
    # whole load rather than truncating. See migration f4a5b6c7d8e9.
    control_number = Column(String(100), nullable=False)  # e.g. "8.24"
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
    )  # PCI-DSS SAQ profile tags — framework-specific, predates `profiles`
    #: Which profile(s) of this control's own framework it belongs to —
    #: ``["L1"]`` or ``["L1", "L2"]`` for a benchmark. Empty means the control
    #: is in scope whatever profile was selected, which is what every
    #: pre-Phase-4 control is. Added by migration c5d6e7f8a9b0.
    #:
    #: The generic one. `saq_profiles` expresses the same idea for PCI-DSS and
    #: is left alone because the PCI scoping queries read it; new content must
    #: use this column, which a test in tests/compliance/ pins.
    profiles = Column(JSONB, nullable=False, default=list, server_default="[]")
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
        CheckConstraint(RULE_CHECK_TYPE_SQL, name="ck_rule_check_type"),
        CheckConstraint(RULE_TARGET_PLATFORM_SQL, name="ck_rule_target_platform"),
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
        # `not_assessed` (migration d6e7f8a9b0c2): the run's scope resolved to
        # no assets, so nothing was evaluated. Distinct from `completed`, which
        # every reader takes to mean "these are the results".
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'not_assessed')",
            name="ck_run_status",
        ),
        # Scan history is always read as "this tenant's runs, newest first"
        # (`/compliance/scans`). Declared here as well as in migration
        # d3e4f5a6b7c8 so a `create_all` schema and a migrated one carry the
        # same indexes.
        Index("ix_compliance_scan_runs_tenant_created", "tenant_id", "created_at"),
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
    # When the run was requested, as opposed to when the worker picked it up.
    # A run that fails before it starts has no `started_at`, so without this
    # column a failed run had no timestamp at all and could not be ordered in
    # scan history. `run_scheduled_scans` also passed this keyword to the
    # constructor while the column did not exist, which made every scheduled
    # compliance scan raise TypeError.
    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    started_at = Column(TIMESTAMPTZ, nullable=True)
    finished_at = Column(TIMESTAMPTZ, nullable=True)
    is_finalized = Column(Boolean, nullable=False, default=False)
    # Populated when a run ends in `failed`, so the operator sees why rather
    # than a silently stalled progress spinner.
    error_message = Column(Text, nullable=True)
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
    # ISO/IEC 27001:2022 clause 6.1.3(d) requires the Statement of
    # Applicability to record, per control, the justification for including it
    # and the justification for excluding it. Neither had anywhere to live, so
    # the SoA this product exported could not be used for certification.
    justification = Column(Text, nullable=True)
    # Who owns the control and when it is next due for review — the two fields
    # an ISMS manager needs in order to run an attestation cycle at all.
    owner = Column(
        String(150),
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
            name="fk_compliance_findings_owner",
        ),
        nullable=True,
    )
    next_review_at = Column(TIMESTAMPTZ, nullable=True)
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
        CheckConstraint(CONTROL_THEME_SQL, name="ck_score_theme"),
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


# The credential store — its vocabularies and ``ComplianceCredential`` — is the
# credential vault's model since G2 (C5): db/models/credentials.py. Re-exported
# so imports from this module keep resolving to the same objects.
from db.models.credentials import (  # noqa: E402,F401
    AUTH_MATERIAL_SQL,
    AUTH_METHOD_NTLM_HASH,
    AUTH_METHOD_SQL,
    AUTH_METHODS,
    AUTH_REQUIRES_KEY,
    AUTH_REQUIRES_PASSWORD,
    ComplianceCredential,
    CREDENTIAL_TYPE_DATABASE,
    CREDENTIAL_TYPE_NETWORK_DEVICE,
    CREDENTIAL_TYPE_SNMP,
    CREDENTIAL_TYPE_SQL,
    CREDENTIAL_TYPE_SSH,
    CREDENTIAL_TYPE_WINDOWS,
    CREDENTIAL_TYPES,
    DATABASE_TRANSPORTS,
    TRANSPORT_MONGODB,
    TRANSPORT_MSSQL,
    TRANSPORT_MYSQL,
    TRANSPORT_ORACLE,
    TRANSPORT_POSTGRESQL,
    TRANSPORT_SMB,
    TRANSPORT_SQL,
    TRANSPORT_SSH,
    TRANSPORT_WINRM,
    TRANSPORTS,
    USABLE_AUTH_METHODS,
    USABLE_CREDENTIAL_TYPES,
    USABLE_TRANSPORTS,
)


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


# ─────────────────────────────────────────────────────────────────────────────
# 9. Attestation Evidence Files
# ─────────────────────────────────────────────────────────────────────────────


class ComplianceEvidenceFile(Base):
    """Uploaded audit evidence backing a manual attestation.

    `ComplianceFinding.evidence_file_ids` has referenced this concept since the
    first migration and nothing implemented it: no table, no upload route, no
    file input. For ISO 27001, where 63 of 93 Annex A controls can only be
    satisfied by attestation, the evidence document *is* the audit trail — a
    control attested with no attached policy, screenshot or signed record is
    not evidence an auditor can accept.

    Bytes live on disk under a tenant-scoped directory rather than in the
    database: evidence is routinely tens of megabytes of scanned PDF, and the
    retention policy already contemplates archiving it.
    """

    __tablename__ = "compliance_evidence_files"
    __table_args__ = (
        Index("ix_compliance_evidence_files_control", "tenant_id", "control_id"),
        # Named explicitly rather than left to `index=True` on the column.
        # SQLAlchemy would auto-name that one `ix_compliance_evidence_files_
        # tenant_id`, while migration d3e4f5a6b7c8 creates and drops
        # `ix_compliance_evidence_files_tenant` — so the two schema paths
        # disagreed. A database built by `db/migrate_production_schema.py`
        # (`create_all` from these models, which is what CI builds) then could
        # not be downgraded: `alembic downgrade -1` tried to drop an index that
        # existed under the other name. One name, declared once.
        Index("ix_compliance_evidence_files_tenant", "tenant_id"),
    )

    id = Column(String(100), primary_key=True)
    tenant_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
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
    filename = Column(String(255), nullable=False)
    content_type = Column(String(120), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    # SHA-256 of the stored bytes. An auditor's question about an evidence file
    # is whether it is the same file that was reviewed; a digest answers it.
    sha256 = Column(String(64), nullable=False)
    storage_path = Column(String(1024), nullable=False)
    uploaded_by = Column(
        String(150), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    uploaded_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
