"""add compliance tables

Revision ID: k2l3m4n5o6p7
Revises: j1k2l3m4n5o6
Create Date: 2026-07-04 02:10:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'k2l3m4n5o6p7'
down_revision = 'j1k2l3m4n5o6'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # 1. compliance_frameworks
    op.create_table(
        'compliance_frameworks',
        sa.Column('id', sa.String(length=100), nullable=False),
        sa.Column('tenant_id', sa.String(length=100), nullable=True),
        sa.Column('code', sa.String(length=50), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('version', sa.String(length=50), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['organizations.id'], name='fk_compliance_frameworks_tenant', ondelete='CASCADE'),
        sa.UniqueConstraint('code', 'tenant_id', name='uq_compliance_framework_code_tenant')
    )
    op.create_index('ix_compliance_frameworks_tenant_id', 'compliance_frameworks', ['tenant_id'])

    # 2. compliance_tenant_frameworks
    op.create_table(
        'compliance_tenant_frameworks',
        sa.Column('id', sa.String(length=100), nullable=False),
        sa.Column('tenant_id', sa.String(length=100), nullable=False),
        sa.Column('framework_id', sa.String(length=100), nullable=False),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('enabled_by', sa.String(length=150), nullable=True),
        sa.Column('enabled_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['organizations.id'], name='fk_compliance_tenant_frameworks_tenant', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['framework_id'], ['compliance_frameworks.id'], name='fk_compliance_tenant_frameworks_fw', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['enabled_by'], ['users.id'], name='fk_compliance_tenant_frameworks_user', ondelete='SET NULL'),
        sa.UniqueConstraint('tenant_id', 'framework_id', name='uq_tenant_framework')
    )
    op.create_index('ix_compliance_tenant_frameworks_tenant_id', 'compliance_tenant_frameworks', ['tenant_id'])
    op.create_index('ix_compliance_tenant_frameworks_framework_id', 'compliance_tenant_frameworks', ['framework_id'])

    # 3. compliance_controls
    op.create_table(
        'compliance_controls',
        sa.Column('id', sa.String(length=100), nullable=False),
        sa.Column('framework_id', sa.String(length=100), nullable=False),
        sa.Column('control_number', sa.String(length=50), nullable=False),
        sa.Column('theme', sa.String(length=10), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('scannability', sa.String(length=20), nullable=False),
        sa.Column('scan_module_hint', sa.String(length=100), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['framework_id'], ['compliance_frameworks.id'], name='fk_compliance_controls_fw', ondelete='CASCADE'),
        sa.UniqueConstraint('framework_id', 'control_number', name='uq_framework_control_number'),
        sa.CheckConstraint("theme IN ('ORG', 'PPL', 'PHY', 'TECH')", name='ck_control_theme'),
        sa.CheckConstraint("scannability IN ('auto', 'semi_auto', 'manual')", name='ck_control_scannability')
    )
    op.create_index('ix_compliance_controls_fw_id', 'compliance_controls', ['framework_id'])

    # 4. compliance_rules
    op.create_table(
        'compliance_rules',
        sa.Column('id', sa.String(length=100), nullable=False),
        sa.Column('rule_family_code', sa.String(length=100), nullable=False),
        sa.Column('version_number', sa.Integer(), nullable=False, server_default=sa.text('1')),
        sa.Column('check_type', sa.String(length=50), nullable=False),
        sa.Column('evidence_source', sa.String(length=50), nullable=True),
        sa.Column('target_platform', sa.String(length=50), nullable=False),
        sa.Column('check_definition', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False, server_default=sa.text("'medium'")),
        sa.Column('severity_weight', sa.Integer(), nullable=False, server_default=sa.text('5')),
        sa.Column('tags', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column('status', sa.String(length=20), nullable=False, server_default=sa.text("'draft'")),
        sa.Column('superseded_by_rule_id', sa.String(length=100), nullable=True),
        sa.Column('remediation_id', sa.String(length=100), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['superseded_by_rule_id'], ['compliance_rules.id'], name='fk_rules_superseded', ondelete='SET NULL'),
        sa.UniqueConstraint('rule_family_code', 'version_number', name='uq_rule_family_version'),
        sa.CheckConstraint("check_type IN ('registry', 'file_content', 'port_state', 'tls_config', 'service_status', 'api_response', 'command_output')", name='ck_rule_check_type'),
        sa.CheckConstraint("target_platform IN ('windows', 'linux', 'network_device', 'cloud', 'any')", name='ck_rule_target_platform'),
        sa.CheckConstraint("severity IN ('critical', 'high', 'medium', 'low', 'info')", name='ck_rule_severity'),
        sa.CheckConstraint("status IN ('draft', 'active', 'archived')", name='ck_rule_status')
    )
    op.create_index('ix_compliance_rules_family', 'compliance_rules', ['rule_family_code'])

    # 5. compliance_rule_dependencies
    op.create_table(
        'compliance_rule_dependencies',
        sa.Column('rule_id', sa.String(length=100), nullable=False),
        sa.Column('depends_on_rule_id', sa.String(length=100), nullable=False),
        sa.Column('dependency_type', sa.String(length=50), nullable=False, server_default=sa.text("'prerequisite'")),
        sa.PrimaryKeyConstraint('rule_id', 'depends_on_rule_id'),
        sa.ForeignKeyConstraint(['rule_id'], ['compliance_rules.id'], name='fk_rule_deps_rule', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['depends_on_rule_id'], ['compliance_rules.id'], name='fk_rule_deps_dep', ondelete='CASCADE')
    )

    # 6. compliance_rule_controls
    op.create_table(
        'compliance_rule_controls',
        sa.Column('rule_id', sa.String(length=100), nullable=False),
        sa.Column('control_id', sa.String(length=100), nullable=False),
        sa.PrimaryKeyConstraint('rule_id', 'control_id'),
        sa.ForeignKeyConstraint(['rule_id'], ['compliance_rules.id'], name='fk_rule_controls_rule', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['control_id'], ['compliance_controls.id'], name='fk_rule_controls_control', ondelete='CASCADE')
    )

    # 7. compliance_remediations
    op.create_table(
        'compliance_remediations',
        sa.Column('id', sa.String(length=100), nullable=False),
        sa.Column('rule_id', sa.String(length=100), nullable=False),
        sa.Column('recommendation_text', sa.Text(), nullable=False),
        sa.Column('fix_type', sa.String(length=50), nullable=False),
        sa.Column('fix_command', sa.Text(), nullable=True),
        sa.Column('fix_target_path', sa.String(length=512), nullable=True),
        sa.Column('documentation_url', sa.String(length=512), nullable=True),
        sa.Column('estimated_score_impact_pct', sa.Numeric(precision=5, scale=2), nullable=True),
        sa.Column('requires_reboot', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['rule_id'], ['compliance_rules.id'], name='fk_remediations_rule', ondelete='CASCADE'),
        sa.CheckConstraint("fix_type IN ('manual', 'script', 'config_template')", name='ck_remediation_fix_type')
    )

    # Add the foreign key constraint on compliance_rules.remediation_id
    op.create_foreign_key(
        'fk_rules_remediation',
        'compliance_rules', 'compliance_remediations',
        ['remediation_id'], ['id'],
        ondelete='SET NULL'
    )

    # 8. compliance_policies
    op.create_table(
        'compliance_policies',
        sa.Column('id', sa.String(length=100), nullable=False),
        sa.Column('framework_id', sa.String(length=100), nullable=False),
        sa.Column('tenant_id', sa.String(length=100), nullable=True),
        sa.Column('policy_family_code', sa.String(length=100), nullable=False),
        sa.Column('version_number', sa.Integer(), nullable=False, server_default=sa.text('1')),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('target_platform', sa.String(length=50), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False, server_default=sa.text("'draft'")),
        sa.Column('superseded_by_policy_id', sa.String(length=100), nullable=True),
        sa.Column('tags', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_by', sa.String(length=150), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['framework_id'], ['compliance_frameworks.id'], name='fk_policies_framework', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['tenant_id'], ['organizations.id'], name='fk_policies_tenant', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['superseded_by_policy_id'], ['compliance_policies.id'], name='fk_policies_superseded', ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], name='fk_policies_creator', ondelete='SET NULL'),
        sa.UniqueConstraint('policy_family_code', 'version_number', name='uq_policy_family_version'),
        sa.CheckConstraint("target_platform IN ('windows', 'linux', 'network_device', 'cloud', 'database', 'any')", name='ck_policy_target_platform'),
        sa.CheckConstraint("status IN ('draft', 'active', 'archived')", name='ck_policy_status')
    )
    op.create_index('ix_compliance_policies_fw', 'compliance_policies', ['framework_id'])
    op.create_index('ix_compliance_policies_tenant', 'compliance_policies', ['tenant_id'])

    # 9. compliance_policy_rules
    op.create_table(
        'compliance_policy_rules',
        sa.Column('policy_id', sa.String(length=100), nullable=False),
        sa.Column('rule_id', sa.String(length=100), nullable=False),
        sa.PrimaryKeyConstraint('policy_id', 'rule_id'),
        sa.ForeignKeyConstraint(['policy_id'], ['compliance_policies.id'], name='fk_policy_rules_policy', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['rule_id'], ['compliance_rules.id'], name='fk_policy_rules_rule', ondelete='CASCADE')
    )

    # 10. compliance_scan_schedules
    op.create_table(
        'compliance_scan_schedules',
        sa.Column('id', sa.String(length=100), nullable=False),
        sa.Column('tenant_id', sa.String(length=100), nullable=False),
        sa.Column('framework_id', sa.String(length=100), nullable=False),
        sa.Column('policy_id', sa.String(length=100), nullable=True),
        sa.Column('scope', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('frequency', sa.String(length=50), nullable=False),
        sa.Column('cron_expression', sa.String(length=100), nullable=True),
        sa.Column('notify_on', sa.String(length=50), nullable=False, server_default=sa.text("'always'")),
        sa.Column('notify_channels', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['organizations.id'], name='fk_scan_schedules_tenant', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['framework_id'], ['compliance_frameworks.id'], name='fk_scan_schedules_framework', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['policy_id'], ['compliance_policies.id'], name='fk_scan_schedules_policy', ondelete='SET NULL'),
        sa.CheckConstraint("frequency IN ('daily', 'weekly', 'monthly', 'quarterly', 'continuous')", name='ck_schedule_frequency'),
        sa.CheckConstraint("notify_on IN ('always', 'on_failure_only', 'on_score_drop')", name='ck_schedule_notify_on')
    )
    op.create_index('ix_compliance_scan_schedules_tenant', 'compliance_scan_schedules', ['tenant_id'])

    # 11. compliance_scan_runs
    op.create_table(
        'compliance_scan_runs',
        sa.Column('id', sa.String(length=100), nullable=False),
        sa.Column('tenant_id', sa.String(length=100), nullable=False),
        sa.Column('framework_id', sa.String(length=100), nullable=False),
        sa.Column('policy_id', sa.String(length=100), nullable=True),
        sa.Column('schedule_id', sa.String(length=100), nullable=True),
        sa.Column('initiated_by', sa.String(length=150), nullable=True),
        sa.Column('scope', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default=sa.text("'queued'")),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_finalized', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['organizations.id'], name='fk_scan_runs_tenant', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['framework_id'], ['compliance_frameworks.id'], name='fk_scan_runs_framework', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['policy_id'], ['compliance_policies.id'], name='fk_scan_runs_policy', ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['schedule_id'], ['compliance_scan_schedules.id'], name='fk_scan_runs_schedule', ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['initiated_by'], ['users.id'], name='fk_scan_runs_initiator', ondelete='SET NULL'),
        sa.CheckConstraint("status IN ('queued', 'running', 'completed', 'failed')", name='ck_run_status')
    )
    op.create_index('ix_compliance_scan_runs_tenant', 'compliance_scan_runs', ['tenant_id'])

    # 12. compliance_findings
    op.create_table(
        'compliance_findings',
        sa.Column('id', sa.String(length=250), nullable=False),
        sa.Column('scan_run_id', sa.String(length=100), nullable=True),
        sa.Column('tenant_id', sa.String(length=100), nullable=False),
        sa.Column('asset_id', sa.String(length=200), nullable=True),
        sa.Column('control_id', sa.String(length=100), nullable=False),
        sa.Column('rule_id', sa.String(length=100), nullable=True),
        sa.Column('source', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column('evidence_file_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column('attested_by', sa.String(length=150), nullable=True),
        sa.Column('remediation_applied_by', sa.String(length=150), nullable=True),
        sa.Column('remediation_applied_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['scan_run_id'], ['compliance_scan_runs.id'], name='fk_findings_run', ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['tenant_id'], ['organizations.id'], name='fk_findings_tenant', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], name='fk_findings_asset', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['control_id'], ['compliance_controls.id'], name='fk_findings_control', ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['rule_id'], ['compliance_rules.id'], name='fk_findings_rule', ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['attested_by'], ['users.id'], name='fk_findings_attestor', ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['remediation_applied_by'], ['users.id'], name='fk_findings_remediator', ondelete='SET NULL'),
        sa.CheckConstraint("source IN ('auto_scan', 'manual_attestation')", name='ck_finding_source'),
        sa.CheckConstraint("status IN ('pass', 'fail', 'not_applicable', 'manual_review', 'exception', 'remediation_applied', 'pending_reverify')", name='ck_finding_status')
    )
    op.create_index('ix_compliance_findings_asset', 'compliance_findings', ['asset_id', 'control_id'])
    op.create_index('ix_compliance_findings_tenant_status', 'compliance_findings', ['tenant_id', 'status'])
    op.create_index('ix_compliance_findings_rule', 'compliance_findings', ['rule_id'])

    # 13. compliance_finding_history
    op.create_table(
        'compliance_finding_history',
        sa.Column('id', sa.String(length=100), nullable=False),
        sa.Column('finding_id', sa.String(length=250), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('changed_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('changed_by', sa.String(length=150), nullable=True),
        sa.Column('source', sa.String(length=50), nullable=False),
        sa.Column('note', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['finding_id'], ['compliance_findings.id'], name='fk_history_finding', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['changed_by'], ['users.id'], name='fk_history_user', ondelete='SET NULL'),
        sa.CheckConstraint("source IN ('auto_scan', 'manual_attestation', 'remediation', 'exception_granted', 'exception_expired')", name='ck_history_source')
    )
    op.create_index('ix_compliance_finding_history_finding', 'compliance_finding_history', ['finding_id'])

    # 14. compliance_exceptions
    op.create_table(
        'compliance_exceptions',
        sa.Column('id', sa.String(length=100), nullable=False),
        sa.Column('tenant_id', sa.String(length=100), nullable=False),
        sa.Column('control_id', sa.String(length=100), nullable=False),
        sa.Column('finding_id', sa.String(length=250), nullable=True),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('compensating_control', sa.Text(), nullable=True),
        sa.Column('requested_by', sa.String(length=150), nullable=False),
        sa.Column('approved_by', sa.String(length=150), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, server_default=sa.text("'pending'")),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['organizations.id'], name='fk_exceptions_tenant', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['control_id'], ['compliance_controls.id'], name='fk_exceptions_control', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['finding_id'], ['compliance_findings.id'], name='fk_exceptions_finding', ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['requested_by'], ['users.id'], name='fk_exceptions_requester', ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['approved_by'], ['users.id'], name='fk_exceptions_approver', ondelete='SET NULL'),
        sa.CheckConstraint("status IN ('pending', 'approved', 'rejected', 'expired')", name='ck_exception_status')
    )
    op.create_index('ix_compliance_exceptions_tenant', 'compliance_exceptions', ['tenant_id'])

    # 15. compliance_scores
    op.create_table(
        'compliance_scores',
        sa.Column('id', sa.String(length=100), nullable=False),
        sa.Column('tenant_id', sa.String(length=100), nullable=False),
        sa.Column('framework_id', sa.String(length=100), nullable=False),
        sa.Column('scan_run_id', sa.String(length=100), nullable=True),
        sa.Column('asset_id', sa.String(length=200), nullable=True),
        sa.Column('theme', sa.String(length=10), nullable=True),
        sa.Column('total_controls', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('applicable_controls', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('pass_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('fail_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('na_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('pending_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('score_pct', sa.Numeric(precision=5, scale=2), nullable=False, server_default=sa.text('0.00')),
        sa.Column('weighted_score_pct', sa.Numeric(precision=5, scale=2), nullable=False, server_default=sa.text('0.00')),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['organizations.id'], name='fk_scores_tenant', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['framework_id'], ['compliance_frameworks.id'], name='fk_scores_framework', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_run_id'], ['compliance_scan_runs.id'], name='fk_scores_run', ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], name='fk_scores_asset', ondelete='CASCADE'),
        sa.CheckConstraint("theme IN ('ORG', 'PPL', 'PHY', 'TECH')", name='ck_score_theme')
    )
    op.create_index('ix_compliance_scores_lookup', 'compliance_scores', ['tenant_id', 'framework_id', 'asset_id'])

    # 16. compliance_evidence_retention_policies
    op.create_table(
        'compliance_evidence_retention_policies',
        sa.Column('id', sa.String(length=100), nullable=False),
        sa.Column('tenant_id', sa.String(length=100), nullable=True),
        sa.Column('framework_id', sa.String(length=100), nullable=True),
        sa.Column('retain_years', sa.Integer(), nullable=False, server_default=sa.text('7')),
        sa.Column('archive_after_years', sa.Integer(), nullable=True),
        sa.Column('encrypt_at_rest', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('immutable_storage', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('updated_by', sa.String(length=150), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['organizations.id'], name='fk_retention_tenant', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['framework_id'], ['compliance_frameworks.id'], name='fk_retention_framework', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['updated_by'], ['users.id'], name='fk_retention_user', ondelete='SET NULL')
    )

    # 17. compliance_integration_connectors
    op.create_table(
        'compliance_integration_connectors',
        sa.Column('id', sa.String(length=100), nullable=False),
        sa.Column('tenant_id', sa.String(length=100), nullable=False),
        sa.Column('connector_type', sa.String(length=50), nullable=False),
        sa.Column('config', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_by', sa.String(length=150), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['organizations.id'], name='fk_connectors_tenant', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], name='fk_connectors_creator', ondelete='SET NULL'),
        sa.CheckConstraint("connector_type IN ('jira', 'servicenow', 'splunk', 'webhook', 'active_directory', 'entra_id', 'edr_generic')", name='ck_connector_type')
    )
    op.create_index('ix_compliance_integration_connectors_tenant', 'compliance_integration_connectors', ['tenant_id'])

    # 18. compliance_notification_rules
    op.create_table(
        'compliance_notification_rules',
        sa.Column('id', sa.String(length=100), nullable=False),
        sa.Column('tenant_id', sa.String(length=100), nullable=False),
        sa.Column('framework_id', sa.String(length=100), nullable=True),
        sa.Column('trigger_type', sa.String(length=50), nullable=False),
        sa.Column('threshold_value', sa.Numeric(precision=5, scale=2), nullable=True),
        sa.Column('notify_channels', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column('action_type', sa.String(length=50), nullable=False, server_default=sa.text("'notify'")),
        sa.Column('integration_connector_id', sa.String(length=100), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['organizations.id'], name='fk_notification_rules_tenant', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['framework_id'], ['compliance_frameworks.id'], name='fk_notification_rules_framework', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['integration_connector_id'], ['compliance_integration_connectors.id'], name='fk_notification_rules_connector', ondelete='SET NULL'),
        sa.CheckConstraint("trigger_type IN ('score_below_threshold', 'control_failed', 'exception_expiring', 'schedule_failed')", name='ck_notif_trigger_type'),
        sa.CheckConstraint("action_type IN ('notify', 'create_incident', 'create_ticket')", name='ck_notif_action_type')
    )
    op.create_index('ix_compliance_notification_rules_tenant', 'compliance_notification_rules', ['tenant_id'])

def downgrade() -> None:
    # Drop in reverse order
    op.drop_index('ix_compliance_notification_rules_tenant', table_name='compliance_notification_rules')
    op.drop_table('compliance_notification_rules')

    op.drop_index('ix_compliance_integration_connectors_tenant', table_name='compliance_integration_connectors')
    op.drop_table('compliance_integration_connectors')

    op.drop_table('compliance_evidence_retention_policies')

    op.drop_index('ix_compliance_scores_lookup', table_name='compliance_scores')
    op.drop_table('compliance_scores')

    op.drop_index('ix_compliance_exceptions_tenant', table_name='compliance_exceptions')
    op.drop_table('compliance_exceptions')

    op.drop_index('ix_compliance_finding_history_finding', table_name='compliance_finding_history')
    op.drop_table('compliance_finding_history')

    op.drop_index('ix_compliance_findings_rule', table_name='compliance_findings')
    op.drop_index('ix_compliance_findings_tenant_status', table_name='compliance_findings')
    op.drop_index('ix_compliance_findings_asset', table_name='compliance_findings')
    op.drop_table('compliance_findings')

    op.drop_index('ix_compliance_scan_runs_tenant', table_name='compliance_scan_runs')
    op.drop_table('compliance_scan_runs')

    op.drop_index('ix_compliance_scan_schedules_tenant', table_name='compliance_scan_schedules')
    op.drop_table('compliance_scan_schedules')

    op.drop_table('compliance_policy_rules')

    op.drop_index('ix_compliance_policies_tenant', table_name='compliance_policies')
    op.drop_index('ix_compliance_policies_fw', table_name='compliance_policies')
    op.drop_table('compliance_policies')

    # Remove FK from compliance_rules before dropping compliance_remediations
    op.drop_constraint('fk_rules_remediation', 'compliance_rules', type_='foreignkey')
    op.drop_table('compliance_remediations')

    op.drop_table('compliance_rule_controls')
    op.drop_table('compliance_rule_dependencies')

    op.drop_index('ix_compliance_rules_family', table_name='compliance_rules')
    op.drop_table('compliance_rules')

    op.drop_index('ix_compliance_controls_fw_id', table_name='compliance_controls')
    op.drop_table('compliance_controls')

    op.drop_index('ix_compliance_tenant_frameworks_framework_id', table_name='compliance_tenant_frameworks')
    op.drop_index('ix_compliance_tenant_frameworks_tenant_id', table_name='compliance_tenant_frameworks')
    op.drop_table('compliance_tenant_frameworks')

    op.drop_index('ix_compliance_frameworks_tenant_id', table_name='compliance_frameworks')
    op.drop_table('compliance_frameworks')
