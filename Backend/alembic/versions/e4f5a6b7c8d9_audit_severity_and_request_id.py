"""audit_logs: severity classification and request correlation id

Phase 1 of the audit-log hardening work. Additive only — two new columns on
``audit_logs``, no index, trigger, grant or table change. Those land in later
phases so each can be rehearsed and verified on its own.

``audit_logs`` is HASH-partitioned by ``org_id`` (8 partitions, created by
``db/migrate_production_schema.py:create_partitions``). ``ADD COLUMN`` on the
partitioned parent propagates to every existing and future partition, so the
partitions are never named here.

Backfill
────────
The severity table is snapshotted as a literal below rather than imported from
``core.audit_taxonomy``. A migration must produce the same result whenever it
runs; importing the live table would make this backfill change silently the
next time someone reclassifies an action. The snapshot covers the 23 distinct
actions present when this was written; anything else backfills to ``medium``,
which is the same conservative default the application applies at write time.

Reversibility
─────────────
``downgrade()`` restores the previous table structure exactly and deletes no
audit rows. It is **not** data-loss-free: dropping ``severity`` and
``request_id`` permanently discards those values, and re-running ``upgrade``
afterwards recomputes severity from the snapshot but cannot recover the
correlation ids, which have no other source. A production downgrade therefore
requires a full backup and explicit approval.
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "e4f5a6b7c8d9"
down_revision = "d3e4f5a6b7c8"
branch_labels = None
depends_on = None


#: Snapshot of core.audit_taxonomy.SEVERITY_BY_ACTION at the time of writing,
#: restricted to actions that can appear in existing rows. Deliberately a copy
#: — see the module docstring.
_SEVERITY_SNAPSHOT = {
    # Authentication
    "user.login": "info",
    "user.logout": "info",
    "user.login_failed": "medium",
    "user.locked": "high",
    "user.mfa_challenge_issued": "info",
    "user.mfa_failed": "high",
    "user.mfa_recovery_used": "high",
    "user.mfa_enabled": "medium",
    "user.mfa_disabled": "high",
    "user.mfa_reset_by_admin": "high",
    "user.verification_token_issued": "info",
    "user.email_verified": "low",
    # Credentials / recovery
    "user.forgot_password_requested": "low",
    "user.password_reset_completed": "high",
    "user.password_reset": "high",
    "user.password_changed": "medium",
    "user.password_change_failed": "medium",
    # Sessions
    "user.session_revoked": "low",
    "user.sessions_revoked_bulk": "medium",
    # User management
    "user.created": "medium",
    "user.updated": "medium",
    "user.profile_updated": "low",
    "user.preferences_updated": "info",
    "user.approved": "high",
    "user.status_changed": "high",
    "user.deleted": "high",
    "user.restored": "high",
    "user.purged": "critical",
    "user.role_changed": "high",
    "user.organization_changed": "high",
    # Organizations
    "organization.created": "high",
    "organization.updated": "medium",
    "organization.activated": "high",
    "organization.deactivated": "high",
    "organization.deleted": "critical",
    "organization.scan_scope_changed": "high",
    # Platform administration
    "admin.email_domain_allowlisted": "medium",
    "admin.email_domain_rule_created": "medium",
    "admin.email_domain_rule_updated": "medium",
    "admin.email_domain_rule_deleted": "medium",
    "auth.email_domain_blocked": "medium",
    "auth.email_domain_flagged": "low",
    # Scanning
    "scan.created": "low",
    "scan.completed": "info",
    "scan.failed": "medium",
    "scan.cancelled": "low",
    # Assets
    "asset_updated": "low",
    "amt_inventory_imported": "medium",
    # Findings
    "finding_open": "info",
    "finding_resolved": "low",
    "finding_false_positive": "medium",
    "finding_accepted": "high",
    "finding_ignored": "high",
    # Compliance
    "install_framework": "medium",
    "uninstall_framework": "high",
    "compliance.rule_updated": "high",
    "create_policy": "medium",
    "trigger_scan": "low",
    "attest_control": "high",
    "upload_evidence": "low",
    "delete_evidence": "high",
    "create_schedule": "low",
    "update_schedule": "low",
    "delete_schedule": "medium",
    "create_credential": "high",
    "delete_credential": "medium",
    "export_soa": "medium",
    "request_remediation": "low",
    "approve_remediation": "high",
    "reject_remediation": "medium",
    "cancel_remediation": "low",
    "request_rollback": "low",
    "approve_rollback": "high",
    "emergency_bypass_remediation": "critical",
    "emergency_bypass_rollback": "critical",
    "request_waiver": "medium",
    "approve_waiver": "high",
    # Reports
    "report.downloaded": "low",
}

_DEFAULT_SEVERITY = "medium"


def upgrade():
    conn = op.get_bind()

    # ADD COLUMN on the partitioned parent reaches every partition. Both are
    # added nullable so no existing row has to be rewritten before the
    # backfill below decides what its severity actually is.
    conn.execute(
        sa.text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS severity VARCHAR(20)")
    )
    conn.execute(
        sa.text(
            "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS request_id VARCHAR(64)"
        )
    )

    # Backfill from the snapshot. One statement with a VALUES join rather than
    # a statement per action: 8 partitions × N actions of individual UPDATEs
    # would be needlessly slow on a large install.
    values = ", ".join(f"(:a{i}, :s{i})" for i in range(len(_SEVERITY_SNAPSHOT)))
    params = {}
    for i, (action, sev) in enumerate(_SEVERITY_SNAPSHOT.items()):
        params[f"a{i}"] = action
        params[f"s{i}"] = sev

    conn.execute(
        sa.text(
            f"""
            UPDATE audit_logs AS al
               SET severity = m.sev
              FROM (VALUES {values}) AS m(act, sev)
             WHERE al.action = m.act
               AND al.severity IS NULL
            """
        ),
        params,
    )

    # Anything the snapshot does not name — an action added between this file
    # being written and it being run — takes the same conservative default the
    # application uses for an unmapped action.
    conn.execute(
        sa.text("UPDATE audit_logs SET severity = :d WHERE severity IS NULL"),
        {"d": _DEFAULT_SEVERITY},
    )

    # Only now can the column become NOT NULL, matching the model. The server
    # default keeps a direct INSERT (outside the ORM) valid rather than
    # failing it; the application always supplies a value explicitly.
    conn.execute(
        sa.text(
            "ALTER TABLE audit_logs "
            "ALTER COLUMN severity SET DEFAULT '%s'" % _DEFAULT_SEVERITY
        )
    )
    conn.execute(sa.text("ALTER TABLE audit_logs ALTER COLUMN severity SET NOT NULL"))


def downgrade():
    conn = op.get_bind()
    # Dropping from the parent removes the column from every partition. See
    # the module docstring: structurally reversible, but the values in these
    # two columns are gone for good.
    conn.execute(sa.text("ALTER TABLE audit_logs DROP COLUMN IF EXISTS request_id"))
    conn.execute(sa.text("ALTER TABLE audit_logs DROP COLUMN IF EXISTS severity"))
