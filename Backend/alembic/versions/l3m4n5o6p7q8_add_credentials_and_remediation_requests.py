"""add credentials and remediation requests

Revision ID: l3m4n5o6p7q8
Revises: k2l3m4n5o6p7
Create Date: 2026-07-07 09:30:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "l3m4n5o6p7q8"
down_revision = "k2l3m4n5o6p7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. compliance_credentials
    op.create_table(
        "compliance_credentials",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("tenant_id", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("username", sa.String(length=150), nullable=False),
        sa.Column("encrypted_password", sa.Text(), nullable=True),
        sa.Column("encrypted_key_content", sa.Text(), nullable=True),
        sa.Column("port", sa.Integer(), nullable=False, server_default=sa.text("22")),
        sa.Column(
            "auth_method",
            sa.String(length=50),
            nullable=False,
            server_default=sa.text("'password'"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["organizations.id"],
            name="fk_compliance_credentials_tenant",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "name", "tenant_id", name="uq_compliance_credentials_name_tenant"
        ),
        sa.CheckConstraint(
            "(auth_method = 'password' AND encrypted_password IS NOT NULL) OR "
            "(auth_method = 'key' AND encrypted_key_content IS NOT NULL)",
            name="ck_compliance_credential_auth",
        ),
        sa.CheckConstraint(
            "auth_method IN ('password', 'key')",
            name="ck_compliance_credential_auth_method",
        ),
    )
    op.create_index(
        "ix_compliance_credentials_tenant_id", "compliance_credentials", ["tenant_id"]
    )

    # 2. compliance_remediation_requests
    op.create_table(
        "compliance_remediation_requests",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("tenant_id", sa.String(length=100), nullable=False),
        sa.Column("finding_id", sa.String(length=250), nullable=False),
        sa.Column("remediation_id", sa.String(length=100), nullable=False),
        sa.Column("credential_id", sa.String(length=100), nullable=True),
        sa.Column("requested_by", sa.String(length=150), nullable=True),
        sa.Column("approved_by", sa.String(length=150), nullable=True),
        sa.Column(
            "status",
            sa.String(length=50),
            nullable=False,
            server_default=sa.text("'pending_approval'"),
        ),
        sa.Column(
            "emergency_bypass",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("execution_log", sa.Text(), nullable=True),
        sa.Column("username", sa.String(length=150), nullable=True),
        sa.Column("encrypted_password", sa.Text(), nullable=True),
        sa.Column("encrypted_key_content", sa.Text(), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("auth_method", sa.String(length=50), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["organizations.id"],
            name="fk_remediation_requests_tenant",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["compliance_findings.id"],
            name="fk_remediation_requests_finding",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["remediation_id"],
            ["compliance_remediations.id"],
            name="fk_remediation_requests_remediation",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["credential_id"],
            ["compliance_credentials.id"],
            name="fk_remediation_requests_credential",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"],
            ["users.id"],
            name="fk_remediation_requests_requester",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["approved_by"],
            ["users.id"],
            name="fk_remediation_requests_approver",
            ondelete="SET NULL",
        ),
        sa.CheckConstraint(
            "status IN ('pending_approval', 'approved', 'rejected', 'executed', 'failed')",
            name="ck_remediation_request_status",
        ),
    )
    op.create_index(
        "ix_compliance_remediation_requests_tenant_id",
        "compliance_remediation_requests",
        ["tenant_id"],
    )
    op.create_index(
        "ix_compliance_remediation_requests_finding_id",
        "compliance_remediation_requests",
        ["finding_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_compliance_remediation_requests_finding_id",
        table_name="compliance_remediation_requests",
    )
    op.drop_index(
        "ix_compliance_remediation_requests_tenant_id",
        table_name="compliance_remediation_requests",
    )
    op.drop_table("compliance_remediation_requests")

    op.drop_index(
        "ix_compliance_credentials_tenant_id", table_name="compliance_credentials"
    )
    op.drop_table("compliance_credentials")
