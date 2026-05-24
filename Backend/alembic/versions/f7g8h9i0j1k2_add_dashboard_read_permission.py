"""add dashboard read permission

Revision ID: f7g8h9i0j1k2
Revises: e6f7g8h9i0j1
Create Date: 2026-05-24 15:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'f7g8h9i0j1k2'
down_revision = 'e6f7g8h9i0j1'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Insert the dashboard:read permission
    op.execute(sa.text("""
        INSERT INTO permissions (resource, action, description)
        VALUES ('dashboard', 'read', 'View the security analytics dashboard')
        ON CONFLICT (resource, action) DO NOTHING
    """))

    # 2. Assign to org_admin, analyst, viewer
    op.execute(sa.text("""
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id
        FROM roles r, permissions p
        WHERE r.name IN ('org_admin', 'analyst', 'viewer')
          AND p.resource = 'dashboard' AND p.action = 'read'
        ON CONFLICT DO NOTHING
    """))


def downgrade() -> None:
    # 1. Remove assignments
    op.execute(sa.text("""
        DELETE FROM role_permissions
        WHERE permission_id IN (
            SELECT id FROM permissions
            WHERE resource = 'dashboard' AND action = 'read'
        )
    """))

    # 2. Remove the permission
    op.execute(sa.text("""
        DELETE FROM permissions
        WHERE resource = 'dashboard' AND action = 'read'
    """))
