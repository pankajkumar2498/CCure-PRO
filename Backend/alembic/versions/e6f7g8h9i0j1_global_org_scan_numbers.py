"""global_org_scan_numbers

Revision ID: e6f7g8h9i0j1
Revises: d5e6f7g8h9i0
Create Date: 2026-05-24 12:00:00.000000

Converts scan number allocation from per-user to global-per-org and
normalizes any existing duplicate scan_no values within the same org.
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e6f7g8h9i0j1'
down_revision = 'd5e6f7g8h9i0'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_scans_org_user_scan_no_idx")
    op.execute("DROP INDEX IF EXISTS ix_scans_org_scan_no_idx")

    op.execute(sa.text("""
        DO $$
        DECLARE
            org_row RECORD;
            scan_row RECORD;
            current_no BIGINT;
        BEGIN
            FOR org_row IN
                SELECT DISTINCT org_id FROM scans
            LOOP
                current_no := 0;
                FOR scan_row IN
                    SELECT id, scan_no
                    FROM scans
                    WHERE org_id = org_row.org_id
                    ORDER BY COALESCE(scan_no, 0), created_at ASC, id ASC
                LOOP
                    IF scan_row.scan_no IS NULL THEN
                        current_no := current_no + 1;
                        UPDATE scans SET scan_no = current_no WHERE id = scan_row.id;
                    ELSIF scan_row.scan_no > current_no THEN
                        current_no := scan_row.scan_no;
                    ELSE
                        current_no := current_no + 1;
                        UPDATE scans SET scan_no = current_no WHERE id = scan_row.id;
                    END IF;
                END LOOP;
            END LOOP;
        END$$;
    """))

    op.execute(sa.text("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_scans_org_scan_no_idx
        ON scans (org_id, scan_no)
        WHERE scan_no IS NOT NULL
    """))


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_scans_org_scan_no_idx")
    op.execute("DROP INDEX IF EXISTS ix_scans_org_scan_no_idx")
    op.execute(sa.text("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_scans_org_user_scan_no_idx
        ON scans (org_id, created_by, scan_no)
        WHERE scan_no IS NOT NULL
    """))
    op.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_scans_org_scan_no_idx
        ON scans (org_id, scan_no)
    """))
