"""
Proxy to the central database models to avoid module import errors during transition.
"""

from sqlalchemy import inspect, text

from db.models import Scan, ScanPhase
from db.base import Base, engine, get_db


def ensure_scan_schema():
    """
    Add and backfill human-facing scan numbers without touching UUID identity.

    create_all() will create the column on fresh databases, but existing
    databases need this additive migration because SQLAlchemy does not alter
    already-created tables.
    """
    inspector = inspect(engine)
    if "scans" not in inspector.get_table_names():
        return

    columns = {col["name"] for col in inspector.get_columns("scans")}
    dialect = engine.dialect.name

    with engine.begin() as conn:
        if "scan_no" not in columns:
            if dialect == "postgresql":
                conn.execute(text("ALTER TABLE scans ADD COLUMN scan_no BIGINT"))
            else:
                conn.execute(text("ALTER TABLE scans ADD COLUMN scan_no INTEGER"))

        if dialect == "postgresql":
            conn.execute(text("""
                WITH existing AS (
                    SELECT org_id, created_by, COALESCE(MAX(scan_no), 0) AS max_scan_no
                    FROM scans
                    WHERE scan_no IS NOT NULL
                    GROUP BY org_id, created_by
                ),
                numbered AS (
                    SELECT
                        s.id,
                        COALESCE(e.max_scan_no, 0) +
                        ROW_NUMBER() OVER (
                            PARTITION BY s.org_id, s.created_by
                            ORDER BY s.created_at ASC, s.id ASC
                        ) AS next_scan_no
                    FROM scans s
                    LEFT JOIN existing e
                      ON e.org_id = s.org_id
                     AND e.created_by IS NOT DISTINCT FROM s.created_by
                    WHERE s.scan_no IS NULL
                )
                UPDATE scans
                SET scan_no = numbered.next_scan_no
                FROM numbered
                WHERE scans.id = numbered.id
            """))
            conn.execute(text("""
                CREATE UNIQUE INDEX IF NOT EXISTS uq_scans_org_user_scan_no_idx
                ON scans (org_id, created_by, scan_no)
                WHERE scan_no IS NOT NULL
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_scans_org_scan_no_idx
                ON scans (org_id, scan_no)
            """))
        else:
            rows = conn.execute(text("""
                SELECT id, org_id, created_by
                FROM scans
                WHERE scan_no IS NULL
                ORDER BY org_id, created_by, created_at ASC, id ASC
            """)).fetchall()
            counters = {}
            for scan_id, org_id, created_by in rows:
                key = (str(org_id), str(created_by))
                if key not in counters:
                    counters[key] = conn.execute(text("""
                        SELECT COALESCE(MAX(scan_no), 0)
                        FROM scans
                        WHERE org_id = :org_id
                          AND created_by = :created_by
                          AND scan_no IS NOT NULL
                    """), {"org_id": org_id, "created_by": created_by}).scalar() or 0
                counters[key] += 1
                conn.execute(text("""
                    UPDATE scans
                    SET scan_no = :scan_no
                    WHERE id = :id
                """), {"scan_no": counters[key], "id": scan_id})

# Map old ScanPhaseResult to the new ScanPhase just to satisfy imports
ScanPhaseResult = ScanPhase
