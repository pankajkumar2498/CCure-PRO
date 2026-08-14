"""
nvd_sync.py
─────────────────────────────────────────────────────────────────────────────
Synchronizes live NIST NVD 2.0 CVE disclosures, CVSS vectors, CPE matches, and
references directly into the dedicated PostgreSQL `vuln_intel` database.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy import text
from sqlalchemy.engine import Engine

from core.vuln_intel import get_vuln_engine
from scans.cve_engine.nvd_client import NvdClient
from scans.cvss import severity_from_score

logger = logging.getLogger(__name__)

# Global sync state tracker for Admin API telemetry
_SYNC_STATE: Dict[str, Any] = {
    "status": "IDLE",  # IDLE, SYNCING, SUCCESS, PARTIAL, FAILED
    "last_sync_start": None,
    "last_sync_finish": None,
    "total_cves_synced": 0,
    "cves_added": 0,
    "cves_updated": 0,
    "cves_skipped": 0,
    "last_error": None,
}

# Prevents two concurrent callers (e.g. admin API + background loop) from
# starting a second sync while one is already in progress.
_SYNC_LOCK: Optional[asyncio.Lock] = None


def _get_sync_lock() -> asyncio.Lock:
    """Return the module-level asyncio.Lock, creating it lazily."""
    global _SYNC_LOCK
    if _SYNC_LOCK is None:
        _SYNC_LOCK = asyncio.Lock()
    return _SYNC_LOCK


def get_nvd_sync_status() -> Dict[str, Any]:
    """Return live NVD sync status and telemetry dict for Admin API endpoints."""
    engine = get_vuln_engine()
    total_count = 0

    engines_to_try = []
    if engine:
        engines_to_try.append(engine)
    from db.base import engine as primary_engine

    engines_to_try.append(primary_engine)

    for eng in engines_to_try:
        try:
            with eng.connect() as conn:
                res = conn.execute(
                    text("SELECT COUNT(*) FROM vulnerability_definitions;")
                )
                total_count = res.scalar() or 0
                if total_count >= 0:
                    break
        except Exception:
            pass

    state = dict(_SYNC_STATE)
    state["database_total_cves"] = total_count

    # Two stores, and they are not the same one.
    #
    # This sync writes `vulnerability_definitions`, which enriches findings
    # that have already been persisted. Scanning reads the `cve`/`cpe` tables,
    # which are loaded separately — so the CPE version ranges every verdict
    # depends on come from there, not from here. Reporting only the count above
    # let an operator run a sync, watch the number rise, and conclude the
    # scanner's data had been refreshed when it had not. Both are reported so
    # drift between them is visible rather than assumed away.
    try:
        from core.vuln_intel import get_feed_freshness

        freshness = get_feed_freshness()
        state["scanner_feed_total_cves"] = freshness.get("cve_count")
        state["scanner_feed_last_modified"] = freshness.get("last_modified")
    except Exception as exc:  # never fail status on a telemetry read
        logger.debug("Scanner feed freshness unavailable: %s", exc)
        state["scanner_feed_total_cves"] = None
        state["scanner_feed_last_modified"] = None

    state["catalogue_table"] = "vulnerability_definitions"
    state["scanner_feed_tables"] = "cve, cpe"
    return state


async def sync_nvd_to_vuln_intel(days_back: int = 90) -> Dict[str, Any]:
    """
    Fetch live CVE records from NVD 2.0 API and upsert into `vuln_intel` database.
    """
    global _SYNC_STATE

    # Atomically check and set SYNCING so two concurrent callers cannot both
    # pass the guard and start duplicate syncs.
    async with _get_sync_lock():
        if _SYNC_STATE["status"] == "SYNCING":
            return {
                "status": "SYNCING",
                "message": "NVD Sync is already running in background.",
            }
        _SYNC_STATE["status"] = "SYNCING"
        _SYNC_STATE["last_sync_start"] = datetime.now(timezone.utc).isoformat()
        _SYNC_STATE["last_error"] = None

    client = NvdClient()
    from db.base import engine as primary_engine

    # Primary target is ccure_test database engine where AssetVulnerability foreign keys live
    working_engines = [primary_engine]

    # Add vuln_intel engine if available for external microservices
    vuln_engine: Optional[Engine] = get_vuln_engine()
    if vuln_engine:
        try:
            with vuln_engine.connect() as conn:
                conn.execute(text("SELECT 1;"))
            working_engines.append(vuln_engine)
        except Exception:
            pass

    # Ensure the lightweight metadata table exists (not managed by Alembic).
    # vulnerability_definitions is intentionally omitted here — it is owned by
    # Alembic migrations, which add CHECK constraints that a plain CREATE TABLE
    # would silently omit, causing constraint violations on upsert.
    for eng in working_engines:
        try:
            with eng.connect() as conn:
                conn.execute(
                    text(
                        """
                        CREATE TABLE IF NOT EXISTS nvd_sync_meta (
                            key VARCHAR(50) PRIMARY KEY,
                            value TEXT,
                            updated_at TIMESTAMPTZ DEFAULT NOW()
                        );
                        """
                    )
                )
                conn.commit()
        except Exception as e:
            logger.warning(
                "Could not verify nvd_sync_meta table on engine %s: %s", eng, e
            )

    # Determine sync starting window
    since = datetime.now(timezone.utc) - timedelta(days=days_back)

    # Check last sync date from meta
    try:
        with working_engines[0].connect() as conn:
            res = conn.execute(
                text("SELECT value FROM nvd_sync_meta WHERE key='last_sync_date';")
            )
            row = res.fetchone()
            if row and row[0]:
                since = datetime.fromisoformat(row[0])
    except Exception as e:
        logger.warning("Could not read nvd_sync_meta timestamp: %s", e)

    added = 0
    skipped = 0

    upsert_sql = text(
        """
        INSERT INTO vulnerability_definitions (
            id, cve_id, cwe_ids, title, description,
            cvss_v2_score, cvss_v3_score, cvss_vector, severity,
            published_at, last_modified_at, "references", affected_software,
            source, is_custom, created_at, updated_at
        ) VALUES (
            :id, :cve_id, CAST(:cwe_ids AS jsonb), :title, :description,
            :cvss_v2_score, :cvss_v3_score, :cvss_vector, :severity,
            :published_at, :last_modified_at, CAST(:references AS jsonb), CAST(:affected_software AS jsonb),
            'nvd', FALSE, NOW(), NOW()
        )
        ON CONFLICT (id) DO UPDATE SET
            title = EXCLUDED.title,
            description = EXCLUDED.description,
            cvss_v3_score = EXCLUDED.cvss_v3_score,
            cvss_vector = EXCLUDED.cvss_vector,
            severity = EXCLUDED.severity,
            -- cwe_ids and published_at were previously omitted here, so rows
            -- inserted before the feed carried weakness data never gained it
            -- and the report showed no CWE for any pre-existing CVE.
            cwe_ids = EXCLUDED.cwe_ids,
            published_at = EXCLUDED.published_at,
            last_modified_at = EXCLUDED.last_modified_at,
            "references" = EXCLUDED."references",
            affected_software = EXCLUDED.affected_software,
            updated_at = NOW();
        """
    )

    def _flush_batch(
        batch: list,
        engines: list,
        sql,
    ) -> tuple:
        """
        Attempt a bulk upsert of ``batch`` on every engine independently.

        Each engine first tries a single bulk execute.  If the database rejects
        the batch (e.g. a CHECK constraint violation on a single bad row), that
        engine falls back to a row-by-row retry so good rows in the same batch
        are not lost.

        ``bad_ids`` is a set so duplicate engine failures for the same CVE ID
        are counted only once in the returned skipped count.

        Returns ``(flushed, skipped)``.
        """
        if not batch:
            return 0, 0

        bad_ids: set = set()

        for eng in engines:
            try:
                with eng.connect() as conn:
                    conn.execute(sql, batch)
                    conn.commit()
                # Bulk path succeeded for this engine — nothing more to do.
            except Exception as bulk_err:
                logger.warning(
                    "Bulk upsert of %d CVEs failed on engine %s (%s). "
                    "Falling back to row-by-row.",
                    len(batch),
                    eng,
                    bulk_err,
                )
                # Row-by-row retry isolates the bad record(s) for THIS engine
                # independently of any other engine in the list.
                for row in batch:
                    try:
                        with eng.connect() as conn:
                            conn.execute(sql, [row])
                            conn.commit()
                    except Exception as row_err:
                        bad_ids.add(row.get("id"))
                        logger.error(
                            "Skipping CVE %s — row rejected by database: %s",
                            row.get("id", "<unknown>"),
                            row_err,
                        )

        skipped_in_batch = len(bad_ids)
        flushed = len(batch) - skipped_in_batch
        return flushed, skipped_in_batch

    try:
        batch = []
        async for cve in client.fetch_modified_since(since=since):
            cpes_json = [c.model_dump() for c in cve.cpe_matches]
            refs_json = [r.url for r in cve.references]

            # Map severity to canonical rating ('critical', 'high', 'medium', 'low', 'none', 'unscored')
            score = cve.cvss.base_score if cve.cvss else None
            sev = severity_from_score(score).lower()

            params = {
                "id": cve.cve_id,
                "cve_id": cve.cve_id,
                "cwe_ids": json.dumps(cve.cwe_ids),
                "title": cve.title,
                "description": cve.description,
                "cvss_v2_score": (
                    cve.cvss.base_score if cve.cvss.version == "2.0" else None
                ),
                "cvss_v3_score": (
                    cve.cvss.base_score if cve.cvss.version in ("3.0", "3.1") else None
                ),
                "cvss_vector": cve.cvss.vector_string,
                "severity": sev,
                "published_at": cve.published_date.date(),
                "last_modified_at": cve.last_modified_date.date(),
                "references": json.dumps(refs_json),
                "affected_software": json.dumps(cpes_json),
            }
            batch.append(params)

            if len(batch) >= 100:
                flushed, s = _flush_batch(batch, working_engines, upsert_sql)
                added += flushed
                skipped += s
                batch.clear()

        # Flush remaining records
        if batch:
            flushed, s = _flush_batch(batch, working_engines, upsert_sql)
            added += flushed
            skipped += s
            batch.clear()

    except Exception as e:
        _SYNC_STATE["status"] = "FAILED"
        _SYNC_STATE["last_error"] = str(e)
        logger.error("Error during live NVD sync: %s", e)

    finally:
        # Always advance the sync window so the next run does not re-process
        # the same CVEs, even if some rows were skipped due to bad data.
        now_str = datetime.now(timezone.utc).isoformat()
        for eng in working_engines:
            try:
                with eng.connect() as conn:
                    conn.execute(
                        text(
                            """
                            INSERT INTO nvd_sync_meta (key, value, updated_at)
                            VALUES ('last_sync_date', :val, NOW())
                            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW();
                            """
                        ),
                        {"val": now_str},
                    )
                    conn.commit()
            except Exception as meta_err:
                logger.warning("Could not update nvd_sync_meta timestamp: %s", meta_err)

        status = (
            "PARTIAL"
            if skipped > 0 and _SYNC_STATE["status"] != "FAILED"
            else ("SUCCESS" if _SYNC_STATE["status"] != "FAILED" else "FAILED")
        )
        _SYNC_STATE["status"] = status
        _SYNC_STATE["last_sync_finish"] = now_str
        _SYNC_STATE["cves_added"] = added
        _SYNC_STATE["cves_skipped"] = skipped
        logger.info(
            "Live NVD Sync finished with status=%s. synced=%d skipped=%d",
            status,
            added,
            skipped,
        )

    return _SYNC_STATE
