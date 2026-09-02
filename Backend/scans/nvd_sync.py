"""
nvd_sync.py
─────────────────────────────────────────────────────────────────────────────
Synchronises live NIST NVD 2.0 CVE disclosures, CVSS vectors, CPE matches and
references into the **application catalogue** — ``vulnerability_definitions``
in the C-CURE application database.

Where this writes, and where it does not:

* ``vulnerability_definitions`` (application DB) is the catalogue
  ``asset_vulnerabilities.vuln_id`` points at. It holds CVE rows *and* the
  non-CVE finding definitions (``config_check``, ``privilege_check``,
  ``plugin_check``) that have no home in a CVE feed. This is what the sync
  populates.
* ``vuln_intel`` remains the source of truth for vulnerability *intelligence* —
  ``cve``, ``cpe``, ``cvss``, ``kev``, ``epss``, ``exploits``, ``osv_*``,
  ``csaf_*``, ``msrc_*`` — loaded by the feed scripts under ``scripts/vuln/``.
  Matching reads those tables; nothing in the product reads a catalogue table
  from that database.

This module used to write ``vulnerability_definitions`` to **both** databases.
The second copy had no reader anywhere in the product, never received the
migrations Alembic applies to the application database (no ``definition_type``
column, no CHECK constraints at all), and had drifted to a fifth of the row
count — while being the copy the status endpoint reported. The write is gone;
the table itself is left in place, untouched.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.engine import Engine

from scans.cve_engine.nvd_client import (
    NVD_MAX_WINDOW_DAYS,
    NvdClient,
    NvdFetchError,
    split_window,
)
from scans.cvss import severity_from_score

logger = logging.getLogger(__name__)

#: Rows per upsert. Small enough that a rejected batch costs little to retry
#: row by row, large enough that a window is not one statement per CVE.
_BATCH_SIZE = 100

#: The only key ``nvd_sync_meta`` carries: the high-water mark of the last
#: window that was paginated to completion *and* persisted.
_CHECKPOINT_KEY = "last_sync_date"

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
    # Whether the requested range was paginated end to end. SUCCESS is only
    # reported when this is True — the two used to be independent, which is how
    # an aborted window came to report success.
    "pagination_complete": None,
    "mode": None,  # "incremental" | "backfill"
    "windows_completed": 0,
    "windows_total": 0,
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


def _catalogue_engine() -> Engine:
    """
    The application database engine — the one and only write target.

    Imported inside the call rather than at module scope so importing this
    module does not require a configured database.
    """
    from db.base import engine as primary_engine

    return primary_engine


# ── Upsert ────────────────────────────────────────────────────────────────────

_UPSERT_SQL = text(
    """
    INSERT INTO vulnerability_definitions (
        id, cve_id, cwe_ids, title, description,
        cvss_v2_score, cvss_v3_score, cvss_v4_score, cvss_vector, cvss_version,
        severity, published_at, last_modified_at, "references", affected_software,
        source, is_custom, created_at, updated_at
    ) VALUES (
        :id, :cve_id, CAST(:cwe_ids AS jsonb), :title, :description,
        :cvss_v2_score, :cvss_v3_score, :cvss_v4_score, :cvss_vector, :cvss_version,
        :severity, :published_at, :last_modified_at,
        CAST(:references AS jsonb), CAST(:affected_software AS jsonb),
        'nvd', FALSE, NOW(), NOW()
    )
    ON CONFLICT (id) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        cvss_v3_score = EXCLUDED.cvss_v3_score,
        -- Added alongside CVSS 4.0 support. Without them a v4 metric was
        -- parsed and then discarded at the column boundary, and every row this
        -- sync wrote left cvss_version NULL — the column that exists to say
        -- which revision cvss_vector belongs to.
        cvss_v4_score = EXCLUDED.cvss_v4_score,
        cvss_version = EXCLUDED.cvss_version,
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


def _row_for_cve(cve: Any) -> Dict[str, Any]:
    """
    One ``CveRecord`` as upsert parameters.

    ``cvss_v4_score`` is written whenever NVD published a v4 metric, even when
    an older revision is the primary score: the columns answer different
    questions, and a v4 metric is not lost merely because v3.1 outranks it in
    the parser's selection order.
    """
    primary = cve.cvss
    v4 = getattr(cve, "cvss_v4", None)
    score = primary.base_score if primary else None
    version = primary.version if primary else None

    return {
        "id": cve.cve_id,
        "cve_id": cve.cve_id,
        "cwe_ids": json.dumps(cve.cwe_ids),
        "title": cve.title,
        "description": cve.description,
        "cvss_v2_score": score if version == "2.0" else None,
        "cvss_v3_score": score if version in ("3.0", "3.1") else None,
        "cvss_v4_score": (
            v4.base_score if v4 else (score if version == "4.0" else None)
        ),
        "cvss_vector": primary.vector_string if primary else None,
        "cvss_version": version,
        # Canonical lowercase, as ck_vuln_def_severity_canonical requires.
        "severity": severity_from_score(score).lower(),
        "published_at": cve.published_date.date(),
        "last_modified_at": cve.last_modified_date.date(),
        "references": json.dumps([r.url for r in cve.references]),
        "affected_software": json.dumps([c.model_dump() for c in cve.cpe_matches]),
    }


def _flush_batch(
    engine: Engine, batch: List[Dict[str, Any]], sql
) -> Tuple[int, int, bool]:
    """
    Upsert one batch. Returns ``(flushed, skipped, fatal)``.

    A bulk failure falls back to row-by-row so one rejected record does not cost
    the other ninety-nine.

    ``fatal`` is the distinction the checkpoint depends on. A handful of
    rejected rows is bad *data*: re-fetching them can only produce the same
    rejection, so refusing to advance would wedge the sync permanently — those
    are counted as skipped and the window is still allowed to advance. But
    *every* row failing is the signature of a database that is unreachable or
    mis-migrated, and advancing over that loses CVEs nothing ever stored.
    """
    if not batch:
        return 0, 0, False

    try:
        with engine.connect() as conn:
            conn.execute(sql, batch)
            conn.commit()
        return len(batch), 0, False
    except Exception as bulk_err:
        logger.warning(
            "Bulk upsert of %d CVEs failed (%s). Falling back to row-by-row.",
            len(batch),
            bulk_err,
        )

    bad_ids: set = set()
    for row in batch:
        try:
            with engine.connect() as conn:
                conn.execute(sql, [row])
                conn.commit()
        except Exception as row_err:
            bad_ids.add(row.get("id"))
            logger.error(
                "Skipping CVE %s — row rejected by database: %s",
                row.get("id", "<unknown>"),
                row_err,
            )

    skipped = len(bad_ids)
    flushed = len(batch) - skipped
    fatal = flushed == 0 and skipped > 0
    if fatal:
        logger.error(
            "Every row in a %d-CVE batch was rejected — treating this as a "
            "persistence failure rather than bad data. The sync checkpoint "
            "will not advance.",
            len(batch),
        )
    return flushed, skipped, fatal


# ── Checkpoint ────────────────────────────────────────────────────────────────


def _ensure_meta_table(engine: Engine) -> None:
    """
    Create ``nvd_sync_meta`` if absent.

    ``vulnerability_definitions`` is intentionally *not* created here — it is
    owned by Alembic, whose migrations add CHECK constraints a plain CREATE
    TABLE would silently omit.
    """
    try:
        with engine.connect() as conn:
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
    except Exception as exc:
        logger.warning("Could not verify nvd_sync_meta table: %s", exc)


def _read_checkpoint(engine: Engine) -> Optional[datetime]:
    """The high-water mark of the last completed window, or None."""
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT value FROM nvd_sync_meta WHERE key = :k;"),
                {"k": _CHECKPOINT_KEY},
            ).fetchone()
        if not row or not row[0]:
            return None
        stamp = datetime.fromisoformat(row[0])
        # A naive value predates timezone-aware writes; UTC is what it meant.
        return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)
    except Exception as exc:
        logger.warning("Could not read nvd_sync_meta checkpoint: %s", exc)
        return None


def _write_checkpoint(engine: Engine, when: datetime) -> bool:
    """
    Advance the checkpoint to ``when``.

    Called **only** after a window has been paginated end to end and its records
    committed. Deliberately not in a ``finally``: it used to be, which meant an
    aborted window still moved the mark past CVEs that were never fetched, and
    the next run began after them.
    """
    try:
        with engine.connect() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO nvd_sync_meta (key, value, updated_at)
                    VALUES (:k, :val, NOW())
                    ON CONFLICT (key) DO UPDATE
                       SET value = EXCLUDED.value, updated_at = NOW();
                    """
                ),
                {"k": _CHECKPOINT_KEY, "val": when.isoformat()},
            )
            conn.commit()
        return True
    except Exception as exc:
        logger.warning("Could not advance nvd_sync_meta checkpoint: %s", exc)
        return False


# ── Status ────────────────────────────────────────────────────────────────────


def get_nvd_sync_status() -> Dict[str, Any]:
    """Return live NVD sync status and telemetry dict for Admin API endpoints."""
    total_count = 0
    try:
        with _catalogue_engine().connect() as conn:
            total_count = (
                conn.execute(
                    text("SELECT COUNT(*) FROM vulnerability_definitions;")
                ).scalar()
                or 0
            )
    except Exception as exc:  # telemetry must never fail the endpoint
        logger.debug("Catalogue count unavailable: %s", exc)

    state = dict(_SYNC_STATE)
    state["database_total_cves"] = total_count

    # Two stores, and they are not the same one.
    #
    # The count above is the *application catalogue* this sync writes, which
    # enriches findings that have already been persisted. Scanning matches
    # against the `cve`/`cpe` tables in the vulnerability-intelligence database,
    # loaded separately — so the CPE version ranges every verdict depends on
    # come from there, not from here. Reporting only one number let an operator
    # run a sync, watch it rise, and conclude the scanner's data had been
    # refreshed when it had not. Both are reported so drift is visible.
    #
    # The count above was previously read from whichever database answered
    # first, and the intelligence database answered first — so this endpoint
    # reported a duplicate table nothing read in place of the catalogue behind
    # every finding in the product.
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
    state["catalogue_database"] = "application"
    state["scanner_feed_tables"] = "cve, cpe"
    state["scanner_feed_database"] = "vuln_intel"

    checkpoint = _read_checkpoint(_catalogue_engine())
    state["checkpoint"] = checkpoint.isoformat() if checkpoint else None

    return state


# ── Sync ──────────────────────────────────────────────────────────────────────


async def sync_nvd_to_vuln_intel(
    days_back: int = 90, backfill: bool = False
) -> Dict[str, Any]:
    """
    Fetch CVEs modified inside a window and upsert them into the application
    catalogue (``vulnerability_definitions``).

    Two modes, and the difference between them is the checkpoint:

    ``backfill=False`` — the daily scheduled run. Resumes from
    ``nvd_sync_meta.last_sync_date`` and advances it as each sub-window
    completes. ``days_back`` is only the cold-start window, used when no
    checkpoint exists yet.

    ``backfill=True`` — an operator asking for history. Covers exactly
    ``days_back`` days ending now, ignores the checkpoint, and **never writes
    it**. A backfill repairs a window already behind the incremental frontier;
    letting it move that frontier is how a partial repair becomes a permanent
    gap. Before this parameter existed, ``days_back`` was read and then
    overridden by the checkpoint on every deployment that had ever synced, so
    the API accepted a value between 1 and 3650 and did nothing with it.

    Any range longer than ``NVD_MAX_WINDOW_DAYS`` is split into consecutive
    sub-windows, because NVD refuses a wider one with a 4xx. That also covers
    the incremental case after a long outage: a checkpoint four months old used
    to produce a request NVD rejected outright.
    """
    global _SYNC_STATE

    mode = "backfill" if backfill else "incremental"

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
        _SYNC_STATE["mode"] = mode
        _SYNC_STATE["pagination_complete"] = None
        _SYNC_STATE["windows_completed"] = 0
        _SYNC_STATE["windows_total"] = 0

    engine = _catalogue_engine()
    client = NvdClient()
    _ensure_meta_table(engine)

    until = datetime.now(timezone.utc)
    if backfill:
        since = until - timedelta(days=days_back)
    else:
        since = _read_checkpoint(engine) or (until - timedelta(days=days_back))

    windows = split_window(since, until, NVD_MAX_WINDOW_DAYS)
    _SYNC_STATE["windows_total"] = len(windows)

    seen = 0
    added = 0
    skipped = 0
    windows_done = 0
    failure: Optional[str] = None

    logger.info(
        "NVD %s sync: %s .. %s (%d window(s), at most %d days each).",
        mode,
        since.isoformat(),
        until.isoformat(),
        len(windows),
        NVD_MAX_WINDOW_DAYS,
    )

    try:
        for w_start, w_end in windows:
            batch: List[Dict[str, Any]] = []
            complete = False
            fatal = False

            try:
                async for cve in client.fetch_modified_since(
                    since=w_start, until=w_end
                ):
                    seen += 1
                    batch.append(_row_for_cve(cve))
                    if len(batch) >= _BATCH_SIZE:
                        flushed, s, fatal = _flush_batch(engine, batch, _UPSERT_SQL)
                        added += flushed
                        skipped += s
                        batch.clear()
                        if fatal:
                            break
                if not fatal:
                    # The generator was exhausted without raising, which is the
                    # only thing that means every page of this window arrived.
                    complete = True
            except NvdFetchError as exc:
                failure = (
                    f"window {w_start.isoformat()}..{w_end.isoformat()} "
                    f"incomplete at startIndex={exc.start_index}: {exc}"
                )
                logger.error(
                    "NVD %s sync stopped: %s. The checkpoint stays where it is, "
                    "so the next run retries this window.",
                    mode,
                    failure,
                )

            if batch and not fatal:
                # Records already fetched are still valid — persist them even
                # though the window as a whole did not finish.
                flushed, s, fatal = _flush_batch(engine, batch, _UPSERT_SQL)
                added += flushed
                skipped += s
                batch.clear()

            if fatal:
                complete = False
                failure = failure or (
                    f"persistence failed for window {w_start.isoformat()}.."
                    f"{w_end.isoformat()}"
                )

            if not complete:
                # Do not attempt later windows: skipping ahead would leave a
                # hole behind the checkpoint that nothing would ever revisit.
                break

            windows_done += 1
            if not backfill:
                _write_checkpoint(engine, w_end)

    except Exception as exc:  # an unexpected fault must never look like success
        failure = f"unexpected error: {exc}"
        logger.exception("Error during live NVD sync: %s", exc)

    pagination_complete = failure is None and windows_done == len(windows)
    if failure:
        status = "PARTIAL" if added else "FAILED"
    elif skipped:
        status = "PARTIAL"
    else:
        status = "SUCCESS"

    now_str = datetime.now(timezone.utc).isoformat()
    _SYNC_STATE["status"] = status
    _SYNC_STATE["last_sync_finish"] = now_str
    _SYNC_STATE["total_cves_synced"] = seen
    _SYNC_STATE["cves_added"] = added
    _SYNC_STATE["cves_skipped"] = skipped
    _SYNC_STATE["last_error"] = failure
    _SYNC_STATE["pagination_complete"] = pagination_complete
    _SYNC_STATE["windows_completed"] = windows_done

    logger.info(
        "Live NVD %s sync finished with status=%s. fetched=%d saved=%d "
        "skipped=%d windows=%d/%d checkpoint_advanced=%s",
        mode,
        status,
        seen,
        added,
        skipped,
        windows_done,
        len(windows),
        "no (backfill)" if backfill else str(windows_done > 0),
    )

    return dict(_SYNC_STATE)
