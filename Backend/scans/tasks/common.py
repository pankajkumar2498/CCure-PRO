"""
The helpers every scan task shares: building an orchestrator bound to the
scan's authorised scope, running a coroutine from a worker thread, recording
a task id, checking for and finalising a cancellation, and settling a failure
so that something is always recorded.

Split from core/tasks.py in G1 (C2, docs/architecture/MODULAR_REFACTORING_LOG.md
§6), unchanged. Logs under ``ccure.tasks``, as the hub did.
"""

import asyncio
import logging
from db.base import SessionLocal
from db.models import Scan
from ccure_platform import api as platform_api
from orchestrator.scan_orchestrator import ScanOrchestrator
from scans.db_helpers import mark_scan_failed

log = logging.getLogger("ccure.tasks")


def _strip_nul(value):
    """Recursively remove NUL (U+0000) from every string in a nested structure.

    Windows collectors read version-resource and registry values that are
    UTF-16LE and occasionally carry an embedded NUL — a truncated
    ``"Microsoft\\x00..."`` publisher string, for instance. PostgreSQL's
    ``jsonb``/``text`` cannot store U+0000, so one such byte anywhere in a
    credentialed report aborts the whole result commit
    (``UntranslatableCharacter: \\u0000 cannot be converted to text``): the scan
    is marked ``failed`` and every finding it produced is lost on the rollback.
    Scrub at the point the report is produced, before anything derived from it
    is persisted or merged into ``scans.options``.
    """
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, dict):
        return {k: _strip_nul(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_strip_nul(v) for v in value]
    return value


def _new_orchestrator(
    db=None, scan_id: str | None = None, user_id: str | None = None
) -> ScanOrchestrator:
    """
    Create one orchestrator per task so parallel scans do not share mutable state.

    When `db` plus either `scan_id` or `user_id` are supplied, the orchestrator
    is bound to the owning organisation's authorised scan scope, so target
    expansion drops anything outside it. Callers that omit them get an unscoped
    orchestrator — acceptable only for paths that never expand targets, such as
    report generation.
    """
    orch = ScanOrchestrator(silent=False)
    if db is not None and (scan_id or user_id):
        try:
            _bind_scan_scope(db, orch, scan_id=scan_id, user_id=user_id)
        except Exception:
            # A scope that cannot be loaded must not silently become
            # "unrestricted". Deny-all is the safe failure here: the scan ends
            # with "no valid targets" rather than scanning whatever it likes.
            log.exception(
                "Could not load scan scope for scan=%s user=%s; denying all targets",
                scan_id,
                user_id,
            )
            orch.scan_scope = []
    return orch


def _bind_scan_scope(
    db,
    orch: ScanOrchestrator,
    scan_id: str | None = None,
    user_id: str | None = None,
) -> None:
    """
    Bind an orchestrator to an organisation's authorised scan scope.

    The scan row is the preferred source because it records the org the scan
    was admitted for. Falling back to the user's current org covers the
    traditional-scan path, which carries no scan id.
    """
    from core.scan_scope import org_scan_scope

    org_id = None
    if scan_id:
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        org_id = getattr(scan_row, "org_id", None) if scan_row is not None else None
    if not org_id and user_id:
        owner = platform_api.user(db, user_id)
        org_id = owner.org_id if owner is not None else None

    orch.apply_scan_scope(org_scan_scope(db, org_id) if org_id else None)


def _run_async(coro):
    """Run async scanner code safely from Celery worker threads or eager contexts."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import threading
        from concurrent.futures import Future

        future = Future()

        def run_in_thread():
            try:
                result = asyncio.run(coro)
                future.set_result(result)
            except BaseException as e:
                future.set_exception(e)

        thread = threading.Thread(target=run_in_thread)
        thread.start()
        return future.result()
    else:
        return asyncio.run(coro)


def _finalize_cancelled(
    db: SessionLocal, scan_id: str, user_id: str, phase: str
) -> None:
    """
    Settle a scan the user cancelled mid-flight.

    The API has already set status='cancelled'; what is left is to stamp the
    completion time, close out any phase row still marked running, and push a
    final progress frame so watching clients stop showing a live scan.
    """
    from core.redis_client import publish_progress_sync
    from scans.db_helpers import mark_scan_cancelled

    try:
        mark_scan_cancelled(db, scan_id, user_id, phase_key=phase)
    except Exception:
        log.exception("Could not finalize cancelled scan %s", scan_id)
        db.rollback()

    try:
        publish_progress_sync(scan_id, 1, {"status": "cancelled"})
    except Exception:
        log.debug("Could not publish cancellation for %s", scan_id, exc_info=True)


def _settle_failure(
    db: SessionLocal,
    scan_id: str,
    user_id: str,
    reason: str,
    status: str = "failed",
) -> None:
    """
    Record a scan failure, and guarantee that *something* is recorded.

    `mark_scan_failed` goes through the ORM — it loads the `Scan`, writes an
    audit event and raises a notification. That is the right thing to do and it
    shares a dependency with the code path that just failed.

    On 4 Sep 2026 a worker holding a stale `Scan` mapper raised
    `InvalidRequestError` on `run_host_discovery_task`'s first query. The
    `except` handler called `mark_scan_failed`, whose own first query raised the
    identical error, so the handler died too and the scan row was never touched.
    Three scans sat in 'running' forever while the target host was up the whole
    time — visible in the UI as a live scan stuck at 10%.

    So the ORM attempt is made first, because a proper failure carries the audit
    entry and the user's notification. If it raises for *any* reason, the scan
    is still settled through `force_terminal_status`, which issues plain SQL and
    touches no mapper. A worse-quality record beats no record: an unsettled scan
    is indistinguishable from a running one, and nothing downstream — the
    watchdog aside — will ever revisit it.
    """
    from core.redis_client import publish_progress_sync
    from core.scan_control import force_terminal_status

    try:
        mark_scan_failed(db, scan_id, user_id, reason, status=status)
    except Exception:
        log.exception(
            "mark_scan_failed could not settle scan %s — falling back to SQL",
            scan_id,
        )
        try:
            db.rollback()
        except Exception:
            pass
        force_terminal_status(scan_id, status=status, reason=reason)

    # Whichever route settled it, tell anyone watching. Without this a browser
    # on the live scan screen keeps showing a scan that is over until its own
    # client-side timeout fires.
    try:
        publish_progress_sync(
            scan_id, 1, {"status": status, "error": reason, "reason": reason}
        )
    except Exception:
        log.debug("Could not publish failure for scan %s", scan_id, exc_info=True)


def _check_cancelled(db: SessionLocal, scan_id: str) -> bool:
    """
    Check if the scan has been marked as cancelled in the DB.

    The ``db`` argument is accepted for call-site compatibility but deliberately
    unused: reading through the caller's session returns the status from that
    session's identity map, which is the snapshot taken when the task first
    loaded the row. That is what made Stop a no-op. ``is_cancelled`` opens its
    own session so it sees what the API actually committed.
    """
    from core.scan_control import is_cancelled

    return is_cancelled(scan_id)


def _update_task_id(db: SessionLocal, scan_id: str, task_id: str):
    """Update the current active task ID for the scan."""
    db.query(Scan).filter(Scan.id == scan_id).update({"current_task_id": task_id})
    db.commit()
