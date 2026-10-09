"""
core/audit_retention.py
─────────────────────────────────────────────────────────────────────────────
Phase 6a. The application-side half of audit-log retention: preconditions,
orchestration and reporting. The half that can actually delete a row lives in
``audit_retention.purge_legacy_v1`` — a SECURITY DEFINER function owned by a
role this process cannot become, installed by
``scripts/audit/bootstrap_chain_retention.sql``.

That split is the whole safety model, and it is deliberate that the rules are
duplicated across it. Everything checked here — retention enabled, the cutoff
floor, a recent backup, no hold — is checked **again inside the function**,
where the caller cannot reach it. This module refusing is a convenience so an
operator gets a clear message; the function refusing is the control. A bug
here cannot widen what the database permits.

**Legacy only.** The purge predicate is ``record_hash IS NULL``, and the
append-only trigger independently refuses a maintenance DELETE of any row that
has a hash. During phase 6a a chained row cannot be deleted by this path even
if every line of Python below were wrong.

What a legacy anchor is
───────────────────────
An accounting record: which organisation, which range, how many rows, what the
chain head looked like afterwards. **Not** continuity evidence and **not** a
copy of what was removed. Legacy rows have no ``record_hash``, so nothing ever
linked to them and there is nothing to verify against later. Phase 6b, where
anchors do carry continuity evidence for chained rows, is a separate approval.

Advisory locking against exports
────────────────────────────────
An export counts, tallies and then streams — up to half a minute at the row
cap. A purge landing in the middle of that would remove rows the header has
already counted, producing a file that contradicts itself.

So the export takes a **shared** lock and the purge takes an **exclusive**,
**non-blocking** one: a purge that cannot get it defers that organisation to
the next run rather than waiting, because retention is daily and deferring is
free while blocking a purge behind a stalled download is not.

**Transaction-scoped, never session-scoped.** ``pg_advisory_lock`` releases
when the *connection* closes, and SQLAlchemy pools connections — a
session-level lock taken by a request would survive being returned to the pool
and leak onto the next unrelated request that happened to draw the same
connection. ``pg_advisory_xact_lock`` always releases on COMMIT or ROLLBACK.
"""

from __future__ import annotations

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "core.audit_retention")


import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config import AppConfig
from db.base import gen_uuid
from ccure_platform.audit_log.export import VERIFICATION_PERFORMED
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError

log = logging.getLogger("ccure.audit.retention")

#: Namespace for this feature's advisory locks. Arbitrary but fixed: two
#: features picking the same (classid, objid) pair would block each other for
#: no reason anybody could see.
RETENTION_LOCK_CLASS = 4207

#: Key used by an export that is not scoped to one organisation — a superadmin
#: reading the whole trail. It cannot decompose per-org, so it takes one lock
#: that every purge also acquires.
GLOBAL_LOCK_KEY = 0

#: Written into `actor_username`. A label, not an account: no user exists that
#: could be confused with it, and the colon makes that visible at a glance.
SYSTEM_ACTOR = "system:retention"

_BACKUP_SUFFIXES = (".dump", ".backup", ".sql", ".sql.gz")


class RetentionRefused(Exception):
    """A precondition failed. Carries a message meant for an operator."""


# ─── Installation state ──────────────────────────────────────────────────────


def retention_installed(conn) -> dict:
    """
    Whether the privileged half is present, reported in enough detail to act on.

    A dict rather than a bool for the same reason ``chain_objects_installed``
    is one: "not installed" and "installed but the role is missing" need
    different responses, and collapsing them to False would send an operator
    looking in the wrong place.
    """
    state = {
        "schema": False,
        "purge_function": False,
        "preview_function": False,
        "anchors": False,
        "holds": False,
        "role": False,
        "installed": False,
    }

    state["schema"] = bool(
        conn.execute(
            text("SELECT 1 FROM pg_namespace WHERE nspname = 'audit_retention'")
        ).scalar()
    )
    state["role"] = bool(
        conn.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = 'audit_maintenance'")
        ).scalar()
    )
    state["anchors"] = bool(
        conn.execute(
            text("SELECT to_regclass('audit_retention.retention_anchors')")
        ).scalar()
    )
    state["holds"] = bool(
        conn.execute(
            text("SELECT to_regclass('audit_retention.retention_holds')")
        ).scalar()
    )
    for key, name in (
        ("purge_function", "purge_legacy_v1"),
        ("preview_function", "preview_legacy_v1"),
    ):
        state[key] = bool(
            conn.execute(
                text(
                    "SELECT 1 FROM pg_proc p JOIN pg_namespace n "
                    "  ON n.oid = p.pronamespace "
                    " WHERE n.nspname = 'audit_retention' AND p.proname = :f"
                ),
                {"f": name},
            ).scalar()
        )

    state["installed"] = all(
        state[k]
        for k in (
            "schema",
            "role",
            "anchors",
            "holds",
            "purge_function",
            "preview_function",
        )
    )
    return state


def chained_retention_installed(conn) -> bool:
    """Whether the phase-6c half is present. Separate from 6a on purpose.

    A database may legitimately carry legacy retention and not chained
    retention -- that was the state throughout phases 6a and 6b -- and the
    difference has to be reportable rather than collapsed into one boolean.
    """
    return bool(
        conn.execute(
            text(
                "SELECT 1 FROM pg_proc p JOIN pg_namespace n "
                "  ON n.oid = p.pronamespace "
                " WHERE n.nspname = 'audit_retention' "
                "   AND p.proname = 'purge_chained_v1'"
            )
        ).scalar()
    )


CHAINED_NOT_INSTALLED_HINT = (
    "Chained-record retention is not installed in this database. A database "
    "administrator must run, as a superuser:\n"
    "    psql -v ON_ERROR_STOP=1 -f "
    "Backend/scripts/audit/bootstrap_chain_retention_chained.sql\n"
    "Until then only pre-chain rows can be removed, which is the safe default."
)


NOT_INSTALLED_HINT = (
    "Audit retention is not installed in this database. A database "
    "administrator must run, as a superuser:\n"
    "    psql -v ON_ERROR_STOP=1 -f "
    "Backend/scripts/audit/bootstrap_chain_retention.sql\n"
    "Until then no purge can run, which is the safe direction."
)


# ─── Preconditions ───────────────────────────────────────────────────────────


def resolve_cutoff(now: datetime | None = None) -> datetime:
    """
    The instant before which a legacy row becomes eligible.

    Raises rather than returning something usable when retention is disabled or
    the configured period is below the floor. ``AUDIT_LOG_RETENTION_DAYS`` is
    operator-supplied and a typo in it — "9" for "90" — is not recoverable,
    because audit rows do not come back. The floor turns that typo into an
    error message instead of a data loss.
    """
    days = AppConfig.AUDIT_LOG_RETENTION_DAYS
    floor = AppConfig.AUDIT_RETENTION_MIN_DAYS

    if days <= 0:
        raise RetentionRefused(
            "AUDIT_LOG_RETENTION_DAYS is 0: retention is disabled and no purge "
            "will run. Set it only to a period agreed with the business or "
            "compliance owner."
        )
    if days < floor:
        raise RetentionRefused(
            f"AUDIT_LOG_RETENTION_DAYS={days} is below the "
            f"AUDIT_RETENTION_MIN_DAYS={floor} floor. The floor is not "
            f"overridable by the same setting it guards."
        )

    return (now or datetime.now(timezone.utc)) - timedelta(days=days)


def newest_backup(directory: str | None = None) -> tuple[Path | None, float | None]:
    """The most recent dump in the backup directory, and its age in hours."""
    target = Path(directory or AppConfig.AUDIT_RETENTION_BACKUP_DIR)
    if not target.is_dir():
        return None, None

    newest: Path | None = None
    newest_mtime = -1.0
    for entry in target.iterdir():
        if not entry.is_file():
            continue
        if not any(entry.name.endswith(suffix) for suffix in _BACKUP_SUFFIXES):
            continue
        mtime = entry.stat().st_mtime
        if mtime > newest_mtime:
            newest, newest_mtime = entry, mtime

    if newest is None:
        return None, None
    # `time.time()` rather than `datetime.now().timestamp()`: st_mtime is a
    # POSIX timestamp, and comparing it against a naive local datetime works
    # only by coincidence of both being local.
    age_hours = (time.time() - newest_mtime) / 3600.0
    return newest, age_hours


def assert_backup_recent() -> str:
    """
    Refuse to purge without a recent dump. Returns a reference to record.

    A hard precondition, not a warning. `archive_mode` is off on this
    deployment, so recovery granularity is "since the last dump" — without one
    a purge is simply unrecoverable, and a warning nobody reads is not a
    control. Setting the window to 0 disables the check and says so loudly,
    because an operator who turns off the last safeguard should see it in the
    log rather than discover it afterwards.
    """
    window = AppConfig.AUDIT_RETENTION_REQUIRE_BACKUP_HOURS
    if window <= 0:
        log.warning(
            "AUDIT_RETENTION_REQUIRE_BACKUP_HOURS=0: the backup precondition is "
            "DISABLED. An audit purge is irreversible and archive_mode is off, "
            "so there may be no recovery point."
        )
        return "backup check disabled"

    path, age = newest_backup()
    if path is None:
        raise RetentionRefused(
            f"No database dump found in "
            f"{AppConfig.AUDIT_RETENTION_BACKUP_DIR!r}. An audit purge is "
            f"irreversible; take one first:\n"
            f"    scripts/backup_db.sh --skip-reference-data"
        )
    if age > window:
        raise RetentionRefused(
            f"The newest dump ({path.name}) is {age:.1f} hours old, older than "
            f"the {window}-hour requirement. Take a fresh backup before purging."
        )
    return f"{path.name} ({age:.1f}h old)"


# ─── Advisory locks ──────────────────────────────────────────────────────────


def _org_key(conn, org_id: str) -> int:
    return conn.execute(text("SELECT hashtext(:o)"), {"o": org_id}).scalar()


def take_export_lock(conn, org_id: str | None) -> None:
    """
    Shared, transaction-scoped. Held for the life of the caller's transaction.

    ``org_id`` is None for a superadmin export that is not scoped to one
    tenant; it cannot decompose per organisation, so it takes the global key
    that every purge also acquires. That is deliberately broader than needed —
    it defers purges of organisations the export may not even touch — and it is
    the safe direction: the cost is a skipped nightly run.
    """
    key = GLOBAL_LOCK_KEY if org_id is None else _org_key(conn, org_id)
    conn.execute(
        text("SELECT pg_advisory_xact_lock_shared(:c, :k)"),
        {"c": RETENTION_LOCK_CLASS, "k": key},
    )


def try_take_purge_lock(conn, org_id: str) -> bool:
    """
    Exclusive and **non-blocking**, on both this organisation's key and the
    global one.

    Non-blocking on purpose. An export streams to a client that may be slow or
    may have stopped reading altogether; a purge that waited would sit holding
    nothing useful until its lock_timeout fired, in a nightly job nobody is
    watching. Returning False lets the run report "deferred, export in
    progress" and try again tomorrow.
    """
    for key in (_org_key(conn, org_id), GLOBAL_LOCK_KEY):
        got = conn.execute(
            text("SELECT pg_try_advisory_xact_lock(:c, :k)"),
            {"c": RETENTION_LOCK_CLASS, "k": key},
        ).scalar()
        if not got:
            return False
    return True


# ─── Holds ───────────────────────────────────────────────────────────────────


def active_holds(conn) -> dict[str, str]:
    """Organisation -> reason, for every hold not yet released."""
    return {
        row[0]: row[1]
        for row in conn.execute(
            text(
                "SELECT org_id, reason FROM audit_retention.retention_holds "
                " WHERE released_at IS NULL ORDER BY org_id"
            )
        )
    }


# ─── Preview ─────────────────────────────────────────────────────────────────


def preview(conn, cutoff: datetime) -> list[dict]:
    """What a purge at this cutoff would remove, per organisation. Read-only."""
    rows = conn.execute(
        text(
            "SELECT org_id, eligible_count, oldest, newest, on_hold, "
            "       legacy_total, chained_total "
            "  FROM audit_retention.preview_legacy_v1(:c)"
        ),
        {"c": cutoff},
    ).fetchall()
    return [
        {
            "org_id": r.org_id,
            "eligible_count": r.eligible_count,
            "oldest": r.oldest,
            "newest": r.newest,
            "on_hold": r.on_hold,
            "legacy_total": r.legacy_total,
            "chained_total": r.chained_total,
        }
        for r in rows
    ]


# ─── The run ─────────────────────────────────────────────────────────────────


#: Sentinel distinguishing "this organisation has no chain head" from any other
#: failure. A bare `except Exception` here would swallow a genuine error --
#: a privilege problem, a lock timeout, a constraint violation -- and report it
#: as a routine skip, which is exactly how a broken purge would go unnoticed.
_NO_CHAIN_HEAD = object()

#: SQLSTATE raised by `audit_chain_lock_head_v1` when the organisation has no
#: head row. `no_data_found` in PL/pgSQL.
_NO_DATA_FOUND = "P0002"


def _call_purge(
    db, org_id: str, cutoff, batch: int, operator: str, backup_ref: str, event_id: str
):
    """Invoke the purge function, separating "no head" from every other error.

    ``event_id`` is the id of the ``audit.retention_purge_executed`` event this
    batch is about to write, generated **before** the call. The anchor records
    it, so an anchor can be resolved to the event that describes it -- and the
    two are written in one transaction, so a dangling reference is impossible.

    It used to be NULL, because the anchor is written inside a SECURITY DEFINER
    function that returns before the event exists and nothing may amend the
    anchor afterwards: `ccure_user` holds no UPDATE on that table and must not.
    Choosing the id first is what resolves that without a new privilege.
    """
    try:
        return db.execute(
            text(
                "SELECT deleted_count, anchor_id, range_from, range_to, "
                "       legacy_remaining "
                "  FROM audit_retention.purge_legacy_v1("
                "       :org, :cutoff, :batch, :floor, :operator, :event, :backup)"
            ),
            {
                "org": org_id,
                "cutoff": cutoff,
                "batch": batch,
                "floor": AppConfig.AUDIT_RETENTION_MIN_DAYS,
                "operator": operator,
                "event": event_id,
                "backup": backup_ref,
            },
        ).fetchone()
    except DatabaseError as exc:
        if getattr(getattr(exc, "orig", None), "pgcode", None) == _NO_DATA_FOUND:
            return _NO_CHAIN_HEAD
        raise


def _purge_one_batch(
    db,
    org_id: str,
    cutoff: datetime,
    batch: int,
    operator: str,
    backup_ref: str,
) -> dict:
    """
    One batch, one transaction: anchor, delete and audit event together.

    The audit event is written **before** the commit that covers the deletion,
    which is the same contract every request handler follows — the row and the
    change it describes share one transaction, so either both land or neither
    does. A failure anywhere in here rolls back the anchor, the deletion and
    the event as one.

    **The advisory lock is taken here, per batch, not once around the run.**
    It is transaction-scoped, and the commit at the end of each batch releases
    it — so a lock acquired once at the top of the run would silently cover
    only the first batch and every batch after it would race an export. Taking
    it per batch also means an export that starts mid-run defers the *rest* of
    the purge rather than being raced by it.
    """
    from ccure_platform.audit_log.writer import log_audit_event

    if not try_take_purge_lock(db, org_id):
        db.rollback()
        return {
            "deleted": 0,
            "anchor_id": None,
            "exhausted": True,
            "deferred": True,
            "no_head": False,
        }

    # Chosen before the purge runs so the anchor can name it. If the batch
    # turns out to be empty, or the transaction rolls back, the id is simply
    # discarded -- it is a UUID4 and nothing has been written under it.
    event_id = gen_uuid()

    result = _call_purge(db, org_id, cutoff, batch, operator, backup_ref, event_id)

    if result is _NO_CHAIN_HEAD:
        # An organisation with pre-chain rows but no chain head. The purge
        # cannot run for it -- there is no head to lock, and locking the head is
        # what stops a purge interleaving with an insert -- so it is skipped and
        # reported.
        #
        # It must not abort the run. Retention is a nightly job over every
        # tenant, and one tenant in an unexpected state taking the other
        # tenants' retention down with it is the wrong failure mode: the
        # backlog for everyone else silently stops draining. Failing closed for
        # the one organisation and continuing is both safer and more visible.
        #
        # A correctly bootstrapped database cannot reach this state --
        # `audit_chain_seed_legacy_v1` creates a head for every organisation
        # holding unhashed rows -- so it means either a tenant created after
        # that seeding whose rows arrived out of band, or a head that was
        # removed. Either is worth an operator seeing.
        db.rollback()
        log.warning(
            "audit retention: organisation %s has pre-chain rows but no chain "
            "head; skipping it. No rows were removed for this tenant. Every "
            "other organisation in this run is unaffected.",
            org_id,
        )
        return {
            "deleted": 0,
            "anchor_id": None,
            "exhausted": True,
            "deferred": False,
            "no_head": True,
        }

    deleted = int(result.deleted_count or 0)
    if deleted == 0:
        db.rollback()
        return {"deleted": 0, "anchor_id": None, "exhausted": True, "deferred": False}

    log_audit_event(
        db,
        None,
        "audit.retention_purge_executed",
        resource_type="audit_log",
        resource_id=str(result.anchor_id),
        changes={
            "kind": "legacy",
            "deleted_count": deleted,
            "cutoff": cutoff.isoformat(),
            "range_from": result.range_from.isoformat() if result.range_from else None,
            "range_to": result.range_to.isoformat() if result.range_to else None,
            "anchor_id": result.anchor_id,
            "legacy_remaining": result.legacy_remaining,
            "backup_reference": backup_ref,
            "operator": operator,
        },
        org_id=org_id,
        system_actor=SYSTEM_ACTOR,
        # The same id the anchor recorded a moment ago, in this transaction.
        event_id=event_id,
    )
    db.commit()

    return {
        "deleted": deleted,
        "anchor_id": result.anchor_id,
        "audit_event_id": event_id,
        "legacy_remaining": result.legacy_remaining,
        "exhausted": deleted < batch,
        "deferred": False,
    }


# ─── Chained retention (phase 6c) ────────────────────────────────────────────


class ArchiveUnacceptable(RetentionRefused):
    """The nominated export cannot authorise a chained purge."""


def describe_archive(db, event_id: str) -> dict:
    """
    Read the nominated ``audit.log_exported`` event and say whether it qualifies.

    Returns a dict with ``acceptable`` and a ``reason`` when it is not, rather
    than raising, so a **dry run can report why an archive would be rejected
    without refusing to run at all**. The mutating path raises; the preview
    explains.

    Every rule here is enforced again inside ``purge_chained_v1``, where the
    caller cannot reach it. This is the courtesy copy, not the control.
    """
    row = (
        db.execute(
            text(
                "SELECT id, action, changes, created_at, org_id "
                "  FROM public.audit_logs WHERE id = :i LIMIT 1"
            ),
            {"i": event_id},
        )
        .mappings()
        .fetchone()
    )

    if row is None:
        return {"acceptable": False, "reason": f"no event with id {event_id!r}"}
    if row["action"] != "audit.log_exported":
        return {
            "acceptable": False,
            "reason": f"event {event_id} is a {row['action']}, not an export",
        }

    changes = row["changes"] or {}
    mode = changes.get("verification_mode")
    failures = changes.get("integrity_failures")

    if mode != VERIFICATION_PERFORMED:
        return {
            "acceptable": False,
            "reason": (
                f"export {event_id} was not verified (verification_mode="
                f"{mode!r}). A chained purge requires verify=true."
            ),
        }
    if failures != 0:
        return {
            "acceptable": False,
            "reason": (
                f"export {event_id} reported {failures} integrity failure(s); "
                f"it cannot authorise a purge"
            ),
        }

    return {
        "acceptable": True,
        "event_id": row["id"],
        "exported_at": row["created_at"],
        "row_count": changes.get("row_count"),
        "verified": changes.get("verified"),
        "format": changes.get("format"),
        "snapshot_upper_bound": changes.get("snapshot_upper_bound"),
    }


def _purge_one_chained_batch(
    db,
    org_id: str,
    cutoff,
    batch: int,
    operator: str,
    backup_ref: str,
    archive_event: str,
    archive_sha256: str,
) -> dict:
    """One chained batch, committed. Same contract as the legacy path.

    The archive is validated **again** inside the SQL function; the check in
    ``run_chained_retention`` is there so an operator gets the reason before
    anything is attempted, not instead of the control.
    """
    from ccure_platform.audit_log.writer import log_audit_event

    if not try_take_purge_lock(db, org_id):
        db.rollback()
        return {"deleted": 0, "anchor_id": None, "exhausted": True, "deferred": True}

    event_id = gen_uuid()

    result = db.execute(
        text(
            "SELECT deleted_count, anchor_id, range_from, range_to, "
            "       new_genesis, events_remaining "
            "  FROM audit_retention.purge_chained_v1("
            "       :org, :cutoff, :batch, :floor, :archive, :sha, "
            "       :operator, :event, :backup)"
        ),
        {
            "org": org_id,
            "cutoff": cutoff,
            "batch": batch,
            "floor": AppConfig.AUDIT_RETENTION_MIN_DAYS,
            "archive": archive_event,
            "sha": archive_sha256,
            "operator": operator,
            "event": event_id,
            "backup": backup_ref,
        },
    ).fetchone()

    deleted = int(result.deleted_count or 0)
    if deleted == 0:
        db.rollback()
        return {"deleted": 0, "anchor_id": None, "exhausted": True, "deferred": False}

    log_audit_event(
        db,
        None,
        "audit.retention_purge_executed",
        resource_type="audit_log",
        resource_id=str(result.anchor_id),
        changes={
            "kind": "chained",
            "deleted_count": deleted,
            "cutoff": cutoff.isoformat(),
            "range_from": result.range_from.isoformat() if result.range_from else None,
            "range_to": result.range_to.isoformat() if result.range_to else None,
            "anchor_id": result.anchor_id,
            "new_genesis": result.new_genesis,
            "events_remaining": result.events_remaining,
            "archive_event_id": archive_event,
            "archive_sha256": archive_sha256,
            "backup_reference": backup_ref,
            "operator": operator,
        },
        org_id=org_id,
        system_actor=SYSTEM_ACTOR,
        event_id=event_id,
    )
    db.commit()

    return {
        "deleted": deleted,
        "anchor_id": result.anchor_id,
        "audit_event_id": event_id,
        "new_genesis": result.new_genesis,
        "events_remaining": result.events_remaining,
        "exhausted": deleted < batch,
        "deferred": False,
    }


def run_chained_retention(
    db,
    org_id: str,
    archive_event: str,
    archive_sha256: str,
    *,
    dry_run: bool = True,
    operator: str | None = None,
    now: datetime | None = None,
) -> dict:
    """
    Remove chained rows for **one** organisation, oldest first, under an archive.

    Deliberately per-organisation and never a sweep. A legacy purge can run
    across every tenant unattended because the rows it removes carry no
    cryptographic evidence and nothing links to them. This one destroys rows
    that do, so it requires a named archive that a person nominated — and an
    archive is specific to the tenant whose trail it contains.

    **Dry run is the default and writes nothing.** It reports what would go and
    whether the archive qualifies, and touches no row.
    """
    state = retention_installed(db)
    if not state["installed"]:
        raise RetentionRefused(NOT_INSTALLED_HINT)
    if not chained_retention_installed(db):
        raise RetentionRefused(CHAINED_NOT_INSTALLED_HINT)

    cutoff = resolve_cutoff(now)
    operator = operator or f"{SYSTEM_ACTOR}@{os.environ.get('HOSTNAME', 'unknown')}"
    archive = describe_archive(db, archive_event)

    eligible = db.execute(
        text(
            "SELECT count(*) FROM public.audit_logs "
            " WHERE org_id = :o AND record_hash IS NOT NULL AND created_at < :c"
        ),
        {"o": org_id, "c": cutoff},
    ).scalar()

    holds = active_holds(db)
    report = {
        "dry_run": dry_run,
        "kind": "chained",
        "org_id": org_id,
        "cutoff": cutoff.isoformat(),
        "archive": archive,
        "on_hold": org_id in holds,
        "eligible_by_age": eligible,
        "deleted_total": 0,
        "batches": [],
        "backup_reference": None,
        "deferred": False,
    }

    if dry_run:
        report["would_delete_total"] = 0 if report["on_hold"] else eligible
        log.info(
            "chained retention DRY RUN for %s: %s row(s) older than the cutoff, "
            "archive acceptable=%s. Nothing was written.",
            org_id,
            eligible,
            archive["acceptable"],
        )
        return report

    if not archive["acceptable"]:
        raise ArchiveUnacceptable(archive["reason"])
    if report["on_hold"]:
        raise RetentionRefused(f"organisation {org_id} is under a retention hold")

    report["backup_reference"] = assert_backup_recent()

    budget = AppConfig.AUDIT_RETENTION_MAX_ROWS_PER_RUN
    batch_size = AppConfig.AUDIT_RETENTION_BATCH_SIZE

    while budget > 0:
        batch = min(batch_size, budget)
        try:
            outcome = _purge_one_chained_batch(
                db,
                org_id,
                cutoff,
                batch,
                operator,
                report["backup_reference"],
                archive_event,
                archive_sha256,
            )
        except Exception:
            db.rollback()
            log.exception(
                "chained retention: batch failed for %s; the anchor, the "
                "deletion and the audit event were all rolled back",
                org_id,
            )
            raise

        if outcome["deferred"]:
            report["deferred"] = True
            break
        if not outcome["deleted"]:
            break

        report["batches"].append(
            {
                "deleted": outcome["deleted"],
                "anchor_id": outcome["anchor_id"],
                "new_genesis": outcome["new_genesis"],
            }
        )
        report["deleted_total"] += outcome["deleted"]
        budget -= outcome["deleted"]
        if outcome["exhausted"]:
            break

    log.info(
        "chained retention: removed %s row(s) from %s across %s batch(es) under "
        "archive %s",
        report["deleted_total"],
        org_id,
        len(report["batches"]),
        archive_event,
    )
    return report


def run_retention(
    db,
    *,
    dry_run: bool = True,
    operator: str | None = None,
    now: datetime | None = None,
) -> dict:
    """
    The whole run. Returns a report; raises ``RetentionRefused`` on a
    precondition failure rather than silently doing nothing.

    **Dry run is the default and writes nothing at all** — no delete, no
    anchor, no head update, no audit event. It reaches the read-only preview
    function and stops there. The mutating path is entered only when a caller
    passes ``dry_run=False`` explicitly, which the CLI requires ``--apply`` for
    and the beat task takes from ``AUDIT_RETENTION_DRY_RUN``.
    """
    state = retention_installed(db)
    if not state["installed"]:
        raise RetentionRefused(NOT_INSTALLED_HINT)

    cutoff = resolve_cutoff(now)
    operator = operator or f"{SYSTEM_ACTOR}@{os.environ.get('HOSTNAME', 'unknown')}"

    rows = preview(db, cutoff)
    eligible = {
        row["org_id"]: row
        for row in rows
        if row["eligible_count"] and not row["on_hold"]
    }
    held = {row["org_id"]: row for row in rows if row["on_hold"]}

    report = {
        "dry_run": dry_run,
        "cutoff": cutoff.isoformat(),
        "retention_days": AppConfig.AUDIT_LOG_RETENTION_DAYS,
        "floor_days": AppConfig.AUDIT_RETENTION_MIN_DAYS,
        "batch_size": AppConfig.AUDIT_RETENTION_BATCH_SIZE,
        "max_rows": AppConfig.AUDIT_RETENTION_MAX_ROWS_PER_RUN,
        "preview": rows,
        "eligible_orgs": sorted(eligible),
        # Reported, never silent. "Nothing was deleted for this tenant" and
        # "this tenant is under hold" are different facts and an operator
        # needs to be able to tell them apart.
        "held_orgs": {org: row for org, row in held.items()},
        "deferred_orgs": [],
        # Organisations skipped because they carry pre-chain rows but no chain
        # head. Reported rather than silent: a correctly bootstrapped database
        # cannot reach that state, so seeing one here means something is worth
        # looking at.
        "no_head_orgs": [],
        "purged": {},
        "deleted_total": 0,
        "backup_reference": None,
        "capped": False,
    }

    if dry_run:
        report["would_delete_total"] = sum(
            row["eligible_count"] for row in eligible.values()
        )
        log.info(
            "audit retention DRY RUN: would delete %s legacy row(s) across %s "
            "organisation(s) at cutoff %s. Nothing was written.",
            report["would_delete_total"],
            len(eligible),
            cutoff.isoformat(),
        )
        return report

    # Everything below mutates. The backup check is deliberately here and not
    # above: a dry run must never be refused for want of a backup, because a
    # dry run is exactly what an operator does *before* taking one.
    report["backup_reference"] = assert_backup_recent()

    budget = AppConfig.AUDIT_RETENTION_MAX_ROWS_PER_RUN
    batch_size = AppConfig.AUDIT_RETENTION_BATCH_SIZE

    for org_id in sorted(eligible):
        if budget <= 0:
            report["capped"] = True
            break

        org_deleted = 0
        while budget > 0:
            batch = min(batch_size, budget)
            try:
                outcome = _purge_one_batch(
                    db, org_id, cutoff, batch, operator, report["backup_reference"]
                )
            except Exception:
                db.rollback()
                log.exception(
                    "audit retention: batch failed for %s; the anchor, the "
                    "deletion and the audit event were all rolled back",
                    org_id,
                )
                raise

            if outcome.get("no_head"):
                if org_id not in report["no_head_orgs"]:
                    report["no_head_orgs"].append(org_id)
                break

            if outcome["deferred"]:
                if org_id not in report["deferred_orgs"]:
                    report["deferred_orgs"].append(org_id)
                log.info(
                    "audit retention: deferring %s, an export holds the shared "
                    "lock. It will be retried on the next run.",
                    org_id,
                )
                break

            org_deleted += outcome["deleted"]
            budget -= outcome["deleted"]
            if outcome["exhausted"]:
                break

        if org_deleted:
            report["purged"][org_id] = org_deleted
            report["deleted_total"] += org_deleted

    if budget <= 0:
        report["capped"] = True

    log.info(
        "audit retention: deleted %s legacy row(s) across %s organisation(s); "
        "%s deferred, %s held, %s without a chain head, capped=%s",
        report["deleted_total"],
        len(report["purged"]),
        len(report["deferred_orgs"]),
        len(report["held_orgs"]),
        len(report["no_head_orgs"]),
        report["capped"],
    )
    return report
