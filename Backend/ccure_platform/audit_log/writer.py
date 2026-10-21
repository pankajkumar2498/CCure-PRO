"""
core/audit.py
─────────────────────────────────────────────────────────────────────────────
The single write path for the audit trail.

The transaction contract
────────────────────────
``log_audit_event`` **raises** if the event cannot be written. It used to
swallow every exception, which meant a failed audit write produced a business
operation that succeeded with no record of it — the one outcome an audit
product must not have. Worse, it was not even a clean silence: the exception
came from ``db.flush()``, so the session was left in a failed state and the
caller's ``db.commit()`` raised anyway. The operator got a 500 *and* lost the
event.

Two rules follow, and both are load-bearing:

1. **Call it before the commit that covers the business change.** The audit
   row and the change it describes must be in the same transaction, so either
   both land or neither does. Calling it after that commit writes a row that
   is never committed — ``get_db`` closes its session without committing —
   which is a silent loss that raising cannot detect. (Phase 4.1 remediates
   the 21 call sites that are in exactly that shape.)

2. **Never call it from an ``except`` handler where raising would replace the
   error being handled.** A caller that must audit an outcome it is about to
   fail on needs its own session and its own ``try``/``except``; see
   ``routers/compliance._audit_refusal``, which swallows deliberately so the
   HTTPException it was about to raise still reaches the client.

**Do not open a second ``SessionLocal()`` to write an audit event while the
request's own transaction is open.** Once the tamper-evidence chain is
installed, the insert takes a ``FOR UPDATE`` lock on the organisation's row in
``audit_chain_heads`` and holds it until commit. A second session writing an
event for the same organisation would block on a lock its own request holds and
could never release. The chain trigger pins ``lock_timeout`` so this fails
loudly rather than hanging forever, but the pattern is prohibited rather than
merely survivable, and it must not spread beyond the one place it already
exists.

**Business mutations happen before the audit write**, which is what gives the
chain a consistent lock order: business rows first, chain head last. Every
current call site follows this. A path that audited first would hold the chain
head across its own work and could deadlock against one that did not.
"""

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "core.audit")


import logging
from typing import Optional, Protocol

from ccure_platform.audit_log.taxonomy import redact_changes, severity_for
from core.ip_resolver import get_client_ip
from ccure_platform.models import AuditLog, PlatformAuditEvent
from fastapi import Request
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class AuditActor(Protocol):
    """
    What the activity log reads from the account an event is attributed to,
    and nothing more. The authenticated principal a route holds satisfies it,
    and so does ``ccure_platform.api.UserView`` (Phase 8.3); the log never needed
    the identity model itself (Phase 8.5).
    """

    id: str
    org_id: str
    username: str


def log_audit_event(
    db: Session,
    user: Optional[AuditActor],
    action: str,
    resource_type: str = None,
    resource_id: str = None,
    changes: dict = None,
    request: Request = None,
    status: str = "success",
    severity: str = None,
    org_id: str = None,
    system_actor: str = None,
    event_id: str = None,
):
    """
    Write one audit event into the caller's transaction.

    ``org_id`` and ``system_actor`` exist for events with **no human actor** —
    at present only the retention purge, which runs on beat and acts on one
    organisation at a time. Without them a background task has no way to write
    an event at all: ``org_id`` is NOT NULL and half the primary key, and it is
    normally read from ``user``.

    They do not weaken the actorless guard. ``user=None`` with no ``org_id``
    still resolves to a NULL ``org_id`` and still fails loudly, which is what
    ``test_an_actorless_audit_call_fails_loudly_rather_than_silently`` asserts:
    an event nobody can attribute is worse than a visible error.

    ``system_actor`` is recorded in ``actor_username`` and is deliberately a
    *label*, not an identity — ``system:retention`` reads as what it is, and no
    account exists that could be confused with it.

    ``event_id`` lets a caller choose the row's id instead of taking the
    column's default. It exists for one case: the retention purge writes an
    anchor recording which audit event describes it, and that anchor is written
    inside a SECURITY DEFINER function that returns *before* this row exists.
    Generating the id first and handing it to both is what makes the anchor and
    the event it names a single atomic fact — there is no path that amends the
    anchor afterwards, and deliberately so: `ccure_user` holds no UPDATE on
    that table and must not.

    It does not weaken anything. The id is still a UUID4, the composite primary
    key still rejects a collision, and the chain trigger still overwrites
    ``prev_hash``/``record_hash`` unconditionally — a caller choosing an id
    gains no influence over the hash or the link.
    """
    ip_address = None
    user_agent = None
    request_id = None

    if request:
        ip_address = get_client_ip(request)
        user_agent = request.headers.get("user-agent")
        # Set by the request-ID middleware in main.py, which also stamps the
        # same value on the X-Request-ID response header and on every log line
        # the request emits. Carrying it here is what lets an audit event be
        # traced back to the API request and application logs that produced it.
        request_id = getattr(request.state, "request_id", None)

    try:
        log_entry = AuditLog(
            org_id=org_id or (user.org_id if user else None),
            user_id=user.id if user else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            # Redacted on the way in, never on display: masking at render time
            # would still leave the secret in the table, the backups, and
            # anything reading the column directly.
            changes=redact_changes(changes),
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            severity=severity or severity_for(action),
            request_id=request_id,
            # Frozen at write time. `user_id` above is a live foreign key that
            # is set to NULL when the account is deleted; these two carry no
            # foreign key, so the event stays attributable afterwards. They are
            # also what makes actor identity hashable — `user_id` cannot enter
            # the tamper-evidence chain precisely because a sanctioned account
            # deletion mutates it, which would break the chain for every event
            # that user ever produced.
            actor_user_id=user.id if user else None,
            actor_username=user.username if user else system_actor,
        )
        if event_id:
            # Set rather than passed to the constructor: assigning the
            # attribute suppresses the column's `gen_uuid` default, so the two
            # cannot both apply and there is still exactly one default.
            log_entry.id = event_id
        db.add(log_entry)
        # Not committed here: the caller owns the transaction, and the whole
        # point is that this row and the change it describes share one.
        db.flush()
    except Exception as exc:
        # Logged with enough to identify the event that was lost, then
        # re-raised. The log line matters because the exception propagates to
        # the caller's error handling, which will report a 500 without ever
        # naming the audit event as the cause.
        #
        # `user_id` and `org_id` are safe to log; the account named in a failed
        # login is deliberately not, for the same reason
        # `core/rate_limit_audit.py` omits it — writing it here would rebuild,
        # in the log file, the account-existence oracle the uniform 200 on
        # /auth/forgot-password exists to prevent.
        logger.error(
            "Audit write failed for action=%s resource=%s/%s org=%s actor=%s "
            "request_id=%s: %s: %s",
            action,
            resource_type,
            resource_id,
            getattr(user, "org_id", None),
            getattr(user, "id", None),
            request_id,
            exc.__class__.__name__,
            exc,
        )
        # The session is now in a failed state and the caller's commit cannot
        # succeed, which is the intended contract: no business change is
        # allowed to persist without its audit event. Deliberately no
        # `db.rollback()` here — rolling back would discard the caller's work
        # while returning control as though nothing had happened, and the
        # caller (or FastAPI's handler, via get_db closing the session) is what
        # decides how to unwind.
        raise


def log_platform_event(
    db: Session,
    action: str,
    *,
    actor: Optional[AuditActor] = None,
    system_actor: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    changes: dict | None = None,
    request: Request = None,
    severity: str | None = None,
):
    """
    Write one event that **no organisation owns** into the platform's own ledger.

    ``log_audit_event`` is tenant-bound — ``org_id`` is required and the chain is
    per organisation — so a catalogue sync, a platform-scope role change or the
    default role being re-pointed has nowhere to go in it without borrowing an
    organisation, which would write a false statement into that tenant's trail.
    The caller decides *attribution*: an event with an owning organisation goes
    through ``log_audit_event`` in that organisation; one without goes here.
    (``ccure_platform.rbac.audit.emit`` makes that choice; see
    ``docs/architecture/RBAC_FOUNDATION.md`` §10.)

    The transaction contract is ``log_audit_event``'s: the row joins the caller's
    transaction, nothing is committed here, and a failed write **raises** — a
    platform change must not persist without its record.

    ``actor`` is a signed-in account; ``system_actor`` is a label for an event
    with no human behind it (``system:rbac-sync``). Exactly one is required.
    """
    if (actor is None) == (system_actor is None):
        raise ValueError("a platform event needs exactly one of actor or system_actor")
    request_id = getattr(request.state, "request_id", None) if request else None
    try:
        row = PlatformAuditEvent(
            action=action,
            severity=severity or severity_for(action),
            actor_kind="user" if actor is not None else "system",
            actor_user_id=actor.id if actor is not None else None,
            actor_label=actor.username if actor is not None else system_actor,
            actor_org_id=getattr(actor, "org_id", None) if actor is not None else None,
            resource_type=resource_type,
            resource_id=resource_id,
            changes=redact_changes(changes),
            request_id=request_id,
        )
        db.add(row)
        db.flush()
    except Exception as exc:
        logger.error(
            "Platform audit write failed for action=%s resource=%s/%s actor=%s: %s: %s",
            action,
            resource_type,
            resource_id,
            getattr(actor, "id", None) or system_actor,
            exc.__class__.__name__,
            exc,
        )
        raise
    return row
