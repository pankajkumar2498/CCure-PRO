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

import logging

from core.audit_taxonomy import redact_changes, severity_for
from core.ip_resolver import get_client_ip
from db.models import AuditLog, User
from fastapi import Request
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def log_audit_event(
    db: Session,
    user: User,
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
