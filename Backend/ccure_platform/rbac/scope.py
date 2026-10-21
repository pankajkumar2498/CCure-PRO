"""
ccure_platform/rbac/scope.py — where a principal may act (final cutover, RBAC-8).

Permission answers WHAT; scope answers WHERE. The engine separates them: platform grants
versus organisation grants, the home organisation, and ``platform.organization.switch``
for any other. This module is the backend seam that asks the engine the *where* question.

* **Platform** — a grant of a platform-scope permission, held through a platform-scope
  assignment; it says nothing about organisations by itself.
* **Organisation** — a grant held through an organisation-scope assignment applies in that
  organisation only.
* **Cross-organisation** — acting in an organisation other than the home one needs the
  platform-scope grant of ``platform.organization.switch``; an organisation-scoped
  permission never reaches another tenant (an organisation administrator stays in its
  organisation), and superadmin has no shortcut — it holds the switch through grants.

A client-named organisation is a *request*, never evidence: it is honoured only with
reach, for an organisation that exists and is active, and the entry is audited
(``rbac.org_switch.entered``, owned by the entered organisation). Without reach it is
ignored (the home organisation is used) and recorded (``rbac.scope.denied``). Fail closed:
a missing organisation is 404, an inactive one 403; an account with no RBAC assignment has
no reach; if the switch cannot be audited it is refused (503).
"""

from __future__ import annotations

import logging

from ccure_platform.rbac import contract as c
from ccure_platform.rbac import engine, resolver
from fastapi import HTTPException
from sqlalchemy.orm import object_session

logger = logging.getLogger("ccure.rbac.scope")

ORG_ACTIVE, ORG_INACTIVE, ORG_MISSING = "active", "inactive", "missing"


def organisation_state(db, org_id: str | None) -> str:
    """``active`` | ``inactive`` | ``missing``. An empty id is missing."""
    if not org_id:
        return ORG_MISSING
    from ccure_platform.models import Organization

    row = (
        db.query(Organization.is_active).filter(Organization.id == str(org_id)).first()
    )
    if row is None:
        return ORG_MISSING
    return ORG_ACTIVE if row[0] else ORG_INACTIVE


class _Session:
    """The request's own session when the account is attached to one, else a
    short-lived read-only one."""

    def __init__(self, user):
        self.user = user
        self.own = False
        self.db = object_session(user)

    def __enter__(self):
        if self.db is None:
            from db.base import SessionLocal

            self.db, self.own = SessionLocal(), True
        return self.db

    def __exit__(self, *exc):
        if self.own:
            self.db.rollback()
            self.db.close()


def _reach(db, user) -> bool:
    """Whether the engine lets the account act outside its home organisation: the
    platform-scope grant of the switch permission. No catalogue or no assignment means no
    reach."""
    principal = resolver.principal_for_user(user)
    catalogue = resolver.load_catalogue(db)
    if not catalogue:
        return False
    grants = resolver.resolve_grants(db, principal)
    return engine.decide(principal, grants, catalogue, c.ORG_SWITCH_KEY).allowed


def acts_across_organisations(user) -> bool:
    """May this account look up or act on resources in organisations other than its
    own? ``platform.organization.switch``, held platform-wide."""
    try:
        with _Session(user) as db:
            return _reach(db, user)
    except Exception:  # noqa: BLE001 - fail closed
        logger.warning("scope reach could not be determined; denied", exc_info=True)
        return False


#: Tests inject the session an event is written on (their data lives in a
#: transaction a second session cannot see). Never set in a running application.
_audit_session = None


def use_audit_session(db):
    """Write scope events on ``db`` instead of a session of their own. Tests only."""
    import contextlib

    @contextlib.contextmanager
    def _cm():
        global _audit_session
        previous, _audit_session = _audit_session, db
        try:
            yield db
        finally:
            _audit_session = previous

    return _cm()


def _audit(user, draft_builder) -> bool:
    """Write one event in its own transaction so it survives the request (a read
    request commits nothing). Returns False if it could not be written."""
    try:
        from ccure_platform.rbac.audit import emit

        if _audit_session is not None:
            emit(_audit_session, [draft_builder()], actor=user)
            return True
        from db.base import SessionLocal

        session = SessionLocal()
        try:
            actor = session.get(type(user), user.id)
            emit(session, [draft_builder()], actor=actor)
            session.commit()
            return True
        finally:
            session.close()
    except Exception:  # noqa: BLE001
        logger.error("RBAC scope audit event could not be written", exc_info=True)
        return False


def audit_isolated(user, draft) -> bool:
    """Write one already-built event in its own transaction (so a refusal that rolls
    the request back still leaves its record). Used by RBAC administration."""
    return _audit(user, lambda: draft)


def _record_denied(user, requested: str, reason: str) -> None:
    from ccure_platform.rbac.audit import EventDraft

    _audit(
        user,
        lambda: EventDraft(
            action="rbac.scope.denied",
            resource_type="organization",
            resource_id=requested,
            changes={"requested_org_id": requested, "reason": reason},
            org_id=getattr(user, "org_id", None),
        ),
    )


class _OrgRefused(Exception):
    def __init__(self, state: str, org_id: str | None):
        self.state, self.org_id = state, org_id


def resolve_active_organisation(user, requested_org_id: str | None = None) -> str:
    """
    The organisation this request acts in. ``requested_org_id`` is what the client asked
    for — a request, not evidence. Nothing requested, or the home organisation → the home
    organisation (which must be active). Another organisation → only with the platform
    switch grant, only if it exists and is active, and the entry is audited; without the
    grant the request is ignored and recorded. Raises 404 for an organisation that does
    not exist and 403 for an inactive one.
    """
    home = str(user.org_id) if getattr(user, "org_id", None) else None
    try:
        with _Session(user) as db:
            if not requested_org_id or requested_org_id == home:
                state = organisation_state(db, home)
                if state != ORG_ACTIVE:
                    raise _OrgRefused(state, home)
                return home
            with db.begin_nested():
                reach = _reach(db, user)
            if not reach:
                _record_denied(user, requested_org_id, "switch_not_granted")
                state = organisation_state(db, home)
                if state != ORG_ACTIVE:
                    raise _OrgRefused(state, home)
                return home
            state = organisation_state(db, requested_org_id)
            if state != ORG_ACTIVE:
                _record_denied(user, requested_org_id, f"organisation_{state}")
                raise _OrgRefused(state, requested_org_id)
            if not _audit_switch(user, home, requested_org_id):
                raise HTTPException(
                    status_code=503,
                    detail="The organisation switch could not be recorded.",
                )
            return requested_org_id
    except _OrgRefused as refused:
        raise HTTPException(
            status_code=404 if refused.state == ORG_MISSING else 403,
            detail=(
                "Organisation not found."
                if refused.state == ORG_MISSING
                else "The organisation is inactive."
            ),
        ) from None


def _audit_switch(user, home: str | None, target: str) -> bool:
    from ccure_platform.rbac.audit import EventDraft

    return _audit(
        user,
        lambda: EventDraft(
            action="rbac.org_switch.entered",
            resource_type="organization",
            resource_id=target,
            changes={"from_org_id": home, "to_org_id": target},
            org_id=target,
        ),
    )


def resource_organisation_allowed(user, resource_org_id: str | None) -> bool:
    """
    May the account act on a resource that belongs to ``resource_org_id``? The caller
    resolves that id from the stored resource, never from the request. Own organisation:
    yes (if active). Another: only with cross-organisation reach and an active
    organisation. Unknown or empty: no.
    """
    if not resource_org_id:
        return False
    same = str(resource_org_id) == str(getattr(user, "org_id", ""))
    if not same and not acts_across_organisations(user):
        _record_denied(user, str(resource_org_id), "cross_organisation_resource")
        return False
    try:
        with _Session(user) as db:
            return organisation_state(db, str(resource_org_id)) == ORG_ACTIVE
    except Exception:  # noqa: BLE001 - fail closed
        return False
