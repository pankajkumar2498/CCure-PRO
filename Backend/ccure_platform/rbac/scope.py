"""
ccure_platform/rbac/scope.py — RBAC-5: *where* a principal may act.

Permission answers WHAT; scope answers WHERE. The engine already separates them
(platform grants versus organisation grants, the home organisation, and
``platform.organization.switch`` for any other); this module is the backend seam that
asks the engine the *where* question for the places legacy code decided it by role name
or by trusting a client-supplied organisation id.

**The scope model.**

* **Platform** — a grant of a platform-scope permission, held through a platform-scope
  assignment. It says nothing about organisations by itself.
* **Organisation** — a grant held through an organisation-scope assignment applies in
  that organisation only.
* **Cross-organisation** — acting in an organisation other than the principal's own
  needs the platform-scope grant of ``platform.organization.switch`` *and* a permission
  held platform-wide. Nothing else reaches another tenant: holding an
  organisation-scoped permission never does (an organisation administrator stays in its
  organisation), and platform scope does not mean "every organisation" without the
  switch. Superadmin has no shortcut: it holds the switch through materialised grants,
  like any other permission.

**What legacy meant, and how it is expressed** (docs/architecture/RBAC_SCOPE.md):

* A superadmin *naming* an organisation (``?org_id=``) acted in it, unvalidated and
  unrecorded → ``resolve_active_organisation``: honoured only with the switch grant,
  the organisation must exist and be active, and the entry is audited.
* A superadmin *looking up by id with no organisation filter* → ``acts_across_
  organisations`` plus ``resource_organisation_allowed``, which resolves the resource's
  real organisation server-side before access.
* ``read_all`` was **organisation-wide visibility within the active organisation**, never
  cross-organisation: it is an organisation-scope permission evaluated for the target
  organisation (``user_has_permission(..., org_id=)``).
* A non-superadmin naming another organisation was silently ignored → still ignored
  (own organisation), now recorded as a denied attempt.

Each is **off unless its path is switched on** (``authority``): off, the legacy rule
stands exactly; on, the new decision is enforced, with the legacy answer as the
fallback when the new model cannot answer (an unprovisioned account, an unsynced
catalogue, an error), and every comparison is recorded.

**Fail closed.** An unknown, missing, or inactive organisation is never acted in. There
is no "archived" or "deleted" column on organisations: deactivation is ``is_active``
false and deletion is absence; both deny.

A client-supplied organisation id is a *request*, never evidence: it is checked against
the principal's grants and the organisation's state before it becomes the active
organisation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from ccure_platform.rbac import authority, resolver
from ccure_platform.rbac import contract as c
from ccure_platform.rbac import engine, governance, legacy_map
from fastapi import HTTPException
from sqlalchemy.orm import object_session

logger = logging.getLogger("ccure.rbac.scope")

PATH_ACTIVE_ORG = "scope.active_organisation"
PATH_CROSS_ORG = "scope.cross_organisation"
PATH_ASSIGN_ROLE = "scope.assign_role"

ORG_ACTIVE, ORG_INACTIVE, ORG_MISSING = "active", "inactive", "missing"


# ── organisation state ────────────────────────────────────────────────────────


def organisation_state(db, org_id: str | None) -> str:
    """``active`` | ``inactive`` | ``missing``. An empty id is missing."""
    if not org_id:
        return ORG_MISSING
    from db.models import Organization

    row = (
        db.query(Organization.is_active).filter(Organization.id == str(org_id)).first()
    )
    if row is None:
        return ORG_MISSING
    return ORG_ACTIVE if row[0] else ORG_INACTIVE


# ── the session a user is attached to ─────────────────────────────────────────


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


# ── the new side: what the engine says about reach ────────────────────────────


def _legacy_reach(user) -> bool:
    from ccure_platform.rbac.legacy_scope import legacy_acts_across_organisations

    return legacy_acts_across_organisations(user)


def _new_reach(db, user) -> bool | None:
    """Whether the engine lets the account act outside its home organisation: the
    platform-scope grant of the switch permission. None when the new model cannot
    answer (never provisioned, catalogue not synced)."""
    principal = resolver.principal_for_user(user)
    catalogue = resolver.load_catalogue(db)
    if not catalogue or not resolver.assignment_summary(db, principal):
        return None
    grants = resolver.resolve_grants(db, principal)
    return engine.decide(principal, grants, catalogue, c.ORG_SWITCH_KEY).allowed


def acts_across_organisations(user) -> bool:
    """May this account look up or act on resources in organisations other than its
    own? Legacy: the superadmin role by name. New: ``platform.organization.switch``."""
    legacy = _legacy_reach(user)
    if not authority.enabled_for(PATH_CROSS_ORG):
        return legacy
    try:
        with _Session(user) as db:
            with db.begin_nested():
                new = _new_reach(db, user)
    except Exception:  # noqa: BLE001 - legacy decides on any failure
        logger.warning("scope reach failed; legacy decides", exc_info=True)
        new = None
    out = (
        authority.Outcome(legacy, authority.SOURCE_LEGACY, PATH_CROSS_ORG, "fallback")
        if new is None
        else authority.Outcome(
            new, authority.SOURCE_NEW, PATH_CROSS_ORG, "reach", diverged=new != legacy
        )
    )
    authority.recorder.record(out)
    return out.allowed


# ── audit ─────────────────────────────────────────────────────────────────────


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


# ── the active organisation ───────────────────────────────────────────────────


def _legacy_target(user, requested: str | None) -> str:
    if requested and _legacy_reach(user):
        return requested
    return str(user.org_id)


def resolve_active_organisation(user, requested_org_id: str | None = None) -> str:
    """
    The organisation this request acts in. ``requested_org_id`` is what the client
    asked for — a request, not evidence.

    Switched off: exactly the legacy rule. Switched on:

    * nothing requested, or the home organisation → the home organisation (which must
      be active);
    * another organisation → only with the platform-scope switch grant, only if it
      exists and is active, and the entry is audited (``rbac.org_switch.entered``,
      owned by the entered organisation); without the grant the request is ignored
      (the home organisation is used, as before) and recorded (``rbac.scope.denied``);
    * the new model cannot answer → the legacy answer.

    Raises 404 for an organisation that does not exist and 403 for an inactive one.
    """
    legacy = _legacy_target(user, requested_org_id)
    if not authority.enabled_for(PATH_ACTIVE_ORG):
        return legacy
    home = str(user.org_id) if getattr(user, "org_id", None) else None
    try:
        with _Session(user) as db:
            if not requested_org_id or requested_org_id == home:
                state = organisation_state(db, home)
                if state != ORG_ACTIVE:
                    raise _OrgRefused(state, home)
                target, source, why = home, authority.SOURCE_NEW, "home"
            else:
                with db.begin_nested():
                    reach = _new_reach(db, user)
                if reach is None:
                    authority.recorder.record(
                        authority.Outcome(
                            True, authority.SOURCE_LEGACY, PATH_ACTIVE_ORG, "fallback"
                        )
                    )
                    return legacy
                if not reach:
                    _record_denied(user, requested_org_id, "switch_not_granted")
                    state = organisation_state(db, home)
                    if state != ORG_ACTIVE:
                        raise _OrgRefused(state, home)
                    target, source, why = home, authority.SOURCE_NEW, "ignored"
                else:
                    state = organisation_state(db, requested_org_id)
                    if state != ORG_ACTIVE:
                        _record_denied(user, requested_org_id, f"organisation_{state}")
                        raise _OrgRefused(state, requested_org_id)
                    if not _audit_switch(user, home, requested_org_id):
                        raise HTTPException(
                            status_code=503,
                            detail="The organisation switch could not be recorded.",
                        )
                    target, source, why = (
                        requested_org_id,
                        authority.SOURCE_NEW,
                        "switch",
                    )
        authority.recorder.record(
            authority.Outcome(
                True, source, PATH_ACTIVE_ORG, why, diverged=target != legacy
            )
        )
        return target
    except _OrgRefused as refused:
        authority.recorder.record(
            authority.Outcome(
                False, authority.SOURCE_NEW, PATH_ACTIVE_ORG, refused.state
            )
        )
        raise HTTPException(
            status_code=404 if refused.state == ORG_MISSING else 403,
            detail=(
                "Organisation not found."
                if refused.state == ORG_MISSING
                else "The organisation is inactive."
            ),
        ) from None
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001 - legacy decides on any failure
        logger.warning("active organisation failed; legacy decides", exc_info=True)
        return legacy


class _OrgRefused(Exception):
    def __init__(self, state: str, org_id: str | None):
        self.state, self.org_id = state, org_id


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


# ── resources: the organisation is resolved server-side ───────────────────────


def resource_organisation_allowed(user, resource_org_id: str | None) -> bool:
    """
    May the account act on a resource that belongs to ``resource_org_id``? The caller
    resolves that id from the stored resource, never from the request. Own
    organisation: yes (if active). Another: only with cross-organisation reach and an
    active organisation. Unknown or empty: no.
    """
    if not resource_org_id:
        return False
    same = str(resource_org_id) == str(getattr(user, "org_id", ""))
    if not authority.enabled_for(PATH_CROSS_ORG):
        return same or _legacy_reach(user)
    if not same and not acts_across_organisations(user):
        _record_denied(user, str(resource_org_id), "cross_organisation_resource")
        return False
    try:
        with _Session(user) as db:
            return organisation_state(db, str(resource_org_id)) == ORG_ACTIVE
    except Exception:  # noqa: BLE001 - fail closed
        return False


# ── assignment hierarchy ──────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AssignmentVerdict:
    allowed: bool
    violations: tuple[str, ...] = ()
    source: str = authority.SOURCE_LEGACY


def _legacy_assignment(db, actor, legacy_role) -> AssignmentVerdict:
    from ccure_platform.rbac.legacy_scope import legacy_assignment_allowed

    ok = legacy_assignment_allowed(actor, legacy_role)
    return AssignmentVerdict(ok, () if ok else ("role_above_actor",))


def check_role_assignment(
    actor, legacy_role, *, target_user_id: str | None, target_org_id: str
) -> AssignmentVerdict:
    """
    May ``actor`` give an account in ``target_org_id`` the legacy role ``legacy_role``?

    Switched off: the legacy rule (a role above the actor's cannot be given). On: the
    RBAC-2 governance rules over the *system role the golden mapping names for that
    legacy role* — organisation boundary, scope and permission ceilings, system-role
    restriction, self-assignment — enforced by ``governance.check_assignment``. A refusal
    is audited as ``rbac.escalation.refused``. The new model cannot answer (actor not
    provisioned, role unmapped, catalogue unsynced) → the legacy answer.
    """
    with _Session(actor) as db:
        legacy = _legacy_assignment(db, actor, legacy_role)
        if not authority.enabled_for(PATH_ASSIGN_ROLE):
            return legacy
        try:
            verdict = _new_assignment(
                db, actor, legacy_role, target_user_id, target_org_id
            )
        except Exception:  # noqa: BLE001
            logger.warning("assignment check failed; legacy decides", exc_info=True)
            verdict = None
        if verdict is None:
            authority.recorder.record(
                authority.Outcome(
                    legacy.allowed,
                    authority.SOURCE_LEGACY,
                    PATH_ASSIGN_ROLE,
                    "fallback",
                )
            )
            return legacy
        authority.recorder.record(
            authority.Outcome(
                verdict.allowed,
                authority.SOURCE_NEW,
                PATH_ASSIGN_ROLE,
                ",".join(verdict.violations),
                diverged=verdict.allowed != legacy.allowed,
            )
        )
    if not verdict.allowed:
        _audit_refusal(actor, legacy_role, target_user_id, target_org_id, verdict)
    return verdict


def _new_assignment(db, actor, legacy_role, target_user_id, target_org_id):
    from ccure_platform.rbac.model import RbacRole, granted_keys, to_role

    role_key = legacy_map.system_role_key_for_legacy(getattr(legacy_role, "name", None))
    if role_key is None:
        return None
    principal = resolver.principal_for_user(actor)
    catalogue = resolver.load_catalogue(db)
    if not catalogue or not resolver.assignment_summary(db, principal):
        return None
    row = db.query(RbacRole).filter_by(key=role_key).one_or_none()
    if row is None:
        return None
    grants = resolver.resolve_grants(db, principal)
    scope_type = row.assignable_scope
    violations = governance.check_assignment(
        principal,
        grants,
        catalogue,
        target_user_id=target_user_id or "",
        target_user_org_id=target_org_id,
        role=to_role(row),
        role_permission_keys=granted_keys(db, row.id),
        scope_type=scope_type,
        scope_org_id=target_org_id if scope_type == "organization" else None,
    )
    return AssignmentVerdict(
        not violations, tuple(sorted(v.code for v in violations)), authority.SOURCE_NEW
    )


def _audit_refusal(actor, legacy_role, target_user_id, target_org_id, verdict) -> None:
    from ccure_platform.rbac.audit import EventDraft

    _audit(
        actor,
        lambda: EventDraft(
            action="rbac.escalation.refused",
            resource_type="rbac_user_role",
            resource_id=target_user_id,
            changes={
                "target_user_id": target_user_id,
                "target_org_id": target_org_id,
                "violations": list(verdict.violations),
                "legacy_role_id": str(getattr(legacy_role, "id", "")),
            },
            org_id=getattr(actor, "org_id", None),
        ),
    )
