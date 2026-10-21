"""
routers/admin_email_domains.py
──────────────────────────────────────────────────────────────────────────────
Management for the email domain ALLOW / DENY rules.

  GET    /admin/email-domains          → list rules
  POST   /admin/email-domains          → create an allow or deny rule
  PATCH  /admin/email-domains/{id}     → flip a verdict or edit the reason
  DELETE /admin/email-domains/{id}     → remove a rule
  GET    /admin/email-domains/lookup   → test an address against the live guard
  GET    /admin/email-domains/stats    → corpus health

Superadmin only, and that is a tenant-isolation decision rather than caution.
These rules are **platform-wide**: one row here changes what every organisation
on the deployment can register with. An org_admin who denied `gmail.com` would
be blocking a different tenant's customers, and an org_admin who allowed a
throwaway service would be opening the door for all of them. Nothing about the
rule table is scoped to an organisation, so nothing below may be reachable by a
role that is.

Note the asymmetry with `POST /admin/users/{id}/approve`, which *can* create an
ALLOW rule under `users:update`. That is deliberate and narrower: it only ever
allows, only the domain of an account already in front of the reviewer, and it
is the escape hatch that makes enforcement safe to leave on. Creating arbitrary
DENY rules is a different power and lives here.
"""

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "routers.admin_email_domains")


import logging
from typing import Optional

from ccure_platform.identity.email_domain_guard import (
    MODE_ENFORCE,
    current_mode,
    evaluate_email,
    invalidate_cache,
)
from ccure_platform.rbac.dependencies import require_authorized
from ccure_platform.audit_log.writer import log_audit_event
from db.base import get_db, utcnow
from ccure_platform.models import User
from ccure_platform.models.email_security import (
    VERDICT_ALLOW,
    VERDICT_DENY,
    DisposableDomain,
    EmailDomainRule,
)
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

router = APIRouter(
    prefix="/admin/email-domains",
    tags=["Admin: Email Domains"],
    dependencies=[Depends(require_authorized("platform.email_domain.read"))],
)
log = logging.getLogger(__name__)


# ── Schemas ──────────────────────────────────────────────────────────────────


def _clean_domain(raw: str) -> str:
    """
    Accept what an administrator will actually paste.

    People paste a whole address, a URL, a trailing dot, mixed case. Rejecting
    those would be technically defensible and would mostly teach people that the
    form is fussy, so the obvious ones are normalised instead. What is *not*
    accepted is anything that fails to look like a domain at all — silently
    storing junk creates a rule that matches nothing and looks like it works.
    """
    value = (raw or "").strip().lower()
    if not value:
        raise ValueError("Domain is required")

    # A pasted address: keep the domain half.
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    # A pasted URL.
    for prefix in ("https://", "http://"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
    value = value.split("/", 1)[0].strip().rstrip(".")

    if not value or "." not in value or ".." in value:
        raise ValueError("Enter a valid domain, for example acme.com")
    if value.startswith((".", "-")) or value.endswith("-"):
        raise ValueError("Enter a valid domain, for example acme.com")
    if len(value) > 255:
        raise ValueError("Domain is too long")
    if any(ch.isspace() for ch in value):
        raise ValueError("Enter a valid domain, for example acme.com")
    return value


class RuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str
    verdict: str
    reason: Optional[str] = Field(default=None, max_length=1000)

    @field_validator("domain")
    @classmethod
    def check_domain(cls, v: str) -> str:
        return _clean_domain(v)

    @field_validator("verdict")
    @classmethod
    def check_verdict(cls, v: str) -> str:
        value = (v or "").strip().lower()
        if value not in (VERDICT_ALLOW, VERDICT_DENY):
            raise ValueError("Verdict must be 'allow' or 'deny'")
        return value


class RuleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Optional[str] = None
    reason: Optional[str] = Field(default=None, max_length=1000)

    @field_validator("verdict")
    @classmethod
    def check_verdict(cls, v):
        if v is None:
            return v
        value = (v or "").strip().lower()
        if value not in (VERDICT_ALLOW, VERDICT_DENY):
            raise ValueError("Verdict must be 'allow' or 'deny'")
        return value


def _serialize(rule: EmailDomainRule) -> dict:
    return {
        "id": rule.id,
        "domain": rule.domain,
        "verdict": rule.verdict,
        "source": rule.source,
        "reason": rule.reason,
        "created_by": rule.created_by,
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
    }


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.get("")
@router.get("/")
def list_rules(
    q: Optional[str] = None,
    verdict: Optional[str] = None,
    source: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.email_domain.read")),
):
    """List the ALLOW / DENY rules, newest first."""
    query = db.query(EmailDomainRule)

    if q:
        needle = f"%{q.strip().lower()}%"
        query = query.filter(
            or_(
                func.lower(EmailDomainRule.domain).like(needle),
                func.lower(func.coalesce(EmailDomainRule.reason, "")).like(needle),
            )
        )
    if verdict:
        query = query.filter(EmailDomainRule.verdict == verdict.strip().lower())
    if source:
        query = query.filter(EmailDomainRule.source == source.strip().lower())

    total = query.count()
    rules = (
        query.order_by(EmailDomainRule.created_at.desc(), EmailDomainRule.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "rules": [_serialize(r) for r in rules],
        "counts": {
            "allow": db.query(EmailDomainRule)
            .filter(EmailDomainRule.verdict == VERDICT_ALLOW)
            .count(),
            "deny": db.query(EmailDomainRule)
            .filter(EmailDomainRule.verdict == VERDICT_DENY)
            .count(),
        },
    }


@router.get("/stats")
@router.get("/stats/")
def rule_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.email_domain.read")),
):
    """
    Corpus health.

    `corpus_size` is the number that matters operationally. The guard fails open
    on an empty corpus — deliberately, because refusing every signup over a
    blocklist that did not load is a worse outage than the abuse it prevents —
    which means an empty corpus is silent. This is where that becomes visible.
    """
    from config import AppConfig

    corpus = db.query(DisposableDomain).count()
    newest = db.query(func.max(DisposableDomain.last_seen_at)).scalar()

    return {
        "mode": AppConfig.EMAIL_DOMAIN_GUARD_MODE,
        "corpus_size": corpus,
        "corpus_healthy": corpus > 0,
        "corpus_last_synced": newest,
        "allow_rules": db.query(EmailDomainRule)
        .filter(EmailDomainRule.verdict == VERDICT_ALLOW)
        .count(),
        "deny_rules": db.query(EmailDomainRule)
        .filter(EmailDomainRule.verdict == VERDICT_DENY)
        .count(),
        "flagged_users": db.query(User)
        .filter(User.is_email_flagged.is_(True), User.is_deleted.is_(False))
        .count(),
    }


@router.get("/lookup")
@router.get("/lookup/")
def lookup(
    q: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.email_domain.read")),
):
    """
    Run an address or domain through the live guard and show the verdict.

    Worth having for one reason: when somebody reports "my customer cannot
    register", this answers *why* in one request — which rule or list matched,
    and at what level — instead of leaving an administrator to guess whether the
    address, the domain, a parent suffix or the corpus is responsible.
    """
    candidate = (q or "").strip()
    if not candidate:
        raise HTTPException(status_code=422, detail="Provide an address or domain")
    if "@" not in candidate:
        candidate = f"probe@{candidate}"

    verdict = evaluate_email(db, candidate)
    return {
        "domain": verdict.domain,
        "blocked": verdict.blocked,
        "reason": verdict.reason,
        "detail": verdict.detail,
        "matched_domain": verdict.matched_domain,
        "matched_source": verdict.matched_source,
        "flags": verdict.flags,
        # `blocked` is the verdict; this is what would actually happen. In
        # `flag` mode the two differ, and an administrator testing a domain
        # needs the second answer, not the first.
        "would_block_registration": verdict.blocked and current_mode() == MODE_ENFORCE,
    }


@router.post("", status_code=201)
@router.post("/", status_code=201)
def create_rule(
    payload: RuleCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.email_domain.manage")),
):
    """
    Create an ALLOW or DENY rule.

    A domain already carrying a rule is rejected with 409 rather than silently
    overwritten: `domain` is unique, and quietly flipping an existing verdict —
    possibly one seeded as part of the never-block floor — is not something
    anyone should be able to do by filling in an add form. Editing goes through
    PATCH, where the intent is explicit.
    """
    existing = (
        db.query(EmailDomainRule)
        .filter(EmailDomainRule.domain == payload.domain)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=(
                f"A rule for {payload.domain} already exists "
                f"({existing.verdict}). Edit or remove it instead."
            ),
        )

    rule = EmailDomainRule(
        domain=payload.domain,
        verdict=payload.verdict,
        source="admin",
        reason=payload.reason,
        created_by=str(current_user.id),
    )
    db.add(rule)

    try:
        db.flush()
    except IntegrityError:
        # Lost a race against a concurrent create for the same domain.
        db.rollback()
        raise HTTPException(
            status_code=409, detail=f"A rule for {payload.domain} already exists."
        )

    log_audit_event(
        db,
        current_user,
        "admin.email_domain_rule_created",
        "email_domain",
        payload.domain,
        {"verdict": payload.verdict, "reason": payload.reason},
        request,
    )
    db.commit()
    db.refresh(rule)

    # The guard caches the rule set per process for CACHE_TTL_SECONDS. Without
    # this an administrator's change appears not to work for up to five minutes,
    # which is exactly long enough for them to conclude it is broken and try
    # something else.
    invalidate_cache()

    log.info(
        "Email domain rule created: %s -> %s by %s",
        payload.domain,
        payload.verdict,
        current_user.id,
    )
    return _serialize(rule)


@router.patch("/{rule_id}")
@router.patch("/{rule_id}/")
def update_rule(
    rule_id: int,
    payload: RuleUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.email_domain.manage")),
):
    """Flip a verdict or edit the note explaining a rule."""
    rule = db.query(EmailDomainRule).filter(EmailDomainRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    changes = {}
    if payload.verdict is not None and payload.verdict != rule.verdict:
        changes["verdict"] = f"{rule.verdict} -> {payload.verdict}"
        rule.verdict = payload.verdict
    if payload.reason is not None and payload.reason != rule.reason:
        changes["reason"] = "updated"
        rule.reason = payload.reason

    if not changes:
        return _serialize(rule)

    # A seeded rule that a human deliberately edits stops being a seeded rule.
    # Leaving source='seed' would make the next person believe the shipped
    # default said this.
    rule.source = "admin"
    rule.created_by = str(current_user.id)
    rule.updated_at = utcnow()

    log_audit_event(
        db,
        current_user,
        "admin.email_domain_rule_updated",
        "email_domain",
        rule.domain,
        changes,
        request,
    )
    db.commit()
    db.refresh(rule)
    invalidate_cache()

    return _serialize(rule)


@router.delete("/{rule_id}", status_code=200)
@router.delete("/{rule_id}/", status_code=200)
def delete_rule(
    rule_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.email_domain.manage")),
):
    """
    Remove a rule.

    The response says what the domain's verdict becomes *without* the rule,
    because that is the question the administrator actually has and it is not
    obvious: deleting an ALLOW on a domain that also sits in the blocklist
    corpus does not return it to neutral, it starts blocking it. `test.com` is
    a live example — it is on a published disposable list.
    """
    rule = db.query(EmailDomainRule).filter(EmailDomainRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    domain = rule.domain
    verdict = rule.verdict

    db.delete(rule)
    log_audit_event(
        db,
        current_user,
        "admin.email_domain_rule_deleted",
        "email_domain",
        domain,
        {"verdict": verdict},
        request,
    )
    db.commit()
    invalidate_cache()

    after = evaluate_email(db, f"probe@{domain}")
    log.info(
        "Email domain rule removed: %s (was %s) by %s", domain, verdict, current_user.id
    )

    return {
        "detail": f"Rule for {domain} removed.",
        "domain": domain,
        "removed_verdict": verdict,
        "now": {
            "blocked": after.blocked,
            "reason": after.reason,
            "matched_source": after.matched_source,
        },
    }
