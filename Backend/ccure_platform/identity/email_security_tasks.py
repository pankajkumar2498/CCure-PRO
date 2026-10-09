"""
ccure_platform/identity/email_security_tasks.py (was core/email_security_tasks.py until Phase 8.3)
──────────────────────────────────────────────────────────────────────────────
Background work for email domain screening.

Kept out of `core/tasks.py` for the same reason `compliance_tasks.py` is: that
module is the scan pipeline, it is already 3,500 lines, and none of this shares
anything with it. Registered on the `default` queue, which the containerised
worker consumes — this work needs a database and an outbound socket, not the
raw-socket privileges the host scanner worker holds.
"""

from __future__ import annotations

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "core.email_security_tasks")

import datetime
import logging

from core.celery_app import celery_app
from db.base import SessionLocal, utcnow

log = logging.getLogger(__name__)


@celery_app.task(name="ccure.tasks.enrich_email_risk", queue="default")
def enrich_email_risk(user_id: str) -> dict:
    """
    Add the network-derived risk signals to one account, after the fact.

    Runs here rather than in the request because `/auth/register` accepts a
    domain chosen by an unauthenticated caller: resolving it inline would let a
    stranger direct DNS and HTTPS lookups from this host at a target of their
    choosing, at whatever rate the limiter allows, and time the results. The
    signals were only ever allowed to raise a flag, so learning them a few
    seconds later costs nothing.

    Merges into whatever the inline guard recorded; it never overwrites the
    blocklist verdict, which is the authoritative half.
    """
    from config import AppConfig

    if not AppConfig.EMAIL_RISK_ENRICHMENT_ENABLED:
        return {"success": True, "skipped": "enrichment disabled"}

    from ccure_platform.identity.email_risk_signals import collect_signals
    from db.models import User

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"success": False, "error": "user not found"}

        risk = dict(user.email_risk or {})
        domain = risk.get("domain") or (user.email or "").rsplit("@", 1)[-1].lower()

        collected = collect_signals(domain)

        flags = sorted(set(risk.get("flags") or []) | set(collected["flags"]))
        signals = {**(risk.get("signals") or {}), **collected["signals"]}

        risk["domain"] = domain
        risk["flags"] = flags
        risk["signals"] = signals
        risk["enriched_at"] = utcnow().isoformat()

        user.email_risk = risk
        if flags and not user.is_email_flagged:
            user.is_email_flagged = True
            user.flagged_at = utcnow()
        db.commit()

        return {"success": True, "user_id": user_id, "flags": flags}
    except Exception as exc:
        db.rollback()
        log.error(
            "Email risk enrichment failed for %s: %s", user_id, exc, exc_info=True
        )
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.retro_scan_email_risk", queue="default")
def retro_scan_email_risk(include_enrichment: bool = False) -> dict:
    """
    Screen every existing account against the guard and record the verdict.

    Flags only. It never deletes an account, never deactivates one and never
    revokes a session. A domain landing on a blocklist after somebody joined is
    not evidence that they are an impostor, and locking out a real customer is a
    far more expensive mistake than showing an administrator a badge they end up
    dismissing.

    Also backfills `email_canonical` where the migration left it NULL because
    two existing accounts canonicalize to the same mailbox. Those duplicates are
    reported here, not resolved: deciding which of two real accounts to keep is
    a job for a person, not a batch job.
    """
    from ccure_platform.identity.email_domain_guard import evaluate_email
    from ccure_platform.identity.email_utils import canonicalize_email
    from db.models import User

    db = SessionLocal()
    try:
        users = db.query(User).filter(User.is_deleted.is_(False)).all()

        flagged = 0
        blocked = 0
        duplicates: list[str] = []
        taken = {u.email_canonical: u.id for u in users if u.email_canonical}

        for user in users:
            verdict = evaluate_email(db, user.email)

            risk = verdict.as_risk_payload()
            existing = dict(user.email_risk or {})
            # Preserve signals a previous enrichment established; the inline
            # verdict knows nothing about MX or domain age.
            if existing.get("signals"):
                risk["signals"] = {**existing["signals"], **risk["signals"]}
                risk["flags"] = sorted(
                    set(risk["flags"]) | set(existing.get("flags") or [])
                )
            risk["scanned_at"] = utcnow().isoformat()

            user.email_risk = risk
            if risk["flags"] or verdict.blocked:
                if not user.is_email_flagged:
                    user.flagged_at = utcnow()
                user.is_email_flagged = True
                flagged += 1
            if verdict.blocked:
                blocked += 1

            if not user.email_canonical:
                canonical = canonicalize_email(user.email)
                if canonical and canonical not in taken:
                    user.email_canonical = canonical
                    taken[canonical] = user.id
                elif canonical:
                    duplicates.append(user.id)

        db.commit()

        if duplicates:
            log.warning(
                "Retro-scan: %d account(s) share a mailbox with an earlier "
                "account and keep email_canonical NULL: %s. Resolve by hand — "
                "nothing was deleted.",
                len(duplicates),
                ", ".join(duplicates),
            )

        result = {
            "success": True,
            "scanned": len(users),
            "flagged": flagged,
            "blocked_domains": blocked,
            "duplicate_mailboxes": duplicates,
        }

        if include_enrichment:
            queued = 0
            for user in users:
                try:
                    enrich_email_risk.delay(user.id)
                    queued += 1
                except Exception:
                    log.warning("Could not queue enrichment for %s", user.id)
            result["enrichment_queued"] = queued

        log.info("Email risk retro-scan complete: %s", result)
        return result
    except Exception as exc:
        db.rollback()
        log.error("Email risk retro-scan failed: %s", exc, exc_info=True)
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.purge_stale_unapproved_accounts", queue="default")
def purge_stale_unapproved_accounts() -> dict:
    """
    Delete accounts that confirmed their mailbox but were never approved.

    `purge_stale_unverified_accounts` cannot reach these. It filters on
    `is_verified = False`, and a throwaway-inbox registrant *does* click the
    verification link — reading that mail is the entire point of temp mail. Both
    fake accounts that reached this deployment's approval queue on 18 Aug 2026
    were marked "email verified" for exactly that reason, so the existing purge
    would have skipped them even had a scheduler been running it.

    Without this second TTL the approval queue only ever grows: a data-retention
    problem, and a slow denial of service against the administrator who reads it.

    Deliberately narrow. `approved_at IS NULL` **and** verified — unverified
    accounts are the other task's business — and only past the TTL. An account
    an administrator has approved is never touched, whatever its email looks
    like.
    """
    from config import AppConfig
    from db.models import User

    ttl_days = AppConfig.UNAPPROVED_ACCOUNT_TTL_DAYS
    if ttl_days <= 0:
        return {"success": True, "purged": 0, "skipped": "TTL disabled"}

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        days=ttl_days
    )
    db = SessionLocal()
    try:
        stale = (
            db.query(User)
            .filter(
                User.approved_at.is_(None),
                User.is_verified.is_(True),
                User.is_deleted.is_(False),
                User.created_at < cutoff,
            )
            .all()
        )
        removed = len(stale)
        for user in stale:
            log.info(
                "Purging never-approved account %s (domain %s, created %s)",
                user.id,
                (user.email or "").rsplit("@", 1)[-1],
                user.created_at,
            )
            db.delete(user)
        db.commit()
        return {"success": True, "purged": removed}
    except Exception as exc:
        db.rollback()
        log.error("Failed to purge unapproved accounts: %s", exc, exc_info=True)
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.sync_disposable_domains", queue="default")
def sync_disposable_domains_task() -> dict:
    """Refresh the disposable-domain corpus from the upstream blocklists."""
    try:
        from scripts.security.sync_disposable_domains import run_sync

        result = run_sync()
        log.info("Disposable domain sync complete: %s", result)
        return result
    except Exception as exc:
        log.error("Disposable domain sync failed: %s", exc, exc_info=True)
        return {"success": False, "error": str(exc)}
