"""
ccure_platform/identity/email_domain_guard.py (was auth/email_domain_guard.py until Phase 8.2)
──────────────────────────────────────────────────────────────────────────────
Decides whether an email address may be used to create an account.

Why this is split in two halves
───────────────────────────────
Everything that decides a request runs **inline and without touching the
network**: a set lookup against rules and a blocklist corpus already resident in
memory. Everything that needs DNS or RDAP runs **after the account is
committed** and can only ever raise a flag.

That split is not a performance nicety. `/auth/register` accepts a domain chosen
by the caller. If the request path resolved MX records or fetched RDAP for that
domain, an unauthenticated stranger could make this server issue outbound
lookups against a host of their choosing, on demand, and would learn how long
each one took. Deferring them removes both problems and costs nothing, because
the signals they produce were never allowed to block anyway.

What blocks, and what merely flags
──────────────────────────────────
Blocking is reserved for evidence that a domain **is** a disposable mail
service: an administrator said so, or a maintained blocklist says so. Every
other signal — young domain, missing MX, a name containing "temp" — flags the
account for the human who approves it and lets the registration through.

The reason is measured, not philosophical. Of the two throwaway domains that
reached this deployment's approval queue on 18 Aug 2026, the canonical
`disposable-email-domains` list contained neither, and merging three lists
(~93k domains) still caught only one. `radiant-flow.org` had valid MX, Cloudflare
nameservers and a 17-month-old registration; no automated signal available here
classifies it. A rule aggressive enough to catch it would also refuse real
companies. So the blocklist takes the cases it is certain about, and the
approval queue — which already existed, and through which both fake accounts
were already inert — gets told everything else.

Failure is always open
──────────────────────
If the rules table is unreachable or the corpus is empty, registration
proceeds. Refusing every signup because a blocklist failed to load is a worse
outage than the abuse it prevents, and it is the kind of outage that arrives at
3am on a deploy nobody associates with email.
"""

from __future__ import annotations

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "auth.email_domain_guard")

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Iterable

logger = logging.getLogger(__name__)

# ── Modes ────────────────────────────────────────────────────────────────────

MODE_OFF = "off"
MODE_FLAG = "flag"
MODE_ENFORCE = "enforce"

# ── Verdict reason codes (stable; surfaced to the frontend and audit log) ────

REASON_OK = "ok"
REASON_ALLOWLISTED = "allowlisted"
REASON_DENYLISTED = "denylisted"
REASON_DISPOSABLE = "disposable"
REASON_MALFORMED = "malformed"

# ── Flag codes (advisory only; never block) ──────────────────────────────────

FLAG_NO_MX = "no_mx"
FLAG_YOUNG_DOMAIN = "young_domain"
FLAG_SUSPICIOUS_NAME = "suspicious_name"
FLAG_RESERVED_TLD = "reserved_tld"
FLAG_HARD_BOUNCE = "hard_bounce"
FLAG_UNASSESSED = "unassessed"

#: Tokens that appear in the names of throwaway services. Matching one is worth
#: a flag and nothing more — "temp" appears in `templeton-associates.com` and
#: `contemporary-design.co.uk`, and 10minuteschool.com is a real school.
_SUSPICIOUS_TOKENS = (
    "tempmail",
    "temp-mail",
    "throwaway",
    "throw-away",
    "trashmail",
    "trash-mail",
    "fakemail",
    "fake-mail",
    "disposable",
    "10minute",
    "10minutemail",
    "guerrillamail",
    "mailinator",
    "yopmail",
    "burnermail",
    "burner-mail",
    "spamgourmet",
    "getnada",
    "maildrop",
    "dropmail",
    "mohmal",
    "emailondeck",
    "minutemail",
    "onetimemail",
    "one-time-mail",
)

#: Reserved by RFC 2606 / RFC 6761. Never resolvable, so never a real mailbox —
#: but flag-only, because the test suite registers against `.test` domains and a
#: block rule here would fail the auth, admin and RBAC suites wholesale.
_RESERVED_TLDS = frozenset({"test", "invalid", "example", "localhost", "local"})

#: Multi-label public suffixes that must never be treated as a registrable
#: domain when walking parent suffixes.
#:
#: A full Public Suffix List is deliberately not used. The two libraries that
#: provide one either fetch it over the network at import time or ship a copy
#: that goes stale silently — neither is acceptable on an air-gapped appliance,
#: and both are a new dependency for a problem this set solves. The walk below
#: stops at two labels, so the only way a suffix could be mistaken for a domain
#: is if it appeared in the blocklist corpus or in an admin rule; this set makes
#: that impossible for the suffixes anyone would plausibly hit.
_PUBLIC_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "me.uk",
        "net.uk",
        "sch.uk",
        "co.in",
        "net.in",
        "org.in",
        "ac.in",
        "edu.in",
        "gov.in",
        "res.in",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "co.nz",
        "net.nz",
        "org.nz",
        "ac.nz",
        "govt.nz",
        "co.za",
        "org.za",
        "net.za",
        "ac.za",
        "gov.za",
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "edu.br",
        "co.jp",
        "or.jp",
        "ne.jp",
        "ac.jp",
        "go.jp",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "edu.cn",
        "com.sg",
        "edu.sg",
        "gov.sg",
        "org.sg",
        "com.my",
        "edu.my",
        "gov.my",
        "org.my",
        "com.hk",
        "edu.hk",
        "gov.hk",
        "org.hk",
        "com.tr",
        "edu.tr",
        "gov.tr",
        "org.tr",
        "com.mx",
        "org.mx",
        "gob.mx",
        "edu.mx",
        "co.kr",
        "or.kr",
        "ne.kr",
        "go.kr",
        "ac.kr",
        "com.ar",
        "org.ar",
        "gob.ar",
        "edu.ar",
        "co.id",
        "or.id",
        "ac.id",
        "go.id",
        "web.id",
        "com.ph",
        "edu.ph",
        "gov.ph",
        "org.ph",
        "co.th",
        "ac.th",
        "go.th",
        "or.th",
        "com.vn",
        "edu.vn",
        "gov.vn",
        "org.vn",
        "com.pk",
        "edu.pk",
        "gov.pk",
        "org.pk",
        "com.bd",
        "edu.bd",
        "gov.bd",
        "org.bd",
        "com.eg",
        "edu.eg",
        "gov.eg",
        "org.eg",
        "com.ng",
        "edu.ng",
        "gov.ng",
        "org.ng",
        "com.sa",
        "edu.sa",
        "gov.sa",
        "org.sa",
        "co.il",
        "org.il",
        "ac.il",
        "gov.il",
    }
)


# ── Verdict ──────────────────────────────────────────────────────────────────


@dataclass
class DomainVerdict:
    """
    The outcome of screening one address.

    `blocked` is the only field that changes application behaviour. `flags` and
    `signals` are carried alongside it so that an accepted-but-suspicious
    address arrives at the approval queue with its reasons attached.
    """

    email: str
    domain: str
    blocked: bool = False
    reason: str = REASON_OK
    detail: str = ""
    matched_domain: str = ""
    matched_source: str = ""
    flags: list[str] = field(default_factory=list)
    signals: dict = field(default_factory=dict)

    @property
    def flagged(self) -> bool:
        return bool(self.flags)

    def as_risk_payload(self) -> dict:
        """The JSONB blob stored on `users.email_risk`.

        Deliberately holds the domain and the verdict, never the local part.
        The address itself is already in `users.email`; copying it into a second
        column that gets read by every admin listing spreads it further for no
        gain.
        """
        return {
            "domain": self.domain,
            "reason": self.reason,
            "blocked": self.blocked,
            "flags": list(self.flags),
            "matched_domain": self.matched_domain,
            "matched_source": self.matched_source,
            "signals": dict(self.signals),
        }


# ── Cached rule set ──────────────────────────────────────────────────────────


class _RuleCache:
    """
    In-process snapshot of the rules table and the blocklist corpus.

    Reloaded on a TTL rather than per request: the corpus is ~93,000 rows, and
    putting that scan on the registration path would trade a real cost for no
    freshness anyone can perceive — the corpus changes weekly.

    Guarded by a lock so that a burst of concurrent registrations after the TTL
    expires produces one reload rather than one per request.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loaded_at = 0.0
        self._allow: frozenset[str] = frozenset()
        self._deny: frozenset[str] = frozenset()
        self._disposable: frozenset[str] = frozenset()
        self._healthy = False

    def invalidate(self) -> None:
        with self._lock:
            self._loaded_at = 0.0

    def get(self, db) -> tuple[frozenset[str], frozenset[str], frozenset[str], bool]:
        from config import AppConfig

        ttl = AppConfig.EMAIL_DOMAIN_CACHE_TTL_SECONDS
        now = time.monotonic()
        if self._loaded_at and (now - self._loaded_at) < ttl:
            return self._allow, self._deny, self._disposable, self._healthy

        with self._lock:
            # Re-check: another thread may have reloaded while this one waited.
            now = time.monotonic()
            if self._loaded_at and (now - self._loaded_at) < ttl:
                return self._allow, self._deny, self._disposable, self._healthy
            self._reload(db)
            return self._allow, self._deny, self._disposable, self._healthy

    def _reload(self, db) -> None:
        from db.models.email_security import (
            VERDICT_ALLOW,
            VERDICT_DENY,
            DisposableDomain,
            EmailDomainRule,
        )

        try:
            rules = db.query(EmailDomainRule.domain, EmailDomainRule.verdict).all()
            corpus = db.query(DisposableDomain.domain).all()
        except Exception as exc:
            # Fail open, loudly. Keep whatever was previously loaded: a
            # transient database blip should not widen the gate any further
            # than it has to.
            logger.error(
                "Email domain guard could not load its rule set (%s): "
                "registrations proceed unscreened until the next reload",
                exc.__class__.__name__,
            )
            self._healthy = False
            self._loaded_at = time.monotonic()
            return

        self._allow = frozenset(d.lower() for d, v in rules if v == VERDICT_ALLOW and d)
        self._deny = frozenset(d.lower() for d, v in rules if v == VERDICT_DENY and d)
        self._disposable = frozenset(row[0].lower() for row in corpus if row[0])
        self._loaded_at = time.monotonic()

        self._healthy = bool(self._disposable)
        if not self._healthy:
            logger.error(
                "Email domain guard loaded an EMPTY disposable-domain corpus. "
                "Registrations are effectively unscreened. Run "
                "scripts/security/sync_disposable_domains.py."
            )
        else:
            logger.info(
                "Email domain guard loaded: %d allow, %d deny, %d disposable",
                len(self._allow),
                len(self._deny),
                len(self._disposable),
            )


_cache = _RuleCache()


def invalidate_cache() -> None:
    """Drop the cached rule set so the next check re-reads the database.

    Called after an administrator edits a rule, so their decision takes effect
    immediately rather than up to `CACHE_TTL_SECONDS` later.
    """
    _cache.invalidate()


# ── Domain parsing ───────────────────────────────────────────────────────────


def extract_domain(email: str) -> str:
    """Return the lowercased domain of an address, or "" if there isn't one."""
    from ccure_platform.identity.email_utils import normalize_email

    normalized = normalize_email(email)
    if normalized.count("@") != 1:
        return ""
    domain = normalized.split("@", 1)[1].strip().rstrip(".")
    if not domain or "." not in domain or ".." in domain:
        return ""
    if domain.startswith(".") or domain.startswith("-"):
        return ""
    return domain


def domain_candidates(domain: str) -> list[str]:
    """
    The domain itself plus every parent worth testing, most specific first.

    `bob.mailinator.com` yields `["bob.mailinator.com", "mailinator.com"]`, so a
    single corpus entry for `mailinator.com` covers the subdomain the service
    actually hands out. Without this, matching is exact-string and every
    disposable provider defeats it by issuing addresses one label deeper.

    Stops at two labels and skips known public suffixes, so `co.uk` can never be
    treated as somebody's domain.
    """
    if not domain:
        return []
    labels = domain.split(".")
    candidates = []
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        if candidate.count(".") < 1:
            continue
        if candidate in _PUBLIC_SUFFIXES:
            continue
        candidates.append(candidate)
    return candidates


def _first_match(candidates: Iterable[str], haystack: frozenset[str]) -> str:
    for candidate in candidates:
        if candidate in haystack:
            return candidate
    return ""


# ── Inline heuristics (flag only, no network) ────────────────────────────────


def _name_flags(domain: str) -> list[str]:
    flags = []
    stripped = domain.replace("-", "").replace(".", "")
    if any(token.replace("-", "") in stripped for token in _SUSPICIOUS_TOKENS):
        flags.append(FLAG_SUSPICIOUS_NAME)
    if domain.rsplit(".", 1)[-1] in _RESERVED_TLDS:
        flags.append(FLAG_RESERVED_TLD)
    return flags


# ── Public API ───────────────────────────────────────────────────────────────


def current_mode() -> str:
    from config import AppConfig

    mode = (AppConfig.EMAIL_DOMAIN_GUARD_MODE or MODE_ENFORCE).strip().lower()
    if mode not in (MODE_OFF, MODE_FLAG, MODE_ENFORCE):
        logger.warning(
            "Unknown EMAIL_DOMAIN_GUARD_MODE=%r; falling back to %r", mode, MODE_FLAG
        )
        return MODE_FLAG
    return mode


def evaluate_email(db, email: str) -> DomainVerdict:
    """
    Screen one address. Never raises; never touches the network.

    The returned verdict is advisory data. Whether `blocked` actually stops
    anything is the caller's decision, made through `assert_email_allowed`.
    """
    from ccure_platform.identity.email_utils import normalize_email

    normalized = normalize_email(email)
    domain = extract_domain(normalized)
    verdict = DomainVerdict(email=normalized, domain=domain)

    if current_mode() == MODE_OFF:
        return verdict

    if not domain:
        verdict.blocked = True
        verdict.reason = REASON_MALFORMED
        verdict.detail = "That email address is not valid."
        return verdict

    try:
        allow, deny, disposable, healthy = _cache.get(db)
    except Exception as exc:
        logger.error(
            "Email domain guard failed while screening (%s); allowing through",
            exc.__class__.__name__,
        )
        verdict.flags.append(FLAG_UNASSESSED)
        verdict.signals["error"] = exc.__class__.__name__
        return verdict

    candidates = domain_candidates(domain)
    verdict.signals["corpus_healthy"] = healthy

    # 1. An explicit ALLOW ends the check. This is the override that makes the
    #    whole design safe to enable: whatever any upstream list decides about a
    #    customer's domain, one row here settles it permanently.
    matched = _first_match(candidates, allow)
    if matched:
        verdict.reason = REASON_ALLOWLISTED
        verdict.matched_domain = matched
        verdict.matched_source = "rule"
        return verdict

    # 2. An explicit DENY.
    matched = _first_match(candidates, deny)
    if matched:
        verdict.blocked = True
        verdict.reason = REASON_DENYLISTED
        verdict.matched_domain = matched
        verdict.matched_source = "rule"
        verdict.detail = (
            "This email domain is not accepted here. Please use your "
            "organisation's email address."
        )
        return verdict

    # 3. The merged upstream corpus.
    matched = _first_match(candidates, disposable)
    if matched:
        verdict.blocked = True
        verdict.reason = REASON_DISPOSABLE
        verdict.matched_domain = matched
        verdict.matched_source = "blocklist"
        verdict.detail = (
            "Disposable and temporary email addresses can't be used to "
            "register. Please use a permanent personal or work address."
        )
        return verdict

    # 4. Nothing matched. Attach advisory flags and accept.
    verdict.flags.extend(_name_flags(domain))
    return verdict


def assert_email_allowed(db, email: str, *, request=None, actor=None) -> DomainVerdict:
    """
    Screen an address and raise HTTP 400 if it must be refused.

    Returns the verdict on success so the caller can persist its flags.

    In `flag` mode this never raises: the verdict is computed and recorded, and
    the registration proceeds. That is what makes a staged rollout possible —
    run for a week, read `auth.email_domain_blocked` in the audit log, then set
    `EMAIL_DOMAIN_GUARD_MODE=enforce` with evidence rather than hope.
    """
    from fastapi import HTTPException

    verdict = evaluate_email(db, email)
    mode = current_mode()

    if verdict.blocked:
        _log_block(
            db, verdict, request=request, actor=actor, enforced=mode == MODE_ENFORCE
        )

    if verdict.blocked and mode == MODE_ENFORCE:
        raise HTTPException(
            status_code=400,
            detail=verdict.detail or "This email address cannot be used to register.",
        )

    return verdict


def _log_block(db, verdict: DomainVerdict, *, request=None, actor=None, enforced=True):
    """
    Record a refusal — domain and verdict, never the local part.

    Two sinks, and which one is used is not a style choice. `audit_logs` has
    `org_id` NOT NULL *and* in its primary key, so `log_audit_event(db, None,
    ...)` builds a row that cannot be inserted. Its own try/except swallows the
    IntegrityError but leaves the bad object pending in the session, and the
    caller's next `commit()` fails on it — turning a refused registration into a
    500 several statements later, in a different function.

    A self-service registration has no actor by definition. So when there is no
    user to attribute the event to, it goes to the security log instead of the
    audit table. Admin-initiated paths do have an actor and are audited
    normally.
    """
    action = "auth.email_domain_blocked" if enforced else "auth.email_domain_flagged"

    # Always emit the structured line. It is the only record that survives every
    # path, including the one where the caller's transaction is about to be
    # rolled back.
    logger.warning(
        "%s domain=%s reason=%s matched=%s source=%s enforced=%s",
        action,
        verdict.domain,
        verdict.reason,
        verdict.matched_domain or "-",
        verdict.matched_source or "-",
        enforced,
    )

    if actor is None or getattr(actor, "org_id", None) is None:
        # No actor to attribute the event to — a self-service registration by
        # definition. `audit_logs.org_id` is NOT NULL *and* part of the primary
        # key, so log_audit_event(db, None, …) builds a row that cannot be
        # inserted; its own try/except swallows the IntegrityError but leaves
        # the bad object pending in the session, and the caller's next commit()
        # fails on it — turning a refused registration into a 500 several
        # statements later, in a different function.
        return

    changes = {
        "reason": verdict.reason,
        "matched_domain": verdict.matched_domain,
        "source": verdict.matched_source,
        "enforced": enforced,
    }

    try:
        from ccure_platform.audit_log.writer import log_audit_event

        if enforced:
            # The caller is about to raise, so anything written on `db` is
            # discarded with the transaction. Use a separate session and commit
            # immediately: a refusal that leaves no trace is exactly the event
            # an audit trail exists to hold.
            #
            # This is the second-session pattern that `core/audit.py`
            # prohibits, and it is safe here for a specific reason rather than
            # by luck. The chain trigger holds a `FOR UPDATE` lock on the
            # organisation's chain head until commit, so a second session
            # writing an event for the *same* organisation would block on a
            # lock its own request holds. This runs at the entry of
            # registration and admin user-creation, before those handlers write
            # any audit event of their own, so the request transaction holds no
            # chain-head lock when this executes.
            #
            # Do not move this call later in a handler, and do not copy the
            # pattern into one that audits earlier. `lock_timeout` on the chain
            # trigger turns a violation into a loud failure rather than a hang,
            # but the guarantee here is the ordering, not the timeout.
            #
            # (An AST sweep for "audits after its last commit" flags this
            # function. That is a false positive: the two branches below are
            # mutually exclusive, and each commits correctly for its own path.)
            from db.base import SessionLocal

            audit_db = SessionLocal()
            try:
                log_audit_event(
                    audit_db,
                    actor,
                    action,
                    "email_domain",
                    verdict.domain,
                    request=request,
                    status="denied",
                    changes=changes,
                )
                audit_db.commit()
            finally:
                audit_db.close()
        else:
            # Flag mode: the request proceeds and the caller commits, so this
            # rides along in the same transaction as the account it describes.
            log_audit_event(
                db,
                actor,
                action,
                "email_domain",
                verdict.domain,
                request=request,
                status="success",
                changes=changes,
            )
    except Exception as exc:  # pragma: no cover - auditing must never break auth
        logger.warning(
            "Could not write email domain audit event: %s", exc.__class__.__name__
        )
