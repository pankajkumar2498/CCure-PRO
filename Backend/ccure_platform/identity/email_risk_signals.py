"""
ccure_platform/identity/email_risk_signals.py (was auth/email_risk_signals.py until Phase 8.2)
──────────────────────────────────────────────────────────────────────────────
The network-derived half of email screening: MX presence and domain age.

Everything here runs on a worker, after the account row is committed, and
produces flags only. Nothing in this module can refuse a registration, and that
is deliberate on two counts.

**It cannot run inline.** These functions take a domain supplied by an
unauthenticated caller. Executed on the request path they would let a stranger
aim DNS queries and HTTPS fetches from this host at a target of their choosing,
at whatever rate the rate limiter allows, and read the timing.

**It must not block.** Neither signal is decisive. `radiant-flow.org` — a
throwaway domain that reached this deployment's approval queue — has valid MX
and was registered 17 months earlier, so both checks pass it. Meanwhile plenty
of legitimate companies register a domain the week they incorporate, and some
run mail through a host these lookups cannot see. A rule strict enough to catch
the former refuses the latter.

So they answer a narrower and more useful question: what should the
administrator looking at this account in the approval queue be told?

Every failure is reported as *unassessed*, never as clean — the same convention
the CSAF and Windows-patch matchers use elsewhere in this codebase. A lookup
that timed out is not evidence of a healthy domain.
"""

from __future__ import annotations

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "auth.email_risk_signals")

import datetime
import logging

logger = logging.getLogger(__name__)

#: RDAP bootstrap. Follows redirects to the authoritative registry for the TLD.
#: Free, no API key, no account, no per-check billing — which is why the plan
#: dropped a commercial reputation API in favour of it.
_RDAP_URL = "https://rdap.org/domain/{domain}"


def mx_hosts(domain: str) -> tuple[list[str] | None, str]:
    """
    Return (hosts, status). `hosts` is None when the lookup could not be made.

    status is one of: "ok", "no_mx", "nxdomain", "unassessed".

    An empty list with status "no_mx" is a real answer — the domain exists and
    publishes no mail exchanger, so it cannot receive the verification email
    that registration is about to send it. That is worth telling an admin. It is
    still not worth blocking over: a handful of domains accept mail on their A
    record, which is legal and rare.
    """
    from config import AppConfig

    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        logger.debug("dnspython unavailable; MX signal not collected")
        return None, "unassessed"

    resolver = dns.resolver.Resolver()
    resolver.timeout = AppConfig.EMAIL_RISK_DNS_TIMEOUT_SECONDS
    resolver.lifetime = AppConfig.EMAIL_RISK_DNS_TIMEOUT_SECONDS

    try:
        answers = resolver.resolve(domain, "MX")
        hosts = sorted(str(r.exchange).rstrip(".").lower() for r in answers)
        # RFC 7505: a single "." target is an explicit declaration that this
        # domain accepts no mail. example.com publishes one.
        if hosts == [""] or hosts == ["."]:
            return [], "no_mx"
        return hosts, "ok"
    except dns.resolver.NXDOMAIN:
        return [], "nxdomain"
    except dns.resolver.NoAnswer:
        return [], "no_mx"
    except (dns.exception.DNSException, Exception) as exc:
        logger.debug("MX lookup for %s failed: %s", domain, exc.__class__.__name__)
        return None, "unassessed"


def domain_registered_at(domain: str) -> tuple[datetime.datetime | None, str]:
    """
    Return (registration datetime in UTC, status) via RDAP.

    status is one of: "ok", "not_found", "unassessed".

    Only the registrable domain is queried — RDAP has no record of
    `mail.example.com`, only of `example.com`.
    """
    from config import AppConfig

    try:
        import requests
    except ImportError:  # pragma: no cover
        return None, "unassessed"

    try:
        response = requests.get(
            _RDAP_URL.format(domain=domain),
            timeout=AppConfig.EMAIL_RISK_RDAP_TIMEOUT_SECONDS,
            headers={"Accept": "application/rdap+json"},
            allow_redirects=True,
        )
    except Exception as exc:
        logger.debug("RDAP lookup for %s failed: %s", domain, exc.__class__.__name__)
        return None, "unassessed"

    if response.status_code == 404:
        return None, "not_found"
    if response.status_code != 200:
        return None, "unassessed"

    try:
        payload = response.json()
    except ValueError:
        return None, "unassessed"

    for event in payload.get("events") or []:
        if event.get("eventAction") != "registration":
            continue
        raw = event.get("eventDate")
        if not raw:
            continue
        try:
            # RDAP dates are ISO 8601, usually with a trailing "Z".
            parsed = datetime.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            return None, "unassessed"
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed.astimezone(datetime.timezone.utc), "ok"

    return None, "not_found"


def collect_signals(domain: str) -> dict:
    """
    Gather every network signal for one domain and say what each one means.

    Returns a dict with a `flags` list and a `signals` mapping, shaped to merge
    straight into `users.email_risk`.
    """
    from config import AppConfig

    from ccure_platform.identity.email_domain_guard import (
        FLAG_NO_MX,
        FLAG_UNASSESSED,
        FLAG_YOUNG_DOMAIN,
    )

    flags: list[str] = []
    signals: dict = {}

    if not domain:
        return {"flags": [FLAG_UNASSESSED], "signals": {}}

    hosts, mx_status = mx_hosts(domain)
    signals["mx_status"] = mx_status
    if hosts is not None:
        signals["mx_hosts"] = hosts[:5]
    if mx_status in ("no_mx", "nxdomain"):
        flags.append(FLAG_NO_MX)
    elif mx_status == "unassessed":
        flags.append(FLAG_UNASSESSED)

    registered, rdap_status = domain_registered_at(domain)
    signals["rdap_status"] = rdap_status
    if registered is not None:
        signals["registered_at"] = registered.isoformat()
        age_days = (datetime.datetime.now(datetime.timezone.utc) - registered).days
        signals["domain_age_days"] = age_days
        if age_days < AppConfig.EMAIL_RISK_MIN_DOMAIN_AGE_DAYS:
            flags.append(FLAG_YOUNG_DOMAIN)
    elif rdap_status == "unassessed" and FLAG_UNASSESSED not in flags:
        flags.append(FLAG_UNASSESSED)

    return {"flags": flags, "signals": signals}
