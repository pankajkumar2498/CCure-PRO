"""
The canonical form of an email address — what ``users.email_canonical`` holds.

Moved here from ``auth/email_utils.py`` (Phase 3 of the modular-platform
programme). The UNIQUE index on ``users.email_canonical`` is only as correct as
this function, and the users model's own schema backfill calls it — which meant
the model importing the auth package, the one direction the models layer must
not depend on. The function is pure (no imports at all), so it sits beside the
column it defines. ``auth.email_utils`` re-exports every name, unchanged.
"""

# Providers whose subaddressing separator is not "+".
#
# Everyone here uses "+" except Yandex, which uses "-". Getting this wrong in
# either direction is harmful: treating "-" as a separator on a provider that
# does not support it would fold `firstname-lastname@gmail.com` into
# `firstname@gmail.com` and refuse a stranger's signup as a duplicate.
_SUBADDRESS_SEPARATORS = {
    "yandex.com": "-",
    "yandex.ru": "-",
}

# Providers that ignore dots in the local part, documented by the provider
# itself. Gmail is the only mainstream one — Outlook, Yahoo, iCloud and Proton
# all treat `a.b@` and `ab@` as different mailboxes, so folding dots for them
# would merge two real people into one account.
_DOT_INSENSITIVE_DOMAINS = {
    "gmail.com",
    "googlemail.com",
}

# Providers known to support "+" subaddressing. A custom company domain may or
# may not — most Exchange and Zimbra deployments do not — so subaddressing is
# stripped only for domains on this list. Guessing would mean rejecting
# `sales+web@acme.com` as a duplicate of an unrelated `sales@acme.com`.
_SUBADDRESS_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "ymail.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "protonmail.com",
    "proton.me",
    "pm.me",
    "fastmail.com",
    "zoho.com",
    "yandex.com",
    "yandex.ru",
}


def normalize_email(email: object) -> str:
    return str(email).strip().lower()


def canonicalize_email(email: object) -> str:
    """
    Reduce an address to the mailbox it actually delivers to.

    This exists to close an account-farming hole that no disposable-domain
    blocklist can touch: `p.kumar+1@gmail.com`, `pkumar+2@gmail.com` and
    `p.k.u.m.a.r@gmail.com` are one Gmail mailbox and three distinct values of
    `users.email`. One real mailbox at a provider nobody would ever block is
    enough to register unlimited accounts.

    Two rules, both applied **only to providers that document the behaviour**:

      * dots in the local part are removed for Gmail,
      * subaddressing (`+tag`, or `-tag` at Yandex) is stripped for the
        providers listed above.

    For every other domain the local part is returned unchanged apart from
    lowercasing. That restraint is the important half. Most corporate mail
    systems do not implement subaddressing, so folding `sales+web@acme.com`
    into `sales@acme.com` would make one company's second signup collide with
    an unrelated colleague's — a false duplicate is indistinguishable from
    "somebody already took your address", and there is no way for the user to
    work around it.

    Returns "" for input with no local part or no domain, which the caller
    should treat as "no canonical form available" rather than as a value to
    store.
    """
    normalized = normalize_email(email)
    if normalized.count("@") != 1:
        return ""

    local, domain = normalized.split("@", 1)
    if not local or not domain:
        return ""

    if domain in _DOT_INSENSITIVE_DOMAINS:
        local = local.replace(".", "")

    if domain in _SUBADDRESS_DOMAINS:
        separator = _SUBADDRESS_SEPARATORS.get(domain, "+")
        local = local.split(separator, 1)[0]

    # googlemail.com is an alias of gmail.com — same mailbox, different string.
    if domain == "googlemail.com":
        domain = "gmail.com"

    if not local:
        # The whole local part was a tag, e.g. "+tag@gmail.com". Not a real
        # address; leave it uncanonicalized rather than inventing a collision.
        return ""

    return f"{local}@{domain}"
