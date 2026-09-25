"""Email and username normalization helpers for authentication flows."""

from sqlalchemy import func

# The canonical-form rules and normalize_email moved to db/email_canonical.py
# (Phase 3) so the users model can compute its own column without importing
# auth. Re-exported here unchanged.
from db.email_canonical import (  # noqa: F401  (re-export)
    _DOT_INSENSITIVE_DOMAINS,
    _SUBADDRESS_DOMAINS,
    _SUBADDRESS_SEPARATORS,
    canonicalize_email,
    normalize_email,
)


def email_matches(column, email: object):
    return func.lower(column) == normalize_email(email)


def username_matches(column, username: object):
    return func.lower(column) == str(username or "").strip().lower()
