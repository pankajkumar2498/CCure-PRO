"""Email normalization helpers for authentication flows."""

from sqlalchemy import func


def normalize_email(email: object) -> str:
    return str(email).strip().lower()


def email_matches(column, email: object):
    return func.lower(column) == normalize_email(email)
