"""Email and username normalization helpers for authentication flows."""

from sqlalchemy import func


def normalize_email(email: object) -> str:
    return str(email).strip().lower()


def email_matches(column, email: object):
    return func.lower(column) == normalize_email(email)


def username_matches(column, username: object):
    return func.lower(column) == str(username or "").strip().lower()
