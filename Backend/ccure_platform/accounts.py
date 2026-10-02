"""
ccure_platform/accounts.py — an account, as a module may see it.

The account views and lookups behind ``ccure_platform.api`` (``user``,
``user_display_names``, ``active_members_with_roles``), moved out of ``api.py``
so platform-internal code (the notification service) can use them without
importing the API facade, which imports that service. ``ccure_platform.api``
re-exports them unchanged.

Two rules every function keeps: the caller's session is used, and only plain
values leave — a view is a frozen dataclass of strings and booleans.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from db.models import Role, User
from sqlalchemy.orm import Session


@dataclass(frozen=True, slots=True, kw_only=True)
class UserView:
    """An account, as a module may see it."""

    id: str
    org_id: str
    username: str
    email: str
    #: The account's own "in-app alerts" preference. Absent means on; only an
    #: explicit ``False`` turns it off.
    in_app_alerts: bool


def _user_view(row: User) -> UserView:
    preferences = row.preferences if isinstance(row.preferences, dict) else {}
    return UserView(
        id=str(row.id),
        org_id=row.org_id,
        username=row.username,
        email=row.email,
        in_app_alerts=preferences.get("in_app_alerts", True) is not False,
    )


# ── accounts ──────────────────────────────────────────────────────────────────


def user(db: Session, user_id: str | None) -> UserView | None:
    """
    The account with this id, or None.

    Deleted, inactive and unapproved accounts are returned as they are: the
    callers this replaces resolved a scan's owner or an audit actor by id, and
    an owner who has since been disabled is still that scan's owner.
    """
    if not user_id:
        return None
    row = db.query(User).filter(User.id == str(user_id)).first()
    return _user_view(row) if row is not None else None


def user_display_names(db: Session, user_ids: Iterable[str]) -> dict[str, str]:
    """
    ``{user id: the name the account is shown by}`` for the ids that exist.

    The name is the email address — the one identifier every account has, and
    what exports have always printed for an owner. An id with no account is
    absent from the result, never mapped to an empty string, so a caller can
    tell "unknown owner" from "owner with no name".
    """
    wanted = {str(u) for u in user_ids if u}
    if not wanted:
        return {}
    rows = db.query(User.id, User.email).filter(User.id.in_(wanted)).all()
    return {str(uid): str(email or "") for uid, email in rows}


def active_members_with_roles(
    db: Session, org_id: str, role_names: Iterable[str]
) -> list[UserView]:
    """
    The active, undeleted accounts in ``org_id`` holding any of ``role_names``.

    Role names are matched exactly, as stored. No matching role gives an empty
    list without querying accounts.
    """
    names = list(role_names)
    role_ids = [r.id for r in db.query(Role).filter(Role.name.in_(names)).all()]
    if not role_ids:
        return []
    rows = (
        db.query(User)
        .filter(
            User.org_id == org_id,
            User.role_id.in_(role_ids),
            User.is_active == True,  # noqa: E712  (SQL comparison)
            User.is_deleted == False,  # noqa: E712
        )
        .all()
    )
    return [_user_view(row) for row in rows]
