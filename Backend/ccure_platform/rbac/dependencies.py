"""
ccure_platform/rbac/dependencies.py — the application's authorization guards.

RBAC-8 (final cutover): **the Platform RBAC engine is the only authorization decision
point.** A guard asks the engine whether the signed-in principal holds a permission *key*
(``module.resource.action``) in the organisation the request acts in, from the grants its
live role assignments materialise — and nothing else:

* no legacy permission atom (``resource:action``), no ``users.role_id``, no role name, no
  display name, no superadmin shortcut;
* no fallback to any other model: an account with no RBAC assignment holds nothing and is
  denied, an inactive or deleted account is denied, a retired role or a revoked assignment
  grants nothing, and a request that names another organisation is judged by the scope
  rules (``scope.py``), never by the client's word.

The old ``require_permission`` / ``require_role`` / ``user_has_permission`` and the
shadow/authority switches are gone. Call sites name the key they enforce.
"""

from __future__ import annotations

import logging
from typing import Union

from ccure_platform.identity.dependencies import get_current_user
from ccure_platform.rbac import contract as c
from ccure_platform.rbac import engine, resolver
from db.base import get_db
from ccure_platform.models import User
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def decide(
    db: Session, user: User, key: str, *, org_id: str | None = None
) -> c.AuthorizationDecision:
    """The engine's decision for ``user`` and ``key`` (in ``org_id``, else the
    account's own organisation). Reads the grants fresh: a revocation, a retired role or
    a removed permission takes effect on the next call."""
    principal = resolver.principal_for_user(user)
    scope = c.ScopeContext(requested_org_id=str(org_id)) if org_id else c.ScopeContext()
    return resolver.authorize(db, principal, key, scope)


def has_permission(
    db: Session,
    account: Union[User, str, None],
    key: str,
    *,
    org_id: str | None = None,
) -> bool:
    """Whether the account holds the permission ``key``. ``account`` is the ``User`` a
    route holds or an account id; no account, or one that does not exist, holds nothing.
    """
    if account is None:
        return False
    if isinstance(account, str):
        account = db.query(User).filter(User.id == account).first()
        if account is None:
            return False
    return decide(db, account, key, org_id=org_id).allowed


def require_authorized(key: str):
    """
    A route dependency that answers 403 unless the signed-in account holds the permission
    ``key``, and hands the route the account.
    """

    def _guard(
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        decision = decide(db, user, key)
        if not decision.allowed:
            logger.warning(
                "RBAC denied: user %s lacks %s (%s).", user.id, key, decision.reason
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient privileges. Missing permission: {key}.",
            )
        return user

    return _guard
