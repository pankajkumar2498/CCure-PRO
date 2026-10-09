"""
ccure_platform/offboarding.py — what happens to a module's data when an account
is permanently removed.

The platform owns ``users``. A module that records who did something (Audit's
scans, asset notes and tags, risk acceptances) owns the rows that point at the
user, and only that module may touch them. Before this contract existed the
user-purge route reached into Audit's tables itself, which made the platform
depend on Audit. Now the route asks, and each module answers for its own data:

    register_user_purge_hook(hook)        a module, once, at start-up
    run_user_purge_hooks(db, user_id)     the platform, inside the purge

A hook is ``hook(db, user_id) -> None``. It runs on the **caller's session, in
the purge's own transaction**, before the user row is deleted, and must not
commit: if the purge fails everything rolls back together, exactly as when the
statements sat in the route. A hook detaches (sets the reference to NULL); it
does not delete the module's records, because a scan or a finding outlives the
person who started it.

Registration is by the module's own code (``ccure_audit/offboarding.py``,
imported by ``main.py``), never by the platform importing the module.

Organisations are archived, never deleted (``archive_organization``), so there
is no organisation hook; hard deletion, when it is built, joins this contract.
"""

from __future__ import annotations

from typing import Callable

from sqlalchemy.orm import Session

UserPurgeHook = Callable[[Session, str], None]

_user_purge_hooks: dict[str, UserPurgeHook] = {}


def register_user_purge_hook(name: str, hook: UserPurgeHook) -> None:
    """Register ``hook`` under a unique ``name`` (re-registering the same one is a no-op)."""
    existing = _user_purge_hooks.get(name)
    if existing is not None and existing is not hook:
        raise ValueError(f"A user-purge hook named {name!r} is already registered.")
    _user_purge_hooks[name] = hook


def registered_user_purge_hooks() -> tuple[str, ...]:
    return tuple(_user_purge_hooks)


def run_user_purge_hooks(db: Session, user_id: str) -> None:
    """Run every registered hook, in registration order, on ``db``."""
    for hook in tuple(_user_purge_hooks.values()):
        hook(db, user_id)
