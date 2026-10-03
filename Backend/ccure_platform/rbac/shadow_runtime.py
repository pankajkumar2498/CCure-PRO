"""
ccure_platform/rbac/shadow_runtime.py — running the comparison beside the legacy check.

``shadow.py`` is the comparison; this is *whether and how it runs*. The legacy
guards (``ccure_platform/rbac/dependencies.py``) call ``observe_permission`` and
``observe_role_check`` **after** they have computed their own answer, and carry on
with that answer whatever happens here.

**RBAC-3 = SHADOW ONLY. LEGACY AUTHORIZATION = AUTHORITATIVE.** Four properties make
that true, and each is tested:

1. **Off by default, and cheap when off.** ``RBAC_SHADOW_MODE`` (``config.py``) is
   ``off`` unless set to exactly ``observe``; anything else is ``off``. When off, an
   observe call returns before it imports, queries or allocates anything.
2. **It returns nothing.** ``observe_*`` return ``None``. There is no value for a
   caller to branch on, so a shadow ALLOW cannot grant, a shadow DENY cannot remove,
   and nothing the comparison finds can reach the response.
3. **It cannot raise.** Everything — configuration, sampling, the database, the
   comparison, recording, logging — is inside a ``try``. A shadow error is *recorded*
   as an ``ERROR`` result and the request continues on the legacy decision.
4. **It cannot touch the request's transaction.** The comparison runs on its **own
   database session**, opened read-only (``SET TRANSACTION READ ONLY``) with a
   statement timeout, and closed afterwards. A failed or slow shadow query neither
   poisons the request's transaction nor writes anything. (Tests inject a session
   with ``use_session``.)

It is also **re-entrancy safe** (a comparison cannot trigger a comparison),
**sampled** (``RBAC_SHADOW_SAMPLE_RATE``), and records into one process-wide
``ShadowRecorder`` whose log lines carry only the fields a ``ShadowResult`` has.
Nothing is persisted: RBAC-3 adds no table and writes no row.

Legacy permission checks carry no organisation, so the comparison runs at the
principal's own organisation (``shadow.py``: scope is deferred to RBAC-5).
"""

from __future__ import annotations

import contextlib
import logging
import random
import threading
from typing import Callable, Iterable

from ccure_platform.rbac import shadow

logger = logging.getLogger("ccure.rbac.shadow")

MODE_OFF = "off"
MODE_OBSERVE = "observe"

_state = threading.local()
_recorder: shadow.ShadowRecorder | None = None
_recorder_lock = threading.Lock()
_warned_mode: set[str] = set()
#: A callable returning a context manager that yields the session to compare on.
#: None means "open a read-only session of the shadow's own". Tests set it.
_session_provider: Callable[[], contextlib.AbstractContextManager] | None = None


# ── configuration ─────────────────────────────────────────────────────────────


def _config():
    from config import AppConfig

    return AppConfig


def mode() -> str:
    """``observe`` only when ``RBAC_SHADOW_MODE`` is exactly that; everything else
    is ``off`` (an unknown value is logged once and treated as off)."""
    raw = (getattr(_config(), "RBAC_SHADOW_MODE", MODE_OFF) or MODE_OFF).strip().lower()
    if raw == MODE_OBSERVE:
        return MODE_OBSERVE
    if raw != MODE_OFF and raw not in _warned_mode:
        _warned_mode.add(raw)
        logger.warning(
            "Unknown RBAC_SHADOW_MODE=%r; shadow authorization stays off", raw
        )
    return MODE_OFF


def enabled() -> bool:
    return mode() == MODE_OBSERVE


def _sample_rate() -> float:
    try:
        rate = float(getattr(_config(), "RBAC_SHADOW_SAMPLE_RATE", 1.0))
    except (TypeError, ValueError):
        return 1.0
    return min(1.0, max(0.0, rate))


def _sampled() -> bool:
    rate = _sample_rate()
    return rate >= 1.0 or (
        rate > 0.0 and random.random() < rate
    )  # noqa: S311 - not security


# ── the recorder ──────────────────────────────────────────────────────────────


def recorder() -> shadow.ShadowRecorder:
    """The process-wide recorder, created on first use."""
    global _recorder
    with _recorder_lock:
        if _recorder is None:
            cfg = _config()
            _recorder = shadow.ShadowRecorder(
                buffer=int(getattr(cfg, "RBAC_SHADOW_MISMATCH_BUFFER", 200)),
                log_matches=bool(getattr(cfg, "RBAC_SHADOW_LOG_MATCHES", False)),
            )
        return _recorder


def reset_recorder() -> None:
    """Discard the process-wide recorder (tests)."""
    global _recorder
    with _recorder_lock:
        _recorder = None


# ── the session ───────────────────────────────────────────────────────────────


@contextlib.contextmanager
def use_session(db):
    """Compare on ``db`` instead of opening a session of the shadow's own. For
    tests, whose data lives in a transaction a second session cannot see. Never
    used in a running application."""
    global _session_provider
    previous = _session_provider

    @contextlib.contextmanager
    def provide():
        yield db

    _session_provider = provide
    try:
        yield db
    finally:
        _session_provider = previous


@contextlib.contextmanager
def _shadow_session():
    """A read-only session of the shadow's own, with a statement timeout, always
    rolled back and closed."""
    provider = _session_provider
    if provider is not None:
        with provider() as db:
            yield db
        return
    from db.base import SessionLocal
    from sqlalchemy import text

    session = SessionLocal()
    try:
        # first statements of the transaction: nothing the comparison does can write
        session.execute(text("SET TRANSACTION READ ONLY"))
        timeout = int(getattr(_config(), "RBAC_SHADOW_STATEMENT_TIMEOUT_MS", 250))
        session.execute(
            text("SELECT set_config('statement_timeout', :ms, true)"),
            {"ms": str(max(1, timeout))},
        )
        yield session
    finally:
        try:
            session.rollback()
        finally:
            session.close()


# ── observing ─────────────────────────────────────────────────────────────────


def observe_permission(
    db,
    user,
    resource: str,
    action: str,
    legacy_allowed: bool,
    *,
    operation: str | None = None,
) -> None:
    """
    Compare the new engine's answer with ``legacy_allowed`` for a legacy
    ``resource:action`` check, and record the result. **Returns None, never raises,
    and has no effect on the caller.** ``db`` (the request's session) is not used:
    the comparison opens its own.
    """
    try:
        if not enabled() or getattr(_state, "active", False) or not _sampled():
            return
        _state.active = True
        try:
            with _shadow_session() as session:
                shadow.shadow_compare(
                    session,
                    user,
                    resource,
                    action,
                    bool(legacy_allowed),
                    operation=operation,
                    recorder=recorder(),
                )
        finally:
            _state.active = False
    except Exception:  # noqa: BLE001 - shadow must never break what it observes
        logger.debug("RBAC shadow observation failed", exc_info=True)
        return None


def observe_role_check(
    user,
    required_roles: Iterable[str],
    legacy_allowed: bool,
    *,
    operation: str | None = None,
) -> None:
    """
    Record that a route is guarded by a role **name** (``require_role``): there is
    no permission to compare, so the result is ``not_comparable``/``role_name_check``
    — live RBAC-4 evidence of which routes still depend on a role name. Returns
    None, never raises, needs no database.
    """
    try:
        if not enabled() or not _sampled():
            return
        recorder().record(
            shadow.role_name_check_result(
                user, required_roles, legacy_allowed, operation=operation
            )
        )
    except Exception:  # noqa: BLE001
        logger.debug("RBAC shadow role-check observation failed", exc_info=True)
        return None


def operation_of(request) -> str | None:
    """
    ``METHOD route-template`` for a request, or None. The *template* — ``/scans/{id}``
    — never the raw path, and never a query string, header, cookie or body: the
    template names an operation, a raw path can carry an identifier.
    """
    try:
        if request is None:
            return None
        route = request.scope.get("route") if hasattr(request, "scope") else None
        template = getattr(route, "path", None)
        method = getattr(request, "method", None)
        if not template:
            return method
        return f"{method} {template}" if method else template
    except Exception:  # noqa: BLE001
        return None
