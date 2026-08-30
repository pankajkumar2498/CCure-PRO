"""
core/checks/intrusive.py
─────────────────────────────────────────────────────────────────────────────
Whether a probe may *change* the target, rather than only observe it.

The distinction this draws
──────────────────────────
Almost everything this product does is observation: read a banner, read a file,
list a package. One probe is not — ``ftp_checker`` creates a directory on the
scanned host and removes it again, because that is the only way to establish
that an anonymous FTP root is writable, and a writable anonymous root on a host
that also serves those files over HTTP is remote code execution.

That detection is worth keeping. It is not worth performing by default. This
product scans production networks and OT segments, where an audit that changes
something is worse than the finding it would have produced — the same judgement
``nuclei_probe`` already makes when it passes ``-exclude-tags
dos,fuzz,intrusive``.

Why a module rather than a parameter
────────────────────────────────────
The vulnerability engine dispatches parallel plugins as ``run(ip, open_ports)``
and ``tests/scans/test_plugin_contract.py`` pins that arity — a plugin with the
wrong one raises ``TypeError`` on every host, is swallowed at DEBUG, and
produces zero findings indefinitely. So the policy cannot arrive as an argument
without changing a contract that exists to prevent exactly that failure.

It is therefore read from one place, at call time. **This module is the seam.**
A per-scan policy engine is GAP-12; when it arrives it replaces
:func:`intrusive_probes_allowed` and nothing else moves. Building half of that
engine here would leave two mechanisms to reconcile later.

Read at call time, never at import
──────────────────────────────────
:func:`intrusive_probes_allowed` consults the setting on every call rather than
capturing it in a module constant. A value frozen at import cannot be changed by
a test, and a probe whose safety gate cannot be exercised is a gate nobody has
checked.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator, Optional

log = logging.getLogger("ccure.checks.intrusive")

__all__ = [
    "allow_intrusive_probes",
    "intrusive_probes_allowed",
]

#: Set by :func:`allow_intrusive_probes` only. ``None`` means "no override in
#: force — consult the configured setting".
_OVERRIDE: Optional[bool] = None


def intrusive_probes_allowed() -> bool:
    """
    True when a probe may write to, or otherwise alter, a scanned host.

    Defaults to False and fails to False: a configuration that cannot be read
    means the operator has not turned this on, and the safe reading of "we do
    not know" is "do not touch the target".
    """
    if _OVERRIDE is not None:
        return _OVERRIDE
    try:
        from config import AppConfig

        return bool(getattr(AppConfig, "SCAN_ALLOW_INTRUSIVE", False))
    except Exception as exc:  # pragma: no cover - configuration import guard
        log.warning(
            "Could not read SCAN_ALLOW_INTRUSIVE (%s: %s); treating intrusive "
            "probes as forbidden.",
            type(exc).__name__,
            exc,
        )
        return False


@contextmanager
def allow_intrusive_probes(allowed: bool = True) -> Iterator[None]:
    """
    Permit — or explicitly forbid — intrusive probes for the duration of a block.

    Intended for tests and for an operator-driven scan that has opted in. The
    previous value is restored on the way out, including on an exception, so a
    block that raises cannot leave the scanner permitted to write to hosts.

    **Process-wide, and deliberately not thread-local.** A thread-local would
    look safer and be worse: the vulnerability engine runs parallel plugins in
    a ``ThreadPoolExecutor``, which does not propagate context to its workers,
    so a thread-local set on the calling thread would be invisible to the very
    probe it was meant to govern — permission silently lost, or silently kept.
    """
    global _OVERRIDE
    previous = _OVERRIDE
    _OVERRIDE = bool(allowed)
    try:
        yield
    finally:
        _OVERRIDE = previous
