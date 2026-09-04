"""
core/checks/registry.py
─────────────────────────────────────────────────────────────────────────────
Where checks are registered, and where a check that cannot possibly run is
rejected instead of quietly accepted.

The failure this is built against
─────────────────────────────────
The existing vulnerability plugins are duck-typed modules. The engine calls
serial plugins with three arguments and parallel plugins with two, catches
every plugin exception at DEBUG level, and moves on. A plugin whose ``run``
takes the wrong number of arguments therefore raises ``TypeError`` on every
host, logs nothing anybody reads, and appears in every list of registered
plugins while never once executing. That is not hypothetical — it is recorded
in CLAUDE.md as one of four defects that each produced *zero findings* until
someone scanned a target they already knew was vulnerable and noticed the
silence.

A registry that accepts anything callable reproduces that defect for every
capability added from here on. So registration validates the signature against
the calling convention the executor will actually use, and refuses at
registration time — at import, in the test suite, in CI — rather than at scan
time on a customer's network.

Registration is not execution
─────────────────────────────
This module deliberately does not run checks. Execution differs per domain: a
network probe runs in a thread pool against an IP, a configuration check runs
against already-collected evidence, a database check runs inside a session. A
single executor here would either be trivial or wrong. What every domain does
share is the need to answer "which checks apply to this target, and are they
all actually callable" — that is what lives here.
"""

from __future__ import annotations

import inspect
import logging
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional

from core.checks.contract import CheckResult, CheckSpec

log = logging.getLogger("ccure.checks.registry")

__all__ = [
    "CheckRegistry",
    "RegisteredCheck",
    "RegistrationError",
    "registry",
]


class RegistrationError(ValueError):
    """A check was declared in a way that guarantees it cannot run."""


@dataclass(frozen=True)
class RegisteredCheck:
    spec: CheckSpec
    run: Callable[..., Any]

    @property
    def check_id(self) -> str:
        return self.spec.check_id


def _accepts_arity(func: Callable[..., Any], arity: int) -> bool:
    """
    Can *func* be called with exactly *arity* positional arguments?

    ``inspect.signature().bind`` answers this correctly for defaults, keyword-
    only parameters, ``*args`` and bound methods, where counting
    ``co_argcount`` does not. A builtin or C callable with no retrievable
    signature is allowed through — refusing it would reject a legitimate
    wrapper, and the arity it was going to be called with is unknowable either
    way.
    """
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        return True
    try:
        signature.bind(*(object(),) * arity)
    except TypeError:
        return False
    return True


class CheckRegistry:
    """
    An in-process index of checks, keyed by check id.

    Thread-safe because the scan engines register from worker threads during
    lazy plugin loading, and a dict mutated from several threads mid-iteration
    raises ``RuntimeError`` in a place nobody would look for it.
    """

    def __init__(self, *, required_arity: int = 1) -> None:
        #: How many positional arguments the executor will pass to ``run``.
        #: One — the target context — for every domain implemented so far.
        self._required_arity = required_arity
        self._checks: Dict[str, RegisteredCheck] = {}
        self._lock = threading.RLock()

    # ── Registration ─────────────────────────────────────────────────────────

    def register(
        self, spec: CheckSpec, run: Callable[..., Any], *, replace: bool = False
    ) -> RegisteredCheck:
        """
        Add a check. Raises :class:`RegistrationError` rather than logging and
        continuing — see the module docstring for why a check that silently
        fails to register is worse than one that never existed.
        """
        if not callable(run):
            raise RegistrationError(
                f"Check {spec.check_id}: run must be callable, got {type(run).__name__}"
            )
        if not _accepts_arity(run, self._required_arity):
            raise RegistrationError(
                f"Check {spec.check_id}: {getattr(run, '__qualname__', run)!r} "
                f"cannot be called with {self._required_arity} positional "
                f"argument(s), which is how the executor calls it. It would "
                f"raise TypeError on every target and be counted as registered "
                f"while never running."
            )
        with self._lock:
            if spec.check_id in self._checks and not replace:
                existing = self._checks[spec.check_id]
                raise RegistrationError(
                    f"Check {spec.check_id} is already registered by "
                    f"{getattr(existing.run, '__module__', '?')}. Two checks "
                    f"sharing an id collapse to one catalogue row and one "
                    f"finding — pass replace=True only if that is intended."
                )
            entry = RegisteredCheck(spec=spec, run=run)
            self._checks[spec.check_id] = entry
        log.debug("Registered check %s (%s)", spec.check_id, spec.domain)
        return entry

    def check(self, spec: CheckSpec, *, replace: bool = False):
        """Decorator form of :meth:`register`."""

        def _decorate(func: Callable[..., Any]) -> Callable[..., Any]:
            self.register(spec, func, replace=replace)
            return func

        return _decorate

    def unregister(self, check_id: str) -> bool:
        with self._lock:
            return self._checks.pop(check_id, None) is not None

    def clear(self) -> None:
        """Drop every registration. For tests; nothing in production calls it."""
        with self._lock:
            self._checks.clear()

    # ── Lookup ───────────────────────────────────────────────────────────────

    def get(self, check_id: str) -> Optional[RegisteredCheck]:
        with self._lock:
            return self._checks.get(check_id)

    def __len__(self) -> int:
        with self._lock:
            return len(self._checks)

    def __contains__(self, check_id: object) -> bool:
        with self._lock:
            return str(check_id) in self._checks

    def __iter__(self) -> Iterator[RegisteredCheck]:
        # Iterate a snapshot: a check registered from another thread mid-loop
        # would otherwise raise "dictionary changed size during iteration".
        with self._lock:
            snapshot = list(self._checks.values())
        return iter(snapshot)

    def select(
        self,
        *,
        domain: Optional[str] = None,
        platform: Optional[str] = None,
        credentialed: Optional[bool] = None,
        allow_intrusive: bool = False,
    ) -> List[RegisteredCheck]:
        """
        The checks applicable to a target, in registration order.

        ``allow_intrusive`` defaults to False in every caller, deliberately.
        This product scans production and OT hosts, and an intrusive check must
        be something an operator turned on rather than something they forgot to
        turn off.
        """
        selected: List[RegisteredCheck] = []
        for entry in self:
            spec = entry.spec
            if domain is not None and spec.domain != domain:
                continue
            # A spec declaring "any" applies to every platform; otherwise the
            # requested platform must be named explicitly.
            if (
                platform is not None
                and "any" not in spec.platforms
                and platform not in spec.platforms
            ):
                continue
            if credentialed is not None and spec.requires_credentials != credentialed:
                continue
            if spec.intrusive and not allow_intrusive:
                continue
            selected.append(entry)
        return selected

    # ── Execution helper ─────────────────────────────────────────────────────

    def run_check(self, check_id: str, context: Any) -> CheckResult:
        """
        Run one registered check and guarantee a :class:`CheckResult` comes
        back.

        A check that raises produces an ERROR result naming the exception, not
        a swallowed log line and not a FAIL. Both of the alternatives are
        wrong in ways this codebase has already paid for: swallowing makes a
        broken check indistinguishable from a clean host, and returning FAIL
        invents a finding out of a bug in our own code.
        """
        entry = self.get(check_id)
        if entry is None:
            raise KeyError(f"No check registered under {check_id!r}")
        target = str(getattr(context, "target", "") or "")
        try:
            result = entry.run(context)
        except Exception as exc:  # noqa: BLE001 — deliberately broad, see docstring
            log.warning(
                "Check %s raised on target %s: %s", check_id, target or "?", exc
            )
            return CheckResult.error_result(
                check_id=check_id,
                target=target,
                reason=f"{type(exc).__name__}: {exc}",
                title=entry.spec.title,
                severity=entry.spec.severity,
            )
        if not isinstance(result, CheckResult):
            return CheckResult.error_result(
                check_id=check_id,
                target=target,
                reason=f"check returned {type(result).__name__}, expected CheckResult",
                title=entry.spec.title,
                severity=entry.spec.severity,
            )
        return result

    def run_all(
        self, checks: Iterable[RegisteredCheck], context: Any
    ) -> List[CheckResult]:
        return [self.run_check(entry.check_id, context) for entry in checks]


#: The process-wide registry. A module-level singleton because check modules
#: register at import time, exactly as the vulnerability plugins are imported
#: for their side effects today.
registry = CheckRegistry()
