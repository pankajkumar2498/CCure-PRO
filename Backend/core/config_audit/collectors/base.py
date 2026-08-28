"""
core/config_audit/collectors/base.py
─────────────────────────────────────────────────────────────────────────────
The collector contract, the collector registry, and the shell helper every
host collector runs its commands through.

Why the shell helper is not the collectors' own ``_run``
────────────────────────────────────────────────────────
``WindowsCollector._run`` and ``LinuxCollector._run`` both end with

    return _clean_output(result.stdout) if result.stdout else ""

which discards the exit code. For bulk inventory that is defensible — a
partially readable service list is still worth having. For a configuration
check it is the central defect: a command that failed returns ``""``, the
comparison reads ``""`` as the host's actual setting, and the check reports a
verdict about a machine whose answer was never obtained.

:class:`ShellRunner` therefore keeps ``exit_code`` and ``success`` and hands
back a :class:`ShellOutput` that a collector must consciously interpret. There
is no method on it that returns a bare string.

Resolution, and the refusal to guess
────────────────────────────────────
:class:`CollectorRegistry` resolves ``(check_type, platform)``. A pair with no
collector resolves to ``None`` and the engine turns that into ERROR — not
NOT_APPLICABLE, and certainly not a pass. "This product cannot perform that
check" and "that check does not apply to this host" are different facts, and
only the second is a legitimate reason for a control to disappear from a
compliance score.
"""

from __future__ import annotations

import base64
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.config_audit.collection import CollectedState, CollectionContext
from core.config_audit.spec import ConfigCheck

log = logging.getLogger("ccure.config_audit.collectors")

__all__ = [
    "Collector",
    "CollectorRegistry",
    "ShellOutput",
    "ShellRunner",
    "collector_registry",
]


@dataclass(frozen=True)
class ShellOutput:
    """
    The result of running one command on a target, with the exit status
    preserved.

    ``ok`` is the property collectors branch on. It is deliberately not a
    truthiness test on ``stdout``: a command that legitimately produces no
    output (``sc.exe query`` for a service that is not installed) is a
    successful read, and a command that failed while printing a diagnostic to
    stdout is not.
    """

    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    ok: bool = False
    #: Set when the command could not be run at all — no executor, transport
    #: raised. Distinct from a command that ran and returned non-zero.
    transport_error: str = ""

    @property
    def text(self) -> str:
        return (self.stdout or "").strip()

    def failure_detail(self) -> str:
        """A one-line reason suitable for ``CollectedState.unavailable``."""
        if self.transport_error:
            return f"command could not be executed: {self.transport_error}"
        detail = (self.stderr or "").strip().splitlines()
        first = detail[0][:300] if detail else ""
        return (
            f"command exited {self.exit_code}"
            f"{f': {first}' if first else ' with no diagnostic output'}"
        )


class ShellRunner:
    """
    Runs commands on a target through any ``BaseExecutor``.

    On Windows the executor may be a WinRM session (already PowerShell) or SSH
    into cmd.exe (needs ``-EncodedCommand``). The encoding decision is the same
    one ``WindowsCollector._wrap_ps`` makes and for the same reason: cmd.exe
    mangles braces, dollar signs and nested quotes, and base64 UTF-16-LE is the
    only quoting-proof way through it. Encoding twice would feed the encoder
    its own output, so detection runs once per runner and is cached.
    """

    _PS_EXE = "powershell.exe"

    def __init__(
        self, executor: Optional[Any], platform: str, *, default_timeout: int = 45
    ) -> None:
        self._executor = executor
        self._platform = (platform or "").strip().lower()
        self._default_timeout = default_timeout
        self._shell_type: Optional[str] = None

    @property
    def available(self) -> bool:
        return self._executor is not None

    def _detect_shell(self) -> str:
        if self._shell_type is not None:
            return self._shell_type
        if self._platform != "windows":
            self._shell_type = "posix"
            return self._shell_type
        try:
            result = self._executor.run("$PSVersionTable.PSVersion.Major", timeout=8)
            cleaned = (result.stdout or "").strip()
            self._shell_type = (
                "powershell" if (result.success and cleaned.isdigit()) else "cmd"
            )
        except Exception:
            # An exception here says the transport is unwell, not that the
            # shell is cmd. Assume the safe encoding, and let the actual
            # command report the transport failure with its own detail.
            self._shell_type = "cmd"
        return self._shell_type

    def _wrap(self, command: str) -> str:
        if self._platform != "windows":
            return command
        if self._detect_shell() == "powershell":
            return command
        encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
        return (
            f"{self._PS_EXE} -NoProfile -NonInteractive -ExecutionPolicy Bypass"
            f" -EncodedCommand {encoded}"
        )

    def run(self, command: str, timeout: Optional[int] = None) -> ShellOutput:
        if self._executor is None:
            return ShellOutput(
                command=command,
                transport_error="no authenticated session to the target",
            )
        try:
            result = self._executor.run(
                self._wrap(command), timeout=timeout or self._default_timeout
            )
        except Exception as exc:  # transport-level failure
            return ShellOutput(
                command=command, transport_error=f"{type(exc).__name__}: {exc}"
            )
        return ShellOutput(
            command=command,
            stdout=result.stdout or "",
            stderr=result.stderr or "",
            exit_code=result.exit_code,
            ok=bool(result.success),
        )


class Collector(ABC):
    """
    Reads one class of configuration item from one class of target.

    A collector never decides whether the host is compliant. It reports what is
    there, what is not there, or that it could not tell — the comparison
    against the expected state happens in the engine, once, for every check
    type. Collectors that evaluate their own rules are how a check type comes
    to have its own private notion of "pass".
    """

    #: The ``check_type`` this collector serves.
    check_type: str = ""
    #: Platforms it serves. ``("any",)`` for a collector that needs no
    #: platform-specific knowledge.
    platforms: Tuple[str, ...] = ()
    #: Recorded on every ``Evidence`` this collector's readings produce, so a
    #: reviewer can see what gathered a value.
    name: str = ""

    @abstractmethod
    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        """Read the item *check* names from the target described by *ctx*."""
        raise NotImplementedError

    # ── Helpers shared by concrete collectors ────────────────────────────────

    def _require(
        self, check: ConfigCheck, *keys: str
    ) -> Tuple[Optional[Dict[str, Any]], Optional[CollectedState]]:
        """
        Pull required parameters out of ``check.collect``.

        A rule missing a parameter its collector needs is a defect in the rule,
        and the honest outcome is "could not evaluate" — returning UNAVAILABLE
        rather than raising, so one malformed rule does not abort the audit of
        every other check on the host.
        """
        params = dict(check.collect or {})
        missing = [k for k in keys if not params.get(k)]
        if missing:
            return None, CollectedState.unavailable(
                f"rule does not supply required parameter(s): " f"{', '.join(missing)}",
                collector=self.name,
            )
        return params, None


class CollectorRegistry:
    """
    Indexes collectors by ``(check_type, platform)``.

    Registration refuses a duplicate rather than overwriting. Two collectors
    claiming the same pair means one of them silently never runs, which is the
    plugin-registration failure CLAUDE.md records — the same defect, one layer
    up.
    """

    def __init__(self) -> None:
        self._by_key: Dict[Tuple[str, str], Collector] = {}

    def register(self, collector: Collector, *, replace: bool = False) -> Collector:
        if not collector.check_type:
            raise ValueError(
                f"{type(collector).__name__}: check_type is required to register"
            )
        if not collector.platforms:
            raise ValueError(
                f"{type(collector).__name__}: platforms is required to register"
            )
        for platform in collector.platforms:
            key = (collector.check_type, platform)
            if key in self._by_key and not replace:
                raise ValueError(
                    f"A collector is already registered for check_type="
                    f"{collector.check_type!r} platform={platform!r}: "
                    f"{type(self._by_key[key]).__name__}. Registering a second "
                    f"would leave one of them permanently unreachable."
                )
            self._by_key[key] = collector
        return collector

    def resolve(self, check_type: str, platform: str) -> Optional[Collector]:
        """
        Find the collector for this pair, falling back to a platform-agnostic
        one. Returns None where nothing can perform the check — the caller must
        render that as an error, never as a passing or inapplicable check.
        """
        platform = (platform or "").strip().lower()
        return self._by_key.get((check_type, platform)) or self._by_key.get(
            (check_type, "any")
        )

    def supported_check_types(self, platform: str) -> List[str]:
        platform = (platform or "").strip().lower()
        return sorted(
            {ct for (ct, plat) in self._by_key if plat == platform or plat == "any"}
        )

    def all_collectors(self) -> Iterable[Collector]:
        seen: set[int] = set()
        for collector in self._by_key.values():
            if id(collector) not in seen:
                seen.add(id(collector))
                yield collector

    def clear(self) -> None:
        self._by_key.clear()


#: Process-wide registry. Populated by importing the platform collector
#: modules, which ``core.config_audit`` does at package import.
collector_registry = CollectorRegistry()
