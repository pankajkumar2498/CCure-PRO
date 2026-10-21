"""
core/config_audit/collection.py
─────────────────────────────────────────────────────────────────────────────
What a collector returns, and the context it is given to work with.

The four statuses are the whole point
─────────────────────────────────────
Every configuration scanner that reports false results does so by collapsing
these into fewer than four:

``COLLECTED``
    A value was read. The only status that reaches the comparison.

``ABSENT``
    The collector ran successfully and established that the thing is not
    there. A registry value that does not exist, a package that is not
    installed, a service that is not defined. This is a real observation, and
    the *rule* decides what it means — see :class:`~core.config_audit.spec.
    AbsencePolicy`. Merging it into COLLECTED-with-a-null makes "no such
    registry value" indistinguishable from "the value is empty", and those
    routinely mean opposite things.

``UNSUPPORTED``
    The check cannot be performed on this target at all — a registry read
    against Linux, a systemd query against a switch. Distinct from ABSENT
    because nothing about the host was established: the check was never in
    scope. Maps to NOT_APPLICABLE.

``UNAVAILABLE``
    Collection failed. No credential, transport refused, command returned a
    non-zero exit, output would not parse. **This can never become a verdict.**
    It is the status that exists so that a host nobody could reach does not
    acquire a compliance score, and it is the one every shortcut deletes:
    reading a failed command's empty stdout as "the setting is not present" is
    how a scanner reports a clean bill of health for a machine it never
    logged into.

``UNAVAILABLE`` requires a ``detail``. An unexplained failure is
indistinguishable in a log from a check that did nothing, which CLAUDE.md
records as how an unregistered plugin looked like a registered one for a whole
release.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Mapping, Optional

__all__ = [
    "CollectedState",
    "CollectionContext",
    "CollectionStatus",
]


class CollectionStatus(str, Enum):
    COLLECTED = "collected"
    ABSENT = "absent"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"

    @property
    def is_observation(self) -> bool:
        """
        True where the collector established something about the target.
        UNSUPPORTED and UNAVAILABLE did not.
        """
        return self in (CollectionStatus.COLLECTED, CollectionStatus.ABSENT)


@dataclass(frozen=True)
class CollectedState:
    """The actual state of one configuration item on one target."""

    status: CollectionStatus
    #: The read value. Meaningful only when ``status`` is COLLECTED.
    value: Any = None
    #: Verbatim collector output, for the evidence record. Redaction happens in
    #: ``Evidence``, which is the object that reaches the database and the
    #: report — doing it here as well would double-redact and obscure what was
    #: actually read during debugging.
    raw: Optional[str] = None
    #: Why, for the three non-COLLECTED statuses. Required for UNAVAILABLE.
    detail: str = ""
    #: Which collector produced this, for the evidence record.
    collector: str = ""

    def __post_init__(self) -> None:
        if (
            self.status is CollectionStatus.UNAVAILABLE
            and not str(self.detail or "").strip()
        ):
            raise ValueError(
                "CollectedState: UNAVAILABLE must carry a detail saying why "
                "collection failed. A silent failure is indistinguishable "
                "from a check that did nothing."
            )

    # ── Named constructors ───────────────────────────────────────────────────
    #
    # Provided because the alternative every collector reaches for under time
    # pressure is returning an empty COLLECTED value, which the comparison then
    # reads as a real reading of "".

    @classmethod
    def collected(
        cls, value: Any, *, raw: Optional[str] = None, collector: str = ""
    ) -> "CollectedState":
        return cls(
            status=CollectionStatus.COLLECTED,
            value=value,
            raw=raw,
            collector=collector,
        )

    @classmethod
    def absent(
        cls, detail: str = "", *, raw: Optional[str] = None, collector: str = ""
    ) -> "CollectedState":
        return cls(
            status=CollectionStatus.ABSENT,
            raw=raw,
            detail=detail,
            collector=collector,
        )

    @classmethod
    def unsupported(cls, detail: str, *, collector: str = "") -> "CollectedState":
        return cls(
            status=CollectionStatus.UNSUPPORTED, detail=detail, collector=collector
        )

    @classmethod
    def unavailable(
        cls, detail: str, *, raw: Optional[str] = None, collector: str = ""
    ) -> "CollectedState":
        return cls(
            status=CollectionStatus.UNAVAILABLE,
            raw=raw,
            detail=detail,
            collector=collector,
        )

    def observed_text(self) -> str:
        """What a report prints in the "Observed" column."""
        if self.status is CollectionStatus.COLLECTED:
            if isinstance(self.value, (list, tuple, set)):
                return ", ".join(str(v) for v in self.value) or "(empty)"
            if self.value is None:
                return "(null)"
            if self.value == "":
                return "(empty)"
            return str(self.value)
        if self.status is CollectionStatus.ABSENT:
            return f"not present{f' — {self.detail}' if self.detail else ''}"
        return self.detail or self.status.value


@dataclass
class CollectionContext:
    """
    Everything a collector is given about the target it is reading from.

    ``executor`` is the ``BaseExecutor`` from ``engines/credentialed/
    ssh_scanner.py`` — the same protocol ``SSHScanner`` and ``WinRMExecutor``
    both satisfy, so a configuration check runs over either transport with no
    knowledge of which. That protocol is why Phase 2 could swap transports
    without touching the Windows collector, and it is reused here for the same
    reason.

    ``system_data`` is what a credentialed collection already gathered for this
    host. A check that can be answered from it should be, rather than opening a
    second session to re-read what is already in hand; the engine passes both
    and each collector decides.

    ``version_compare`` orders two package or software versions, the way the
    package matcher does (epochs, ``~``, distribution release tags). The SCAP
    evaluator's version comparisons use it. It is passed in by whoever builds
    the context (``core/tasks.py``, from the credentialed engine's matcher)
    rather than imported, so the configuration audit depends on no engine
    (B10). Without one, a version comparison cannot be made and reads as
    unknown, never as a verdict.
    """

    target: str
    platform: str
    #: The host's own OS string and version, when collection has established
    #: them. ``platform`` distinguishes Windows from Linux and no further;
    #: benchmark content needs to tell Ubuntu from RHEL, and a check that names
    #: an OS constraint cannot be judged without these.
    os_name: str = ""
    os_version_id: str = ""
    executor: Optional[Any] = None
    system_data: Mapping[str, Any] = field(default_factory=dict)
    asset_id: Optional[str] = None
    org_id: Optional[str] = None
    #: Per-check command timeout, seconds.
    timeout: int = 45
    #: Set where the check's parameters must be resolved against a sub-target
    #: (a database instance, a virtual host) rather than the host itself.
    scope: Mapping[str, Any] = field(default_factory=dict)
    #: ``compare(left, right)`` → negative, zero or positive, or None when the
    #: two cannot be ordered. See the class docstring.
    version_compare: Optional[Callable[[str, str], Optional[int]]] = None
    #: Memo of command output within one run, so several checks reading the
    #: same expensive listing (installed packages, `auditpol /get /category:*`)
    #: pay for it once. Keyed by the collector on whatever it considers the
    #: identity of the read.
    cache: Dict[str, Any] = field(default_factory=dict)

    @property
    def has_credentials(self) -> bool:
        return self.executor is not None

    def cached(self, key: str, produce: Callable[[], Any]) -> Any:
        """
        Return ``cache[key]``, computing it once on first request.

        A miss stores whatever *produce* returned, including a failure state:
        re-running a command that already failed once against an unreachable
        host multiplies the timeout by the number of checks that need it.
        """
        if key not in self.cache:
            self.cache[key] = produce()
        return self.cache[key]
