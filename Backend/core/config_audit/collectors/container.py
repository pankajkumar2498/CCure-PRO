"""
core/config_audit/collectors/container.py
─────────────────────────────────────────────────────────────────────────────
The ``container`` collector — runs a named probe against a container runtime or
a Kubernetes cluster, over the host's own credentialed session. Phase 9
(GAP-17).

Its own check type, for the Phase 5 reason
──────────────────────────────────────────
``structured_config`` reads a document and addresses a value inside it. This
answers a different question: *which running things are offending*. The
collector enumerates, the probe filters in Python, and the rule asserts the
list is empty — so a clean host produces ABSENT and ``AbsencePolicy.PASS``
makes it a pass, while a breached one names exactly what to fix.

That is the same shape ``privilege`` has, and the same argument applies: the
enumeration is not a shell one-liner a rule author should be pasting.

Absence, and the estate this runs across
────────────────────────────────────────
Most hosts in an estate run no containers at all, so the difference between
"no offending containers" and "no container runtime" is the difference between
a useful rule set and one that reports a clean bill of health for software that
is not there.

So the probes distinguish **two** failures where one code would have done, and
the split is the whole reason this collector reads exit statuses at all:

``97`` — the tool is not installed. This is not a Docker or Kubernetes host,
so the check was never in scope: **UNSUPPORTED → NOT_APPLICABLE**, the same
answer Phase 8 gives a host with no nginx configuration file. Reporting ERROR
here would hand eight findings-shaped errors to every host in an estate that
does not run Kubernetes, which is most of them.

``96`` — the tool is installed but not answering. It *is* a host of this kind
and we failed to assess it: **UNAVAILABLE → ERROR**. This must never collapse
into either of the other two, because ``docker ps`` against a dead daemon
returns the same empty list a clean host does.

That is a deliberate departure from the Phase 3 and Phase 5 use of exit 97,
where a missing ``find`` *is* an error. The difference is whether the thing
being enumerated exists everywhere: every Linux host has SUID binaries, so
failing to list them is a gap; not every host has a container runtime, so not
finding one is an answer.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from core.config_audit.collection import CollectedState, CollectionContext
from core.config_audit.collectors.base import Collector, CollectorRegistry, ShellRunner
from core.config_audit.containers import (
    TOOL_MISSING,
    TOOL_UNREACHABLE,
    probe_for,
    probe_names,
)
from core.config_audit.spec import ConfigCheck

log = logging.getLogger("ccure.config_audit.collectors.container")

__all__ = ["ContainerCollector", "register_container_collector"]

#: Offender lists are evidence, not a data export. A cluster with a thousand
#: non-compliant pods produces a finding nobody reads if every one is listed.
_MAX_OFFENDERS = 40


def _runner(ctx: CollectionContext) -> ShellRunner:
    key = "__shell_runner__"
    if key not in ctx.cache:
        ctx.cache[key] = ShellRunner(
            ctx.executor, ctx.platform, default_timeout=ctx.timeout
        )
    return ctx.cache[key]


class ContainerCollector(Collector):
    """
    Runs one named probe and reports the offenders it found.

    ``check.collect`` keys:

    ``probe``   required — the probe name, from ``containers.probe_names()``
    """

    check_type = "container"
    platforms = ("linux",)
    name = "container"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "probe")
        if failure is not None:
            return failure
        params = params or {}

        try:
            probe = probe_for(str(params["probe"]))
        except KeyError as exc:
            # A rule naming a probe nothing implements is a defect in the rule.
            # UNAVAILABLE rather than raising, so one bad rule does not abort
            # the audit of every other check on the host.
            return CollectedState.unavailable(str(exc), collector=self.name)

        runner = _runner(ctx)
        if not runner.available:
            return CollectedState.unavailable(
                "no authenticated session to the host", collector=self.name
            )

        # Cached per probe: several rules legitimately read the same
        # enumeration — every Kubernetes pod rule runs `kubectl get pods` — and
        # without this the audit pays for it once per rule.
        cache_key = f"__container_probe__{probe.name}"

        def _run() -> Any:
            return runner.run(probe.command, timeout=max(ctx.timeout, 60))

        out = ctx.cached(cache_key, _run)

        if out.exit_code == TOOL_MISSING:
            # Not a host of this kind. UNSUPPORTED → NOT_APPLICABLE, the same
            # answer Phase 8 gives a host with no nginx configuration file:
            # most hosts in an estate run no Kubernetes and they are not
            # failing its rules.
            return CollectedState.unsupported(
                f"{probe.requires} is not installed on this host, so it does "
                f"not appear to run this runtime",
                collector=self.name,
            )
        if out.exit_code == TOOL_UNREACHABLE:
            # It *is* a host of this kind and we could not assess it. That is a
            # genuine gap and must never read as "nothing found" — `docker ps`
            # against a dead daemon returns the same empty list a clean host
            # does.
            return CollectedState.unavailable(
                f"{probe.requires} is installed but is not answering, so "
                f"nothing was established about this host's containers",
                collector=self.name,
            )
        if not out.ok:
            return CollectedState.unavailable(
                out.failure_detail(),
                raw=(out.stderr or out.stdout)[:400],
                collector=self.name,
            )

        try:
            offenders = list(probe.extract(out.text))
        except Exception as exc:  # noqa: BLE001 — reported, never a verdict
            # A probe that cannot parse what it was given has established
            # nothing. Reading the failure as "no offenders" is the inversion
            # this whole collection vocabulary exists to prevent.
            log.debug("Probe %s could not parse its output: %s", probe.name, exc)
            return CollectedState.unavailable(
                f"the {probe.name} probe ran but its output could not be "
                f"interpreted: {exc}",
                raw=out.text[:400],
                collector=self.name,
            )

        raw = self._evidence(probe, out.text, offenders)

        if str(params.get("result") or "rows").strip().lower() == "count":
            return CollectedState.collected(
                len(offenders), raw=raw, collector=self.name
            )

        if not offenders:
            # A search that returned nothing is a real result — unlike a
            # missing file, which says nothing at all. The rule's absence
            # policy decides, and for these it is PASS.
            return CollectedState.absent(
                f"the {probe.name} probe found nothing offending",
                raw=raw,
                collector=self.name,
            )

        return CollectedState.collected(
            offenders[:_MAX_OFFENDERS], raw=raw, collector=self.name
        )

    @staticmethod
    def _evidence(probe: Any, output: str, offenders: list) -> str:
        lines = [
            f"probe: {probe.name}",
            f"needs: {probe.requires}",
            f"offenders: {len(offenders)}",
        ]
        lines.extend(str(o) for o in offenders[:_MAX_OFFENDERS])
        if len(offenders) > _MAX_OFFENDERS:
            lines.append(f"… and {len(offenders) - _MAX_OFFENDERS} more")
        if not offenders:
            # Enough of the raw output to show the enumeration really ran, so a
            # reader can tell a genuinely clean host from a probe that returned
            # nothing for an uninteresting reason.
            lines.append("raw output (first 200 chars): " + (output or "")[:200])
        return "\n".join(lines)


def register_container_collector(registry: CollectorRegistry) -> None:
    registry.register(ContainerCollector())
