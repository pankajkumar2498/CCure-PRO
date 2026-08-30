"""
core/config_audit/collectors/scap.py
─────────────────────────────────────────────────────────────────────────────
The ``scap_rule`` collector: evaluates one compiled OVAL definition.

Why a check type rather than a translation into the existing ones
─────────────────────────────────────────────────────────────────
A Phase 3 ``ConfigCheck`` is one read compared against one expected state. An
OVAL definition is a **criteria tree** over several tests, each with its own
existence semantics — 619 ``AND`` and 333 ``OR`` nodes in the measured corpus.
There is no faithful way to flatten "either this package is absent or its
configuration file sets this directive" into a single read, and an unfaithful
one produces a verdict rather than an error.

So the rule carries the compiled definition and this collector walks it,
delegating each leaf to :mod:`core.scap.probes`. That is the same shape Phase 9
used for ``container``: the rule names what to evaluate, the logic lives in
code, and nothing that reaches a shell comes out of rule data unquoted.

Three outcomes, and the third is the important one
──────────────────────────────────────────────────
TRUE  → ``compliant``      → the rule's expectation matches → PASS
FALSE → ``non_compliant``  → the expectation does not match → FAIL
UNKNOWN → UNAVAILABLE      → **ERROR**, never a verdict

The last line is GAP-05's central rule. A definition using an OVAL construct
this build cannot evaluate never reaches here — the converter refuses it at
load time and records the control as unimplemented — but a *runtime* failure
(an unreadable file, an absent tool, a probe defect) lands here and must stay
visibly unassessed.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

from core.config_audit.collection import CollectedState, CollectionContext
from core.config_audit.collectors.base import Collector
from core.config_audit.spec import ConfigCheck

log = logging.getLogger("ccure.config_audit.scap")

__all__ = [
    "COMPLIANT",
    "NON_COMPLIANT",
    "ScapRuleCollector",
    "register_scap_collectors",
]

#: The two values a compiled rule collects. Spelled out rather than boolean so
#: a report's "Actual" column reads as a sentence rather than as ``False``.
COMPLIANT = "compliant"
NON_COMPLIANT = "non_compliant"


class ScapRuleCollector(Collector):
    """Walks a compiled OVAL definition and reports the host's state."""

    check_type = "scap_rule"
    platforms = ("linux",)
    name = "scap_rule"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "definition")
        if failure is not None:
            return failure
        params = params or {}

        compiled = params.get("definition")
        if not isinstance(compiled, Mapping):
            return CollectedState.unavailable(
                "the rule's compiled OVAL definition is not a mapping, so it "
                "could not be evaluated",
                collector=self.name,
            )

        from core.scap.evaluate import (
            Outcome,
            evaluate_applicability,
            evaluate_definition,
        )

        # Applicability first. A rule conditional on a platform the host does
        # not have is **not applicable**, not a failure — and this is the
        # largest false-positive class the phase measured: without it, 128 of
        # 146 Ubuntu STIG rules produced verdicts against a container, 102 of
        # them findings about software that is not installed.
        applicability = params.get("applicability")
        if isinstance(applicability, Mapping):
            verdict = evaluate_applicability(ctx, applicability)
            if verdict is Outcome.FALSE:
                return CollectedState.unsupported(
                    "the benchmark makes this rule conditional on a platform "
                    "this host does not have",
                    collector=self.name,
                )
            if verdict is Outcome.UNKNOWN:
                return CollectedState.unavailable(
                    "whether this rule applies to the host could not be "
                    "established, so it was not evaluated",
                    collector=self.name,
                )

        result = evaluate_definition(ctx, compiled)
        raw = "\n".join(result.notes) or result.detail

        if result.outcome is Outcome.UNKNOWN:
            return CollectedState.unavailable(
                result.detail
                or "the OVAL definition could not be evaluated on this host",
                raw=raw,
                collector=self.name,
            )
        value = COMPLIANT if result.outcome is Outcome.TRUE else NON_COMPLIANT
        return CollectedState.collected(value, raw=raw, collector=self.name)


def register_scap_collectors(registry: Any) -> None:
    registry.register(ScapRuleCollector())
