"""
core/scan_policy/spec.py
─────────────────────────────────────────────────────────────────────────────
The effective assessment configuration: what a scan will actually assess.

    ScanPolicy row  ──resolve──>  EffectivePolicy  ──snapshot──>  scans.options
                                        │
                                        └──> benchmark selection, check
                                             selection, section selection,
                                             port selection, intensity

``EffectivePolicy`` is frozen, and that is not decoration. It is written into
the scan's own record at dispatch and read back by the worker, by the API and
by the report generator months later, so a value that could change between
those readings would make the record a description of something other than
what ran.

Two rules the whole phase rests on
──────────────────────────────────
**A field either changes assessment behaviour or it is not here.** Every
attribute below is read by something: benchmark selection, ``select_checks``,
the section list, the port arguments, the intrusive gate, or validation. A
knob nobody honours is worse than a missing one — an operator who sets it
believes the scan did something it did not. Fields the engine cannot honour
are recorded in ``docs/gap_closure/GAP_TRACKER.md`` as unimplemented and are
deliberately absent from this dataclass rather than accepted and ignored.

**An empty collection means "no restriction", never "nothing".** ``()`` for
``framework_ids`` selects every framework the tenant has installed, which is
the pre-policy behaviour and therefore what a policy that says nothing about
frameworks must do. Reading it as "select no frameworks" would let an
under-specified policy silently reduce a scan to nothing while still reporting
success — the single most dangerous defect available in a policy engine. The
resolver never converts an unset field into a restriction, and
``tests/scans/test_scan_policy_spec.py`` pins that direction.

The fingerprint
───────────────
``policy_fingerprint`` hashes the *behavioural* fields only — not the policy's
id, name, description or version. Two scans carrying the same fingerprint were
assessed the same way, whoever renamed the policy in between; two carrying
different fingerprints were not, and GAP-13's comparison says so rather than
implying the delta is a change in the estate. Renaming a policy must not make
a scan incomparable with the one before it, and editing what it assesses must.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, fields, replace
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

__all__ = [
    "CHECK_FAMILIES",
    "EffectivePolicy",
    "FIELD_AREAS",
    "POLICY_SCAN_KINDS",
    "SEVERITY_ORDER",
    "next_version_number",
    "policy_fingerprint",
    "severity_at_least",
]


# ─────────────────────────────────────────────────────────────────────────────
# Vocabularies
# ─────────────────────────────────────────────────────────────────────────────

#: Which pipeline a policy may drive — defined in db/scan_policy_kinds.py
#: (Phase 3), because it is also the domain of the ``scan_policies.scan_kind``
#: CHECK constraint and the model must not import this package. Re-exported
#: here unchanged, so everything that reads it from the spec still does.
from db.scan_policy_kinds import (  # noqa: E402,F401  (re-export)
    POLICY_KIND_ANY,
    POLICY_KIND_CREDENTIALED,
    POLICY_KIND_NETWORK,
    POLICY_SCAN_KINDS,
)

#: Severity vocabulary, weakest first, and the floor comparison over it —
#: defined in the check kernel (G4), because benchmark selection applies a
#: policy's floor too and must not import scan policy. Re-exported here
#: unchanged, so everything that reads them from the spec still does.
from core.checks.contract import (  # noqa: E402,F401  (re-export)
    SEVERITY_ORDER,
    severity_at_least,
)

#: A "check family" is a ``ConfigCheck.domain``, and the vocabulary is
#: **imported, never restated**. ``ConfigCheck.__post_init__`` raises SpecError
#: on a domain outside ``CHECK_DOMAINS``, so a second list here would let a
#: policy accept a family name the engine refuses to construct a check with —
#: the policy would select zero checks and the host would report clean.
#:
#: This was not hypothetical: the first version of this module enumerated its
#: own list including "benchmark" and "middleware", neither of which is a
#: domain. Found by a test that built a check from a rule the policy had
#: happily validated.
from core.checks.contract import CHECK_DOMAINS  # noqa: E402

CHECK_FAMILIES: Tuple[str, ...] = tuple(CHECK_DOMAINS)


def next_version_number(existing: Sequence[int]) -> int:
    """
    The version a new member of a policy family takes.

    ``max + 1`` rather than ``len + 1``: a family whose version 2 was deleted
    must not reissue 2, because the scans that ran under the original still
    name it in their snapshots and two different configurations answering to
    one identifier is precisely what the version number exists to prevent.
    """
    return (max(existing) + 1) if existing else 1


# ─────────────────────────────────────────────────────────────────────────────
# The effective configuration
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class EffectivePolicy:
    """
    The fully-resolved assessment configuration for one scan.

    Frozen, and written into ``scans.options`` before the scan runs. The worker
    reads it back from there rather than being handed it separately, so the
    historical record and what actually executed cannot disagree — there is one
    source, and it is the one the auditor reads.
    """

    # ── Identity. Not part of the fingerprint. ───────────────────────────────
    policy_id: Optional[str] = None
    policy_name: str = ""
    policy_family_code: str = ""
    version_number: int = 0
    scan_kind: str = POLICY_KIND_ANY

    # ── What is assessed ─────────────────────────────────────────────────────
    #: Framework ids to resolve benchmark checks from. Empty = every framework
    #: the tenant has installed and this installation offers, which is the
    #: pre-policy behaviour.
    framework_ids: Tuple[str, ...] = ()
    #: Benchmark profile, e.g. "stig". Empty = every control the benchmark
    #: defines, which is what `benchmark_checks_for_org` already does.
    benchmark_profile: Optional[str] = None
    #: ``ConfigCheck.domain`` values. Empty = every domain.
    check_families: Tuple[str, ...] = ()
    #: "windows" / "linux". Empty = resolve both and let the engine's own
    #: platform targeting narrow them, which is what happens today because the
    #: target's OS is not known until the session is open.
    platforms: Tuple[str, ...] = ()
    #: Credentialed collector sections. Empty = the collector's default set.
    sections: Tuple[str, ...] = ()
    #: Whether the twenty built-in checks run alongside benchmark content. On
    #: by default: they are what makes the engine produce a result at all on a
    #: tenant with no benchmark installed.
    include_builtin_checks: bool = True

    # ── What is filtered out ─────────────────────────────────────────────────
    min_severity: Optional[str] = None
    excluded_check_ids: Tuple[str, ...] = ()
    excluded_tags: Tuple[str, ...] = ()
    #: Addresses and ranges removed from the target set, in the same syntax
    #: ``exclude_ips`` already accepts on every scan route.
    excluded_targets: Tuple[str, ...] = ()

    # ── How deep ─────────────────────────────────────────────────────────────
    custom_ports: Optional[str] = None
    exclude_ports: Optional[str] = None
    discovery_intensity: Optional[str] = None
    port_scan_intensity: Optional[str] = None
    os_detection: Optional[bool] = None
    #: Whether a probe may change the target. Off unless a policy says
    #: otherwise, and it can only ever be turned on deliberately — the same
    #: trade ``core/checks/intrusive.py`` already records.
    allow_intrusive: bool = False

    # ── Binding ──────────────────────────────────────────────────────────────
    #: Refuse to start rather than silently run unauthenticated. A credentialed
    #: assessment that quietly degrades reports a host as clean because nothing
    #: could be collected from it.
    require_credential: bool = False

    # ── Provenance ───────────────────────────────────────────────────────────
    #: "policy" when a stored policy produced this, "request" when it is the
    #: request's own parameters carried through unchanged. The second is what
    #: preserves pre-policy behaviour and it must be visible as such: a report
    #: saying "policy: none" is honest, one inventing a policy name is not.
    source: str = "request"

    # ── Derived ──────────────────────────────────────────────────────────────

    def behavioural(self) -> Dict[str, Any]:
        """
        The fields that decide what is assessed, canonically ordered.

        Identity and provenance are excluded: renaming a policy does not change
        a scan, and a fingerprint that moved when somebody fixed a typo would
        make every scan incomparable with the one before it.
        """
        payload = asdict(self)
        for key in _IDENTITY_FIELDS:
            payload.pop(key, None)
        return {k: payload[k] for k in sorted(payload)}

    def fingerprint(self) -> str:
        return policy_fingerprint(self)

    def as_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["fingerprint"] = self.fingerprint()
        return payload

    def describe(self) -> Dict[str, str]:
        """
        Human-readable rows for the report's methodology section.

        "Every framework installed" rather than an empty string, because a
        blank cell in an audit report reads as "not recorded" and this is a
        recorded decision to restrict nothing.
        """
        return {
            "Policy": self.policy_name or "None (scan request defaults)",
            "Policy version": (
                f"{self.policy_family_code} v{self.version_number}"
                if self.policy_family_code
                else "Not applicable"
            ),
            "Configuration ID": self.fingerprint()[:16],
            "Benchmarks": (
                ", ".join(self.framework_ids)
                if self.framework_ids
                else "Every framework installed for this organisation"
            ),
            "Benchmark profile": self.benchmark_profile or "All profiles",
            "Platform scope": (
                ", ".join(self.platforms) if self.platforms else "Windows and Linux"
            ),
            "Check families": (
                ", ".join(self.check_families)
                if self.check_families
                else "All families"
            ),
            "Assessment sections": (
                ", ".join(self.sections) if self.sections else "Collector default set"
            ),
            "Built-in checks": (
                "Included" if self.include_builtin_checks else "Excluded"
            ),
            "Severity threshold": (
                f"{self.min_severity} and above"
                if self.min_severity
                else "No threshold"
            ),
            "Check exclusions": (
                ", ".join(self.excluded_check_ids)
                if self.excluded_check_ids
                else "None"
            ),
            "Tag exclusions": (
                ", ".join(self.excluded_tags) if self.excluded_tags else "None"
            ),
            "Target exclusions": (
                ", ".join(self.excluded_targets) if self.excluded_targets else "None"
            ),
            "Port selection": self.custom_ports or "Scanner default",
            "Port exclusions": self.exclude_ports or "None",
            "Intrusive probes": (
                "Permitted" if self.allow_intrusive else "Not permitted"
            ),
            "Credential required": "Yes" if self.require_credential else "No",
        }

    def with_identity(self, **kwargs: Any) -> "EffectivePolicy":
        """A copy carrying different identity fields. Used by the resolver."""
        return replace(self, **kwargs)


#: Fields excluded from the fingerprint. Identity and provenance, nothing else.
_IDENTITY_FIELDS: Tuple[str, ...] = (
    "policy_id",
    "policy_name",
    "policy_family_code",
    "version_number",
    "source",
)


def policy_fingerprint(policy: EffectivePolicy) -> str:
    """
    A stable identifier for *what this configuration assesses*.

    SHA-256 over the canonical JSON of the behavioural fields. Stable across
    processes and releases as long as the field set does not change; a field
    added by a later phase changes every fingerprint, which is correct — the
    configurations really are no longer the same shape — and shows up as
    "not comparable" rather than as a silent equality.
    """
    payload = json.dumps(
        policy.behavioural(), sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


#: Coverage areas each field answers, read by
#: ``scripts/measure_scan_policy_coverage.py``. Declared beside the fields so
#: an area cannot claim coverage from a field that was removed.
FIELD_AREAS: Dict[str, str] = {
    "framework_ids": "pol.select.frameworks",
    "benchmark_profile": "pol.select.profile",
    "check_families": "pol.select.families",
    "platforms": "pol.select.platforms",
    "sections": "pol.select.sections",
    "include_builtin_checks": "pol.select.builtin",
    "min_severity": "pol.filter.severity",
    "excluded_check_ids": "pol.filter.check_exclusions",
    "excluded_tags": "pol.filter.tag_exclusions",
    "excluded_targets": "pol.filter.target_exclusions",
    "custom_ports": "pol.depth.ports",
    "discovery_intensity": "pol.depth.discovery",
    "port_scan_intensity": "pol.depth.port_scan",
    "allow_intrusive": "pol.safety.intrusive",
    "require_credential": "pol.bind.credential",
}


# ─────────────────────────────────────────────────────────────────────────────
# Construction from stored configuration
# ─────────────────────────────────────────────────────────────────────────────


def _tuple(value: Any) -> Tuple[str, ...]:
    """
    Normalise a stored list into an ordered, de-duplicated tuple of strings.

    Order is preserved rather than sorted: ``framework_ids`` is shown to a
    reader in the report, and reordering what somebody typed is a small
    surprise for no gain. De-duplication matters because a repeated framework
    id would resolve its checks twice and count them twice in the score.
    """
    if value in (None, "", []):
        return ()
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        return ()
    seen: list[str] = []
    for item in items:
        token = str(item).strip()
        if token and token not in seen:
            seen.append(token)
    return tuple(seen)


def _opt_str(value: Any) -> Optional[str]:
    if value in (None, "", []):
        return None
    return str(value).strip() or None


def _opt_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    return bool(value)


def effective_from_config(
    config: Mapping[str, Any],
    *,
    policy_id: Optional[str] = None,
    policy_name: str = "",
    policy_family_code: str = "",
    version_number: int = 0,
    scan_kind: str = POLICY_KIND_ANY,
    source: str = "policy",
) -> EffectivePolicy:
    """
    Build an :class:`EffectivePolicy` from a stored ``scan_policies.config``.

    Unknown keys are ignored rather than raising. The configuration is
    validated on the way *in* (``validate_policy``), so a row that reaches here
    carrying something this build does not know is an older or newer release's
    row — and refusing to run a scan because of a key we do not read would turn
    a forward-compatible field into an outage.
    """
    config = dict(config or {})
    return EffectivePolicy(
        policy_id=policy_id,
        policy_name=policy_name,
        policy_family_code=policy_family_code,
        version_number=version_number,
        scan_kind=scan_kind,
        framework_ids=_tuple(config.get("framework_ids")),
        benchmark_profile=_opt_str(config.get("benchmark_profile")),
        check_families=_tuple(config.get("check_families")),
        platforms=_tuple(config.get("platforms")),
        sections=_tuple(config.get("sections")),
        include_builtin_checks=bool(config.get("include_builtin_checks", True)),
        min_severity=_opt_str(config.get("min_severity")),
        excluded_check_ids=_tuple(config.get("excluded_check_ids")),
        excluded_tags=_tuple(config.get("excluded_tags")),
        excluded_targets=_tuple(config.get("excluded_targets")),
        custom_ports=_opt_str(config.get("custom_ports")),
        exclude_ports=_opt_str(config.get("exclude_ports")),
        discovery_intensity=_opt_str(config.get("discovery_intensity")),
        port_scan_intensity=_opt_str(config.get("port_scan_intensity")),
        os_detection=_opt_bool(config.get("os_detection")),
        allow_intrusive=bool(config.get("allow_intrusive", False)),
        require_credential=bool(config.get("require_credential", False)),
        source=source,
    )


#: The configuration keys a stored policy may carry. Anything else is refused
#: at validation, because a misspelled key is a setting the operator believes
#: is in force and that nothing reads.
CONFIG_KEYS: Tuple[str, ...] = tuple(
    f.name
    for f in fields(EffectivePolicy)
    if f.name not in _IDENTITY_FIELDS and f.name != "scan_kind"
)
