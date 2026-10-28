"""
core/scan_policy/validation.py
─────────────────────────────────────────────────────────────────────────────
Refusing an invalid policy before a scan starts, and saying why.

The rule this module exists for
───────────────────────────────
**A policy that cannot do what it says must fail loudly, never fall back.**
Silently broadening scope hands an operator an assessment they did not ask
for; silently narrowing it hands them a clean report on hosts nobody looked
at. Both are worse than a 400 with a sentence naming the problem.

So there is no "nearest usable policy", no default substituted for an
unrecognised value, and no framework quietly dropped because the tenant has
not installed it. Every refusal names the field and the offending value.

Two-stage, deliberately
───────────────────────
:func:`validate_policy` is **static**: it checks the configuration against
this build's vocabularies and internal consistency, and it needs no database.
It runs when a policy is written, so a typo is caught by the person who made
it rather than by a scan at 02:00.

:func:`validate_for_dispatch` is **contextual**: it checks the policy against
*this* organisation's installed content and *this* scan's kind and credential
at the moment of dispatch. It re-runs at every dispatch and is never inherited
from creation time — the same rule ``core/scheduling/dispatcher.py`` applies
to scan scope, and for the same reason. A framework uninstalled in June
must stop being scanned in July.

Warnings are not refusals
─────────────────────────
A policy that selects a framework the tenant *has* installed but which
resolves to zero executable rules is not invalid — content can legitimately be
all-manual. It produces a warning that reaches the API response and the
validation endpoint, so an operator can see that a policy will assess nothing
before they schedule it nightly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from core.scan_policy.spec import (
    CHECK_FAMILIES,
    CONFIG_KEYS,
    POLICY_KIND_ANY,
    POLICY_SCAN_KINDS,
    SEVERITY_ORDER,
    EffectivePolicy,
)

log = logging.getLogger("ccure.scan_policy.validation")

__all__ = [
    "PolicyValidationError",
    "PolicyValidationResult",
    "assert_credential_ok",
    "validate_for_dispatch",
    "validate_policy",
]


class PolicyValidationError(ValueError):
    """
    A policy that cannot be used, with every problem listed at once.

    All problems rather than the first: an operator fixing a policy through an
    API should not have to make four round trips to discover four typos.
    """

    def __init__(self, errors: Sequence[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


@dataclass
class PolicyValidationResult:
    """Whether a policy is usable, and everything worth telling the operator."""

    valid: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        self.valid = False
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def raise_if_invalid(self) -> None:
        if not self.valid:
            raise PolicyValidationError(self.errors)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Vocabularies this build honours
# ─────────────────────────────────────────────────────────────────────────────

#: Intensity words the discovery and port engines accept. Read from the scan
#: routes' own validator rather than restated, so a policy cannot accept an
#: intensity the engine would reject at dispatch.
_INTENSITIES = ("light", "normal", "deep")

#: Platform values ``ConfigCheck.applies_to_platform`` understands. "any" is
#: deliberately not offered on a *policy*: as a selection it means the same as
#: naming nothing, and offering two spellings of "no restriction" invites a
#: reader to think they differ.
_PLATFORMS = ("windows", "linux")

#: Sections the credentialed collectors understand. A section a collector does
#: not serve is silently ignored today, so naming one in a policy would be a
#: setting that does nothing — refused instead.
_SECTIONS = (
    "system",
    "packages",
    "services",
    "users",
    "network",
    "security",
    "storage",
    "processes",
    "firewall",
    "logs",
    "compliance",
    "identity",
)


def _port_spec_ok(spec: str) -> bool:
    """
    Whether a port expression is well-formed.

    Deliberately strict about *shape* only — ``22,80,8000-8100``. Whether a
    port is sensible is the scanner's business; whether the string will parse
    is this module's, because a malformed one fails inside Nmap where the error
    reads as a scan failure rather than as a policy defect.
    """
    for token in str(spec).split(","):
        token = token.strip()
        if not token:
            return False
        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2:
                return False
            bounds = []
            for part in parts:
                if not part.strip().isdigit():
                    return False
                bounds.append(int(part))
            low, high = bounds
            if not (0 < low <= high <= 65535):
                return False
        else:
            if not token.isdigit() or not 0 < int(token) <= 65535:
                return False
    return True


def _target_expr_ok(expr: str) -> bool:
    """Whether an exclusion expression parses as an address, range or CIDR."""
    import ipaddress

    token = str(expr).strip()
    if not token:
        return False
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        pass
    if "-" in token:
        low, _, high = token.partition("-")
        try:
            ipaddress.ip_address(low.strip())
        except ValueError:
            return False
        high = high.strip()
        if high.isdigit():
            return 0 <= int(high) <= 255
        try:
            ipaddress.ip_address(high)
            return True
        except ValueError:
            return False
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — static validation
# ─────────────────────────────────────────────────────────────────────────────


def validate_policy(
    config: Mapping[str, Any],
    *,
    scan_kind: str = POLICY_KIND_ANY,
) -> PolicyValidationResult:
    """
    Check a stored configuration against this build's vocabularies.

    No database, no organisation, no target. Everything here is knowable when
    the policy is written, and a refusal knowable at write time belongs at
    write time — the same principle ``core/scap`` applies to OVAL constructs,
    where a shape check moved from the probe into the compiler turns a
    per-host scan error into one message at load.
    """
    result = PolicyValidationResult()
    config = dict(config or {})

    if scan_kind not in POLICY_SCAN_KINDS:
        result.add_error(
            f"scan_kind {scan_kind!r} is not one of {', '.join(POLICY_SCAN_KINDS)}"
        )

    # An unknown key is a setting the operator believes is in force and which
    # nothing reads. That is the failure mode a free-form JSONB column invites
    # and the reason this validator exists at all.
    unknown = sorted(set(config) - set(CONFIG_KEYS))
    if unknown:
        result.add_error(
            f"unknown policy setting(s): {', '.join(unknown)}. "
            f"Supported settings: {', '.join(sorted(CONFIG_KEYS))}"
        )

    policy = EffectivePolicy(scan_kind=scan_kind)
    from core.scan_policy.spec import effective_from_config

    try:
        policy = effective_from_config(config, scan_kind=scan_kind)
    except Exception as exc:  # noqa: BLE001
        result.add_error(f"policy configuration could not be read: {exc}")
        return result

    for family in policy.check_families:
        if family not in CHECK_FAMILIES:
            result.add_error(
                f"check family {family!r} is not one this build carries. "
                f"Known families: {', '.join(CHECK_FAMILIES)}"
            )

    for platform in policy.platforms:
        if platform not in _PLATFORMS:
            result.add_error(
                f"platform {platform!r} is not one of {', '.join(_PLATFORMS)}"
            )

    for section in policy.sections:
        if section not in _SECTIONS:
            result.add_error(
                f"assessment section {section!r} is not one the collectors "
                f"serve. Known sections: {', '.join(_SECTIONS)}"
            )

    if policy.min_severity and policy.min_severity not in SEVERITY_ORDER:
        result.add_error(
            f"min_severity {policy.min_severity!r} is not one of "
            f"{', '.join(SEVERITY_ORDER)}"
        )

    for label, value in (
        ("discovery_intensity", policy.discovery_intensity),
        ("port_scan_intensity", policy.port_scan_intensity),
    ):
        if value and value not in _INTENSITIES:
            result.add_error(
                f"{label} {value!r} is not one of {', '.join(_INTENSITIES)}"
            )

    for label, value in (
        ("custom_ports", policy.custom_ports),
        ("exclude_ports", policy.exclude_ports),
    ):
        if value and not _port_spec_ok(value):
            result.add_error(
                f"{label} {value!r} is not a well-formed port expression "
                "(expected e.g. '22,80,8000-8100')"
            )

    for target in policy.excluded_targets:
        if not _target_expr_ok(target):
            result.add_error(
                f"excluded target {target!r} is not an address, range or CIDR"
            )

    # ── Combinations that are individually valid and jointly meaningless ────
    if not policy.include_builtin_checks and not policy.framework_ids:
        # Excluding the built-ins while naming no framework means the
        # configuration audit resolves nothing at all — a scan that reports
        # success having assessed no configuration. Refused rather than warned:
        # the result is indistinguishable from a clean host.
        result.add_error(
            "a policy that excludes the built-in checks must name at least one "
            "framework, or the configuration audit assesses nothing and the "
            "host reports as clean"
        )

    if policy.benchmark_profile and not policy.framework_ids:
        # A profile without a framework applies the filter across every
        # installed benchmark, which is almost never what anybody means and
        # silently drops controls from frameworks that use different profile
        # names.
        result.add_warning(
            "benchmark_profile is set but no framework is named, so the "
            "profile filter applies to every installed benchmark; controls in "
            "benchmarks that use different profile names will be excluded"
        )

    if policy.scan_kind == "network":
        credentialed_only = {
            "benchmark_profile": policy.benchmark_profile,
            "check_families": policy.check_families,
            "sections": policy.sections,
            "framework_ids": policy.framework_ids,
            "min_severity": policy.min_severity,
        }
        named = sorted(k for k, v in credentialed_only.items() if v)
        if named:
            result.add_warning(
                "this policy's scan_kind is 'network', so "
                f"{', '.join(named)} will have no effect — those settings "
                "govern the credentialed configuration audit. Use scan_kind "
                "'credentialed' or 'any' if you meant them to apply."
            )

    if policy.allow_intrusive:
        # Not an error — it is a legitimate, deliberate choice. But it is the
        # one setting here that lets the scanner change a host it is auditing,
        # and a policy carrying it should never do so silently.
        result.add_warning(
            "intrusive probes are permitted by this policy: a scan may write "
            "to a target to establish a finding (currently only the anonymous "
            "FTP write test). Do not enable this against production or OT "
            "hosts without authorisation."
        )

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — contextual validation, re-run at every dispatch
# ─────────────────────────────────────────────────────────────────────────────


def validate_for_dispatch(
    db,
    policy: EffectivePolicy,
    *,
    org_id: str,
    scan_kind: str,
    has_credential: bool,
) -> PolicyValidationResult:
    """
    Check a resolved policy against this organisation, right now.

    Re-run at every dispatch and never inherited from creation time. A policy
    written in March and firing in November is a stored intent, not a standing
    authorisation — the rule the schedule dispatcher already applies to scan
    scope.
    """
    result = validate_policy(_config_of(policy), scan_kind=policy.scan_kind)

    if policy.scan_kind != POLICY_KIND_ANY and policy.scan_kind != scan_kind:
        result.add_error(
            f"policy is for {policy.scan_kind!r} scans and this is a "
            f"{scan_kind!r} scan. A policy applied to the wrong kind would "
            "restrict nothing it was written to restrict."
        )

    assert_credential_ok(policy, has_credential=has_credential, result=result)

    if policy.framework_ids:
        _validate_frameworks(db, policy, org_id=org_id, result=result)

    return result


def assert_credential_ok(
    policy: EffectivePolicy,
    *,
    has_credential: bool,
    result: Optional[PolicyValidationResult] = None,
) -> PolicyValidationResult:
    """
    Refuse a policy that needs a credential when none is available.

    The alternative is the failure this product has already had to fix twice:
    a scan that degrades quietly to unauthenticated, collects nothing, and
    reports the host as clean. ``require_credential`` exists so an operator can
    say "an unauthenticated result is not an acceptable answer here".
    """
    result = result if result is not None else PolicyValidationResult()
    if policy.require_credential and not has_credential:
        result.add_error(
            "this policy requires an authenticated session and no credential "
            "is in scope for the scan. Attach a credential, or clear "
            "require_credential to accept an unauthenticated result."
        )
    return result


def _validate_frameworks(
    db,
    policy: EffectivePolicy,
    *,
    org_id: str,
    result: PolicyValidationResult,
) -> None:
    """
    Every named framework must exist, be offered here, and be installed here.

    Three separate conditions with three different messages, because they need
    three different actions: a typo, a parked catalogue, and a marketplace
    installation somebody has to perform. Collapsing them into "framework not
    available" is how an operator spends an afternoon on the wrong one.
    """
    # The catalogue is compliance's, and it answers through its read module
    # (G4); validation queries no compliance table itself.
    import core.compliance_catalogue.reads as catalogue

    named = set(policy.framework_ids)

    existing = catalogue.existing_framework_ids(db, named)
    missing = sorted(named - existing)
    if missing:
        result.add_error(
            "framework(s) not present in this installation: " + ", ".join(missing)
        )

    parked = sorted(f for f in (named & existing) if not catalogue.is_offered(f))
    if parked:
        result.add_error(
            "framework(s) shipped but not active in this installation: "
            + ", ".join(parked)
            + ". A parked catalogue cannot be scored, so a scan naming one "
            "would assess nothing against it."
        )

    installed = catalogue.installed_framework_ids(db, org_id, named)
    not_installed = sorted((named & existing) - set(parked) - installed)
    if not_installed:
        result.add_error(
            "framework(s) not installed for this organisation: "
            + ", ".join(not_installed)
            + ". Install them from the compliance marketplace first."
        )

    # Content that is installed but resolves to nothing executable is a
    # warning, not an error: an all-manual catalogue is legitimate content, and
    # refusing it would make a policy that names ISO 27001 alongside a
    # benchmark impossible to write.
    usable = sorted(named & installed)
    if usable:
        _warn_on_empty_frameworks(db, usable, policy=policy, result=result)


def _warn_on_empty_frameworks(
    db,
    framework_ids: Sequence[str],
    *,
    policy: EffectivePolicy,
    result: PolicyValidationResult,
) -> None:
    """Warn where a selected framework resolves to no executable check."""
    import core.compliance_catalogue.reads as catalogue

    seen = catalogue.active_rule_link_counts(db, framework_ids)

    empty = sorted(fid for fid, count in seen.items() if count == 0)
    if empty:
        result.add_warning(
            "framework(s) with no active rule, so they contribute no "
            "automated check to this scan: " + ", ".join(empty)
        )


def _config_of(policy: EffectivePolicy) -> Dict[str, Any]:
    """The stored-config view of a resolved policy, for re-validation."""
    payload = policy.as_dict()
    for key in (
        "policy_id",
        "policy_name",
        "policy_family_code",
        "version_number",
        "scan_kind",
        "source",
        "fingerprint",
    ):
        payload.pop(key, None)
    return payload
