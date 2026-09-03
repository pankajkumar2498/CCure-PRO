"""
core/scan_policy/resolver.py
─────────────────────────────────────────────────────────────────────────────
Turning "the caller named policy X" into the configuration a scan will run.

    policy_id + request parameters ──> EffectivePolicy ──> snapshot ──> scan

Precedence, and why it is this way round
────────────────────────────────────────
**Where a policy names a setting, the policy wins.** The request's value for
that setting is not used, and the API response says which of the caller's
parameters the policy displaced. Anything else makes the policy advisory: a
client that always sends ``discovery_intensity="normal"`` — as the current
frontend does, because it is the field's default — would silently override
every policy that asked for ``deep``.

The overrides are **reported, never silent**. A scan that assessed something
other than what the request asked for must say so at the moment it is
accepted, not only in a report generated afterwards.

Where a policy says nothing, the request's value is carried through unchanged.
That is what preserves the pre-policy behaviour: a scan with no ``policy_id``
resolves to an ``EffectivePolicy`` built entirely from its own request, with
``source="request"``, and behaves exactly as it did before this phase existed.

The no-policy path is not a no-op
─────────────────────────────────
It still produces a snapshot. A scan run without a policy has an effective
configuration — its own parameters — and recording it is what lets GAP-13 tell
two such scans apart when somebody changed the port range between them. The
snapshot's ``source`` is ``"request"`` and its ``policy_name`` is empty, so no
report can imply a policy was chosen when none was.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any, Dict, List, Mapping, Optional, Tuple

from core.scan_policy.spec import (
    POLICY_KIND_ANY,
    EffectivePolicy,
    effective_from_config,
)
from core.scan_policy.validation import PolicyValidationResult, validate_for_dispatch

log = logging.getLogger("ccure.scan_policy.resolver")

__all__ = [
    "PolicyResolution",
    "ResolvedPolicyError",
    "effective_for_request",
    "resolve_policy",
]


class ResolvedPolicyError(ValueError):
    """A named policy that cannot be used for this scan, with the reason."""

    def __init__(self, message: str, *, errors: Optional[List[str]] = None):
        self.errors = list(errors or [message])
        super().__init__(message)


class PolicyResolution:
    """
    The resolved configuration plus everything the caller should be told.

    ``overrides`` names the request parameters the policy displaced, so the API
    can return them. A silently overridden parameter is the difference between
    a policy engine and a policy suggestion.
    """

    def __init__(
        self,
        policy: EffectivePolicy,
        *,
        overrides: Optional[Dict[str, Any]] = None,
        validation: Optional[PolicyValidationResult] = None,
    ):
        self.policy = policy
        self.overrides = dict(overrides or {})
        self.validation = validation or PolicyValidationResult()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy.policy_id,
            "policy_name": self.policy.policy_name,
            "fingerprint": self.policy.fingerprint(),
            "source": self.policy.source,
            "overrides": dict(self.overrides),
            "warnings": list(self.validation.warnings),
        }


def _load_policy_row(db, policy_id: str, org_id: str):
    """
    Fetch a policy inside its tenant.

    The organisation filter is part of the query, exactly as
    ``routers/scan_schedules._get_schedule`` does it. Fetching by id and
    comparing afterwards answers differently for "no such policy" and "not
    yours", which is a cross-tenant enumeration oracle.
    """
    from db.models.scan_policies import ScanPolicy

    return (
        db.query(ScanPolicy)
        .filter(ScanPolicy.id == policy_id, ScanPolicy.org_id == org_id)
        .first()
    )


def resolve_policy(
    db,
    *,
    policy_id: Optional[str],
    org_id: str,
    scan_kind: str,
    request_options: Optional[Mapping[str, Any]] = None,
    has_credential: bool = False,
) -> PolicyResolution:
    """
    Resolve the effective configuration for one scan.

    Raises :class:`ResolvedPolicyError` when a named policy cannot be used —
    it does not exist for this tenant, it is archived or disabled, it is for a
    different scan kind, or its content is no longer installed. Never falls
    back to another policy or to the request's own parameters: a scan that
    silently ran under a different configuration than the one named is the
    failure this whole phase is meant to remove.
    """
    request_options = dict(request_options or {})

    if not policy_id:
        return PolicyResolution(effective_for_request(request_options, scan_kind))

    row = _load_policy_row(db, policy_id, org_id)
    if row is None:
        # 404-shaped, for the reason above: a distinct "exists but not yours"
        # confirms the id across tenants.
        raise ResolvedPolicyError(f"Scan policy {policy_id} not found.")

    if not row.is_usable:
        # Named separately because the two need different actions: a draft
        # needs finishing, a disabled one needs re-enabling, an archived one
        # needs a successor.
        if row.status == "archived":
            raise ResolvedPolicyError(
                f"Scan policy {row.name!r} is archived and cannot start a new "
                "scan. Use its successor, or a different policy."
            )
        if row.status == "draft":
            raise ResolvedPolicyError(
                f"Scan policy {row.name!r} is still a draft. Activate it "
                "before using it for a scan."
            )
        raise ResolvedPolicyError(
            f"Scan policy {row.name!r} is disabled and cannot start a new scan."
        )

    policy = effective_from_config(
        row.config or {},
        policy_id=str(row.id),
        policy_name=str(row.name or ""),
        policy_family_code=str(row.policy_family_code or ""),
        version_number=int(row.version_number or 1),
        scan_kind=str(row.scan_kind or POLICY_KIND_ANY),
        source="policy",
    )

    validation = validate_for_dispatch(
        db,
        policy,
        org_id=org_id,
        scan_kind=scan_kind,
        has_credential=has_credential,
    )
    if not validation.valid:
        raise ResolvedPolicyError(
            f"Scan policy {row.name!r} cannot be used for this scan: "
            + "; ".join(validation.errors),
            errors=validation.errors,
        )

    policy, overrides = _merge_request(policy, request_options)
    return PolicyResolution(policy, overrides=overrides, validation=validation)


#: Request parameter names, mapped onto the policy fields they correspond to.
#: Only fields a scan request can actually carry — a policy's framework
#: selection has no request counterpart, so there is nothing to override.
_REQUEST_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("custom_ports", "custom_ports"),
    ("exclude_ports", "exclude_ports"),
    ("discovery_intensity", "discovery_intensity"),
    ("port_scan_intensity", "port_scan_intensity"),
    ("os_detection", "os_detection"),
    ("sections", "sections"),
)


def _merge_request(
    policy: EffectivePolicy, request_options: Mapping[str, Any]
) -> Tuple[EffectivePolicy, Dict[str, Any]]:
    """
    Fill in what the policy does not say from the request, and record what it
    displaced.

    Two directions, and they are not symmetric:

    * The policy names a value → the policy wins, and the request's value is
      recorded in ``overrides`` so the caller is told. Not silent.
    * The policy says nothing → the request's value is carried through, so a
      policy that only sets a severity floor does not reset the port range to
      the scanner default.
    """
    overrides: Dict[str, Any] = {}
    updates: Dict[str, Any] = {}

    for request_key, field_name in _REQUEST_FIELDS:
        requested = request_options.get(request_key)
        current = getattr(policy, field_name)
        policy_says = current not in (None, "", ())

        if policy_says:
            if requested not in (None, "", []) and _differs(requested, current):
                overrides[request_key] = {
                    "requested": requested,
                    "policy": list(current) if isinstance(current, tuple) else current,
                }
            continue

        if requested in (None, "", []):
            continue

        if field_name == "sections":
            from core.scan_policy.spec import _tuple  # local: normalisation only

            updates[field_name] = _tuple(requested)
        elif field_name == "os_detection":
            updates[field_name] = bool(requested)
        else:
            updates[field_name] = str(requested)

    if updates:
        policy = replace(policy, **updates)
    return policy, overrides


def _differs(requested: Any, current: Any) -> bool:
    if isinstance(current, tuple):
        from core.scan_policy.spec import _tuple

        return _tuple(requested) != current
    if isinstance(current, bool):
        return bool(requested) != current
    return str(requested) != str(current)


def effective_for_request(
    request_options: Mapping[str, Any], scan_kind: str = POLICY_KIND_ANY
) -> EffectivePolicy:
    """
    The effective configuration of a scan that named no policy.

    Built from the request's own parameters, ``source="request"`` and no policy
    name — so the report says "None (scan request defaults)" rather than
    inventing one, and GAP-13 can still tell two such scans apart when their
    parameters differ.
    """
    from core.scan_policy.spec import _tuple

    request_options = dict(request_options or {})
    excluded = request_options.get("excluded_targets")
    if excluded in (None, "", []):
        # `exclude_ips` is the request's spelling. Comma-separated on every
        # scan route, and carried into the snapshot so a scan that excluded a
        # subnet is not later compared with one that did not as though they
        # covered the same estate.
        raw = request_options.get("exclude_ips")
        excluded = [t.strip() for t in str(raw).split(",")] if raw else []

    return EffectivePolicy(
        scan_kind=scan_kind,
        custom_ports=_none_if_blank(request_options.get("custom_ports")),
        exclude_ports=_none_if_blank(request_options.get("exclude_ports")),
        discovery_intensity=_none_if_blank(request_options.get("discovery_intensity")),
        port_scan_intensity=_none_if_blank(request_options.get("port_scan_intensity")),
        os_detection=(
            None
            if request_options.get("os_detection") is None
            else bool(request_options.get("os_detection"))
        ),
        sections=_tuple(request_options.get("sections")),
        excluded_targets=_tuple(excluded),
        source="request",
    )


def _none_if_blank(value: Any) -> Optional[str]:
    if value in (None, "", []):
        return None
    return str(value).strip() or None
