"""
The envelope every contract message carries, and the reference types they share.

Every message is self-describing: it names its contract and schema version, the
tenant it belongs to, the module that produced it, when, and the correlation id
that ties it to the request or event that caused it. A message that is stored,
forwarded, dead-lettered or re-read from a pull feed months later still says
all of that without its HTTP headers.

**The tenant in the body is checked, never trusted.** The receiver compares
``tenant_id`` with the tenant bound to the caller's service credential and
refuses a mismatch (``tenant_mismatch``, 403). A caller cannot choose its tenant
by writing a different value here — the cross-tenant defect of finding F1 must
not reappear on the integration surface.
"""

from __future__ import annotations

from typing import Annotated, Optional
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    StringConstraints,
    model_validator,
)

from ccure_contracts.common.v1.fields import owned
from ccure_contracts.common.v1.vocabulary import Module, ValueStatus

# ── Primitive types ───────────────────────────────────────────────────────────

#: An identifier minted by the module that owns the object. Opaque to everyone
#: else: a consumer stores and returns it, and never parses it. (Audit's own
#: identifiers embed an organisation slug and an IP address; reading meaning
#: out of them is exactly the coupling these contracts exist to prevent.)
OpaqueId = Annotated[
    str,
    StringConstraints(
        min_length=1, max_length=400, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@\-]*$"
    ),
]

#: A lowercase hex SHA-256 digest.
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

#: ``1.<minor>``. The major version is also in the URL path (``/api/v1/``).
SchemaVersion = Annotated[str, StringConstraints(pattern=r"^1\.(0|[1-9][0-9]*)$")]

ShortText = Annotated[str, StringConstraints(min_length=1, max_length=500)]
LongText = Annotated[str, StringConstraints(min_length=1, max_length=20000)]


class ContractModel(BaseModel):
    """
    Base of every contract type.

    ``extra="forbid"``: the published schema of a version describes exactly
    what that version carries. Tolerance for a *newer* minor version is the
    receiver's job — it strips fields it does not know before validating (see
    the versioning section of the design document) — not the schema's.

    ``frozen=True``: a received message is read-only (SRS 7.6.1).
    """

    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


# ── Envelope ──────────────────────────────────────────────────────────────────


class CcureSourceV1(ContractModel):
    """Which module, and which build of it, produced a message."""

    module: Module = owned("producer", "The producing module.")
    module_version: ShortText = owned(
        "producer", "The producing module's release, for diagnosing a bad message."
    )
    instance: Optional[ShortText] = owned(
        "producer",
        "The deployment instance, where a module runs more than one.",
        default=None,
    )


class CcureEnvelopeV1(ContractModel):
    """
    Fields every contract message carries. Each concrete message class narrows
    ``contract`` to its own literal name and adds a typed ``data`` payload.
    """

    contract: ShortText = owned("producer", "The contract this message conforms to.")
    schema_version: SchemaVersion = owned(
        "producer",
        "The contract's schema version, 1.<minor>. A minor increase only adds "
        "optional fields.",
    )
    message_id: UUID = owned(
        "producer",
        "Unique per message and stable across retries of the same message. It is "
        "the idempotency key: a receiver that has seen it answers with its "
        "original result and does nothing else.",
    )
    tenant_id: OpaqueId = owned(
        "platform",
        "The organisation (platform tenant) the message belongs to. Checked "
        "against the tenant bound to the caller's service credential.",
    )
    source: CcureSourceV1 = owned("producer", "The producing module.")
    produced_at: AwareDatetime = owned(
        "producer", "When the message was produced. RFC 3339, timezone required."
    )
    correlation_id: OpaqueId = owned(
        "producer",
        "Ties together every message and log line caused by one originating "
        "request or event. Propagated unchanged from the message that caused "
        "this one; a new root starts a new id.",
    )
    causation_id: Optional[UUID] = owned(
        "producer",
        "The message_id of the message that directly caused this one, if any.",
        default=None,
    )


# ── Measured values ───────────────────────────────────────────────────────────


class CcureMeasuredValueV1(ContractModel):
    """
    A number that may not be available, with the reason when it is not.

    This is how a contract says "unknown" without saying "zero". A value is
    present exactly when ``status`` is ``available``; any other status carries
    no value and must say why.
    """

    status: ValueStatus = owned(
        "producer", "Whether a value is present, and if not why."
    )
    value: Optional[float] = owned(
        "producer", "The value; present only when status is available.", default=None
    )
    unit: Optional[ShortText] = owned(
        "producer", "Unit of the value, e.g. 'seconds', 'percent'.", default=None
    )
    reason: Optional[ShortText] = owned(
        "producer",
        "Why no value is present. Required unless status is available.",
        default=None,
    )

    @model_validator(mode="after")
    def _present_exactly_when_available(self) -> "CcureMeasuredValueV1":
        if self.status is ValueStatus.AVAILABLE:
            if self.value is None:
                raise ValueError("an available value must carry a value")
        else:
            if self.value is not None:
                raise ValueError(
                    f"status {self.status.value!r} must not carry a value — "
                    "unknown is not zero"
                )
            if not self.reason:
                raise ValueError(f"status {self.status.value!r} must say why")
        return self


# ── References ────────────────────────────────────────────────────────────────


class CcureFrameworkRefV1(ContractModel):
    """A compliance framework, named by code and version (e.g. ISO27001_2022 / 2022)."""

    code: ShortText = owned(
        "platform",
        "Framework code from the shared framework vocabulary (open decision D3).",
    )
    version: ShortText = owned("platform", "Framework version as published.")


class CcureControlRefV1(ContractModel):
    """One control of one framework, e.g. ISO27001_2022 / 2022 / A.8.9."""

    framework: CcureFrameworkRefV1 = owned("platform", "The framework.")
    control_id: ShortText = owned(
        "platform",
        "The control's identifier as the framework publishes it (A.8.9, PR.AA-01, "
        "AC-2). Namespace rules are open decision D3.",
    )


class CcureBaselineRefV1(ContractModel):
    """A specific version of a Policy Pro baseline, as Audit received it."""

    baseline_id: OpaqueId = owned("policy_pro", "Policy Pro's baseline identifier.")
    baseline_version: int = owned(
        "policy_pro", "Monotonic version number of the baseline.", ge=1
    )
    content_sha256: Optional[Sha256] = owned(
        "audit",
        "Digest Audit computed over the canonical JSON of the baseline as "
        "received. Lets both sides prove which content a result refers to.",
        default=None,
    )


class CcureAssetRefV1(ContractModel):
    """
    An asset as Audit knows it.

    ``asset_id`` is Audit's identifier and is opaque. It is **not** stable
    across a change of IP address today (open question Q5), so the identity
    attributes are carried beside it for correlation by other modules.
    """

    asset_id: OpaqueId = owned("audit", "Audit's asset identifier. Opaque.")
    ip_address: Optional[ShortText] = owned(
        "audit", "IPv4 or IPv6 address at assessment time.", default=None
    )
    mac_address: Optional[ShortText] = owned(
        "audit", "MAC address, where discovered.", default=None, availability="partial"
    )
    hostname: Optional[ShortText] = owned(
        "audit", "Hostname, where resolved.", default=None, availability="partial"
    )


class CcureFindingRefV1(ContractModel):
    """A finding, by Audit's identifier."""

    finding_id: OpaqueId = owned("audit", "Audit's finding identifier. Opaque.")


class CcureEvidenceRefV1(ContractModel):
    """
    A pointer to evidence Audit holds, retrievable through the evidence
    endpoint by a caller with ``audit:evidence:read`` for the same tenant.
    Evidence is referenced, not embedded, so a large or sensitive record is
    fetched only by a consumer entitled to it.
    """

    evidence_id: OpaqueId = owned("audit", "Audit's evidence identifier. Opaque.")
    kind: ShortText = owned(
        "audit",
        "What the evidence is: 'check_observation', 'finding_proof', "
        "'uploaded_file', 'attestation', 'incident_evidence'.",
    )
    collected_at: Optional[AwareDatetime] = owned(
        "audit", "When the evidence was collected.", default=None
    )
    sha256: Optional[Sha256] = owned(
        "audit", "Digest of the evidence content, where it is a file.", default=None
    )


class CcureAssessmentRefV1(ContractModel):
    """An Audit assessment (a scan or a compliance run)."""

    assessment_id: OpaqueId = owned("audit", "Audit's assessment identifier. Opaque.")
    completed_at: Optional[AwareDatetime] = owned(
        "audit", "When the assessment reached its terminal state.", default=None
    )
    scan_policy_fingerprint: Optional[Sha256] = owned(
        "audit",
        "Fingerprint of the scan policy snapshot the assessment ran under "
        "(GAP-12). Two results with different fingerprints assessed different "
        "things and are not directly comparable.",
        default=None,
        availability="partial",
    )
