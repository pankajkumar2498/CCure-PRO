"""
The error model shared by every integration endpoint.

Errors are RFC 9457 problem details (``application/problem+json``), extended
with a machine-readable ``code``, the request's ``correlation_id``, whether the
caller should retry, and field-level validation messages.

The error model is not enveloped: it answers a request, it is never stored or
forwarded as a message in its own right.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from ccure_contracts.common.v1.envelope import ContractModel, OpaqueId, ShortText
from ccure_contracts.common.v1.fields import owned


class ProblemCode(str, Enum):
    """
    Every refusal an integration endpoint can give. ``retryable`` in the design
    document's table says which a caller may retry unchanged.
    """

    INVALID_PAYLOAD = "invalid_payload"  # 422, not retryable
    UNSUPPORTED_SCHEMA_VERSION = "unsupported_schema_version"  # 400, not retryable
    UNSUPPORTED_CONTRACT = "unsupported_contract"  # 400, not retryable
    UNAUTHENTICATED = "unauthenticated"  # 401, not retryable until re-authenticated
    INSUFFICIENT_SCOPE = "insufficient_scope"  # 403, not retryable
    TENANT_MISMATCH = "tenant_mismatch"  # 403, not retryable
    NOT_FOUND = "not_found"  # 404, not retryable
    VERSION_CONFLICT = "version_conflict"  # 409, not retryable
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"  # 409, not retryable
    PAYLOAD_TOO_LARGE = "payload_too_large"  # 413, not retryable
    RATE_LIMITED = "rate_limited"  # 429, retryable after Retry-After
    INTEGRATION_DISABLED = "integration_disabled"  # 503, retryable later
    UNAVAILABLE = "unavailable"  # 503, retryable
    INTERNAL_ERROR = "internal_error"  # 500, retryable with backoff


class CcureFieldErrorV1(ContractModel):
    """One validation failure, located by JSON Pointer."""

    pointer: ShortText = owned(
        "producer",
        "RFC 6901 JSON Pointer to the offending field, e.g. /data/controls/3.",
    )
    message: ShortText = owned("producer", "What is wrong with it.")


class CcureProblemV1(ContractModel):
    """An RFC 9457 problem detail."""

    type: ShortText = owned(
        "producer",
        "URI identifying the problem type: "
        "https://ccurepro.cdac.in/problems/<code>.",
    )
    title: ShortText = owned("producer", "Short, stable summary of the problem type.")
    status: int = owned("producer", "HTTP status code.", ge=400, le=599)
    detail: Optional[ShortText] = owned(
        "producer",
        "Explanation of this occurrence. Never echoes a secret or another "
        "tenant's data.",
        default=None,
    )
    code: ProblemCode = owned("producer", "Machine-readable problem code.")
    correlation_id: Optional[OpaqueId] = owned(
        "producer", "The correlation id of the refused request.", default=None
    )
    retryable: bool = owned(
        "producer", "Whether sending the same message again may succeed."
    )
    retry_after_seconds: Optional[int] = owned(
        "producer", "Minimum wait before retrying, where known.", default=None, ge=0
    )
    errors: List[CcureFieldErrorV1] = owned(
        "producer", "Field-level validation failures.", default_factory=list
    )
