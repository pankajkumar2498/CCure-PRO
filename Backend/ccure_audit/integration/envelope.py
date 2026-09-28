"""
The envelope fields every outbound message carries.

The adapter never invents them. Message ids, correlation ids and timestamps
belong to the delivery machinery (outbox, feeds — the integration phase), so a
mapper takes them from an :class:`EnvelopeContext` its caller supplies. That
keeps every mapper a pure function: the same views and context always give the
same message, which is what makes an outbox retry resend an identical message.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from ccure_contracts.registry import SCHEMA_VERSION

AUDIT_MODULE = "audit"


@dataclass(frozen=True)
class EnvelopeContext:
    """What the caller knows about the message being produced."""

    message_id: UUID
    tenant_id: str
    module_version: str
    produced_at: datetime
    correlation_id: str
    causation_id: Optional[UUID] = None
    instance: Optional[str] = None


def envelope(contract: str, ctx: EnvelopeContext) -> Dict[str, Any]:
    """The envelope fields for *contract*, as a dict ready for ``model_validate``."""
    source: Dict[str, Any] = {
        "module": AUDIT_MODULE,
        "module_version": ctx.module_version,
    }
    if ctx.instance:
        source["instance"] = ctx.instance
    fields: Dict[str, Any] = {
        "contract": contract,
        "schema_version": SCHEMA_VERSION,
        "message_id": ctx.message_id,
        "tenant_id": ctx.tenant_id,
        "source": source,
        "produced_at": ctx.produced_at,
        "correlation_id": ctx.correlation_id,
    }
    if ctx.causation_id is not None:
        fields["causation_id"] = ctx.causation_id
    return fields
