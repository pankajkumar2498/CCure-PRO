"""
Cursor paging for the pull feeds Audit serves.

Push is the primary delivery path; a pull feed over the same messages exists so
a consumer that was down, not yet built, or missed deliveries can catch up
without Audit depending on how that consumer designed its own API.
"""

from __future__ import annotations

from typing import Optional

from pydantic import AwareDatetime

from ccure_contracts.common.v1.envelope import ContractModel, ShortText
from ccure_contracts.common.v1.fields import owned


class CcureFeedPositionV1(ContractModel):
    next_cursor: Optional[ShortText] = owned(
        "audit",
        "Opaque cursor for the next page; null when the consumer is caught up. "
        "Cursors are stable: re-reading from a cursor returns the same messages.",
        default=None,
    )
    has_more: bool = owned("audit", "Whether another page is available now.")
    retained_from: Optional[AwareDatetime] = owned(
        "audit",
        "Oldest message still retained. A cursor older than this answers 410 "
        "and the consumer must resynchronise (open question Q6).",
        default=None,
    )
