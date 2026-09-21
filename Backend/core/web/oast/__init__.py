"""
core/web/oast — controlled out-of-band (OAST) blind vulnerability detection.

Phase 9. A self-hosted collaborator (no public interact.sh, no outbound
internet required), per-scan collision-proof interaction tokens that leak no
scan information, correlation of DNS/HTTP callbacks back to the payload that
caused them, and an active probe engine for the classes where a callback is the
only evidence (blind SSRF, out-of-band command injection, blind XXE).
"""

from core.web.oast.client import (
    HttpOastClient,
    LocalOastClient,
    build_oast,
)
from core.web.oast.engine import OastEngine
from core.web.oast.receiver import OastReceiver
from core.web.oast.session import (
    OAST_FINDING_TYPES,
    OastSession,
    token_from_host,
    token_from_path,
)

__all__ = [
    "OastSession",
    "OastEngine",
    "OastReceiver",
    "HttpOastClient",
    "LocalOastClient",
    "build_oast",
    "OAST_FINDING_TYPES",
    "token_from_host",
    "token_from_path",
]
