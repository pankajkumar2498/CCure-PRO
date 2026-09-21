"""
core/web/workflow — authenticated multi-step workflow engine (Phase 13).

Replays a validated, application-agnostic workflow (login → dashboard →
resource → action) in one browser session, captures the authenticated
endpoints/forms it reaches for the existing DETECT engines, handles CSRF /
dynamic values / conditions / timeouts / retries / cancellation, keeps every
navigation in scope, and never logs or exposes a password, token or cookie.
"""

from core.web.workflow.actions import (
    KNOWN_ACTIONS,
    normalize_workflow,
    validate_workflow,
)
from core.web.workflow.engine import WorkflowEngine

__all__ = [
    "WorkflowEngine",
    "validate_workflow",
    "normalize_workflow",
    "KNOWN_ACTIONS",
]
