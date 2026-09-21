"""
core/web/workflow/actions.py
────────────────────────────────────────────────────────────────────────────
The workflow action vocabulary and its validation (Phase 13).

A workflow is *validated configuration*, never code and never an
application-specific script baked into the product. It is an ordered list of
actions the engine replays in a real browser session, so an operator can
express "log in → open the dashboard → open a resource → perform an action"
for their own application without CCure knowing anything about it in advance.

Each action is a dict ``{"action": "<type>", ...params}``. This module owns the
list of types, the parameters each needs, and a validator that rejects a
malformed workflow before anything is executed — a scan should fail at
configuration time with a clear message, not halfway through a browser session.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

#: Every supported action and the parameter keys it requires. Optional keys
#: (timeouts, retries, secret flag, condition modifiers) are validated by type
#: in ``validate_workflow`` rather than listed here.
REQUIRED_PARAMS: Dict[str, Tuple[str, ...]] = {
    "open": ("url",),  # navigate to an absolute/relative URL
    "navigate": ("url",),  # alias of open (kept because operators say "navigate")
    "click": ("selector",),  # click an element
    "type": ("selector", "value"),  # enter text into a field
    "enter_text": ("selector", "value"),  # alias of type
    "select": ("selector", "value"),  # choose an option in a <select>
    "submit": (),  # submit a form (selector defaults to the enclosing form)
    "wait": (),  # wait for a duration (ms) or a selector
    "extract": ("name",),  # capture a value into {{name}} for later steps
    "verify": (),  # assert a condition (contains / selector / not_contains)
    "capture_token": ("name",),  # capture an auth token (localStorage/cookie/dom)
    "capture_cookie": ("name",),  # capture a named cookie's value
    "api_request": ("url",),  # issue an HTTP request from the browser session
}

#: Actions that carry a user-entered value which may be a secret. Their `value`
#: is protected in storage and masked in every log/error/event.
VALUE_BEARING_ACTIONS = frozenset({"type", "enter_text", "select"})

#: Actions that reach a URL and must therefore be scope-checked at runtime.
NAVIGATING_ACTIONS = frozenset({"open", "navigate", "api_request"})

KNOWN_ACTIONS = frozenset(REQUIRED_PARAMS)


def normalize_workflow(config: Any) -> Dict[str, Any]:
    """
    Accept either a bare list of actions or ``{"actions": [...], ...}`` and
    return the dict form. Never raises.
    """
    if isinstance(config, list):
        return {"actions": config}
    if isinstance(config, dict):
        return config
    return {"actions": []}


def validate_workflow(config: Any) -> List[str]:
    """
    Return a list of human-readable errors, empty when the workflow is valid.

    Checks structure and per-action required parameters, so a bad workflow is
    refused at save/dispatch time with a specific message rather than failing
    mid-session.
    """
    errors: List[str] = []
    wf = normalize_workflow(config)
    actions = wf.get("actions")
    if not isinstance(actions, list) or not actions:
        return ["workflow must contain a non-empty 'actions' list"]

    timeout = wf.get("timeout_ms")
    if timeout is not None and (not isinstance(timeout, int) or timeout <= 0):
        errors.append("workflow timeout_ms must be a positive integer")

    for i, step in enumerate(actions, 1):
        if not isinstance(step, dict):
            errors.append(f"action {i}: must be an object")
            continue
        atype = str(step.get("action") or "").strip().lower()
        if atype not in KNOWN_ACTIONS:
            errors.append(
                f"action {i}: unknown action '{step.get('action')}' "
                f"(known: {', '.join(sorted(KNOWN_ACTIONS))})"
            )
            continue
        for param in REQUIRED_PARAMS[atype]:
            if param not in step or step.get(param) in (None, ""):
                errors.append(f"action {i} ({atype}): missing required '{param}'")
        # Per-action shape checks.
        if atype == "wait":
            if "ms" not in step and "selector" not in step:
                errors.append(f"action {i} (wait): needs 'ms' or 'selector'")
            if "ms" in step and (not isinstance(step["ms"], int) or step["ms"] < 0):
                errors.append(f"action {i} (wait): 'ms' must be a non-negative integer")
        if atype == "verify" and not any(
            k in step for k in ("contains", "not_contains", "selector")
        ):
            errors.append(
                f"action {i} (verify): needs 'contains', 'not_contains' or 'selector'"
            )
        retries = step.get("retries")
        if retries is not None and (not isinstance(retries, int) or retries < 0):
            errors.append(f"action {i} ({atype}): 'retries' must be a non-negative int")
    return errors


def action_type(step: dict) -> str:
    """Canonical (lowercased) action type, with open/navigate and type/enter_text
    folded to one spelling each."""
    t = str((step or {}).get("action") or "").strip().lower()
    if t == "navigate":
        return "open"
    if t == "enter_text":
        return "type"
    return t
