"""
The checker against the Phase 10.1 golden baseline (``route_auth_matrix.json``).

Every refusal the matrix recorded from the live application is reproduced with
an equivalent input, and the checker's code must map to the same status and
message. Valid-credential cases recorded as accepted (200 / 101) must be
allowed. The matrix is the source; if a case is missing from it the test fails.
"""

from __future__ import annotations

import pytest

from conftest import load_matrix
from token_check.checker import REFUSALS, decide


def _observed(matrix, dotted):
    node = matrix
    for part in dotted.split("."):
        node = node[part]
    if isinstance(node, dict) and "edge" in node:
        node = node["edge"]
    return node


def _inputs(m):
    """matrix path → (policy, authorization, query) that reproduces it."""
    ticket, access = m.token("ticket"), m.token()
    return {
        "classes.bearer.missing": ("bearer", None, ""),
        "classes.bearer.empty_bearer": ("bearer", "Bearer ", ""),
        "classes.bearer.non_bearer_scheme": ("bearer", "Basic dXNlcjpwYXNz", ""),
        "classes.bearer.invalid_garbage": ("bearer", "Bearer not-a-token", ""),
        "classes.bearer.invalid_alg_none": ("bearer", "Bearer eyJhbGciOiJub25lIn0.e30.", ""),
        "classes.bearer.invalid_legacy_hs256": ("bearer", f"Bearer {m.legacy()}", ""),
        "classes.bearer.invalid_es256_unknown_kid": ("bearer", f"Bearer {m.token(kid='kid-x')}", ""),
        "classes.bearer.post_missing": ("bearer", None, ""),
        "classes.bearer.ticket_as_bearer": ("bearer", f"Bearer {ticket}", ""),
        "classes.bearer.valid": ("bearer", f"Bearer {access}", ""),
        "classes.ticket_or_bearer.missing": ("ticket_or_bearer", None, ""),
        "classes.ticket_or_bearer.invalid_ticket": ("ticket_or_bearer", None, "ticket=not-a-token"),
        "classes.ticket_or_bearer.invalid_ticket_legacy_hs256": ("ticket_or_bearer", None, f"ticket={m.legacy('ticket')}"),
        "classes.ticket_or_bearer.invalid_ticket_es256_unknown_kid": ("ticket_or_bearer", None, f"ticket={m.token('ticket', kid='kid-x')}"),
        "classes.ticket_or_bearer.invalid_bearer": ("ticket_or_bearer", "Bearer not-a-token", ""),
        "classes.ticket_or_bearer.invalid_ticket_and_invalid_bearer": ("ticket_or_bearer", "Bearer not-a-token", "ticket=not-a-token"),
        "classes.ticket_or_bearer.export_missing": ("ticket_or_bearer", None, ""),
        "classes.ticket_or_bearer.export_invalid_ticket": ("ticket_or_bearer", None, "ticket=not-a-token"),
        "classes.ticket_or_bearer.delete_missing": ("ticket_or_bearer", None, ""),
        "classes.ticket_or_bearer.delete_invalid_ticket": ("ticket_or_bearer", None, "ticket=not-a-token"),
        "classes.ticket_or_bearer.valid_bearer": ("ticket_or_bearer", f"Bearer {access}", ""),
        "classes.ticket_or_bearer.valid_ticket": ("ticket_or_bearer", None, f"ticket={ticket}"),
        "classes.ticket_or_bearer.ticket_replay_within_60s": ("ticket_or_bearer", None, f"ticket={ticket}"),
        "classes.ticket_or_bearer.valid_ticket_plus_valid_bearer": ("ticket_or_bearer", f"Bearer {access}", f"ticket={ticket}"),
        "classes.ticket_or_bearer.access_token_as_ticket": ("ticket_or_bearer", None, f"ticket={access}"),
        "classes.ticket_or_bearer.valid_bearer_plus_garbage_ticket": ("ticket_or_bearer", f"Bearer {access}", "ticket=not-a-token"),
        "classes.ticket_or_bearer.expired_ticket": ("ticket_or_bearer", None, f"ticket={m.expired('ticket')}"),
        "classes.ws_ticket.valid_ticket": ("ticket", None, f"ticket={ticket}"),
        "classes.ws_ticket.ticket_reuse_same_route": ("ticket", None, f"ticket={ticket}"),
        "classes.ws_ticket.ticket_reuse_other_route": ("ticket", None, f"ticket={ticket}"),
        "classes.ws_ticket.access_token_as_ticket": ("ticket", None, f"ticket={access}"),
        "classes.sse.missing./notifications/stream": ("bearer", None, ""),
        "classes.sse.invalid./notifications/stream": ("bearer", "Bearer not-a-token", ""),
        "classes.sse.missing./scans/events": ("bearer", None, ""),
        "classes.sse.invalid./scans/events": ("bearer", "Bearer not-a-token", ""),
    }


def _observed_node(matrix, key):
    if ".missing./" in key or ".invalid./" in key:
        head, path = key.split("./", 1)
        return _observed(matrix, head)["/" + path]["edge"]
    return _observed(matrix, key)


def test_every_recorded_outcome_is_reproduced(mint, verify):
    matrix = load_matrix()
    failures = []
    for key, (policy, auth, query) in _inputs(mint).items():
        observed = _observed_node(matrix, key)
        status = observed.get("status")
        assert isinstance(status, int), f"{key}: the matrix has no recorded status"
        d = decide(policy=policy, method="GET", authorization=auth, raw_query=query, verify=verify)
        if status in (200, 101):
            if not d.allowed:
                failures.append(f"{key}: recorded {status}, checker refused with {d.code}")
            continue
        if d.allowed:
            failures.append(f"{key}: recorded {status}, checker allowed")
            continue
        want_status, want_message = REFUSALS[d.code]
        got = (want_status, want_message or None)
        recorded_message = observed.get("message")
        if policy == "ticket":  # WebSocket refusals have no body
            recorded_message = None
        if got != (status, recorded_message):
            failures.append(f"{key}: recorded {(status, recorded_message)}, checker {got} ({d.code})")
    assert not failures, "\n".join(failures)


def test_ws_refusals_in_the_matrix_are_all_403():
    matrix = load_matrix()
    observed = matrix["classes"]["ws_ticket"]["observed"]
    statuses = {v["edge"]["status"] for v in observed.values()} | {v["direct"]["status"] for v in observed.values()}
    assert statuses == {403} == {REFUSALS["ws_refused"][0]}


def test_no_401_in_the_matrix_carried_www_authenticate():
    """X2-a: the checker emits no challenge header, and the baseline never had one."""
    matrix = load_matrix()
    seen = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("status") == 401 and node.get("www_authenticate"):
                seen.append(node.get("case"))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(matrix["classes"])
    assert not seen, seen
