"""T2 — the checker's decision table, written out case by case."""

from __future__ import annotations

from urllib.parse import quote

import pytest

from token_check import checker
from token_check.checker import REFUSALS, decide, last_ticket, scheme_and_credentials


def _d(verify, policy, auth=None, query="", method="GET"):
    return decide(policy=policy, method=method, authorization=auth, raw_query=query, verify=verify)


def test_refusal_table_is_the_characterised_application_behaviour():
    assert REFUSALS == {
        "missing_bearer": (403, "Not authenticated"),
        "non_bearer_scheme": (403, "Invalid authentication credentials"),
        "invalid_bearer": (401, "Invalid or expired token"),
        "missing_flexible": (401, "Authentication token is missing."),
        "invalid_ticket": (401, "Invalid or expired download ticket."),
        "ws_refused": (403, ""),
    }


# ── none / OPTIONS ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("policy", ["none", "bearer", "ticket_or_bearer", "ticket"])
def test_options_never_needs_a_credential(verify, policy):
    d = _d(verify, policy, method="OPTIONS")
    assert d.allowed and d.status == 204


def test_none_reads_no_credential(mint):
    def exploding_verify(*_):
        raise AssertionError("a public route must not verify anything")

    d = _d(exploding_verify, "none", auth="Bearer garbage", query="ticket=garbage")
    assert d.allowed


def test_unknown_policy_fails_closed(verify):
    for policy in ("", "Bearer", "public", "unrouted", "BEARER"):
        with pytest.raises(checker.PolicyError):
            _d(verify, policy, auth="Bearer x")


# ── bearer (HTTPBearer()) ─────────────────────────────────────────────────────


@pytest.mark.parametrize("auth,code", [
    (None, "missing_bearer"),
    ("", "missing_bearer"),
    ("Bearer", "missing_bearer"),
    ("Bearer ", "missing_bearer"),
    (" Bearer x", "missing_bearer"),  # empty scheme
    ("Basic dXNlcjpwYXNz", "non_bearer_scheme"),
    ("Token abc", "non_bearer_scheme"),
    ("Bearer not-a-token", "invalid_bearer"),
])
def test_bearer_refusals(verify, auth, code):
    d = _d(verify, "bearer", auth=auth)
    assert (d.allowed, d.code) == (False, code)


@pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER", "bEaReR"])
def test_bearer_scheme_is_case_insensitive(verify, mint, scheme):
    assert _d(verify, "bearer", auth=f"{scheme} {mint.token()}").allowed


def test_bearer_double_space_keeps_the_leading_space_and_fails(verify, mint):
    d = _d(verify, "bearer", auth=f"Bearer  {mint.token()}")
    assert d.code == "invalid_bearer"


@pytest.mark.parametrize("make", [
    lambda m: m.token("ticket"),
    lambda m: m.token("refresh"),
    lambda m: m.token("mfa_challenge"),
    lambda m: m.token("service_access"),
    lambda m: m.expired(),
    lambda m: m.legacy(),
    lambda m: m.token(kid="kid-unknown"),
    lambda m: m.token(key=m.other),
    lambda m: m.token(iss="https://evil.example"),
    lambda m: m.token(aud="urn:evil"),
    lambda m: m.token(ptype="service"),
    lambda m: m.token(jti=None),
])
def test_bearer_only_accepts_a_valid_access_token(verify, mint, make):
    d = _d(verify, "bearer", auth=f"Bearer {make(mint)}")
    assert (d.allowed, d.code) == (False, "invalid_bearer")


def test_bearer_ignores_a_ticket_in_the_query(verify, mint):
    # Strict routes do not take tickets: a valid ticket does not help, a bad one does not hurt.
    assert not _d(verify, "bearer", query=f"ticket={mint.token('ticket')}").allowed
    assert _d(verify, "bearer", auth=f"Bearer {mint.token()}", query="ticket=garbage").allowed


def test_bearer_success_carries_the_principal(verify, mint):
    d = _d(verify, "bearer", auth=f"Bearer {mint.token()}")
    assert d.allowed and d.principal["sub"] == "usr_gw" and d.principal["kind"] == "access"
    assert d.principal["ptype"] == "user" and d.principal["jti"]


# ── ticket_or_bearer (get_current_user_flexible) ─────────────────────────────


def test_flexible_missing_credential(verify):
    for auth in (None, "", "Bearer", "Bearer ", "Basic abc", "Token x"):
        d = _d(verify, "ticket_or_bearer", auth=auth)
        assert d.code == "missing_flexible", auth


def test_flexible_ticket_first(verify, mint):
    ticket, access = mint.token("ticket"), mint.token()
    # a valid ticket is enough, whatever the header says
    assert _d(verify, "ticket_or_bearer", auth="Bearer garbage", query=f"ticket={ticket}").allowed
    assert _d(verify, "ticket_or_bearer", auth="Basic x", query=f"ticket={ticket}").allowed
    # a present, bad ticket refuses even with a valid bearer (observed live)
    d = _d(verify, "ticket_or_bearer", auth=f"Bearer {access}", query="ticket=garbage")
    assert d.code == "invalid_ticket"
    # an empty ticket is absent: the bearer decides
    assert _d(verify, "ticket_or_bearer", auth=f"Bearer {access}", query="ticket=").allowed
    assert _d(verify, "ticket_or_bearer", auth=f"Bearer {access}", query="ticket").allowed
    assert _d(verify, "ticket_or_bearer", query="ticket=").code == "missing_flexible"


@pytest.mark.parametrize("make", [
    lambda m: m.token(),  # an access token is not a ticket
    lambda m: m.token("refresh"),
    lambda m: m.expired("ticket"),
    lambda m: m.legacy("ticket"),
    lambda m: m.token("ticket", kid="kid-unknown"),
    lambda m: "not-a-token",
])
def test_flexible_bad_ticket(verify, mint, make):
    d = _d(verify, "ticket_or_bearer", query=f"ticket={make(mint)}")
    assert d.code == "invalid_ticket"


def test_flexible_last_ticket_wins(verify, mint):
    good = mint.token("ticket")
    assert _d(verify, "ticket_or_bearer", query=f"ticket=garbage&ticket={good}").allowed
    assert _d(verify, "ticket_or_bearer", query=f"ticket={good}&ticket=garbage").code == "invalid_ticket"


def test_flexible_ticket_is_percent_decoded(verify, mint):
    good = mint.token("ticket")
    assert _d(verify, "ticket_or_bearer", query="ticket=" + quote(good, safe="")).allowed
    assert _d(verify, "ticket_or_bearer", query="a=1&ticket=" + good + "&b=2").allowed


def test_flexible_bearer_path(verify, mint):
    assert _d(verify, "ticket_or_bearer", auth=f"Bearer {mint.token()}").allowed
    assert _d(verify, "ticket_or_bearer", auth="Bearer garbage").code == "invalid_bearer"
    assert _d(verify, "ticket_or_bearer", auth=f"Bearer {mint.token('ticket')}").code == "invalid_bearer"


# ── ticket (the WebSocket logins) ────────────────────────────────────────────


def test_ws_valid_ticket(verify, mint):
    d = _d(verify, "ticket", query=f"ticket={mint.token('ticket')}")
    assert d.allowed and d.principal["kind"] == "ticket"


@pytest.mark.parametrize("query_of", [
    lambda m: "",
    lambda m: "ticket=",
    lambda m: "ticket=not-a-token",
    lambda m: f"ticket={m.token()}",
    lambda m: f"ticket={m.expired('ticket')}",
    lambda m: f"ticket={m.legacy('ticket')}",
    lambda m: f"ticket={m.token('ticket', kid='kid-unknown')}",
    lambda m: f"ticket={m.token('ticket', sub='')}",
])
def test_ws_refusals_are_all_the_same_bare_403(verify, mint, query_of):
    d = _d(verify, "ticket", query=query_of(mint))
    assert (d.allowed, d.code, d.status) == (False, "ws_refused", 403)


def test_ws_ignores_the_authorization_header(verify, mint):
    assert not _d(verify, "ticket", auth=f"Bearer {mint.token()}").allowed
    assert _d(verify, "ticket", auth="Bearer garbage", query=f"ticket={mint.token('ticket')}").allowed


# ── parsing primitives ───────────────────────────────────────────────────────


def test_scheme_and_credentials_is_fastapis():
    assert scheme_and_credentials(None) == ("", "")
    assert scheme_and_credentials("") == ("", "")
    assert scheme_and_credentials("Bearer") == ("Bearer", "")
    assert scheme_and_credentials("Bearer  x y") == ("Bearer", " x y")


def test_last_ticket_accepts_bytes_and_str():
    assert last_ticket(b"ticket=a&ticket=b") == "b"
    assert last_ticket("ticket=a+b") == "a b"
    assert last_ticket("x=1") == ""
