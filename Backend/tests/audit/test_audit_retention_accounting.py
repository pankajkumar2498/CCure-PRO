"""
tests/audit/test_audit_retention_accounting.py
─────────────────────────────────────────────────────────────────────────────
Phase 6b: both directions of the head-vs-surviving-rows rule, without a
database.

This exists because one direction of that rule was **NOT VERIFIED** through all
of phase 6a, and could not be made verifiable by any legitimate means.

`legacy_event_count` is seeded from a `COUNT` by `audit_chain_seed_legacy_v1`
when the chain is bootstrapped, and afterwards only ever decremented, by
`audit_chain_note_legacy_purge_v1`. The first is granted to nobody; the second
is executable by `audit_maintenance` alone. So on a test organisation — whose
pre-chain rows are injected *after* that seeding — the counter reads 0 while
rows exist, and the head can never be *ahead* of them. The break direction is
unreachable, and the only way to reach it would be to grant a privilege the
design deliberately withholds.

Extracting the comparison into a pure function resolves that: the rule is
asserted directly, in both directions, on every database including one with no
retention installed at all. The integration test next door still covers the
live scenario where it *is* reachable, and still skips honestly where it is not.

The direction is the whole point of the rule, so it is what these tests pin:

  * head **ahead** of the rows → rows vanished without the counter moving →
    a **break**. Sanctioned retention moves both in one transaction.
  * head **behind** the rows → rows were inserted unhashed, with the chain
    trigger disabled → a **note**. That is how real pre-chain history exists at
    all, and reporting it as tampering would cry wolf on the ordinary case.
"""

import pytest
from scripts.audit.verify_chain import legacy_accounting_status


# ─── The break direction ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "head,surviving,missing",
    [
        (1, 0, 1),
        (10, 9, 1),
        (515, 500, 15),
        (1_000_000, 1, 999_999),
    ],
)
def test_a_head_ahead_of_the_rows_is_a_break(head, surviving, missing):
    """
    The case phase 6a could never reach on a test database, asserted directly.

    A shortfall means pre-chain rows were removed by something that did not
    tell the chain head — which is exactly the shape of an out-of-band
    deletion, and exactly what sanctioned retention cannot look like.
    """
    issue, note = legacy_accounting_status(head, surviving)

    assert issue is not None, "an unexplained shortfall was not reported"
    assert note is None, "a break must not be softened into a note"
    assert "outside the purge path" in issue
    assert str(head) in issue and str(surviving) in issue


def test_the_break_message_names_both_numbers():
    """An operator has to be able to act on it without re-deriving the counts."""
    issue, _ = legacy_accounting_status(319, 300)
    assert "319" in issue and "300" in issue


# ─── The note direction ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "head,surviving,extra",
    [
        (0, 1, 1),
        (0, 6, 6),
        (100, 105, 5),
    ],
)
def test_a_head_behind_the_rows_is_a_note_not_a_break(head, surviving, extra):
    """
    Rows written with the chain trigger disabled. Real pre-chain history is
    made this way, and so is every legacy fixture in these suites — calling it
    tampering would make the verifier useless by making it always shout.
    """
    issue, note = legacy_accounting_status(head, surviving)

    assert issue is None, "an ordinary unhashed insert was reported as tampering"
    assert note is not None
    assert str(extra) in note
    assert "chain trigger" in note


# ─── Agreement ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("value", [0, 1, 515, 1_000_000])
def test_agreement_is_neither_a_break_nor_a_note(value):
    """The state a correctly bootstrapped, correctly purged database is in."""
    assert legacy_accounting_status(value, value) == (None, None)


def test_a_purge_keeps_the_two_in_agreement():
    """
    The invariant retention maintains: the head falls by exactly what was
    removed, in the same transaction, so agreement is preserved from any
    starting point where it held.
    """
    head = surviving = 515
    for deleted in (100, 300, 115):
        head -= deleted
        surviving -= deleted
        assert legacy_accounting_status(head, surviving) == (None, None)
    assert head == 0 and surviving == 0


def test_only_one_of_the_two_is_ever_set():
    """A caller appends the break to one list and the note to another."""
    for head in range(0, 6):
        for surviving in range(0, 6):
            issue, note = legacy_accounting_status(head, surviving)
            assert not (issue and note), f"both set at head={head} rows={surviving}"
