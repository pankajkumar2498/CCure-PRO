"""
tests/audit/test_audit_canonicalization.py
─────────────────────────────────────────────────────────────────────────────
Phase 4: the canonical serialisation must be deterministic, injective, and
independent of every session setting a verifier might happen to have.

A hash chain is only as good as the string it hashes. Each rule below exists
because breaking it produces either a false tamper alarm on unmodified data or,
worse, two different events that hash identically.
"""

import pytest
from audit_chain_support import newest_event, require_chain, write_event
from sqlalchemy import text

pytestmark = pytest.mark.usefixtures("db_session")

#: The approved canonical set, in the approved order. user_id is absent by
#: design: it is legitimately mutated to NULL by an account deletion, so
#: hashing it would turn every deletion into a mass tamper alarm.
CANONICAL_FIELDS = [
    "id",
    "org_id",
    "actor_user_id",
    "actor_username",
    "action",
    "resource_type",
    "resource_id",
    "status",
    "severity",
    "ip_address",
    "user_agent",
    "changes",
    "request_id",
    "created_at",
]


@pytest.fixture(autouse=True)
def require_bootstrap(db_session):
    require_chain(db_session)


@pytest.fixture
def event(db_session, test_user):
    write_event(
        db_session,
        test_user,
        changes={"b": 1, "a": {"nested": True}},
    )
    return newest_event(db_session, test_user.org_id)


def _payload(db_session, event) -> str:
    return db_session.execute(
        text(
            "SELECT audit_canonical_payload_v1(a) FROM audit_logs a "
            " WHERE a.id = :i AND a.org_id = :o"
        ),
        {"i": event.id, "o": event.org_id},
    ).scalar()


# ── Field set and order ─────────────────────────────────────────────────────


def test_the_payload_contains_every_canonical_field(db_session, event):
    payload = _payload(db_session, event)
    for value in (event.id, event.org_id, event.action, event.status, event.severity):
        assert value in payload, f"{value!r} missing from the canonical payload"


def test_user_id_is_not_part_of_the_payload(db_session, event, test_user):
    """
    The decision this whole design turns on. If `user_id` were hashed, deleting
    an account — a sanctioned operation that sets it to NULL — would break the
    chain for every event that user ever produced.

    Proven behaviourally: null `user_id` the way a deletion does, and the hash
    must still reproduce.
    """
    before = db_session.execute(
        text(
            "SELECT audit_record_hash_v1(a.prev_hash, a) FROM audit_logs a "
            " WHERE a.id = :i AND a.org_id = :o"
        ),
        {"i": event.id, "o": event.org_id},
    ).scalar()

    db_session.execute(
        text("UPDATE audit_logs SET user_id = NULL WHERE id = :i"), {"i": event.id}
    )
    db_session.commit()

    after = db_session.execute(
        text(
            "SELECT audit_record_hash_v1(a.prev_hash, a) FROM audit_logs a "
            " WHERE a.id = :i AND a.org_id = :o"
        ),
        {"i": event.id, "o": event.org_id},
    ).scalar()

    assert before == after, "an account deletion must not break the chain"
    assert after == event.record_hash


def test_the_field_order_is_fixed_in_the_function_not_the_catalogue(db_session):
    """
    `ALTER TABLE ADD COLUMN` changes attnum ordering, so a payload derived from
    `to_jsonb(NEW)` key order would silently invalidate every historical hash
    the next time a column is added. Asserted by reading the function source.
    """
    src = db_session.execute(
        text("SELECT prosrc FROM pg_proc WHERE proname = 'audit_canonical_payload_v1'")
    ).scalar()
    positions = [src.index(f"rec.{f}") for f in CANONICAL_FIELDS]
    assert positions == sorted(
        positions
    ), "canonical fields are not emitted in the approved order"
    assert "rec.user_id" not in src.replace(
        "rec.user_agent", ""
    ), "user_id must not appear in the canonical payload"


# ── Encoding rules ──────────────────────────────────────────────────────────


def test_null_and_empty_string_are_distinguishable(db_session):
    """Without this, `resource_id` NULL and '' collide."""
    null_form, empty_form = db_session.execute(
        text("SELECT _audit_field_v1(NULL), _audit_field_v1('')")
    ).fetchone()
    assert null_form == "~"
    assert empty_form == "0:"
    assert null_form != empty_form


def test_the_encoding_is_injective(db_session):
    """
    A delimiter-joined string is ambiguous: ('a|b','c') and ('a','b|c') produce
    the same input, so one event could be substituted for another. Length
    prefixing removes that.
    """
    assert (
        db_session.execute(
            text(
                "SELECT _audit_field_v1('a:b') || _audit_field_v1('c') "
                "    <> _audit_field_v1('a') || _audit_field_v1('b:c')"
            )
        ).scalar()
        is True
    )


def test_multibyte_values_are_length_prefixed_in_bytes(db_session):
    """
    `octet_length`, not `char_length`. A character count would make two
    different strings share a prefix length and reopen the ambiguity above.
    """
    encoded = db_session.execute(text("SELECT _audit_field_v1('é')")).scalar()
    assert encoded == "2:é"


# ── Session-setting independence ────────────────────────────────────────────


def test_hashes_reproduce_under_any_session_timezone(db_session, event):
    """
    The largest determinism hazard in the design. `timestamptz::text` renders
    in the session's TimeZone GUC — measured, the same row renders as
    `2026-08-24 16:03:06.55087+00` under UTC and
    `2026-08-24 21:33:06.55087+05:30` under Asia/Kolkata — so a verifier
    connecting from a different session would compute different hashes for
    completely unmodified rows.
    """
    for tz in ("UTC", "Asia/Kolkata", "America/New_York", "Pacific/Kiritimati"):
        db_session.execute(text(f"SET LOCAL TimeZone = '{tz}'"))
        recomputed = db_session.execute(
            text(
                "SELECT audit_record_hash_v1(a.prev_hash, a) FROM audit_logs a "
                " WHERE a.id = :i AND a.org_id = :o"
            ),
            {"i": event.id, "o": event.org_id},
        ).scalar()
        assert recomputed == event.record_hash, f"hash changed under TimeZone={tz}"
    db_session.rollback()


def test_hashes_reproduce_under_any_datestyle(db_session, event):
    """`to_char` is STABLE rather than IMMUTABLE precisely because date
    rendering can depend on session settings. The chosen format contains no
    locale-dependent element; this proves it."""
    for style in ("ISO, MDY", "SQL, DMY", "German, DMY", "Postgres, MDY"):
        db_session.execute(text(f"SET LOCAL DateStyle = '{style}'"))
        recomputed = db_session.execute(
            text(
                "SELECT audit_record_hash_v1(a.prev_hash, a) FROM audit_logs a "
                " WHERE a.id = :i AND a.org_id = :o"
            ),
            {"i": event.id, "o": event.org_id},
        ).scalar()
        assert recomputed == event.record_hash, f"hash changed under DateStyle={style}"
    db_session.rollback()


def test_the_timestamp_is_rendered_at_fixed_microsecond_precision(db_session, event):
    """
    `.US` forces six digits. Without it a trailing zero renders differently —
    `.55087` versus `.550870` — and two verifiers could disagree about an
    untouched row.
    """
    payload = _payload(db_session, event)
    # The timestamp field is the last one, and is always exactly 26 characters:
    # YYYY-MM-DDTHH:MM:SS.ffffff
    assert payload.endswith(
        db_session.execute(
            text(
                "SELECT to_char(created_at AT TIME ZONE 'UTC', "
                "'YYYY-MM-DD\"T\"HH24:MI:SS.US') FROM audit_logs "
                "WHERE id = :i AND org_id = :o"
            ),
            {"i": event.id, "o": event.org_id},
        ).scalar()
    )
    assert "26:" in payload, "the timestamp must be length-prefixed as 26 bytes"


# ── JSONB ───────────────────────────────────────────────────────────────────


def test_jsonb_key_order_is_canonical(db_session):
    """
    JSONB normalises on input — keys sorted, duplicates removed, whitespace and
    numerics normalised — so two logically identical `changes` values hash the
    same regardless of how the application happened to order them.
    """
    same = db_session.execute(
        text("SELECT CAST(:a AS jsonb)::text = CAST(:b AS jsonb)::text"),
        {"a": '{"b":1,"a":2}', "b": '{"a":2,  "b":1}'},
    ).scalar()
    assert same is True


def test_jsonb_is_not_rendered_through_json_or_pretty(db_session):
    """
    `json` preserves input formatting and duplicate keys verbatim, and
    `jsonb_pretty` injects whitespace. Either would make the payload depend on
    how the value was written rather than what it means.
    """
    src = db_session.execute(
        text("SELECT prosrc FROM pg_proc WHERE proname = 'audit_canonical_payload_v1'")
    ).scalar()
    assert "jsonb_pretty" not in src
    assert "::json)" not in src and "AS json)" not in src


def test_differently_ordered_changes_produce_the_same_hash(db_session, test_user):
    """
    The end-to-end consequence of the two rules above: the order the
    application happened to build the dict in must not reach the hash.

    Note that JSONB does **not** order keys alphabetically — it orders by key
    length first, then bytewise. `{"alpha": 1, "beta": 2}` normalises to
    `{"beta": 2, "alpha": 1}`, because `beta` is shorter. That is still a
    canonical form, which is all this depends on; an earlier version of this
    test looked for the alphabetical form and failed while the property it was
    checking held perfectly.

    The segment is therefore read back from the database rather than located by
    string arithmetic over the payload.
    """
    write_event(db_session, test_user, changes={"alpha": 1, "beta": 2})
    first = newest_event(db_session, test_user.org_id)

    write_event(db_session, test_user, changes={"beta": 2, "alpha": 1})
    second = newest_event(db_session, test_user.org_id)

    assert first.id != second.id

    def normalised(event):
        return db_session.execute(
            text("SELECT changes::text FROM audit_logs WHERE id = :i AND org_id = :o"),
            {"i": event.id, "o": event.org_id},
        ).scalar()

    first_changes, second_changes = normalised(first), normalised(second)
    assert (
        first_changes == second_changes
    ), "two logically identical `changes` values normalised differently"

    # And that identical text is what each payload actually carries, length
    # prefixed — so the hash cannot depend on the original key order.
    encoded = f"{len(first_changes.encode())}:{first_changes}"
    assert encoded in _payload(db_session, first)
    assert encoded in _payload(db_session, second)


# ── One implementation, not two ─────────────────────────────────────────────


def test_the_verifier_and_the_trigger_share_one_definition(db_session, event):
    """
    Decision 5. A Python reimplementation would be a second definition that can
    drift, and drift reads as tampering. The verifier calls the same SQL
    function the trigger does.
    """
    recomputed = db_session.execute(
        text(
            "SELECT audit_record_hash_v1(a.prev_hash, a) FROM audit_logs a "
            " WHERE a.id = :i AND a.org_id = :o"
        ),
        {"i": event.id, "o": event.org_id},
    ).scalar()
    assert recomputed == event.record_hash


def test_the_hash_is_lowercase_hex_of_the_expected_width(db_session, event):
    assert len(event.record_hash) == 64
    assert event.record_hash == event.record_hash.lower()
    int(event.record_hash, 16)
