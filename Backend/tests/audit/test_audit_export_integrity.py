"""
tests/audit/test_audit_export_integrity.py
─────────────────────────────────────────────────────────────────────────────
Phase 5: what the export is allowed to *claim* about the rows it carries.

The endpoint suite next door proves the right rows leave. This one proves the
label beside each of them is earned, which is the property the whole
tamper-evidence chain exists to support: an export that says `verified` beside
a row nobody checked launders an unverified record into an audit file, and is
worse than having no export at all.

Three states, each proved independently:

  * ``legacy_unverifiable`` — no ``record_hash`` at all. Pre-chain history,
    which no amount of machinery can verify retrospectively.
  * ``verified``            — the stored hash was recomputed through the
    database's own canonical function and reproduced exactly.
  * ``INTEGRITY_FAILURE``   — it was recomputed and did **not** reproduce.

And a fourth for the mode the caller can ask for:

  * ``not_verified``        — a stored hash that was deliberately not checked,
    because the export was requested with ``verify=false``.

Tampering discipline
────────────────────
The failure case has to be visible to a second database session — the CSV is
streamed from one — so unlike the `expect_refused` probes in the chain suites
the tamper here **must** be committed. The fixture therefore restores the
original value in an unconditional ``finally`` and then asserts the row
verifies again, so a failure inside the test cannot leave a broken chain row
behind. The append-only trigger is suspended through
``suspended_immutability`` in both directions and is never dropped
independently of the transaction that restores it.
"""

from datetime import datetime, timezone

import pytest
from audit_chain_support import recompute, require_chain, write_event
from db.audit_hardening import suspended_immutability
from db.base import gen_uuid
from db.models import AuditLog
from reporting.audit_export import (
    INTEGRITY_FAILURE,
    INTEGRITY_LEGACY,
    INTEGRITY_NOT_VERIFIED,
    INTEGRITY_VERIFIED,
)
from sqlalchemy import text
from test_audit_export import parse_csv

EXPORT = "/admin/audit-logs/export"


def _legacy_event(db_session, org_id, **kw) -> AuditLog:
    """
    An event with no hash — the shape every row written before phase 4 has.

    Inserted through raw SQL with the chain trigger bypassed? No: the trigger
    would hash it. It is inserted normally and then has its hash cleared, which
    is exactly the state the 515 pre-chain rows on the live database are in.
    """
    row = AuditLog(
        id=gen_uuid(),
        org_id=org_id,
        action=kw.get("action", "user.login"),
        resource_type="user",
        resource_id="legacy-1",
        status="success",
        severity="info",
        ip_address="10.180.6.14",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(row)
    db_session.commit()

    with suspended_immutability(db_session):
        db_session.execute(
            text(
                "UPDATE audit_logs SET record_hash = NULL, prev_hash = NULL "
                " WHERE id = :i AND org_id = :o"
            ),
            {"i": row.id, "o": org_id},
        )
    db_session.commit()
    return row


@pytest.fixture
def chained_event(db_session, test_user):
    """One genuinely chained event, written through the application's own path."""
    require_chain(db_session)
    write_event(db_session, test_user, "user.profile_updated")
    return (
        db_session.query(AuditLog)
        .filter(
            AuditLog.org_id == test_user.org_id,
            AuditLog.record_hash.isnot(None),
        )
        .order_by(AuditLog.created_at.desc())
        .first()
    )


@pytest.fixture
def tampered_event(db_session, test_user, chained_event):
    """
    A chained event whose stored ``record_hash`` no longer matches its content.

    Forging the row's own hash is one of the three ways somebody covers their
    tracks, and it is the reversible one: the original is a single known
    string, so the restore is exact and the chain ends the test byte-identical
    to how it started.
    """
    original = chained_event.record_hash
    forged = "0" * 64
    assert original != forged

    with suspended_immutability(db_session):
        db_session.execute(
            text(
                "UPDATE audit_logs SET record_hash = :h WHERE id = :i AND org_id = :o"
            ),
            {"h": forged, "i": chained_event.id, "o": chained_event.org_id},
        )
    db_session.commit()

    try:
        yield chained_event
    finally:
        # Unconditional, and it must stay that way: everything above is
        # committed, so an exception in the test body would otherwise leave a
        # permanently broken chain row in the database for every suite that
        # runs afterwards.
        with suspended_immutability(db_session):
            db_session.execute(
                text(
                    "UPDATE audit_logs SET record_hash = :h "
                    " WHERE id = :i AND org_id = :o"
                ),
                {"h": original, "i": chained_event.id, "o": chained_event.org_id},
            )
        db_session.commit()

        restored = db_session.execute(
            text("SELECT record_hash FROM audit_logs WHERE id = :i AND org_id = :o"),
            {"i": chained_event.id, "o": chained_event.org_id},
        ).scalar()
        assert restored == original, "the tamper fixture failed to clean up"
        assert (
            recompute(db_session, chained_event.id, chained_event.org_id) == original
        ), "the row does not verify again after the fixture restored it"


def _integrity_of(rows: list[dict], event_id: str) -> str:
    match = [row for row in rows if row["id"] == event_id]
    assert match, f"{event_id} is not in the export"
    return match[0]["integrity"]


def _preamble_value(preamble: list[str], label: str) -> str:
    line = next(item for item in preamble if item.lstrip("# ").startswith(label))
    return line.split(":", 1)[1].strip()


# ─── State 1: legacy, unverifiable ───────────────────────────────────────────


def test_a_row_with_no_hash_is_legacy_unverifiable(
    client, auth_headers, db_session, test_user
):
    legacy = _legacy_event(db_session, test_user.org_id)
    res = client.get(EXPORT, headers=auth_headers, params={"q": legacy.id})
    assert res.status_code == 200, res.text
    _, rows = parse_csv(res.text)
    assert _integrity_of(rows, legacy.id) == INTEGRITY_LEGACY


def test_a_legacy_row_is_never_labelled_verified(
    client, auth_headers, db_session, test_user
):
    """
    The whole point of the four-word vocabulary. A pre-chain row folded into a
    "verified" total is a false clean bill of health over history that carries
    no guarantee whatsoever.
    """
    legacy = _legacy_event(db_session, test_user.org_id)
    res = client.get(EXPORT, headers=auth_headers, params={"q": legacy.id})
    preamble, rows = parse_csv(res.text)

    assert _integrity_of(rows, legacy.id) != INTEGRITY_VERIFIED
    assert _preamble_value(preamble, "verified ") == "0"
    assert _preamble_value(preamble, "legacy_unverifiable") == "1"
    assert "predate the tamper-evidence chain" in res.text
    assert "cannot be cryptographically verified" in res.text


# ─── State 2: verified ───────────────────────────────────────────────────────


def test_a_chained_row_is_verified(client, auth_headers, chained_event):
    res = client.get(EXPORT, headers=auth_headers, params={"q": chained_event.id})
    assert res.status_code == 200, res.text
    preamble, rows = parse_csv(res.text)

    assert _integrity_of(rows, chained_event.id) == INTEGRITY_VERIFIED
    assert _preamble_value(preamble, "verified ") == "1"
    assert _preamble_value(preamble, "INTEGRITY_FAILURE") == "0"
    assert res.headers["x-audit-integrity"] == "VERIFIED"
    assert res.headers["x-audit-verification-mode"] == "performed"
    assert "VERIFICATION PERFORMED" in res.text


def test_the_verified_row_carries_the_hash_it_was_verified_against(
    client, auth_headers, chained_event
):
    res = client.get(EXPORT, headers=auth_headers, params={"q": chained_event.id})
    _, rows = parse_csv(res.text)
    assert rows[0]["record_hash"] == chained_event.record_hash
    assert len(rows[0]["record_hash"]) == 64


# ─── State 3: integrity failure ──────────────────────────────────────────────


def test_a_tampered_row_is_reported_as_an_integrity_failure(
    client, auth_headers, tampered_event
):
    res = client.get(EXPORT, headers=auth_headers, params={"q": tampered_event.id})
    assert res.status_code == 200, "the export is still produced; it is marked"
    _, rows = parse_csv(res.text)
    assert _integrity_of(rows, tampered_event.id) == INTEGRITY_FAILURE


def test_a_tampered_export_is_marked_in_every_channel(
    client, auth_headers, tampered_event
):
    """
    Row label, summary count, response header, filename and audit event — all
    five. Any one of them alone can be missed: a header is invisible to
    somebody opening the file, a row label is invisible to a client that never
    parses it, and a filename survives being forwarded when nothing else does.
    """
    res = client.get(EXPORT, headers=auth_headers, params={"q": tampered_event.id})
    preamble, rows = parse_csv(res.text)

    assert _integrity_of(rows, tampered_event.id) == INTEGRITY_FAILURE
    assert _preamble_value(preamble, "INTEGRITY_FAILURE") == "1"
    assert res.headers["x-audit-integrity"] == "FAILED"
    assert "INTEGRITY-FAILURE" in res.headers["content-disposition"]
    assert "WARNING:" in res.text
    assert "modified outside the application" in res.text


def test_a_tampered_export_records_a_failed_audit_event(
    client, auth_headers, db_session, test_user, tampered_event
):
    from db.base import SessionLocal

    res = client.get(EXPORT, headers=auth_headers, params={"q": tampered_event.id})
    assert res.status_code == 200
    res.read()

    independent = SessionLocal()
    try:
        row = (
            independent.query(AuditLog)
            .filter(
                AuditLog.org_id == test_user.org_id,
                AuditLog.action == "audit.log_exported",
            )
            .order_by(AuditLog.created_at.desc())
            .first()
        )
    finally:
        independent.close()

    assert row is not None
    assert row.status == "failure", (
        "an export that surfaced a broken row is not a successful export; "
        "`status` is what a reviewer filters on"
    )
    assert row.changes["integrity_failures"] == 1


def test_a_tampered_pdf_is_marked_too(client, auth_headers, tampered_event):
    res = client.get(
        EXPORT,
        headers=auth_headers,
        params={"q": tampered_event.id, "format": "pdf"},
    )
    assert res.status_code == 200
    assert res.content.startswith(b"%PDF-")
    assert res.headers["x-audit-integrity"] == "FAILED"
    assert "INTEGRITY-FAILURE" in res.headers["content-disposition"]


# ─── State 4: verification not performed ─────────────────────────────────────


def test_verify_false_never_claims_verification(client, auth_headers, chained_event):
    """
    A row whose hash was not recomputed is `not_verified`, never `verified` —
    the stored hash is the value under suspicion, not the evidence.
    """
    res = client.get(
        EXPORT,
        headers=auth_headers,
        params={"q": chained_event.id, "verify": "false"},
    )
    assert res.status_code == 200, res.text
    preamble, rows = parse_csv(res.text)

    assert _integrity_of(rows, chained_event.id) == INTEGRITY_NOT_VERIFIED
    assert _preamble_value(preamble, "verified ") == "0"
    assert _preamble_value(preamble, "not_verified") == "1"
    assert res.headers["x-audit-integrity"] == "NOT_VERIFIED"
    assert res.headers["x-audit-verification-mode"] == "not_requested"


def test_verify_false_says_so_in_words(client, auth_headers, chained_event):
    """
    A file that merely omits the claim reads, to anybody who did not issue the
    request, exactly like one that made it.
    """
    res = client.get(
        EXPORT,
        headers=auth_headers,
        params={"q": chained_event.id, "verify": "false"},
    )
    assert "VERIFICATION WAS NOT PERFORMED" in res.text
    assert "verify=false" in res.text
    assert "VERIFICATION PERFORMED." not in res.text


def test_verify_false_is_recorded_on_the_audit_event(
    client, auth_headers, db_session, test_user, chained_event
):
    from db.base import SessionLocal

    res = client.get(
        EXPORT,
        headers=auth_headers,
        params={"q": chained_event.id, "verify": "false"},
    )
    assert res.status_code == 200
    res.read()

    independent = SessionLocal()
    try:
        row = (
            independent.query(AuditLog)
            .filter(
                AuditLog.org_id == test_user.org_id,
                AuditLog.action == "audit.log_exported",
            )
            .order_by(AuditLog.created_at.desc())
            .first()
        )
    finally:
        independent.close()

    assert row.changes["verification_requested"] is False
    assert row.changes["verification_mode"] == "not_requested"
    assert row.changes["verified"] == 0
    assert row.changes["not_verified"] == 1


def test_verification_is_on_by_default(client, auth_headers, chained_event):
    """`verify=true` is the normal evidence mode; it must not need asking for."""
    res = client.get(EXPORT, headers=auth_headers, params={"q": chained_event.id})
    assert res.headers["x-audit-verification-mode"] == "performed"


# ─── Mixed sets ──────────────────────────────────────────────────────────────


def test_the_summary_counts_add_up_to_the_row_count(
    client, auth_headers, db_session, test_user, chained_event
):
    _legacy_event(db_session, test_user.org_id, action="user.logout")
    res = client.get(EXPORT, headers=auth_headers)
    preamble, rows = parse_csv(res.text)

    counted = sum(
        int(_preamble_value(preamble, label))
        for label in (
            "verified ",
            "not_verified",
            "legacy_unverifiable",
            "INTEGRITY_FAILURE",
        )
    )
    assert counted == len(rows)
    assert counted == int(_preamble_value(preamble, "Events in this file"))


def test_every_row_carries_one_of_the_four_known_states(
    client, auth_headers, db_session, test_user, chained_event
):
    from reporting.audit_export import INTEGRITY_STATES

    _legacy_event(db_session, test_user.org_id, action="user.logout")
    res = client.get(EXPORT, headers=auth_headers)
    _, rows = parse_csv(res.text)
    assert rows
    unknown = {row["integrity"] for row in rows} - set(INTEGRITY_STATES)
    assert not unknown, f"unrecognised integrity label(s): {unknown}"


def test_verification_uses_the_databases_own_hash_function(
    client, auth_headers, chained_event, db_session
):
    """
    Not a Python reimplementation. Two definitions of a canonical form drift,
    and drift is indistinguishable from tampering — the verifier would report
    breaks that never happened, on the one trail nobody can then trust.
    """
    import inspect

    import routers.audit as audit_router

    source = inspect.getsource(audit_router._integrity_expression)
    assert "audit_record_hash_v1" in source
    assert "sha256" not in source and "hashlib" not in source

    # And the verdict it produces agrees with the shared support helper, which
    # calls that same SQL function directly.
    res = client.get(EXPORT, headers=auth_headers, params={"q": chained_event.id})
    _, rows = parse_csv(res.text)
    assert rows[0]["record_hash"] == recompute(
        db_session, chained_event.id, chained_event.org_id
    )


# ─── Spreadsheet safety ──────────────────────────────────────────────────────


def test_a_formula_in_a_field_is_neutralised(
    client, auth_headers, db_session, test_user
):
    """
    `user_agent` is attacker-chosen and lands in a cell. An audit export is
    opened in Excel by the person least able to afford it executing something.
    """
    row = AuditLog(
        id=gen_uuid(),
        org_id=test_user.org_id,
        action="user.login",
        resource_type="user",
        resource_id="=1+1",
        status="success",
        severity="info",
        ip_address="10.180.6.14",
        user_agent="=cmd|'/c calc'!A0",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(row)
    db_session.commit()

    res = client.get(EXPORT, headers=auth_headers, params={"q": row.id})
    _, rows = parse_csv(res.text)
    assert rows[0]["user_agent"].startswith("'=")
    assert rows[0]["resource_id"].startswith("'=")
    assert "spreadsheet cannot execute them as formulas" in res.text
