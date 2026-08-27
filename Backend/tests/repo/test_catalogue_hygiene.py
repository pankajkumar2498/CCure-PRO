"""
tests/repo/test_catalogue_hygiene.py
─────────────────────────────────────────────────────────────────────────────
A test run must not leave rows behind in the vulnerability catalogue.

Why this exists
───────────────
The suite writes ``vulnerability_definitions`` rows as a side effect of
exercising the scan-sync path: a scan payload carrying a ``cve_id`` makes
``scans/asset_syncer.py`` upsert a catalogue row for it. ``_purge_test_data``
removed organisations, users, frameworks, controls and roles, and the findings
went with their organisation through ON DELETE CASCADE — but the catalogue rows
those findings pointed at were the one thing nothing reached. They accumulated,
run after run.

On the live application database that left **24** rows titled "Test
vulnerability" and "Package CVE", dated 2026-06-19 to 2026-08-10 — the last on
the day of the incident recorded in CLAUDE.md, when a full-suite run inherited
the API container's ``DATABASE_URL``. Each of them reads to a person, and to
any tool, as a published CVE.

The three database-name guards in ``conftest`` stop a run reaching a real
database. This is the second line: even if one did, it would leave no catalogue
residue behind.

The tests below assert the guard *works*, by exercising it, rather than
asserting the code that implements it looks right.
"""

import pytest
from conftest import SYNTHETIC_CVE_PREFIX, _purge_test_data
from db.base import engine
from sqlalchemy import text

#: Ids used only by this module. Distinct from anything another test mints, so
#: a failure here can never be another suite's residue.
_SYNTHETIC_ID = f"{SYNTHETIC_CVE_PREFIX}hygiene01"
_REAL_LOOKING_ID = "CVE-2014-0160"

_INSERT = text(
    "INSERT INTO vulnerability_definitions "
    '(id, cve_id, title, severity, source, cwe_ids, "references", '
    " affected_software, is_custom, created_at, updated_at) "
    "VALUES (:i, :i, :t, 'high', 'pytest-hygiene', '[]'::jsonb, '[]'::jsonb, "
    "        '[]'::jsonb, false, now(), now()) "
    "ON CONFLICT (id) DO NOTHING"
)


def _exists(conn, definition_id: str) -> bool:
    return bool(
        conn.execute(
            text("SELECT 1 FROM vulnerability_definitions WHERE id = :i"),
            {"i": definition_id},
        ).scalar()
    )


@pytest.fixture
def catalogue_rows():
    """
    Insert one synthetic row and one real-looking row, and guarantee both are
    gone afterwards whatever the test does.

    The real-looking row is cleaned up here rather than by the purge, because
    the whole point of the second test is that the purge must *not* touch it —
    so this fixture has to be the thing that removes it.
    """
    with engine.begin() as conn:
        conn.execute(_INSERT, {"i": _SYNTHETIC_ID, "t": "synthetic hygiene row"})
        conn.execute(_INSERT, {"i": _REAL_LOOKING_ID, "t": "real-looking hygiene row"})
    try:
        yield
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM vulnerability_definitions WHERE id = ANY(:ids)"),
                {"ids": [_SYNTHETIC_ID, _REAL_LOOKING_ID]},
            )


def test_the_purge_removes_synthetic_catalogue_rows(catalogue_rows):
    """
    The defect this guards: catalogue rows a test created outliving the run.

    Asserted by running the real purge, not by reading its source — a guard
    that checks the implementation looks right passes just as happily when the
    statement it inspects has been made a no-op.
    """
    with engine.begin() as conn:
        assert _exists(conn, _SYNTHETIC_ID), "fixture did not insert its row"

    _purge_test_data()

    with engine.begin() as conn:
        assert not _exists(conn, _SYNTHETIC_ID), (
            f"{_SYNTHETIC_ID} survived _purge_test_data(). Catalogue residue "
            "accumulates across runs and, on a real database, reads as a "
            "published CVE."
        )


def test_the_purge_leaves_real_catalogue_rows_alone(catalogue_rows):
    """
    The opposite failure, and the more expensive one.

    ``asset_vulnerabilities.vuln_id`` is ON DELETE RESTRICT, so a purge that
    over-reached into real feed data would either destroy advisories the feeds
    took hours to sync or start failing on the foreign key. The synthetic
    prefix is a year that cannot exist in the CVE numbering scheme, which is
    what keeps the two populations separable.
    """
    _purge_test_data()

    with engine.begin() as conn:
        assert _exists(conn, _REAL_LOOKING_ID), (
            f"{_REAL_LOOKING_ID} was deleted by _purge_test_data(). The purge "
            "must only ever match the synthetic prefix "
            f"{SYNTHETIC_CVE_PREFIX!r}."
        )


def test_the_synthetic_prefix_cannot_match_a_published_cve():
    """
    The whole scheme rests on this. CVE year fields are real calendar years, so
    9999 is unreachable — which is why a LIKE on the prefix can never select a
    genuine advisory.
    """
    assert SYNTHETIC_CVE_PREFIX.startswith("CVE-")
    year = SYNTHETIC_CVE_PREFIX.split("-")[1]
    assert year == "9999", (
        "the synthetic prefix must use an impossible CVE year; anything a real "
        "advisory could use would put feed data inside the purge's reach"
    )


def test_the_cleanup_script_and_the_test_guard_agree_on_the_prefix():
    """
    ``scripts/cleanup_test_catalogue_residue.py`` cleans databases that already
    have residue; ``conftest`` stops new residue appearing. Two spellings of one
    convention would leave a gap between them where rows survive.
    """
    from scripts.cleanup_test_catalogue_residue import (
        SYNTHETIC_CVE_PREFIX as script_prefix,
    )

    assert script_prefix == SYNTHETIC_CVE_PREFIX
