"""catalogue: retype fabricated network-check CVEs as plugin checks

Revision ID: e7f8a9b0c1d2
Revises: d6e7f8a9b0c1
Create Date: 2026-08-28

Phase 6 — GAP-06, unauthenticated network vulnerability checks.

The defect this repairs
───────────────────────
``scans/asset_syncer.py`` wrote every finding to ``vulnerability_definitions``
with ``id`` and ``cve_id`` both set to the finding's identifier and
``definition_type`` left at its ``'cve'`` default. For a real CVE that is
correct. For the twelve ad-hoc ``MISC-`` identifiers the network plugins
minted — and for the unbounded ``MISC-NUCLEI-<template>`` family — it filed a
configuration weakness as a published vulnerability.

``ck_vuln_def_cve_id_matches_type`` could not catch it. That constraint asks
whether a ``cve`` row carries a ``cve_id``, and these rows did; the string was
simply not a CVE. So each inherited everything a CVE row means downstream: KEV
membership lookups, EPSS scoring, CVSS band tables, exploit-provenance joins,
and a "look this up in NVD" link that resolves to nothing.

What this migration does
────────────────────────
1. **Renames the twelve known plugin identifiers** to the ``CCURE-CHK-…``
   identifiers ``engines/vulnerability/network_checks.py`` now declares, and
   repoints every stored finding at them.
2. **Renames ``MISC-NUCLEI-<template>`` to ``CCURE-CHK-NUCLEI-<template>``**,
   by pattern rather than by list, because that family is one row per Nuclei
   template and cannot be enumerated here.
3. **Retypes whatever is left** that is filed as ``cve`` without a real CVE
   identifier — the credentialed "not assessed" markers among them — setting
   ``definition_type`` to ``plugin_check`` and ``cve_id`` to NULL **without**
   renaming. Those identifiers belong to other subsystems; correcting their
   typing is this migration's business, renaming them is not.

Why rename rather than leave the old identifiers alone
──────────────────────────────────────────────────────
Leaving them would mean the same condition on the same host appears under two
identifiers — the old row from before the upgrade and a new one from the next
scan — so its finding history splits in half and a triager sees one problem
twice. Renaming keeps ``first_found_at``, the status, the notes and the
remediation state attached to the condition they describe.

Why the identifier map is duplicated here
─────────────────────────────────────────
It is deliberately a literal rather than an import from
``network_checks.legacy_identifier_map()``. A migration must do the same thing
in five years' time as it does today; one that reads live application code
would silently change meaning the first time a check is renamed, and would
then disagree with itself between two databases upgraded at different times.
``tests/scans/test_network_check_identifiers.py`` asserts this literal and the
catalogue agree, which is the same duplicate-and-guard arrangement
``DEFINITION_TYPE_SQL`` uses between the model and its migration.

Collisions are expected, not exceptional
────────────────────────────────────────
``MISC-SMB-SIGNING`` and ``MISC-NUCLEI-SMB-SIGNING`` are two identifiers for
one condition and both map to ``CCURE-CHK-SMB-SIGNING-NOT-REQUIRED``. A host
that carried both in one scan would violate
``uq_asset_vuln_scan_asset_cve`` the moment the second is repointed. The
duplicate is therefore resolved rather than allowed to abort the upgrade: the
row with the earliest ``first_found_at`` survives, because it is the one whose
history is longer.

Finding primary keys are rewritten too
──────────────────────────────────────
``asset_vulnerabilities.id`` is built as ``fnd_{asset}_{family}_{identifier}``,
so a renamed finding whose key still ends in the old identifier is invisible to
``_resolve_finding_id`` on the next scan — the reopened-vulnerability check
would miss it and the condition would be reported as newly discovered every
time. Nothing references that column, so it is safe to rewrite.

Downgrade
─────────
Reverses the renames exactly and restores the ``cve`` typing those rows had.
Identifiers minted after the upgrade have no earlier name to return to and are
left as ``plugin_check``, which the constraint accepts.
"""

from alembic import op
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = "e7f8a9b0c1d2"
down_revision = "d6e7f8a9b0c1"
branch_labels = None
depends_on = None


#: Must agree with ``network_checks.legacy_identifier_map()``. Asserted by
#: ``tests/scans/test_network_check_identifiers.py`` — see the module
#: docstring for why it is a literal here rather than an import.
LEGACY_IDENTIFIERS: dict[str, str] = {
    "MISC-DNS-AXFR": "CCURE-CHK-DNS-ZONE-TRANSFER",
    "MISC-DNS-RECURSION": "CCURE-CHK-DNS-OPEN-RECURSION",
    "MISC-FTP-ANON": "CCURE-CHK-FTP-ANONYMOUS-LOGIN",
    "MISC-HTTP-DEFAULT-CREDS": "CCURE-CHK-HTTP-DEFAULT-CREDENTIALS",
    "MISC-LDAP-ANON-BIND": "CCURE-CHK-LDAP-ANONYMOUS-BIND",
    "MISC-MEMCACHED-NOAUTH": "CCURE-CHK-MEMCACHED-NO-AUTHENTICATION",
    "MISC-MONGO-NOAUTH": "CCURE-CHK-MONGODB-NO-AUTHENTICATION",
    "MISC-MQTT-NOAUTH": "CCURE-CHK-MQTT-NO-AUTHENTICATION",
    "MISC-NUCLEI-SMB-SIGNING": "CCURE-CHK-SMB-SIGNING-NOT-REQUIRED",
    "MISC-REDIS-NOAUTH": "CCURE-CHK-REDIS-NO-AUTHENTICATION",
    "MISC-SMB-SIGNING": "CCURE-CHK-SMB-SIGNING-NOT-REQUIRED",
    "MISC-TELNET-EXPOSURE": "CCURE-CHK-TELNET-EXPOSED",
}

#: ``vulnerability_definitions.id`` as widened by ``e1f2a3b4c5d6``.
DEFINITION_ID_MAX_LENGTH = 120

#: A well-formed CVE identifier, in the spelling Postgres understands.
CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,}$"


def _copy_columns(conn) -> str:
    """
    The column list for copying a catalogue row, read from the database.

    Written out by hand first, which was wrong twice over: it omitted
    ``is_custom``, a NOT NULL column with only a Python-side default, so the
    copy failed outright — and even corrected it would have gone stale the
    first time the table gained a column, silently dropping that column's value
    for every renamed row. Reading ``information_schema`` makes the statement
    describe whatever table it is actually running against, which is what a
    migration replayed years later needs.
    """
    rows = conn.execute(
        text(
            """
            SELECT column_name
              FROM information_schema.columns
             WHERE table_name = 'vulnerability_definitions'
               AND column_name NOT IN ('id', 'cve_id', 'definition_type')
             ORDER BY ordinal_position
            """
        )
    ).scalars()
    return ", ".join(f'"{name}"' for name in rows)


def _rename(conn, old: str, new: str, columns: str) -> None:
    """
    Move every finding on *old* onto *new*, then retire *old*.

    The order matters and is forced by the schema:
    ``asset_vulnerabilities.vuln_id`` is a foreign key declared ``RESTRICT``
    with no ``ON UPDATE CASCADE``, so the destination row has to exist before
    anything can point at it and the source row cannot be removed until
    nothing does.
    """
    exists = conn.execute(
        text("SELECT 1 FROM vulnerability_definitions WHERE id = :old"),
        {"old": old},
    ).first()
    if not exists:
        return

    # 1. Create the destination, carrying the old row's content across. Typing
    #    is corrected on the way: plugin_check with a NULL cve_id.
    conn.execute(
        text(
            f"""
            INSERT INTO vulnerability_definitions
                (id, cve_id, definition_type, {columns})
            SELECT :new, NULL, 'plugin_check', {columns}
              FROM vulnerability_definitions
             WHERE id = :old
            ON CONFLICT (id) DO NOTHING
            """
        ),
        {"old": old, "new": new},
    )

    # 2. Resolve duplicates before repointing, in both directions.
    #
    #    Two legacy identifiers can name one condition — MISC-SMB-SIGNING and
    #    MISC-NUCLEI-SMB-SIGNING both do — so a host may already carry a
    #    finding on the destination by the time the second source is processed.
    #    The surviving row is the one with the earlier ``first_found_at``,
    #    because that is the history a reviewer has already seen; which of the
    #    two happens to be processed first is an artefact of sort order and
    #    must not decide it.
    #
    #    Both collision shapes have to be handled. The primary key is
    #    ``fnd_{asset}_{family}_{identifier}``, so renaming makes two rows
    #    collide on it; ``uq_asset_vuln_scan_asset_cve`` is a *different* key,
    #    and two rows differing only in ``source_family`` collide on that one
    #    while their primary keys stay distinct. The first version of this
    #    migration checked only the second and aborted the upgrade on the
    #    first.
    renamed_pk = (
        "(CASE WHEN a.id LIKE '%' || :old "
        "THEN left(a.id, length(a.id) - length(:old)) || :new "
        "ELSE a.id END)"
    )
    for keep_existing in (True, False):
        # keep_existing: drop the incoming row where the destination's history
        # is at least as long. Otherwise: drop the destination where the
        # incoming row is strictly older. `<=` against `<` means an exact tie
        # is resolved once, by the first pass, and never by both.
        victim, other = ("a", "b") if keep_existing else ("b", "a")
        comparison = (
            "b.first_found_at <= a.first_found_at"
            if keep_existing
            else "a.first_found_at < b.first_found_at"
        )
        for collision in (
            f"{renamed_pk} = b.id AND a.org_id = b.org_id",
            "a.org_id = b.org_id "
            "AND a.scan_id IS NOT DISTINCT FROM b.scan_id "
            "AND a.asset_id = b.asset_id",
        ):
            conn.execute(
                text(
                    f"""
                    DELETE FROM asset_vulnerabilities {victim}
                    USING asset_vulnerabilities {other}
                    WHERE a.vuln_id = :old
                      AND b.vuln_id = :new
                      AND {collision}
                      AND {comparison}
                    """
                ),
                {"old": old, "new": new},
            )

    # 3. Repoint the survivors, rewriting the primary key so the next scan's
    #    _resolve_finding_id() finds them. Without this the reopened check
    #    misses and every renamed condition is reported as newly discovered.
    conn.execute(
        text(
            """
            UPDATE asset_vulnerabilities
               SET vuln_id = :new,
                   id = CASE
                            WHEN id LIKE '%' || :old
                            THEN left(id, length(id) - length(:old)) || :new
                            ELSE id
                        END
             WHERE vuln_id = :old
            """
        ),
        {"old": old, "new": new},
    )

    # 4. Retire the source. RESTRICT guarantees this cannot succeed while a
    #    finding still points at it, which is the check that step 3 worked.
    conn.execute(
        text("DELETE FROM vulnerability_definitions WHERE id = :old"),
        {"old": old},
    )


def upgrade() -> None:
    conn = op.get_bind()
    if conn.dialect.name != "postgresql":
        # The statements above use Postgres DELETE ... USING and are written
        # for the only engine this product's catalogue runs on. A SQLite test
        # database bootstraps from the models and has no legacy rows to fix.
        return

    columns = _copy_columns(conn)

    # ── 1. The twelve declared plugin identifiers ────────────────────────────
    #
    # Sorted so the outcome does not depend on dict ordering: two identifiers
    # sharing a destination must resolve the same way on every database.
    for old, new in sorted(LEGACY_IDENTIFIERS.items()):
        _rename(conn, old, new, columns)

    # ── 2. The Nuclei template family, by pattern ────────────────────────────
    #
    # One row per template with no CVE tag, so it cannot be enumerated in a
    # literal. Over-length results are excluded rather than truncated: a
    # truncated key merges two unrelated templates onto one catalogue row,
    # which is the collision `definition_id_for_check` refuses for the same
    # reason. Those rows still get their typing corrected by step 3, so the
    # fabricated-CVE defect is repaired for every row either way.
    nuclei = conn.execute(
        text(
            """
            SELECT id
              FROM vulnerability_definitions
             WHERE id LIKE 'MISC-NUCLEI-%'
               AND length('CCURE-CHK-NUCLEI-' || substring(id from 13))
                   <= :limit
            """
        ),
        {"limit": DEFINITION_ID_MAX_LENGTH},
    ).scalars()
    for old in list(nuclei):
        _rename(conn, old, "CCURE-CHK-NUCLEI-" + old[len("MISC-NUCLEI-") :], columns)

    # ── 3. Everything still filed as a CVE without being one ─────────────────
    #
    # Renaming these is out of scope — they belong to the credentialed path and
    # to any producer added since. Correcting the typing is not: a row typed
    # `cve` is a row the feeds will join to.
    conn.execute(
        text(
            """
            UPDATE vulnerability_definitions
               SET definition_type = 'plugin_check',
                   cve_id = NULL
             WHERE definition_type = 'cve'
               AND (cve_id IS NULL OR cve_id !~ :pattern)
            """
        ),
        {"pattern": CVE_PATTERN},
    )


def downgrade() -> None:
    conn = op.get_bind()
    if conn.dialect.name != "postgresql":
        return

    # Reverse only what this migration renamed. A destination shared by two
    # sources cannot be split back into two — the information identifying which
    # finding came from which identifier was consumed by the merge — so the
    # first source in sorted order takes it back. Recorded here rather than
    # left as a surprise: this downgrade is faithful, not lossless.
    columns = _copy_columns(conn)

    restored: set[str] = set()
    for old, new in sorted(LEGACY_IDENTIFIERS.items()):
        if new in restored:
            continue
        restored.add(new)
        _rename_back(conn, new, old, columns)

    nuclei = conn.execute(
        text(
            """
            SELECT id FROM vulnerability_definitions
             WHERE id LIKE 'CCURE-CHK-NUCLEI-%'
            """
        )
    ).scalars()
    for new in list(nuclei):
        _rename_back(
            conn, new, "MISC-NUCLEI-" + new[len("CCURE-CHK-NUCLEI-") :], columns
        )


def _rename_back(conn, new: str, old: str, columns: str) -> None:
    """
    Rename *new* to *old* and restore the ``cve`` typing it previously had.

    Skips anything whose old identifier will not fit ``cve_id``, which is
    ``varchar(30)``. That is not a defensive nicety: it is the reason the
    pre-phase code could never store a fabricated identifier longer than
    thirty characters, and a downgrade that tried would abort on exactly the
    rows the upgrade was most needed for.
    """
    if len(old) > 30:
        return

    exists = conn.execute(
        text("SELECT 1 FROM vulnerability_definitions WHERE id = :new"),
        {"new": new},
    ).first()
    if not exists:
        return

    conn.execute(
        text(
            f"""
            INSERT INTO vulnerability_definitions
                (id, cve_id, definition_type, {columns})
            SELECT :old, :old, 'cve', {columns}
              FROM vulnerability_definitions
             WHERE id = :new
            ON CONFLICT (id) DO NOTHING
            """
        ),
        {"old": old, "new": new},
    )
    conn.execute(
        text(
            """
            UPDATE asset_vulnerabilities
               SET vuln_id = :old,
                   id = CASE
                            WHEN id LIKE '%' || :new
                            THEN left(id, length(id) - length(:new)) || :old
                            ELSE id
                        END
             WHERE vuln_id = :new
            """
        ),
        {"old": old, "new": new},
    )
    conn.execute(
        text("DELETE FROM vulnerability_definitions WHERE id = :new"),
        {"new": new},
    )
