"""compliance_credentials: admit the database wire-protocol transports

Revision ID: f8a9b0c1d2e3
Revises: e7f8a9b0c1d2
Create Date: 2026-08-29

Phase 7 — GAP-10, authenticated database assessment.

What this changes
─────────────────
Five values added to ``ck_compliance_credential_transport``: ``postgresql``,
``mysql``, ``mssql``, ``oracle`` and ``mongodb``. ``ssh`` and ``winrm`` are kept
verbatim, so no existing credential stops satisfying the constraint and no row
is rewritten.

Nothing else in the schema changes. ``credential_type`` already admitted
``database`` — Phase 2 reserved it there precisely so that this phase would not
need an ALTER on a table holding live encrypted credentials — and
``compliance_rules`` already admitted the ``database_query`` check type and the
``database`` target platform, reserved by Phase 3's ``b4c5d6e7f8a9``. So the
whole of GAP-10's persistence cost is this one constraint.

Why one transport per engine rather than a single ``database``
──────────────────────────────────────────────────────────────
``transport`` answers "how does this credential reach the target". For a host
that is a shell protocol and one value covers many operating systems; for a
database the transport *is* the wire protocol, and a credential written for
PostgreSQL cannot authenticate to MySQL. Naming them individually keeps the
engine inside the closed vocabulary a CHECK constraint enforces, rather than in
free-form ``options`` where nothing would validate it.

Why ``oracle`` and ``mongodb`` are here with no implementation
──────────────────────────────────────────────────────────────
The same reservation this migration is the beneficiary of. Both have a usable
Python driver; neither could be stood up as a disposable target in this
environment, so neither was validated and neither ships. Naming them now means
the phase that adds them adds a collector. ``USABLE_TRANSPORTS`` in
``db/models/compliance.py`` is what stops the API creating one in the meantime,
so the column being permissive costs nothing.

Downgrade
─────────
Refuses if any credential uses one of the new transports, naming the rows.
Re-adding the narrower constraint over such a row fails at the ALTER with a
PostgreSQL error that names the constraint and not the offending record, which
leaves an operator with nothing to act on.
"""

from alembic import op
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = "f8a9b0c1d2e3"
down_revision = "e7f8a9b0c1d2"
branch_labels = None
depends_on = None


#: Must render byte-identically to ``db.models.compliance.TRANSPORTS``.
TRANSPORTS = (
    "ssh",
    "winrm",
    "postgresql",
    "mysql",
    "mssql",
    "oracle",
    "mongodb",
)

OLD_TRANSPORTS = ("ssh", "winrm")

NEW_TRANSPORTS = tuple(t for t in TRANSPORTS if t not in OLD_TRANSPORTS)


def _sql_in_list(values) -> str:
    """See db/models/compliance.py — str(("k",)) yields an invalid SQL list."""
    return "(" + ", ".join("'%s'" % v for v in values) + ")"


def _replace_check(values) -> None:
    op.drop_constraint(
        "ck_compliance_credential_transport", "compliance_credentials", type_="check"
    )
    op.create_check_constraint(
        "ck_compliance_credential_transport",
        "compliance_credentials",
        "transport IN %s" % _sql_in_list(values),
    )


def upgrade() -> None:
    _replace_check(TRANSPORTS)


def downgrade() -> None:
    rows = (
        op.get_bind()
        .execute(
            text(
                "SELECT id, name, transport FROM compliance_credentials "
                "WHERE transport IN %s LIMIT 10" % _sql_in_list(NEW_TRANSPORTS)
            )
        )
        .fetchall()
    )
    if rows:
        raise RuntimeError(
            "Cannot narrow transport: %d compliance_credentials row(s) use a "
            "database transport (%s). Remove or reassign them before "
            "downgrading — re-adding the constraint would otherwise fail "
            "without naming which credentials are responsible."
            % (
                len(rows),
                ", ".join("%s/%s=%s" % (r[0], r[1], r[2]) for r in rows),
            )
        )
    _replace_check(OLD_TRANSPORTS)
