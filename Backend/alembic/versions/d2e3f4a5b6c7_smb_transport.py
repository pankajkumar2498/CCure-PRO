"""compliance_credentials: admit the SMB Windows transport

Revision ID: d2e3f4a5b6c7
Revises: c1d2e3f4a5b6
Create Date: 2026-09-01

Phase 12 — GAP-02 extension, Windows authenticated scanning over SMB, Remote
Registry and WMI/DCOM.

What this changes
─────────────────
One value added to ``ck_compliance_credential_transport``: ``smb``. Every
existing value is kept verbatim, so no stored credential stops satisfying the
constraint and no row is rewritten. That is the whole persistence cost of the
phase — ``credential_type`` has admitted ``windows`` since Phase 2, and nothing
about the finding model, the rule catalogue or the asset schema changes, because
SMB is a transport under the existing ``WindowsCollector`` rather than a second
way of assessing Windows.

Why a transport value rather than a credential type
───────────────────────────────────────────────────
``credential_type`` answers *what kind of thing* the credential is for and
``transport`` answers *how it gets there*. A Windows credential reached over
WinRM and the same credential reached over SMB are one credential — same
account, same password, same domain — differing only in the wire protocol. That
distinction is exactly why the two columns were separated in
``a3b4c5d6e7f8``, and this is the first case that uses the separation for
Windows rather than for databases.

Why it is not the default for Windows
─────────────────────────────────────
WinRM stays the default in ``_TYPE_DEFAULTS``. It executes commands, so it can
drive every check this product has; SMB cannot execute commands at all and
serves the subset that can be read from WMI and the registry. SMB is the
transport that reaches hosts WinRM cannot — it is on by default where WinRM,
on client editions, is not — so it widens reach rather than replacing depth.
Neither is a strict superset of the other and the operator chooses.

Downgrade
─────────
Any credential stored as ``smb`` is moved back to ``winrm`` before the
constraint is narrowed, matching what ``f8a9b0c1d2e3`` does for the database
transports: a downgrade that leaves a row violating the constraint it is about
to create fails halfway and leaves the schema in neither state. The rows are
reported so an operator can see which credentials were rewritten.
"""

from alembic import op
from sqlalchemy import text

revision = "d2e3f4a5b6c7"
down_revision = "c1d2e3f4a5b6"
branch_labels = None
depends_on = None


TRANSPORTS = (
    "ssh",
    "winrm",
    "smb",
    "postgresql",
    "mysql",
    "mssql",
    "oracle",
    "mongodb",
)

OLD_TRANSPORTS = tuple(t for t in TRANSPORTS if t != "smb")


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
    bind = op.get_bind()
    rows = bind.execute(
        text("SELECT id, name FROM compliance_credentials WHERE transport = 'smb'")
    ).fetchall()
    if rows:
        print(
            f"  {len(rows)} credential(s) stored with transport 'smb' are being "
            "moved to 'winrm' so the narrowed constraint can be created:"
        )
        for row in rows:
            print(f"    {row[0]}  {row[1]}")
        bind.execute(
            text(
                "UPDATE compliance_credentials SET transport = 'winrm' "
                "WHERE transport = 'smb'"
            )
        )
    _replace_check(OLD_TRANSPORTS)
