"""compliance_controls: widen control_number for benchmark rule names

Revision ID: f4a5b6c7d8e9
Revises: e3f4a5b6c7d8
Create Date: 2026-09-01

Loading published SCAP content — GAP-05's reader, applied to real SSG STIG
benchmarks for the first time.

What this changes
─────────────────
``compliance_controls.control_number`` goes from ``varchar(50)`` to
``varchar(100)``. Nothing else.

Why 50 was never going to be enough
───────────────────────────────────
The column was sized for a control *number* and its comment says so — ``8.24``,
``A.5.1``, ``PR.AA-05``. Every catalogue that ships in this repository is
numbered that way, so the ceiling was invisible for thirteen frameworks.

A benchmark recommendation is not numbered, it is *named*. SSG identifies a
rule as ``harden_sshd_ciphers_opensshserver_conf_crypto_policy`` — 52
characters, and the XCCDF 1.2 scaffolding is already stripped by
``core/scap``. Measured across the four SSG 0.1.81 STIG profiles that convert
(RHEL 8, RHEL 9, Ubuntu 22.04, Ubuntu 24.04): 1,350 controls, of which **24
exceed 50 characters**, the longest being 62.

The failure mode is what makes this worth a migration rather than a note. The
load is one transaction, so the first over-long control aborts the whole
benchmark with ``StringDataRightTruncation`` — 488 controls rejected because of
seven of them. Same shape as the ``cve_id varchar(30)`` ceiling that used to
abort a whole scan's finding sync.

Why not truncate to fit
───────────────────────
``uq_framework_control_number`` is UNIQUE on ``(framework_id,
control_number)``. Two sibling recommendations sharing a 50-character prefix
would truncate to the same value, and the second would either collide or
silently overwrite the first — one row standing for two different
requirements, in a compliance report. That is the rule
``definition_id_for_check`` already applies to catalogue identifiers: refuse an
over-long id rather than truncate it, because a truncated key merges controls.

Why 100
───────
It is the width of ``compliance_controls.id``, the sibling column this value is
slugged into (``cct_<code>_<slug>``), so the two no longer disagree about how
long an identifier may be. Measured headroom: 38 characters over the longest
identifier in the content this was written for.

Increasing a ``varchar`` length is a catalogue-only change in PostgreSQL 9.2
and later — no table rewrite, no row touched, so this is safe against a live
compliance catalogue.

Downgrade
─────────
Refuses if any row would not fit in 50, naming the offenders. Narrowing over
such a row fails at the ALTER with a PostgreSQL error that names the column and
not the records responsible.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = "f4a5b6c7d8e9"
down_revision = "e3f4a5b6c7d8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "compliance_controls",
        "control_number",
        existing_type=sa.String(length=50),
        type_=sa.String(length=100),
        existing_nullable=False,
    )


def downgrade() -> None:
    rows = (
        op.get_bind()
        .execute(
            text(
                "SELECT framework_id, control_number FROM compliance_controls "
                "WHERE length(control_number) > 50 LIMIT 10"
            )
        )
        .fetchall()
    )
    if rows:
        raise RuntimeError(
            "Cannot narrow control_number to 50: %d compliance_controls row(s) "
            "are longer (%s). Remove the benchmark content that carries them "
            "before downgrading — narrowing over such a row would otherwise "
            "fail without naming which controls are responsible."
            % (
                len(rows),
                ", ".join("%s:%s" % (r[0], r[1]) for r in rows),
            )
        )
    op.alter_column(
        "compliance_controls",
        "control_number",
        existing_type=sa.String(length=100),
        type_=sa.String(length=50),
        existing_nullable=False,
    )
