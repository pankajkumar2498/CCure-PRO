"""credential store: generalize from SSH-only to typed credentials

Revision ID: a3b4c5d6e7f8
Revises: f2a3b4c5d6e7
Create Date: 2026-08-27

Phase 2, GAP-00-C. The hard dependency for native Windows collection, and for
database and network-device authentication in Phases 10 and 11.

What this changes
─────────────────
``compliance_credentials`` gains four columns and has two CHECK constraints
replaced:

  1. ``credential_type``  new, NOT NULL, server default ``'ssh'``, indexed
  2. ``transport``        new, NOT NULL, server default ``'ssh'``
  3. ``domain``           new, nullable
  4. ``options``          new, NOT NULL JSONB, server default ``'{}'``
  5. ``ck_compliance_credential_auth_method`` widened to admit ``ntlm`` and
     ``kerberos``
  6. ``ck_compliance_credential_auth`` rewritten so the widened methods still
     require their material

Existing rows are untouched in meaning. Every row in this table today is an SSH
credential, so the ``'ssh'`` backfill is what they already were — asserted
below rather than assumed.

Why the table is not renamed
────────────────────────────
It is a misnomer: this has been the store for credentialed *scans* since before
Phase 1, and ``scan_schedules.credential_id`` points at it. Renaming would mean
an ALTER on a table holding live encrypted credentials for a cosmetic gain, so
the misnomer is documented on the model instead.

Why there is no credential_type/auth_method CHECK
─────────────────────────────────────────────────
The compatibility matrix ("ssh may use password or key; windows may use
password, ntlm or kerberos") grows with every credential type Phases 10 and 11
add, and each growth would be another CHECK migration on a table holding
customer credentials. The pairing is enforced in the API and asserted by a
test. Same trade as ``scan_kind`` in ``scan_schedules``.

Downgrade
─────────
Refuses if any non-SSH credential exists. Narrowing the CHECK back would
otherwise fail on a Windows credential's ``ntlm`` method, and dropping the
columns would silently reduce a Windows credential to an SSH one pointed at
port 5985 — which would then try to authenticate, and fail, against a service
that is not SSH.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "a3b4c5d6e7f8"
down_revision = "f2a3b4c5d6e7"
branch_labels = None
depends_on = None


CREDENTIAL_TYPES = ("ssh", "windows", "database", "network_device", "snmp")
TRANSPORTS = ("ssh", "winrm")
AUTH_METHODS = ("password", "key", "ntlm", "kerberos")
AUTH_REQUIRES_PASSWORD = ("password", "ntlm", "kerberos")
AUTH_REQUIRES_KEY = ("key",)


#: Must render byte-identically to the constants in
#: ``db/models/compliance.py``, or a fresh install (build from
#: ``Base.metadata``, stamp head) and an upgraded install end up with textually
#: different constraints and autogenerate reports a spurious diff forever.
def _sql_in_list(values) -> str:
    """See db/models/compliance.py — str(("key",)) yields an invalid SQL list."""
    return "(" + ", ".join("'%s'" % v for v in values) + ")"


CREDENTIAL_TYPE_SQL = "credential_type IN %s" % _sql_in_list(CREDENTIAL_TYPES)
TRANSPORT_SQL = "transport IN %s" % _sql_in_list(TRANSPORTS)
AUTH_METHOD_SQL = "auth_method IN %s" % _sql_in_list(AUTH_METHODS)
AUTH_MATERIAL_SQL = (
    "(auth_method IN %s AND encrypted_password IS NOT NULL) OR "
    "(auth_method IN %s AND encrypted_key_content IS NOT NULL)"
) % (_sql_in_list(AUTH_REQUIRES_PASSWORD), _sql_in_list(AUTH_REQUIRES_KEY))


def upgrade() -> None:
    bind = op.get_bind()

    if bind.dialect.name == "postgresql":
        # The backfill below declares every existing row an SSH credential.
        # That is true of this table today, but it is a claim about customer
        # data, so it is checked rather than assumed: a row using an auth
        # method SSH cannot perform would be silently mislabelled.
        strays = bind.execute(
            sa.text(
                "SELECT count(*) FROM compliance_credentials "
                "WHERE auth_method NOT IN ('password', 'key')"
            )
        ).scalar()
        if strays:
            raise RuntimeError(
                f"{strays} credential(s) use an auth_method outside "
                "('password','key'), so the backfill to credential_type='ssh' "
                "would mislabel them. Set credential_type explicitly for those "
                "rows before applying a3b4c5d6e7f8."
            )

    op.add_column(
        "compliance_credentials",
        sa.Column(
            "credential_type",
            sa.String(length=32),
            nullable=False,
            server_default="ssh",
        ),
    )
    op.add_column(
        "compliance_credentials",
        sa.Column(
            "transport", sa.String(length=32), nullable=False, server_default="ssh"
        ),
    )
    op.add_column(
        "compliance_credentials",
        sa.Column("domain", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "compliance_credentials",
        sa.Column(
            "options",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
    )
    op.create_index(
        "ix_compliance_credentials_type", "compliance_credentials", ["credential_type"]
    )

    # ── Replace the two auth constraints ─────────────────────────────────────
    #
    # Dropped before the columns are constrained, and recreated after, so the
    # widened method set and its material requirement land together. Doing it
    # the other way round leaves a window in which an 'ntlm' row is legal but
    # unconstrained.
    op.drop_constraint(
        "ck_compliance_credential_auth", "compliance_credentials", type_="check"
    )
    op.drop_constraint(
        "ck_compliance_credential_auth_method", "compliance_credentials", type_="check"
    )
    op.create_check_constraint(
        "ck_compliance_credential_auth_method",
        "compliance_credentials",
        AUTH_METHOD_SQL,
    )
    op.create_check_constraint(
        "ck_compliance_credential_auth", "compliance_credentials", AUTH_MATERIAL_SQL
    )
    op.create_check_constraint(
        "ck_compliance_credential_type", "compliance_credentials", CREDENTIAL_TYPE_SQL
    )
    op.create_check_constraint(
        "ck_compliance_credential_transport", "compliance_credentials", TRANSPORT_SQL
    )


def downgrade() -> None:
    bind = op.get_bind()

    if bind.dialect.name == "postgresql":
        non_ssh = bind.execute(
            sa.text(
                "SELECT count(*) FROM compliance_credentials "
                "WHERE credential_type <> 'ssh' OR transport <> 'ssh'"
            )
        ).scalar()
        if non_ssh:
            raise RuntimeError(
                f"Cannot downgrade a3b4c5d6e7f8: {non_ssh} credential(s) are "
                "not SSH. Dropping these columns would reduce a Windows "
                "credential to an SSH one pointed at port 5985, which would "
                "then attempt SSH against a WinRM listener. Delete or convert "
                "those credentials first if this downgrade is really intended."
            )

    op.drop_constraint(
        "ck_compliance_credential_transport", "compliance_credentials", type_="check"
    )
    op.drop_constraint(
        "ck_compliance_credential_type", "compliance_credentials", type_="check"
    )
    op.drop_constraint(
        "ck_compliance_credential_auth", "compliance_credentials", type_="check"
    )
    op.drop_constraint(
        "ck_compliance_credential_auth_method", "compliance_credentials", type_="check"
    )
    op.create_check_constraint(
        "ck_compliance_credential_auth_method",
        "compliance_credentials",
        "auth_method IN ('password', 'key')",
    )
    op.create_check_constraint(
        "ck_compliance_credential_auth",
        "compliance_credentials",
        "(auth_method = 'password' AND encrypted_password IS NOT NULL) OR "
        "(auth_method = 'key' AND encrypted_key_content IS NOT NULL)",
    )

    op.drop_index("ix_compliance_credentials_type", table_name="compliance_credentials")
    op.drop_column("compliance_credentials", "options")
    op.drop_column("compliance_credentials", "domain")
    op.drop_column("compliance_credentials", "transport")
    op.drop_column("compliance_credentials", "credential_type")
