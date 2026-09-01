"""compliance_credentials: NT-hash auth and encrypted-key passphrases

Revision ID: e3f4a5b6c7d8
Revises: d2e3f4a5b6c7
Create Date: 2026-09-01

Phase 13 — authentication-method cleanup.

What this changes
─────────────────
Two things, both additive:

* ``ck_compliance_credential_auth_method`` gains ``ntlm_hash``. Every existing
  value is kept verbatim, so no stored credential stops satisfying the
  constraint and no row is rewritten.
* ``encrypted_key_passphrase`` is added, nullable. Every existing row reads
  NULL, which is exactly "this key has no passphrase" — the behaviour those
  rows already had.

Why ``ntlm_hash`` is an auth method and not a transport or a type
─────────────────────────────────────────────────────────────────
It answers "what material is presented", which is the question ``auth_method``
exists for. The same Windows credential over the same SMB transport is one
credential whether it carries a password or that password's NT hash; only the
material differs. Pass-the-Hash also removes a reason to store a reversible
plaintext domain password in this table at all, which is a security improvement
to the credential store rather than only a reach improvement.

The hash lives in ``encrypted_password`` — the column for "the secret presented
in the password's place", encrypted at rest identically. A column of its own
would be a migration for no gain.

Why ``kerberos`` is not removed from the constraint
───────────────────────────────────────────────────
It stays in the column's vocabulary and is refused by the API through
``USABLE_AUTH_METHODS``, which is the same arrangement ``oracle`` and
``mongodb`` have in ``TRANSPORTS``. Narrowing the constraint would mean an
ALTER on a table of live encrypted credentials to remove a value nothing can
create, and would make the phase that implements Kerberos need a migration
rather than a mechanism. Verified before writing this: zero stored credentials
use it.

Downgrade
─────────
Any credential stored as ``ntlm_hash`` is a *hash*, and there is no password to
turn it back into — rewriting it to ``ntlm`` would leave a credential whose
material cannot authenticate. Such rows are therefore reported and deleted,
which is the only honest option: the operator re-creates them with a password.
The passphrase column is dropped, which is lossless for any key that never had
one and destroys the passphrase for any key that did.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

revision = "e3f4a5b6c7d8"
down_revision = "d2e3f4a5b6c7"
branch_labels = None
depends_on = None


AUTH_METHODS = ("password", "key", "ntlm", "ntlm_hash", "kerberos")
OLD_AUTH_METHODS = tuple(m for m in AUTH_METHODS if m != "ntlm_hash")

#: Which secret column each method requires. ``ck_compliance_credential_auth``
#: renders this, and it is a *second* constraint naming the auth methods — one
#: that a migration touching only the vocabulary would miss, leaving a schema
#: that admits ``ntlm_hash`` in one constraint and rejects every row using it in
#: the other. The model and this file must render identically.
AUTH_REQUIRES_PASSWORD = ("password", "ntlm", "ntlm_hash", "kerberos")
OLD_AUTH_REQUIRES_PASSWORD = tuple(
    m for m in AUTH_REQUIRES_PASSWORD if m != "ntlm_hash"
)
AUTH_REQUIRES_KEY = ("key",)


def _sql_in_list(values) -> str:
    """See db/models/compliance.py — str(("k",)) yields an invalid SQL list."""
    return "(" + ", ".join("'%s'" % v for v in values) + ")"


def _replace_check(values, password_methods) -> None:
    op.drop_constraint(
        "ck_compliance_credential_auth_method", "compliance_credentials", type_="check"
    )
    op.create_check_constraint(
        "ck_compliance_credential_auth_method",
        "compliance_credentials",
        "auth_method IN %s" % _sql_in_list(values),
    )
    # The material-integrity constraint names the same methods and must move
    # with them, or a credential the vocabulary admits is rejected by the row
    # rule the moment anyone saves one.
    op.drop_constraint(
        "ck_compliance_credential_auth", "compliance_credentials", type_="check"
    )
    op.create_check_constraint(
        "ck_compliance_credential_auth",
        "compliance_credentials",
        (
            "(auth_method IN %s AND encrypted_password IS NOT NULL) OR "
            "(auth_method IN %s AND encrypted_key_content IS NOT NULL)"
        )
        % (_sql_in_list(password_methods), _sql_in_list(AUTH_REQUIRES_KEY)),
    )


def upgrade() -> None:
    op.add_column(
        "compliance_credentials",
        sa.Column("encrypted_key_passphrase", sa.Text(), nullable=True),
    )
    _replace_check(AUTH_METHODS, AUTH_REQUIRES_PASSWORD)


def downgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        text(
            "SELECT id, name FROM compliance_credentials WHERE auth_method = 'ntlm_hash'"
        )
    ).fetchall()
    if rows:
        print(
            f"  {len(rows)} credential(s) authenticate by NT hash and cannot be "
            "expressed without it. They are being removed; re-create them with a "
            "password after the downgrade:"
        )
        for row in rows:
            print(f"    {row[0]}  {row[1]}")
        bind.execute(
            text("DELETE FROM compliance_credentials WHERE auth_method = 'ntlm_hash'")
        )
    _replace_check(OLD_AUTH_METHODS, OLD_AUTH_REQUIRES_PASSWORD)
    op.drop_column("compliance_credentials", "encrypted_key_passphrase")
