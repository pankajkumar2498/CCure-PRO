"""
db/models/credentials.py — the credential vault's model: ``compliance_credentials``.

The platform's credential store, for every authenticated collector: SSH,
Windows (WinRM and SMB), databases. Its table keeps the name it was created
with — renaming it would mean an ALTER on live encrypted credentials for a
cosmetic gain (CLAUDE.md, "Data model notes").

Moved here from ``db/models/compliance.py`` by G2 (C5,
docs/architecture/MODULAR_REFACTORING_LOG.md §6), verbatim: the class, its
constraints and the vocabularies they are rendered from. The table, its rows
and its CHECK constraints are unchanged, and no migration was needed. That
module still re-exports every name defined here, so existing imports resolve
to the same objects. The service over this table is ``core/credential_vault.py``;
code outside the credential vault asks it rather than querying the model.
"""

from db.base import TIMESTAMPTZ, Base, utcnow
from sqlalchemy import (
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from db.constraint_sql import sql_in_list as _sql_in_list


#: What a stored credential is *for*. The discriminator that turns this from an
#: SSH credential store into the platform's credential store.
#:
#: ``database``, ``network_device`` and ``snmp`` are reserved: nothing collects
#: with them yet, and the API refuses to create one, but naming them here means
#: Phases 10 and 11 add a collector rather than a CHECK-constraint migration on
#: a table that by then holds customer credentials. Same reasoning as
#: ``scan_kind`` in ``scan_schedules``.
CREDENTIAL_TYPE_SSH = "ssh"
CREDENTIAL_TYPE_WINDOWS = "windows"
CREDENTIAL_TYPE_DATABASE = "database"
CREDENTIAL_TYPE_NETWORK_DEVICE = "network_device"
CREDENTIAL_TYPE_SNMP = "snmp"

CREDENTIAL_TYPES = (
    CREDENTIAL_TYPE_SSH,
    CREDENTIAL_TYPE_WINDOWS,
    CREDENTIAL_TYPE_DATABASE,
    CREDENTIAL_TYPE_NETWORK_DEVICE,
    CREDENTIAL_TYPE_SNMP,
)

#: The types something can actually authenticate with today. ``database`` was
#: added in Phase 7 (GAP-10) once a collector, a transport and validated
#: content existed for it — the reservation above is what made that a one-line
#: change rather than a CHECK migration on a table holding customer records.
USABLE_CREDENTIAL_TYPES = (
    CREDENTIAL_TYPE_SSH,
    CREDENTIAL_TYPE_WINDOWS,
    CREDENTIAL_TYPE_DATABASE,
)

#: How the credential reaches the target. Kept separate from the type because
#: they are not the same question — a Windows host can be reached over WinRM or
#: over SSH (the OpenSSH-on-Windows arrangement this product used to require),
#: and both are ``windows`` credentials.
TRANSPORT_SSH = "ssh"
TRANSPORT_WINRM = "winrm"
#: Windows over SMB, Remote Registry and WMI/DCOM. A second Windows transport
#: rather than a replacement: WinRM is off by default on Windows *client*
#: editions, so an estate of workstations is reachable through this one and not
#: through that one. Both drive the same ``WindowsCollector``.
TRANSPORT_SMB = "smb"

#: Database transports, added in Phase 7. There is one per engine rather than a
#: single ``database`` value because for a database the transport *is* the wire
#: protocol, and a credential is only usable against the engine it was written
#: for. Putting the engine in ``options`` instead would express the same thing
#: while giving up the CHECK constraint that keeps it a closed vocabulary.
#:
#: ``oracle`` and ``mongodb`` are reserved exactly as ``database`` itself was:
#: named here so the phase that implements them adds a collector rather than a
#: migration on live encrypted credentials. Nothing can create one — the API
#: validates against ``USABLE_TRANSPORTS`` below.
TRANSPORT_POSTGRESQL = "postgresql"
TRANSPORT_MYSQL = "mysql"
TRANSPORT_MSSQL = "mssql"
TRANSPORT_ORACLE = "oracle"
TRANSPORT_MONGODB = "mongodb"

TRANSPORTS = (
    TRANSPORT_SSH,
    TRANSPORT_WINRM,
    TRANSPORT_SMB,
    TRANSPORT_POSTGRESQL,
    TRANSPORT_MYSQL,
    TRANSPORT_MSSQL,
    TRANSPORT_ORACLE,
    TRANSPORT_MONGODB,
)

#: The database transports this build can actually open a session with. Kept
#: separate from ``TRANSPORTS`` for the same reason ``USABLE_CREDENTIAL_TYPES``
#: is kept separate from ``CREDENTIAL_TYPES``: the column admits the reserved
#: values so a later phase needs no migration, and the API refuses them so a
#: user cannot save a credential nothing would ever use.
DATABASE_TRANSPORTS = (TRANSPORT_POSTGRESQL, TRANSPORT_MYSQL, TRANSPORT_MSSQL)

USABLE_TRANSPORTS = (
    TRANSPORT_SSH,
    TRANSPORT_WINRM,
    TRANSPORT_SMB,
    *DATABASE_TRANSPORTS,
)

#: ``password`` and ``key`` are the original two and their meaning is unchanged.
#: ``ntlm`` and ``kerberos`` are Windows domain authentication; both present a
#: password, so both live in ``encrypted_password``.
#: Pass-the-Hash. Named so the resolver can branch on it without repeating the
#: literal, which is how ``ntlm`` and ``kerberos`` came to be compared against
#: ``== "password"`` and resolve to no material at all.
AUTH_METHOD_NTLM_HASH = "ntlm_hash"

#: ``ntlm_hash`` is Pass-the-Hash: the NT hash is presented where a password
#: would be, so a domain estate never has to store a reversible plaintext
#: password in this table to be scanned. ``kerberos`` remains in the column's
#: vocabulary and is deliberately **not** usable — see ``USABLE_AUTH_METHODS``.
AUTH_METHODS = ("password", "key", "ntlm", "ntlm_hash", "kerberos")

#: The methods something can actually authenticate with today.
#:
#: Kept separate from ``AUTH_METHODS`` for exactly the reason
#: ``USABLE_TRANSPORTS`` is kept separate from ``TRANSPORTS``: the column admits
#: the reserved value so the phase that implements it adds a mechanism rather
#: than a migration on live encrypted credentials, and the API refuses it so
#: nobody can save a credential that cannot work.
#:
#: ``kerberos`` is the reserved one. It was accepted by the API and by
#: ``WinRMExecutor`` while the runtime had no Kerberos at all — pywinrm raises
#: ``requested auth method is kerberos, but pykerberos is not installed`` at the
#: first command, so the credential failed on the customer's network rather than
#: at the moment somebody saved it. Implementing it needs a GSSAPI stack, a
#: ticket cache and a domain controller to validate against; none of those could
#: be stood up here, so it is refused rather than half-supported.
USABLE_AUTH_METHODS = ("password", "key", "ntlm", "ntlm_hash")

#: Which secret column each method requires. This is a data-integrity rule — a
#: credential that names a method whose material is absent can never
#: authenticate, and would fail at scan time on a customer's network rather
#: than at the moment somebody saved it.
#:
#: ``ntlm_hash`` stores the hash in ``encrypted_password``: it is the material
#: presented in the password's place, encrypted at rest exactly as a password
#: is, and giving it a column of its own would add a migration for no gain.
AUTH_REQUIRES_PASSWORD = ("password", "ntlm", "ntlm_hash", "kerberos")
AUTH_REQUIRES_KEY = ("key",)


#: Rendered exactly as migration a3b4c5d6e7f8 renders them, so a bootstrapped
#: database and an upgraded one produce byte-identical CHECK constraints.
CREDENTIAL_TYPE_SQL = "credential_type IN %s" % _sql_in_list(CREDENTIAL_TYPES)
TRANSPORT_SQL = "transport IN %s" % _sql_in_list(TRANSPORTS)
AUTH_METHOD_SQL = "auth_method IN %s" % _sql_in_list(AUTH_METHODS)
AUTH_MATERIAL_SQL = (
    "(auth_method IN %s AND encrypted_password IS NOT NULL) OR "
    "(auth_method IN %s AND encrypted_key_content IS NOT NULL)"
) % (_sql_in_list(AUTH_REQUIRES_PASSWORD), _sql_in_list(AUTH_REQUIRES_KEY))


class ComplianceCredential(Base):
    """
    The platform's credential store — for every authenticated collector, not
    only compliance.

    **The name is a misnomer and is kept deliberately.** This table was written
    for compliance remediation and has been the store for credentialed *scans*
    since before Phase 1; ``scan_schedules.credential_id`` and
    ``routers/credentialed.py`` both point at it. Renaming it would mean an
    ALTER on a table holding live encrypted credentials for a purely cosmetic
    gain, so the misnomer is recorded here instead — the same treatment
    ``Backend/reports/`` versus ``Backend/reporting/`` gets in CLAUDE.md.

    Generalised in Phase 2 (GAP-00-C) from SSH-only to a discriminated store:

    * ``credential_type`` — what it is for (``ssh``, ``windows``, and three
      reserved for later phases).
    * ``transport`` — how it reaches the target (``ssh``, ``winrm``). Separate
      from the type on purpose: a Windows host reached over OpenSSH is a
      ``windows`` credential with an ``ssh`` transport.
    * ``domain`` — the Windows domain or Kerberos realm. Stored in its own
      column rather than folded into ``username`` as ``DOMAIN\\user``, because
      the two forms (``DOMAIN\\user`` and ``user@realm``) are not
      interchangeable across authentication methods and guessing which one a
      caller meant from a backslash is how a credential silently fails to
      authenticate.
    * ``options`` — transport specifics as JSONB, so a later credential type
      needs no migration.

    Existing rows are unaffected: the backfill makes them ``ssh``/``ssh``,
    which is what they already were.

    **Secrets live only here.** Scans and schedules store ``credential_id``.
    """

    __tablename__ = "compliance_credentials"
    __table_args__ = (
        UniqueConstraint(
            "name", "tenant_id", name="uq_compliance_credentials_name_tenant"
        ),
        CheckConstraint(AUTH_MATERIAL_SQL, name="ck_compliance_credential_auth"),
        CheckConstraint(AUTH_METHOD_SQL, name="ck_compliance_credential_auth_method"),
        CheckConstraint(CREDENTIAL_TYPE_SQL, name="ck_compliance_credential_type"),
        CheckConstraint(TRANSPORT_SQL, name="ck_compliance_credential_transport"),
        Index("ix_compliance_credentials_type", "credential_type"),
        # Deliberately *no* CHECK pairing credential_type with auth_method.
        # The compatibility matrix grows every time a credential type is added
        # (Phases 10, 11), and a CHECK migration on a table holding customer
        # credentials for each one is the cost this avoids. The pairing is
        # enforced in the API and asserted by a test instead — same trade as
        # scan_kind in scan_schedules.
    )

    id = Column(String(100), primary_key=True)
    tenant_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(255), nullable=False)
    username = Column(String(150), nullable=False)
    encrypted_password = Column(Text, nullable=True)
    encrypted_key_content = Column(Text, nullable=True)
    #: Passphrase for an encrypted private key. Its own column rather than a
    #: second meaning for ``encrypted_password``: the two unlock different
    #: things, an operator can hold one without the other, and overloading the
    #: password column would make ``AUTH_REQUIRES_PASSWORD`` — which is a
    #: data-integrity rule — mean two incompatible things at once.
    #:
    #: A key with no passphrase leaves this NULL, which is how every existing
    #: row reads, so unencrypted keys keep working untouched.
    encrypted_key_passphrase = Column(Text, nullable=True)
    port = Column(Integer, nullable=False, default=22)
    auth_method = Column(String(50), nullable=False, default="password")

    # ── Generalisation (Phase 2, GAP-00-C) ───────────────────────────────────
    #: No ``index=True``: the index is declared once, by name, in
    #: ``__table_args__``, matching migration a3b4c5d6e7f8. With both,
    #: ``create_all`` names it ``ix_compliance_credentials_credential_type``
    #: while the migration names it ``ix_compliance_credentials_type`` — so a
    #: fresh install has one index and an upgraded install the other, and
    #: ``downgrade`` fails on a fresh database with "index does not exist".
    #: Caught by the migration round-trip; the same trap as ``definition_type``
    #: in findings.py and ``org_id`` in scan_schedules.py.
    credential_type = Column(
        String(32),
        nullable=False,
        default=CREDENTIAL_TYPE_SSH,
        server_default=CREDENTIAL_TYPE_SSH,
    )
    transport = Column(
        String(32),
        nullable=False,
        default=TRANSPORT_SSH,
        server_default=TRANSPORT_SSH,
    )
    #: Windows domain (``CORP``) or Kerberos realm (``CORP.EXAMPLE.COM``).
    #: NULL for a local account, which is a different fact from an empty
    #: string: ``.\\Administrator`` and ``CORP\\Administrator`` are different
    #: principals and only one of them exists on a workgroup machine.
    domain = Column(String(255), nullable=True)
    #: Transport specifics — ``use_tls``, ``verify_cert``, ``winrm_path``,
    #: ``read_timeout``. JSONB so a credential type added in a later phase
    #: needs no migration to carry its own settings.
    #:
    #: **Never put a secret here.** Secrets go in the two encrypted columns;
    #: this is returned to the UI and written to logs.
    options = Column(JSONB, nullable=False, default=dict, server_default="{}")

    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    def principal(self) -> str:
        """
        The account name in the form its authentication method expects.

        Kerberos wants ``user@REALM``; NTLM and Windows password auth want
        ``DOMAIN\\user``; SSH wants the bare name. Deriving this in one place
        is the point — a caller that guessed from the presence of a backslash
        would build ``CORP\\user@CORP.EXAMPLE.COM`` for a Kerberos credential
        whose username already carried the domain.
        """
        user = (self.username or "").strip()
        realm = (self.domain or "").strip()
        if not realm or "\\" in user or "@" in user:
            return user
        if self.auth_method == "kerberos":
            return f"{user}@{realm.upper()}"
        if self.credential_type == CREDENTIAL_TYPE_WINDOWS:
            return f"{realm}\\{user}"
        return user
