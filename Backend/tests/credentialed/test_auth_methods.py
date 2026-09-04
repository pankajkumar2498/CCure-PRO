"""
Credential authentication methods: what this build can do, and what it refuses.

Three capabilities added and three deliberately withheld. The thread running
through all six is the rule this credential store already applies to transports
and credential types: **the column admits a reserved value so a later phase adds
a mechanism rather than a migration, and the API refuses it so nobody saves a
credential that cannot authenticate.**

Kerberos is the case that made the rule necessary. It was accepted by the API
and by ``WinRMExecutor`` while the runtime had no Kerberos at all — pywinrm
raises ``requested auth method is kerberos, but pykerberos is not installed`` at
the *first command*, so the credential failed on the customer's network rather
than at the moment somebody saved it.
"""

import pytest
from db.models.compliance import (
    AUTH_METHODS,
    AUTH_REQUIRES_KEY,
    AUTH_REQUIRES_PASSWORD,
    USABLE_AUTH_METHODS,
)
from engines.credentialed.smb_executor import (
    _EMPTY_LM_HASH,
    SMBConfigurationError,
    _normalise_nt_hash,
)
from engines.credentialed.ssh_scanner import (
    ELEVATION_METHODS,
    UNSUPPORTED_ELEVATION,
    _rewrite_sudo_for_stdin,
)

NT_HASH = "8846f7eaee8fb117ad06bdd830b7586c"  # NT hash of "password", a fixture


# ─────────────────────────────────────────────────────────────────────────────
# Kerberos: refused, and refused early
# ─────────────────────────────────────────────────────────────────────────────


def test_kerberos_stays_in_the_column_vocabulary():
    """
    Not removed from the constraint. Narrowing it would mean an ALTER on a table
    of live encrypted credentials to delete a value nothing can create, and
    would make the phase that implements Kerberos need a migration rather than a
    mechanism — the arrangement ``oracle`` and ``mongodb`` already have.
    """
    assert "kerberos" in AUTH_METHODS


def test_kerberos_is_not_usable():
    assert "kerberos" not in USABLE_AUTH_METHODS


def test_the_api_refuses_a_kerberos_credential():
    from pydantic import ValidationError

    from routers.credentials import ScanCredentialCreate

    with pytest.raises(ValidationError):
        ScanCredentialCreate(
            name="k", username="u", password="p", auth_method="kerberos"
        )


def test_windows_credentials_are_not_offered_kerberos():
    from db.models.compliance import CREDENTIAL_TYPE_WINDOWS
    from routers.credentials import TYPE_AUTH_MATRIX

    assert "kerberos" not in TYPE_AUTH_MATRIX[CREDENTIAL_TYPE_WINDOWS]


def test_the_winrm_executor_refuses_kerberos_at_construction():
    """
    Not at the first command. pywinrm's session constructs happily and fails
    later, which puts the error on the customer's network instead of in front of
    whoever configured it.
    """
    from engines.credentialed.winrm_executor import (
        WinRMConfigurationError,
        WinRMExecutor,
    )

    with pytest.raises(WinRMConfigurationError, match="Kerberos"):
        WinRMExecutor(ip="10.0.0.1", username="u", password="p", auth_method="kerberos")


def test_the_refusal_names_a_method_that_does_work():
    from engines.credentialed.winrm_executor import UNAVAILABLE_AUTH

    assert "ntlm" in UNAVAILABLE_AUTH["kerberos"]


def test_credssp_is_not_offered_anywhere():
    """Explicitly out of scope; it must not arrive by accident."""
    assert "credssp" not in AUTH_METHODS
    assert "credssp" not in USABLE_AUTH_METHODS


# ─────────────────────────────────────────────────────────────────────────────
# Pass-the-Hash
# ─────────────────────────────────────────────────────────────────────────────


def test_a_bare_nt_hash_is_accepted():
    assert _normalise_nt_hash(NT_HASH) == NT_HASH


def test_an_lm_colon_nt_pair_keeps_only_the_nt_half():
    """Every dumping tool prints the pair, so an operator pastes the pair."""
    assert _normalise_nt_hash(f"{_EMPTY_LM_HASH}:{NT_HASH}") == NT_HASH


def test_a_hash_is_normalised_to_lower_case():
    assert _normalise_nt_hash(NT_HASH.upper()) == NT_HASH


@pytest.mark.parametrize(
    "bad", ["not-a-hash", "8846f7ea", NT_HASH + "ff", "zzzz" * 8, "  "]
)
def test_an_unparseable_hash_is_refused_rather_than_sent(bad):
    """
    A value that is not a hash would be presented as though it were one and
    produce a failed logon against a real account — a lockout risk created by a
    typo. Refusing is the safe direction.
    """
    if bad.strip() == "":
        assert _normalise_nt_hash(bad) is None
        return
    with pytest.raises(SMBConfigurationError):
        _normalise_nt_hash(bad)


def test_the_refusal_does_not_quote_the_value():
    """The rejected value is still credential material."""
    try:
        _normalise_nt_hash("deadbeef")
    except SMBConfigurationError as exc:
        assert "deadbeef" not in str(exc)


def test_no_hash_is_no_hash():
    assert _normalise_nt_hash(None) is None


def test_the_executor_sends_the_hash_and_never_the_password():
    """
    Passing both would let impacket fall back to the password if the hash were
    rejected — two failed logons instead of one, and no way to tell which
    material the target refused.
    """
    import inspect

    from engines.credentialed import smb_executor

    source = inspect.getsource(smb_executor.SMBExecutor._new_smb)
    assert "nthash=self._nt_hash" in source
    # The password argument on the hash branch is the empty literal.
    assert (
        'smb.login(\n                    self.username,\n                    "",'
        in source
    )


def test_the_lm_half_is_the_documented_placeholder():
    """
    Computing a real LM hash would mean holding the plaintext this method exists
    to avoid, and modern Windows does not accept LM authentication anyway.
    """
    assert _EMPTY_LM_HASH == "aad3b435b51404eeaad3b435b51404ee"


def test_ntlm_hash_reads_its_material_from_the_password_column():
    assert "ntlm_hash" in AUTH_REQUIRES_PASSWORD
    assert "ntlm_hash" not in AUTH_REQUIRES_KEY


def test_a_stored_hash_never_leaves_the_resolver_as_a_password():
    """
    The material dict feeds every transport. A hash arriving as ``password``
    would be presented as plaintext against the account by any of them.
    """
    import inspect

    from core import tasks

    source = inspect.getsource(tasks._resolve_stored_credential)
    assert 'material["nt_hash"] = decrypt_credential' in source
    assert "AUTH_METHOD_NTLM_HASH" in source


# ─────────────────────────────────────────────────────────────────────────────
# Encrypted private keys
# ─────────────────────────────────────────────────────────────────────────────


def _encrypted_key(passphrase: bytes):
    """A real Ed25519 key, encrypted, generated per-test. Never written to disk."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    ).decode()


def _plain_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    return (
        ed25519.Ed25519PrivateKey.generate()
        .private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode()
    )


def test_an_encrypted_key_loads_when_the_passphrase_is_supplied(real_ssh_connect):
    """
    The capability. Without it paramiko raises "not a valid ... private key
    file", which reads as a malformed key rather than a locked one — so an
    estate mandating passphrase-protected keys could not be scanned at all.
    """
    from engines.credentialed.ssh_scanner import SSHScanner

    scanner = SSHScanner(
        ip="10.0.0.5",
        username="svc",
        key_content=_encrypted_key(b"correct horse"),
        key_passphrase="correct horse",
    )
    # connect() fails on the socket, not on the key: reaching a connection error
    # proves the key parsed.
    with pytest.raises(RuntimeError) as excinfo:
        scanner.connect()
    assert "private key" not in str(excinfo.value).lower()


def test_a_wrong_passphrase_fails_on_the_key_not_the_network(real_ssh_connect):
    from engines.credentialed.ssh_scanner import SSHScanner

    scanner = SSHScanner(
        ip="10.0.0.5",
        username="svc",
        key_content=_encrypted_key(b"correct horse"),
        key_passphrase="wrong",
    )
    with pytest.raises(RuntimeError, match="passphrase is wrong|not a recognised"):
        scanner.connect()


def test_an_unencrypted_key_still_works_with_no_passphrase(real_ssh_connect):
    """The existing behaviour, untouched."""
    from engines.credentialed.ssh_scanner import SSHScanner

    scanner = SSHScanner(ip="10.0.0.5", username="svc", key_content=_plain_key())
    with pytest.raises(RuntimeError) as excinfo:
        scanner.connect()
    assert "private key" not in str(excinfo.value).lower()


def test_the_passphrase_never_appears_in_an_exception(real_ssh_connect):
    """
    The failure path quotes paramiko's message, and a passphrase in a raised
    exception reaches the scan record and the log.
    """
    from engines.credentialed.ssh_scanner import SSHScanner

    secret = "S3cret-Passphrase-Value"
    scanner = SSHScanner(
        ip="10.0.0.5",
        username="svc",
        key_content="-- not a key --",
        key_passphrase=secret,
    )
    with pytest.raises(RuntimeError) as excinfo:
        scanner.connect()
    assert secret not in str(excinfo.value)


def test_the_passphrase_is_wiped_on_disconnect():
    from engines.credentialed.ssh_scanner import SSHScanner

    scanner = SSHScanner(
        ip="10.0.0.5", username="svc", key_content=_plain_key(), key_passphrase="x"
    )
    scanner.disconnect()
    assert scanner._key_passphrase is None


def test_the_passphrase_is_redacted_from_anything_logged():
    from engines.credentialed.ssh_scanner import SSHScanner

    scanner = SSHScanner(
        ip="10.0.0.5", username="svc", key_content="k", key_passphrase="hunter2"
    )
    assert "hunter2" not in scanner._redact("failed with hunter2 in the message")


def test_the_passphrase_has_its_own_column():
    """
    Overloading ``encrypted_password`` would make ``AUTH_REQUIRES_PASSWORD`` — a
    data-integrity rule — mean two incompatible things at once.
    """
    from db.models import ComplianceCredential

    assert "encrypted_key_passphrase" in ComplianceCredential.__table__.columns


# ─────────────────────────────────────────────────────────────────────────────
# Linux elevation programs
# ─────────────────────────────────────────────────────────────────────────────


def test_sudo_is_unchanged():
    rewritten, lines = _rewrite_sudo_for_stdin("sudo -n id", "sudo")
    assert rewritten == "sudo -S -p '' id"
    assert lines == 1


def test_dzdo_reuses_sudos_option_syntax():
    """Delinea/Centrify document dzdo as a drop-in sudo replacement."""
    rewritten, lines = _rewrite_sudo_for_stdin("sudo -n id", "dzdo")
    assert rewritten == "dzdo -S -p '' id"
    assert lines == 1


def test_pfexec_takes_no_password_and_no_sudo_flags():
    """
    Solaris RBAC authorises from the account's own profile. Writing a password
    would leave it unread in the command's stdin, where whatever the command
    runs could consume it — and pfexec accepts none of sudo's options.
    """
    rewritten, lines = _rewrite_sudo_for_stdin("sudo -n id", "pfexec")
    assert rewritten == "pfexec id"
    assert lines == 0


def test_an_unsupported_method_elevates_nothing_rather_than_guessing():
    """
    Shipping an untested translation of somebody's privilege-escalation command
    is how a scanner runs the wrong thing as root. The command runs
    unprivileged and whatever it could not read is recorded as unavailable.
    """
    rewritten, lines = _rewrite_sudo_for_stdin("sudo -n id", "pbrun")
    assert rewritten == "sudo -n id"
    assert lines == 0


@pytest.mark.parametrize("method", ["su", "pbrun", "ksu"])
def test_every_unsupported_method_carries_a_reason(method):
    """A gap nobody can act on is worse than no gap at all."""
    assert method in UNSUPPORTED_ELEVATION
    assert len(UNSUPPORTED_ELEVATION[method]) > 40
    assert method not in ELEVATION_METHODS


def test_supported_and_unsupported_do_not_overlap():
    assert not (set(ELEVATION_METHODS) & set(UNSUPPORTED_ELEVATION))


def test_no_elevation_program_receives_its_password_on_the_command_line():
    """
    The property the whole elevation path exists to hold: anything in argv is
    visible in ``ps`` to every local user on the target.
    """
    for method, spec in ELEVATION_METHODS.items():
        rewritten, _ = _rewrite_sudo_for_stdin("sudo -n id", method)
        assert "echo" not in rewritten, method
        assert "|" not in rewritten, method
        if spec["password"] == "stdin":
            assert "-S" in rewritten, method


def test_a_password_is_written_only_for_a_method_that_reads_stdin():
    from engines.credentialed.ssh_scanner import CommandResult, SSHScanner

    captured = {}

    class _Client:
        def exec_command(self, command, timeout=None, get_pty=False):
            raise RuntimeError("stop")

    for method, expect_stdin in (("sudo", True), ("pfexec", False)):
        scanner = SSHScanner(
            ip="10.0.0.5", username="u", password="pw", elevation_method=method
        )
        sent = []
        scanner.run = lambda cmd, timeout=None, stdin_data=None: (
            sent.append(stdin_data) or CommandResult(success=True)
        )
        scanner.run_sudo("sudo -n id")
        captured[method] = sent[0]
        assert (sent[0] is not None) is expect_stdin, method
    assert captured["sudo"] == "pw\n"
    assert captured["pfexec"] is None


def test_the_resolver_really_returns_a_hash_and_not_a_password(db_session, test_org):
    """
    Behavioural, not a source scan.

    The static check above passed while ``AUTH_METHOD_NTLM_HASH`` was never
    defined, so ``_resolve_stored_credential`` raised ImportError on every
    credential — caught by the validation endpoint's broad handler and reported
    as a generic failure. Reading the source proves the line is written; only
    calling it proves the line runs.
    """
    import uuid

    from core.security_crypto import encrypt_credential
    from core.tasks import _resolve_stored_credential
    from db.base import gen_compliance_credential_id
    from db.models import ComplianceCredential

    cred = ComplianceCredential(
        id=gen_compliance_credential_id(test_org.slug),
        tenant_id=test_org.id,
        name=f"pth-{uuid.uuid4().hex[:6]}",
        username="svc_scan",
        credential_type="windows",
        transport="smb",
        auth_method="ntlm_hash",
        port=445,
        encrypted_password=encrypt_credential(NT_HASH),
    )
    db_session.add(cred)
    db_session.commit()

    material = _resolve_stored_credential(db_session, None, cred.id)
    assert material["nt_hash"] == NT_HASH
    assert material["password"] is None, "the hash must never travel as a password"


def test_the_resolver_returns_a_key_passphrase_when_one_is_stored(db_session, test_org):
    import uuid

    from core.security_crypto import encrypt_credential
    from core.tasks import _resolve_stored_credential
    from db.base import gen_compliance_credential_id
    from db.models import ComplianceCredential

    cred = ComplianceCredential(
        id=gen_compliance_credential_id(test_org.slug),
        tenant_id=test_org.id,
        name=f"key-{uuid.uuid4().hex[:6]}",
        username="svc",
        credential_type="ssh",
        transport="ssh",
        auth_method="key",
        port=22,
        encrypted_key_content=encrypt_credential("-----BEGIN KEY-----"),
        encrypted_key_passphrase=encrypt_credential("unlock-me"),
    )
    db_session.add(cred)
    db_session.commit()

    material = _resolve_stored_credential(db_session, None, cred.id)
    assert material["key_content"] == "-----BEGIN KEY-----"
    assert material["key_passphrase"] == "unlock-me"
    assert material["password"] is None
