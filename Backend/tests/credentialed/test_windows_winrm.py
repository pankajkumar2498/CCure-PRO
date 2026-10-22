"""
tests/credentialed/test_windows_winrm.py
─────────────────────────────────────────────────────────────────────────────
Native Windows credentialed assessment over WinRM (Phase 2).

These run without a Windows host. The transport is faked where a real one
would be needed, because what is under test is *this* code — credential
handling, transport selection, error classification, thread safety — not
Microsoft's. Real-target results against a live Windows 11 host are recorded
in ``docs/gap_closure/GAP_TRACKER.md``; they are evidence, not a substitute for
these.

Two of the classes below are **regression tests for defects that real-target
validation found**, and both would have shipped without it:

  * ``TestWinRMThreadSafety`` — a shared pywinrm NTLM session corrupted under
    the collector's parallel section execution, failing every section with
    "the specified credentials were rejected" on a valid credential.
  * ``TestCoverageReportsTheRealTransport`` — the audit reported "collected
    over SSH" for evidence gathered over WinRM.
"""

import threading
import uuid

import pytest
from core.security_crypto import decrypt_credential, encrypt_credential
from db.base import gen_compliance_credential_id
from db.models import ComplianceCredential, Organization
from db.models.compliance import (
    AUTH_REQUIRES_KEY,
    AUTH_REQUIRES_PASSWORD,
    CREDENTIAL_TYPE_SSH,
    CREDENTIAL_TYPE_WINDOWS,
    TRANSPORT_WINRM,
)
from engines.credentialed.coverage import credentialed_coverage
from engines.credentialed.winrm_executor import (
    WinRMAuthenticationError,
    WinRMConfigurationError,
    WinRMConnectionError,
    WinRMError,
    WinRMExecutor,
    WinRMPermissionError,
)

BASE = "/credentials"


def _win_cred_body(**overrides):
    body = {
        "name": f"win-{uuid.uuid4().hex[:8]}",
        "username": "svc_scan",
        "credential_type": "windows",
        "auth_method": "ntlm",
        "password": "not-a-real-password",
        "domain": "CORP",
    }
    body.update(overrides)
    return body


# ─────────────────────────────────────────────────────────────────────────────
# GAP-00-C — the generalized credential model
# ─────────────────────────────────────────────────────────────────────────────


class TestCredentialModel:
    def test_existing_ssh_credentials_keep_working(self, db_session, test_org):
        """
        The generalisation must not change what an existing row means. Every
        credential in this table before Phase 2 was SSH, and the migration
        backfills exactly that.
        """
        cred = ComplianceCredential(
            id=gen_compliance_credential_id(test_org.slug),
            tenant_id=test_org.id,
            name=f"legacy-{uuid.uuid4().hex[:6]}",
            username="root",
            auth_method="password",
            port=22,
            encrypted_password=encrypt_credential("pw"),
        )
        db_session.add(cred)
        db_session.commit()
        db_session.refresh(cred)

        assert cred.credential_type == CREDENTIAL_TYPE_SSH
        assert cred.transport == "ssh"
        assert cred.principal() == "root"

    @pytest.mark.parametrize(
        "credential_type,auth_method,domain,username,expected",
        [
            # Kerberos wants user@REALM, upper-cased.
            (
                CREDENTIAL_TYPE_WINDOWS,
                "kerberos",
                "corp.example.com",
                "svc",
                "svc@CORP.EXAMPLE.COM",
            ),
            # NTLM and Windows password auth want DOMAIN\user.
            (CREDENTIAL_TYPE_WINDOWS, "ntlm", "CORP", "svc", "CORP\\svc"),
            (CREDENTIAL_TYPE_WINDOWS, "password", "CORP", "svc", "CORP\\svc"),
            # A local Windows account has no domain — verified against the real
            # host, where a WORKGROUP machine authenticates a bare name.
            (CREDENTIAL_TYPE_WINDOWS, "ntlm", None, "pankaj", "pankaj"),
            # SSH never gets a domain prefix.
            (CREDENTIAL_TYPE_SSH, "password", "CORP", "root", "root"),
            # A username that already carries its own qualifier is left alone,
            # rather than becoming CORP\CORP\svc.
            (CREDENTIAL_TYPE_WINDOWS, "ntlm", "CORP", "OTHER\\svc", "OTHER\\svc"),
            (CREDENTIAL_TYPE_WINDOWS, "kerberos", "CORP", "svc@X.COM", "svc@X.COM"),
        ],
    )
    def test_principal_uses_the_form_the_auth_method_expects(
        self, credential_type, auth_method, domain, username, expected
    ):
        cred = ComplianceCredential(
            credential_type=credential_type,
            auth_method=auth_method,
            domain=domain,
            username=username,
        )
        assert cred.principal() == expected

    def test_secret_is_encrypted_at_rest(self, db_session, test_org):
        secret = "s3cret-" + uuid.uuid4().hex
        cred = ComplianceCredential(
            id=gen_compliance_credential_id(test_org.slug),
            tenant_id=test_org.id,
            name=f"enc-{uuid.uuid4().hex[:6]}",
            username="svc",
            credential_type=CREDENTIAL_TYPE_WINDOWS,
            transport=TRANSPORT_WINRM,
            auth_method="ntlm",
            port=5985,
            encrypted_password=encrypt_credential(secret),
        )
        db_session.add(cred)
        db_session.commit()

        assert secret not in cred.encrypted_password
        assert decrypt_credential(cred.encrypted_password) == secret

    def test_ntlm_and_kerberos_resolve_their_material(self, db_session, test_org):
        """
        The defect this guards: ``_resolve_stored_credential`` matched
        ``auth_method == "password"`` literally, so ntlm and kerberos resolved
        to a credential with *no material at all* and the connection was
        attempted with None — failing as "authentication rejected" for a
        credential that was never actually sent.
        """
        from scans.tasks.credentialed import _resolve_stored_credential

        for method in ("ntlm", "kerberos"):
            cred = ComplianceCredential(
                id=gen_compliance_credential_id(test_org.slug) + method[:2],
                tenant_id=test_org.id,
                name=f"{method}-{uuid.uuid4().hex[:6]}",
                username="svc",
                domain="CORP",
                credential_type=CREDENTIAL_TYPE_WINDOWS,
                transport=TRANSPORT_WINRM,
                auth_method=method,
                port=5985,
                encrypted_password=encrypt_credential("pw-" + method),
            )
            db_session.add(cred)
            db_session.commit()

            material = _resolve_stored_credential(db_session, None, cred.id)
            assert material["password"] == "pw-" + method, (
                f"{method} resolved no password; the credential would be sent "
                "as None and fail as 'rejected'"
            )
            assert material["transport"] == TRANSPORT_WINRM
            assert material["auth_method"] == method

    def test_auth_material_sets_cover_every_method(self):
        """A method in neither set resolves no material and can never work."""
        from db.models.compliance import AUTH_METHODS

        covered = set(AUTH_REQUIRES_PASSWORD) | set(AUTH_REQUIRES_KEY)
        assert set(AUTH_METHODS) == covered


# ─────────────────────────────────────────────────────────────────────────────
# Transport configuration and error classification
# ─────────────────────────────────────────────────────────────────────────────


class TestWinRMConfiguration:
    def test_basic_over_plain_http_is_refused(self):
        """It puts the password on the wire in base64."""
        with pytest.raises(WinRMConfigurationError, match="base64"):
            WinRMExecutor("10.0.0.1", "u", "p", port=5985, auth_method="basic")

    def test_basic_over_https_is_allowed(self):
        w = WinRMExecutor("10.0.0.1", "u", "p", port=5986, auth_method="basic")
        assert w.use_tls is True
        assert w.endpoint.startswith("https://")

    def test_password_method_maps_to_ntlm_not_basic(self):
        """
        The credential store says "password" for any password-presenting
        method. On Windows that must become NTLM: Basic would put the password
        on the wire and require AllowUnencrypted on the target — which the
        real host has set to false.
        """
        w = WinRMExecutor("10.0.0.1", "u", "p", port=5985, auth_method="password")
        assert w.auth_method == "ntlm"

    def test_tls_is_inferred_from_the_port(self):
        assert WinRMExecutor("10.0.0.1", "u", "p", port=5986).use_tls is True
        assert WinRMExecutor("10.0.0.1", "u", "p", port=5985).use_tls is False

    def test_an_unknown_auth_method_is_refused(self):
        with pytest.raises(WinRMConfigurationError, match="unsupported"):
            WinRMExecutor("10.0.0.1", "u", "p", auth_method="telepathy")

    @pytest.mark.parametrize(
        "message,expected",
        [
            (
                "the specified credentials were rejected by the server",
                WinRMAuthenticationError,
            ),
            ("HTTP 401 Unauthorized", WinRMAuthenticationError),
            ("403 Forbidden", WinRMPermissionError),
            ("certificate verify failed", WinRMConfigurationError),
            ("Connection refused", WinRMConnectionError),
            ("Max retries exceeded", WinRMConnectionError),
        ],
    )
    def test_errors_are_classified_not_flattened(self, message, expected):
        """
        Four causes needing four different actions. Collapsing them is how a
        fixable firewall rule gets recorded as "host unreachable" and ignored.
        Each case here was observed against the real host or is the literal
        message pywinrm emits.
        """
        w = WinRMExecutor("10.0.0.1", "u", "p", port=5985)
        assert isinstance(w._classify(Exception(message)), expected)


# ─────────────────────────────────────────────────────────────────────────────
# REGRESSION — defect found by real-target validation
# ─────────────────────────────────────────────────────────────────────────────


class TestWinRMThreadSafety:
    """
    A pywinrm NTLM session is not thread-safe, and ``WindowsCollector`` runs
    its sections in a thread pool.

    Measured against a real Windows 11 host before the fix:

        sequential, one session, 10 commands      10/10 succeeded
        concurrent, one shared session, 8 threads  0/8 succeeded
        concurrent, one session per thread         8/8 succeeded

    The failures arrived as ``SpnegoError (6): invalid Message Integrity
    Check``, HTTP 400, and — most misleadingly — "the specified credentials
    were rejected by the server" on a valid credential. Every section of every
    real Windows scan failed, looking exactly like a bad password.
    """

    def test_each_thread_gets_its_own_session(self, monkeypatch):
        built = []

        class _FakeSession:
            def __init__(self):
                self.owner = threading.get_ident()
                built.append(self)

            def run_ps(self, command):
                class _R:
                    std_out = b"ok"
                    std_err = b""
                    status_code = 0

                return _R()

        w = WinRMExecutor("10.0.0.1", "u", "p", port=5985)
        monkeypatch.setattr(w, "_build_session", lambda: _FakeSession())

        # Counted from what was actually constructed, NOT keyed on
        # threading.get_ident(): Python reuses thread identifiers once a thread
        # exits, so short-lived workers collide on the same key and a
        # correct implementation looks like a broken one.
        # A barrier keeps all six threads alive simultaneously. Without it
        # they finish fast enough that Python recycles thread identifiers, so
        # `owner` collapses to one value and a correct implementation looks
        # broken — and, worse, the test would not actually have exercised
        # concurrency, which is the entire thing under test.
        barrier = threading.Barrier(6)

        def worker():
            barrier.wait(timeout=10)
            w.run("whoami")
            barrier.wait(timeout=10)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(built) == 6, (
            f"expected one session per thread, got {len(built)} — threads "
            "shared a pywinrm session, which is the exact condition that "
            "corrupted the NTLM context and failed every collector section "
            "with a misleading 'credentials rejected'"
        )
        assert len({id(s) for s in built}) == 6
        assert (
            len({s.owner for s in built}) == 6
        ), "each session must have been constructed by the thread that uses it"

    def test_a_session_is_reused_within_one_thread(self, monkeypatch):
        """Per-thread, not per-command: re-handshaking NTLM for every one of
        the collector's dozens of commands would triple the round trips."""
        built = []

        class _FakeSession:
            def __init__(self):
                built.append(self)

            def run_ps(self, command):
                class _R:
                    std_out = b"ok"
                    std_err = b""
                    status_code = 0

                return _R()

        w = WinRMExecutor("10.0.0.1", "u", "p", port=5985)
        monkeypatch.setattr(w, "_build_session", lambda: _FakeSession())
        for _ in range(5):
            w.run("whoami")
        assert len(built) == 1

    def test_run_after_disconnect_is_refused(self, monkeypatch):
        """Otherwise a stale thread rebuilds a session with a password the
        context manager was supposed to have dropped."""
        w = WinRMExecutor("10.0.0.1", "u", "p", port=5985)
        monkeypatch.setattr(w, "_build_session", lambda: object())
        w.disconnect()
        with pytest.raises(WinRMConnectionError, match="after disconnect"):
            w.run("whoami")


class TestCoverageReportsTheRealTransport:
    """
    The audit's coverage block is its own statement of how its evidence was
    obtained. It read "over SSH" unconditionally, so a Windows host collected
    over WinRM still reported SSH — telling a reader checking whether OpenSSH
    was required exactly the wrong thing.
    """

    def test_winrm_collection_is_not_reported_as_ssh(self):
        scanner = credentialed_coverage(transport="winrm")["scanner"]
        assert "WinRM" in scanner
        assert "over SSH" not in scanner

    def test_ssh_collection_still_reports_ssh(self):
        assert "SSH" in credentialed_coverage(transport="ssh")["scanner"]

    def test_the_default_is_unchanged_for_existing_callers(self):
        assert "SSH" in credentialed_coverage()["scanner"]


# ─────────────────────────────────────────────────────────────────────────────
# Collector is transport-agnostic
# ─────────────────────────────────────────────────────────────────────────────


class _FakeExecutor:
    """A BaseExecutor that answers from a script. No network, no Windows."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def connect(self):
        pass

    def disconnect(self):
        pass

    def run(self, command, timeout=None):
        from engines.credentialed.ssh_scanner import CommandResult

        self.calls.append(command)
        for needle, reply in self.answers.items():
            if needle in command:
                return CommandResult(stdout=reply, exit_code=0, success=True)
        return CommandResult(stdout="", exit_code=0, success=True)


def test_windows_collector_drives_any_executor():
    """
    The claim Phase 2 rests on: one collector, two transports. If this needed
    an SSH-specific type the phase would have meant a second Windows collector
    and a second finding path.
    """
    from engines.credentialed.windows_collector import WindowsCollector

    fake = _FakeExecutor({"PSVersionTable": "7"})
    collector = WindowsCollector(fake)
    assert collector.shell_type == "powershell", (
        "a transport that answers PSVersionTable must be treated as native "
        "PowerShell; wrapping would double-encode, since pywinrm already "
        "base64-encodes UTF-16-LE itself"
    )


def test_powershell_shell_type_means_commands_are_not_wrapped():
    from engines.credentialed.windows_collector import WindowsCollector

    collector = WindowsCollector(_FakeExecutor({"PSVersionTable": "7"}))
    assert collector._wrap_ps("Get-Thing") == "Get-Thing"


# ─────────────────────────────────────────────────────────────────────────────
# Credential API
# ─────────────────────────────────────────────────────────────────────────────


class TestCredentialAPI:
    def test_create_read_update_delete_windows_credential(self, client, auth_headers):
        created = client.post(BASE, json=_win_cred_body(), headers=auth_headers)
        assert created.status_code == 201, created.text
        cred = created.json()
        assert cred["credential_type"] == "windows"
        assert cred["transport"] == "winrm"
        assert cred["port"] == 5985, "a Windows credential defaults to the WinRM port"
        assert cred["principal"] == "CORP\\svc_scan"
        assert cred["has_secret"] is True

        listed = client.get(BASE, headers=auth_headers).json()
        assert any(c["id"] == cred["id"] for c in listed["credentials"])

        edited = client.patch(
            f"{BASE}/{cred['id']}", json={"username": "svc2"}, headers=auth_headers
        )
        assert edited.status_code == 200
        assert edited.json()["username"] == "svc2"
        assert (
            edited.json()["has_secret"] is True
        ), "editing a non-secret field must not blank the password"

        assert (
            client.delete(f"{BASE}/{cred['id']}", headers=auth_headers).status_code
            == 200
        )
        assert (
            client.get(f"{BASE}/{cred['id']}", headers=auth_headers).status_code == 404
        )

    def test_no_response_ever_carries_secret_material(self, client, auth_headers):
        secret = "very-secret-" + uuid.uuid4().hex
        created = client.post(
            BASE, json=_win_cred_body(password=secret), headers=auth_headers
        )
        cred_id = created.json()["id"]
        for response in (
            created,
            client.get(BASE, headers=auth_headers),
            client.get(f"{BASE}/{cred_id}", headers=auth_headers),
        ):
            body = response.text
            assert secret not in body
            assert "encrypted_password" not in body
            assert "encrypted_key_content" not in body

    def test_the_type_auth_matrix_is_enforced(self, client, auth_headers):
        """An SSH credential cannot use NTLM, and a Windows one cannot use a
        private key. The database deliberately carries no CHECK for this."""
        ssh_ntlm = client.post(
            BASE,
            json=_win_cred_body(credential_type="ssh", auth_method="ntlm"),
            headers=auth_headers,
        )
        assert ssh_ntlm.status_code == 400
        assert "cannot use auth_method" in ssh_ntlm.json()["detail"]

        win_key = client.post(
            BASE,
            json=_win_cred_body(auth_method="key", private_key="x", password=None),
            headers=auth_headers,
        )
        assert win_key.status_code == 400

    def test_reserved_credential_types_are_refused(self, client, auth_headers):
        """The column admits them so a later phase needs no CHECK migration; the
        API must not let one be created that nothing can authenticate with.

        ``database`` was on this list until Phase 7 (GAP-10) implemented a
        transport, a collector and validated content for it, at which point it
        moved to ``USABLE_CREDENTIAL_TYPES``. The two remaining entries keep the
        property under test — that the column being permissive does not make the
        API permissive — and the assertion below keeps ``database`` honest from
        the other side.
        """
        for reserved in ("network_device", "snmp"):
            response = client.post(
                BASE,
                json=_win_cred_body(credential_type=reserved),
                headers=auth_headers,
            )
            assert response.status_code == 422, reserved

    def test_the_database_credential_type_is_no_longer_reserved(self):
        """
        The other half of the test above. If ``database`` were ever removed from
        the usable set, the loop there would keep passing while the capability
        silently disappeared.
        """
        from db.models.compliance import (
            CREDENTIAL_TYPE_DATABASE,
            CREDENTIAL_TYPES,
            USABLE_CREDENTIAL_TYPES,
        )

        assert CREDENTIAL_TYPE_DATABASE in CREDENTIAL_TYPES
        assert CREDENTIAL_TYPE_DATABASE in USABLE_CREDENTIAL_TYPES

    def test_secrets_are_refused_in_the_options_field(self, client, auth_headers):
        """`options` is returned to clients in clear and written to logs."""
        response = client.post(
            BASE,
            json=_win_cred_body(options={"password": "oops"}),
            headers=auth_headers,
        )
        assert response.status_code == 422

    def test_a_method_change_without_material_is_a_400_not_a_500(
        self, client, auth_headers
    ):
        """
        Uses an SSH credential, where `key` is a permitted method — so the
        type/auth matrix passes and the *material* check is what fires. On a
        Windows credential the matrix rejects `key` first, which is correct but
        tests a different branch.
        """
        cred = client.post(
            BASE,
            json=_win_cred_body(
                credential_type="ssh", auth_method="password", domain=None
            ),
            headers=auth_headers,
        ).json()
        response = client.patch(
            f"{BASE}/{cred['id']}", json={"auth_method": "key"}, headers=auth_headers
        )
        assert response.status_code == 400
        assert "private key" in response.json()["detail"]

    def test_another_tenants_credential_is_404(self, client, auth_headers, db_session):
        from db.base import gen_org_id

        other = Organization(id=gen_org_id("rivalcred"), name="Rival", slug="rivalcred")
        db_session.add(other)
        db_session.commit()
        foreign = ComplianceCredential(
            id=gen_compliance_credential_id(other.slug),
            tenant_id=other.id,
            name="theirs",
            username="svc",
            auth_method="password",
            port=22,
            encrypted_password=encrypt_credential("pw"),
        )
        db_session.add(foreign)
        db_session.commit()

        assert (
            client.get(f"{BASE}/{foreign.id}", headers=auth_headers).status_code == 404
        )
        assert (
            client.delete(f"{BASE}/{foreign.id}", headers=auth_headers).status_code
            == 404
        )

    def test_every_route_requires_authentication(self, client):
        for method, url in [
            ("get", BASE),
            ("post", BASE),
            ("get", f"{BASE}/types"),
            ("get", f"{BASE}/x"),
            ("patch", f"{BASE}/x"),
            ("delete", f"{BASE}/x"),
            ("post", f"{BASE}/x/validate"),
        ]:
            call = getattr(client, method)
            response = call(url, json={}) if method in ("post", "patch") else call(url)
            assert response.status_code in (401, 403), f"{method} {url}"

    def test_types_endpoint_reports_winrm_availability_from_the_build(
        self, client, auth_headers
    ):
        """A UI that offered Windows credentials on a build without pywinrm
        would collect them and then fail every scan."""
        payload = client.get(f"{BASE}/types", headers=auth_headers).json()
        windows = [t for t in payload["types"] if t["value"] == "windows"][0]
        from engines.credentialed.winrm_executor import WINRM_AVAILABLE

        assert windows["available"] is WINRM_AVAILABLE
        assert windows["default_port"] == 5985


class TestCredentialValidation:
    def test_validation_classifies_failure_rather_than_flattening_it(
        self, client, auth_headers, monkeypatch
    ):
        cred = client.post(BASE, json=_win_cred_body(), headers=auth_headers).json()

        import engines.credentialed.winrm_executor as wexec

        def _boom(*args, **kwargs):
            raise WinRMAuthenticationError("rejected")

        monkeypatch.setattr(wexec, "WinRMExecutor", _boom)
        response = client.post(
            f"{BASE}/{cred['id']}/validate",
            json={"target": "127.0.0.1"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["reason"] == "authentication_failed"

    def test_validation_refuses_a_target_outside_the_scan_scope(
        self, client, auth_headers, db_session, test_org
    ):
        """
        This makes an outbound authentication attempt at a caller-named
        address. Without the scope check it is a way to make this host try
        credentials against anything reachable.
        """
        cred = client.post(BASE, json=_win_cred_body(), headers=auth_headers).json()
        test_org.scan_scope_cidrs = ["192.0.2.0/24"]
        db_session.commit()

        response = client.post(
            f"{BASE}/{cred['id']}/validate",
            json={"target": "203.0.113.9"},
            headers=auth_headers,
        )
        assert response.status_code == 403


def test_credential_changes_are_audited(client, auth_headers, db_session):
    from db.models import AuditLog

    cred = client.post(BASE, json=_win_cred_body(), headers=auth_headers).json()
    client.patch(f"{BASE}/{cred['id']}", json={"username": "x"}, headers=auth_headers)
    client.delete(f"{BASE}/{cred['id']}", headers=auth_headers)

    actions = {
        row.action
        for row in db_session.query(AuditLog)
        .filter(AuditLog.resource_id == cred["id"])
        .all()
    }
    assert {"credential.created", "credential.updated", "credential.deleted"} <= actions


def test_audit_records_never_contain_the_secret(client, auth_headers, db_session):
    from db.models import AuditLog

    secret = "audit-secret-" + uuid.uuid4().hex
    cred = client.post(
        BASE, json=_win_cred_body(password=secret), headers=auth_headers
    ).json()
    rows = db_session.query(AuditLog).filter(AuditLog.resource_id == cred["id"]).all()
    assert rows
    for row in rows:
        assert secret not in str(row.changes or "")
