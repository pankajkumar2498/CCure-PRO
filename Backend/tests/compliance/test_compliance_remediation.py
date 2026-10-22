"""
Module: tests.test_compliance_remediation
Purpose: Test credentials manager, maker-checker authorization queue, and execution tasks.
Author:  Compliance Dev Team
"""

from unittest.mock import MagicMock, patch

from core.compliance_tasks import (
    _execute_ssh_remediation,
    _resolve_remediation_credentials,
    _sanitize_remediation_logs,
)


def test_log_sanitization():
    """Verify stdout/stderr logs are sanitized to remove passwords and tokens."""
    raw_output = "STDOUT: password='super_secret_ssh_pass' token=abc123xyz db_url=postgresql://postgres:myPass123@localhost:5432/db"
    sanitized = _sanitize_remediation_logs(raw_output)

    assert "super_secret_ssh_pass" not in sanitized
    assert "myPass123" not in sanitized
    assert "[REDACTED]" in sanitized or "REDACTED" in sanitized
    assert "[REDACTED_CREDENTIALS]" in sanitized or "REDACTED" in sanitized


def test_resolve_remediation_credentials():
    """Verify that credentials can be resolved and decrypted correctly from DB records."""
    db_mock = MagicMock()

    request_mock = MagicMock()
    request_mock.credential_id = "ccrd_stored"
    request_mock.auth_method = None

    cred_mock = MagicMock()
    cred_mock.username = "root"
    cred_mock.port = 2222
    cred_mock.auth_method = "password"

    from core.security_crypto import encrypt_credential

    cred_mock.encrypted_password = encrypt_credential("resolved_pass")
    cred_mock.encrypted_key_content = None

    db_mock.query().filter_by().first.return_value = cred_mock

    creds = _resolve_remediation_credentials(db_mock, request_mock, {})
    assert creds["username"] == "root"
    assert creds["port"] == 2222
    assert creds["password"] == "resolved_pass"


def test_a_key_credential_keeps_its_stored_password_and_bare_username():
    """
    The credential vault resolves remediation's stored credentials since G2
    (``credential_vault.stored_secrets``), in the form remediation always used:
    every secret the row holds, whatever the auth method, and the username as
    stored. A key credential that also stores a password (for sudo) keeps it,
    and a Windows credential's domain is not folded into the username, unlike
    the collectors' ``connection_material``.
    """
    from core.security_crypto import encrypt_credential

    db_mock = MagicMock()
    cred_mock = MagicMock()
    cred_mock.username = "auditor"
    cred_mock.domain = "CORP"
    cred_mock.credential_type = "windows"
    cred_mock.port = 22
    cred_mock.auth_method = "key"
    cred_mock.encrypted_password = encrypt_credential("sudo-pass")
    cred_mock.encrypted_key_content = encrypt_credential("KEY MATERIAL")
    db_mock.query().filter_by().first.return_value = cred_mock

    creds = _resolve_remediation_credentials(
        db_mock, None, {"stored_cred_id": "ccrd_k"}
    )
    assert creds == {
        "username": "auditor",
        "port": 22,
        "auth_method": "key",
        "password": "sudo-pass",
        "key_content": "KEY MATERIAL",
    }


def test_an_unknown_stored_credential_leaves_the_just_in_time_values():
    db_mock = MagicMock()
    db_mock.query().filter_by().first.return_value = None
    creds = _resolve_remediation_credentials(
        db_mock,
        None,
        {"stored_cred_id": "ccrd_gone", "jit_username": "jit", "jit_port": 2200},
    )
    assert creds["username"] == "jit" and creds["port"] == 2200
    assert creds["password"] is None and creds["key_content"] is None


@patch("engines.credentialed.ssh_scanner.SSHScanner")
def test_execute_ssh_remediation_error(MockScanner):
    """Verify that execution errors are captured gracefully and returned as failure results."""
    scanner_instance = MockScanner.return_value
    scanner_instance.connect.side_effect = Exception("Connection Timeout")

    res = _execute_ssh_remediation(
        ip="192.168.1.10",
        port=22,
        username="admin",
        password="pwd",
        key_content=None,
        command="sudo service restart",
        target_platform="linux",
    )

    assert res["success"] is False
    assert "Connection Timeout" in res["error"]
