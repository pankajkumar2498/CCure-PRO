"""
The credentialed scan pipeline's transport and port decisions.

``test_transport_resolution.py`` covers the resolver in isolation. These cover
the two places that call it, and the regressions they exist for are the ones a
unit test of the resolver could never have caught:

* the phase-3.5 enrichment path read the stored credential and then called the
  auditor **without the transport**, so every credential on the main scan path
  was driven over SSH — a Windows credential opened an SSH handshake against a
  WinRM listener and the host was recorded as a connection failure; and
* it resolved the port as ``int(material.get("port") or 22)``, an SSH port
  standing in for every credential type.
"""

import pytest
from db.models.compliance import (
    CREDENTIAL_TYPE_DATABASE,
    CREDENTIAL_TYPE_SSH,
    CREDENTIAL_TYPE_WINDOWS,
)


def _material(**kw):
    """A decrypted credential in the shape ``_resolve_stored_credential`` emits."""
    material = {
        "username": "root",
        "password": "pw",
        "key_content": None,
        "port": 22,
        "auth_method": "password",
        "credential_type": CREDENTIAL_TYPE_SSH,
        "transport": "ssh",
        "domain": None,
        "options": {},
    }
    material.update(kw)
    return material


def _host(ip="10.0.0.5", ports=()):
    return {
        "ip_address": ip,
        "is_active": True,
        "open_ports": [dict(p) for p in ports],
        "cves": [],
    }


def _port(port, **kw):
    record = {"port": port, "protocol": "tcp", "state": "open"}
    record.update(kw)
    return record


@pytest.fixture()
def enrichment(monkeypatch):
    """
    Drive ``_apply_credentialed_enrichment`` with a captured auditor.

    The auditor records what it was called with and then raises, so the audit's
    own post-processing — asset sync, risk, coverage — stays out of the way of
    what these assert, which is the arguments it was handed.
    """
    import scans.tasks.credentialed as tasks_mod

    calls = []

    def _capture(**kwargs):
        calls.append(kwargs)
        raise RuntimeError("stop after capture")

    monkeypatch.setattr(tasks_mod, "audit_credentialed_host", _capture)

    def _run(material, hosts):
        monkeypatch.setattr(
            tasks_mod,
            "_credentialed_plan_for_scan",
            lambda db, scan_row: [{"material": material, "networks": None}],
        )
        return tasks_mod._apply_credentialed_enrichment(None, object(), hosts)

    _run.calls = calls
    return _run


# ─────────────────────────────────────────────────────────────────────────────
# The transport reaches the auditor
# ─────────────────────────────────────────────────────────────────────────────


def test_a_windows_credential_is_driven_over_winrm_not_ssh(enrichment):
    """
    The regression. This path passed no transport at all, so the auditor's
    ``transport="ssh"`` default applied to every credential and a Windows
    credential opened an SSH handshake against a WinRM listener.
    """
    material = _material(
        credential_type=CREDENTIAL_TYPE_WINDOWS,
        transport="winrm",
        port=5985,
        username="CORP\\svc_scan",
        auth_method="ntlm",
        domain="CORP",
    )
    enrichment(material, [_host(ports=[_port(5985, service="wsman")])])

    assert len(enrichment.calls) == 1
    call = enrichment.calls[0]
    assert call["transport"] == "winrm"
    assert call["port"] == 5985


def test_the_windows_auth_method_and_domain_are_carried(enrichment):
    """
    NTLM wants ``DOMAIN\\user`` and Kerberos wants ``user@REALM``. Dropping
    either leaves the executor guessing between them, which is how a good
    credential silently fails to authenticate.
    """
    material = _material(
        credential_type=CREDENTIAL_TYPE_WINDOWS,
        transport="winrm",
        port=5986,
        auth_method="kerberos",
        domain="CORP.EXAMPLE.COM",
        options={"verify_cert": True, "winrm_path": "/custom"},
    )
    enrichment(material, [_host(ports=[_port(5986, service="wsman")])])

    call = enrichment.calls[0]
    assert call["auth_method"] == "kerberos"
    assert call["domain"] == "CORP.EXAMPLE.COM"
    assert call["credential_options"]["verify_cert"] is True
    assert call["credential_options"]["winrm_path"] == "/custom"


def test_an_ssh_credential_is_still_driven_over_ssh(enrichment):
    enrichment(_material(), [_host(ports=[_port(22, service="ssh")])])
    assert enrichment.calls[0]["transport"] == "ssh"


def test_a_database_credential_is_not_handed_to_the_host_auditor(enrichment):
    """
    A database credential names an instance, not a host. Handing one here opens
    an SSH session against a database port and reports the machine unreachable —
    the standalone task branches on this and this path did not.
    """
    material = _material(
        credential_type=CREDENTIAL_TYPE_DATABASE, transport="postgresql", port=5432
    )
    summary = enrichment(material, [_host(ports=[_port(5432, service="postgresql")])])

    assert enrichment.calls == []
    assert "database credential" in summary["credentialed_skipped"][0]["reason"]


# ─────────────────────────────────────────────────────────────────────────────
# The port is resolved from what the scan discovered
# ─────────────────────────────────────────────────────────────────────────────


def test_sshd_on_a_non_standard_port_is_reached_without_editing_the_credential(
    enrichment,
):
    """
    ``compliance_credentials.port`` is NOT NULL with a model default of 22, so
    "the operator chose 22" and "nobody said" are the same row. This host was
    skipped with "port 22/tcp not open" on a scan that had already identified
    sshd on 2222.
    """
    enrichment(
        _material(port=22),
        [_host(ports=[_port(2222, service="ssh", product="OpenSSH 9.6")])],
    )
    assert enrichment.calls[0]["port"] == 2222


def test_a_conventional_host_is_still_reached_on_the_conventional_port(enrichment):
    """The fix must not change what already worked."""
    enrichment(_material(port=22), [_host(ports=[_port(22, service="ssh")])])
    assert enrichment.calls[0]["port"] == 22


def test_a_windows_credential_carrying_the_model_default_port_still_finds_winrm(
    enrichment,
):
    """
    A Windows credential can carry 22 without anyone having chosen it. On a host
    running both sshd and WinRM, leading with the stated port would send a
    WS-Management request to sshd while the real listener sat identified two
    entries away.
    """
    material = _material(
        credential_type=CREDENTIAL_TYPE_WINDOWS, transport="winrm", port=22
    )
    enrichment(
        material,
        [_host(ports=[_port(22, service="ssh"), _port(5986, service="wsman")])],
    )

    call = enrichment.calls[0]
    assert call["port"] == 5986
    assert call["credential_options"]["use_tls"] is True


def test_a_non_standard_winrm_port_leaves_tls_to_the_executor(enrichment):
    """
    nmap carries the TLS fact in a ``tunnel`` attribute this product does not
    parse, so off the two conventional ports nothing has established it. The
    option must be absent rather than guessed — a wrong guess addresses an HTTPS
    listener as ``http://``.
    """
    material = _material(
        credential_type=CREDENTIAL_TYPE_WINDOWS, transport="winrm", port=5985
    )
    enrichment(
        material,
        [
            _host(
                ports=[
                    _port(47001, service="http", product="Microsoft HTTPAPI httpd 2.0")
                ]
            )
        ],
    )

    call = enrichment.calls[0]
    assert call["port"] == 47001
    assert "use_tls" not in call["credential_options"]


def test_a_host_with_nothing_listening_for_the_transport_is_skipped(enrichment):
    summary = enrichment(
        _material(port=22), [_host(ports=[_port(443, service="https")])]
    )
    assert enrichment.calls == []
    reason = summary["credentialed_skipped"][0]["reason"]
    assert "not open" in reason
    assert "22/tcp" in reason


def test_open_ports_that_are_not_the_transport_are_never_authenticated_to(enrichment):
    """Resolution, not credential spraying."""
    summary = enrichment(
        _material(port=22),
        [
            _host(
                ports=[
                    _port(80, service="http"),
                    _port(3306, service="mysql"),
                    _port(8080, service="http-proxy"),
                ]
            )
        ],
    )
    assert enrichment.calls == []
    assert summary["credentialed_hosts"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# The standalone scan: attempt, then resolve, and never re-present a rejection
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture()
def audit_calls(monkeypatch):
    """Capture what ``_audit_host_over_transport`` attempts, in order."""
    import scans.tasks.credentialed as tasks_mod

    calls = []

    def install(behaviour):
        def _auditor(**kwargs):
            calls.append(kwargs)
            outcome = behaviour(kwargs)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        monkeypatch.setattr(tasks_mod, "audit_credentialed_host", _auditor)

    install.calls = calls
    install.module = tasks_mod
    return install


_REPORT = ({"coverage": {}}, {}, "linux")


def test_the_conventional_path_makes_one_attempt_and_opens_no_probe(
    audit_calls, monkeypatch
):
    """
    A scan against a normally configured host must cost exactly what it always
    did. Resolution is a response to failure, not a step on the way in.
    """
    from engines.credentialed import transport_resolver

    probed = []
    monkeypatch.setattr(
        transport_resolver,
        "_default_probe",
        lambda t: lambda *a, **k: probed.append(a) or True,
    )
    audit_calls(lambda kw: _REPORT)

    result = audit_calls.module._audit_host_over_transport(
        ip="10.0.0.5", username="root", password="pw", port=22, transport="ssh"
    )
    assert result == _REPORT
    assert len(audit_calls.calls) == 1
    assert probed == []


def test_a_rejected_credential_is_never_retried_on_another_port(audit_calls):
    """
    The property that keeps resolution from becoming a lockout. Something
    answered and said no; presenting the same credential elsewhere adds failed
    logons against an account this product must not lock out.
    """
    audit_calls(
        lambda kw: RuntimeError("SSH authentication failed for root@10.0.0.5: bad")
    )

    with pytest.raises(RuntimeError, match="authentication failed"):
        audit_calls.module._audit_host_over_transport(
            ip="10.0.0.5", username="root", password="pw", port=22, transport="ssh"
        )
    assert len(audit_calls.calls) == 1


def test_a_winrm_rejection_is_recognised_by_type_and_not_retried(audit_calls):
    winrm_executor = pytest.importorskip("engines.credentialed.winrm_executor")

    audit_calls(
        lambda kw: winrm_executor.WinRMAuthenticationError("credentials rejected")
    )
    with pytest.raises(winrm_executor.WinRMAuthenticationError):
        audit_calls.module._audit_host_over_transport(
            ip="10.0.0.5", username="u", password="pw", port=5985, transport="winrm"
        )
    assert len(audit_calls.calls) == 1


def test_a_silent_port_is_retried_on_a_reachable_one(audit_calls, monkeypatch):
    from engines.credentialed import transport_resolver

    monkeypatch.setattr(
        transport_resolver, "_default_probe", lambda t: lambda ip, p, t2: p == 2222
    )
    audit_calls(
        lambda kw: (
            _REPORT
            if kw["port"] == 2222
            else RuntimeError("Cannot reach 10.0.0.5:22 — host is down")
        )
    )

    result = audit_calls.module._audit_host_over_transport(
        ip="10.0.0.5", username="root", password="pw", port=22, transport="ssh"
    )
    assert result == _REPORT
    assert [c["port"] for c in audit_calls.calls] == [22, 2222]


def test_the_port_that_just_refused_is_not_probed_again(audit_calls, monkeypatch):
    from engines.credentialed import transport_resolver

    probed = []

    def _probe_factory(_transport):
        def _probe(ip, port, timeout):
            probed.append(port)
            return port == 2222

        return _probe

    monkeypatch.setattr(transport_resolver, "_default_probe", _probe_factory)
    audit_calls(
        lambda kw: (
            _REPORT if kw["port"] == 2222 else RuntimeError("Cannot reach 10.0.0.5:22")
        )
    )

    audit_calls.module._audit_host_over_transport(
        ip="10.0.0.5", username="root", password="pw", port=22, transport="ssh"
    )
    assert 22 not in probed


def test_nothing_reachable_re_raises_the_original_failure(audit_calls, monkeypatch):
    """
    "Unreachable" and "failed" drive different UI, so the exception that
    survives has to be the one that describes what actually happened.
    """
    from engines.credentialed import transport_resolver

    monkeypatch.setattr(
        transport_resolver, "_default_probe", lambda t: lambda *a, **k: False
    )
    audit_calls(lambda kw: RuntimeError("Cannot reach 10.0.0.5:22 — no route to host"))

    with pytest.raises(RuntimeError, match="no route to host"):
        audit_calls.module._audit_host_over_transport(
            ip="10.0.0.5", username="root", password="pw", port=22, transport="ssh"
        )


def test_a_fault_in_resolution_never_masks_the_original_failure(
    audit_calls, monkeypatch
):
    """
    Resolution is a best-effort second look. A fault in it would otherwise
    replace the host's real error and decide the scan record's status.
    """
    from engines.credentialed import transport_resolver

    def _explode(_transport):
        raise AttributeError("no probe here")

    monkeypatch.setattr(transport_resolver, "_default_probe", _explode)
    audit_calls(lambda kw: RuntimeError("Cannot reach 10.0.0.5:22 — host is down"))

    with pytest.raises(RuntimeError, match="host is down"):
        audit_calls.module._audit_host_over_transport(
            ip="10.0.0.5", username="root", password="pw", port=22, transport="ssh"
        )


def test_the_resolved_tls_setting_reaches_the_retry(audit_calls, monkeypatch):
    from engines.credentialed import transport_resolver

    monkeypatch.setattr(
        transport_resolver, "_default_probe", lambda t: lambda ip, p, t2: p == 5986
    )
    audit_calls(
        lambda kw: (
            _REPORT
            if kw["port"] == 5986
            else RuntimeError("Cannot reach 10.0.0.5:5985 — connection refused")
        )
    )

    audit_calls.module._audit_host_over_transport(
        ip="10.0.0.5",
        username="u",
        password="pw",
        port=5985,
        transport="winrm",
        credential_options={},
    )
    assert audit_calls.calls[-1]["credential_options"]["use_tls"] is True


# ─────────────────────────────────────────────────────────────────────────────
# Telling "nothing answered" from "something said no"
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "message,is_transport",
    [
        ("Cannot reach 10.0.0.5:22 — host is down", True),
        ("Cannot reach 10.0.0.5:22 — [Errno 111] Connection refused", True),
        ("SSH connection error to 10.0.0.5: [Errno 113] No route to host", True),
        ("SSH authentication failed for root@10.0.0.5: bad password", False),
        ("the specified credentials were rejected by the server", False),
    ],
)
def test_transport_failures_are_told_apart_from_rejections(message, is_transport):
    from scans.tasks.credentialed import _is_transport_failure

    assert _is_transport_failure(RuntimeError(message)) is is_transport


# ─────────────────────────────────────────────────────────────────────────────
# The API surface: a stated port, and a pre-flight that resolves
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture()
def stored_credential(db_session, test_org):
    """An SSH credential carrying the conventional port."""
    import uuid

    from core.security_crypto import encrypt_credential
    from db.base import gen_compliance_credential_id
    from db.models import ComplianceCredential

    cred = ComplianceCredential(
        id=gen_compliance_credential_id(test_org.slug),
        tenant_id=test_org.id,
        name=f"transport-{uuid.uuid4().hex[:6]}",
        username="root",
        auth_method="password",
        port=22,
        encrypted_password=encrypt_credential("pw"),
    )
    db_session.add(cred)
    db_session.commit()
    return cred


@pytest.fixture()
def queued_scan(monkeypatch):
    """Stand the pre-flight socket down and capture what the task was given."""
    from core.celery_app import registered_task
    from core.task_names import RUN_CREDENTIALED_SCAN
    from engines.credentialed.ssh_scanner import SSHScanner

    monkeypatch.setattr(SSHScanner, "test_connectivity", lambda *a, **k: True)
    captured = {}

    class _Task:
        id = "task-transport"

    def _fake_delay(**kwargs):
        captured.update(kwargs)
        return _Task()

    # The route dispatches by registered name (G1); this is the task it finds.
    monkeypatch.setattr(registered_task(RUN_CREDENTIALED_SCAN), "delay", _fake_delay)
    return captured


def test_a_port_on_the_request_overrides_the_stored_credential(
    client, auth_headers, stored_credential, queued_scan
):
    """
    The stored credential's port used to overwrite the request's
    unconditionally, so the field was dead whenever a credential was named and
    there was no way to point one credential at a host whose listener had moved.
    """
    response = client.post(
        "/scan/credentialed",
        headers=auth_headers,
        json={
            "ip": "10.180.6.140",
            "credential_id": stored_credential.id,
            "port": 2222,
        },
    )
    assert response.status_code == 200, response.text
    assert queued_scan["port"] == 2222


def test_the_stored_port_is_used_when_the_request_names_none(
    client, auth_headers, stored_credential, queued_scan
):
    response = client.post(
        "/scan/credentialed",
        headers=auth_headers,
        json={"ip": "10.180.6.140", "credential_id": stored_credential.id},
    )
    assert response.status_code == 200, response.text
    assert queued_scan["port"] == 22


def test_an_ad_hoc_request_naming_no_port_leaves_it_to_the_worker(
    client, auth_headers, queued_scan
):
    """
    ``None`` means "resolve it", not 22. The worker applies the transport's own
    default, which for a WinRM credential is not an SSH port.
    """
    response = client.post(
        "/scan/credentialed",
        headers=auth_headers,
        json={"ip": "10.180.6.140", "username": "root", "password": "secret"},
    )
    assert response.status_code == 200, response.text
    assert queued_scan["port"] is None
