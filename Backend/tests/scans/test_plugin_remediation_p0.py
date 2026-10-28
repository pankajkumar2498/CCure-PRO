"""Corrected assertions for audit D06-D09, D13 and D15; local fixtures only."""

import importlib
import socketserver
import struct
import subprocess
import sys
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rrset
import pytest
from core.checks.plugin_outcomes import coverage_summary, result_with_outcome
from core.credential_scope import credential_plan_entries
from engines.vulnerability.plugins import default_creds, dns_probe, ldap_probe
from engines.vulnerability.vulnerability_engine import VulnerabilityEngine
from pydantic import ValidationError


def axfr_message(*records):
    message = dns.message.Message()
    message.flags = dns.flags.QR | dns.flags.AA
    message.answer = list(records)
    return message


def soa(serial=1):
    return dns.rrset.from_text(
        "example.test.",
        60,
        "IN",
        "SOA",
        f"ns.example.test. hostmaster.example.test. {serial} 60 60 60 60",
    )


@pytest.mark.parametrize(
    "messages",
    [
        [],
        [axfr_message()],
        [axfr_message(soa())],
        [axfr_message(soa(), soa(2))],
        [axfr_message(soa(), soa(), soa())],
    ],
)
def test_d06_empty_or_incomplete_axfr_is_unknown_not_vulnerable(monkeypatch, messages):
    monkeypatch.setattr(dns.query, "xfr", lambda *a, **kw: iter(messages))
    result = dns_probe._check_zone_transfer("192.0.2.1", "example.test.")
    assert result["vulnerable"] is None
    assert result["status"] == "failed"


def test_d06_complete_authoritative_axfr_has_boundaries_and_zone(monkeypatch):
    record = dns.rrset.from_text("www.example.test.", 60, "IN", "A", "192.0.2.10")
    monkeypatch.setattr(
        dns.query,
        "xfr",
        lambda *a, **kw: iter([axfr_message(soa(), record), axfr_message(soa())]),
    )
    result = dns_probe._check_zone_transfer("192.0.2.1", "example.test.")
    assert result["vulnerable"] is True
    assert result["records"] == 3
    assert result["zone"] == "example.test."


@pytest.mark.parametrize(
    "exc,status,verdict",
    [
        (
            dns.query.TransferError(dns.rcode.REFUSED),
            "completed_with_no_findings",
            False,
        ),
        (dns.exception.Timeout(), "timed_out", None),
    ],
)
def test_d06_refused_and_timeout_are_distinct(monkeypatch, exc, status, verdict):
    monkeypatch.setattr(dns.query, "xfr", MagicMock(side_effect=exc))
    result = dns_probe._check_zone_transfer("192.0.2.1", "example.test.")
    assert result["status"] == status
    assert result["vulnerable"] is verdict


def test_d06_root_zone_is_unsupported(monkeypatch):
    transfer = MagicMock()
    monkeypatch.setattr(dns.query, "xfr", transfer)
    assert dns_probe._check_zone_transfer("192.0.2.1", ".")["status"] == "unsupported"
    transfer.assert_not_called()


@pytest.mark.parametrize(
    "rcode,recursive,answers,expected",
    [
        (0, True, True, True),
        (0, True, False, False),
        (5, True, False, False),
        (0, False, True, False),
    ],
)
def test_d06_recursion_requires_a_valid_external_answer(
    monkeypatch, rcode, recursive, answers, expected
):
    def reply(query, *a, **kw):
        response = dns.message.make_response(query)
        response.set_rcode(rcode)
        if recursive:
            response.flags |= dns.flags.RA
        if answers:
            response.answer.append(
                dns.rrset.from_text("google.com.", 60, "IN", "A", "192.0.2.9")
            )
        return response

    monkeypatch.setattr(dns.query, "udp", reply)
    assert dns_probe._check_recursion("192.0.2.1") is expected


def ldap_connection(
    monkeypatch, *, contexts=("dc=example,dc=test",), entry=False, code=0, bind=True
):
    import ldap3

    connection = MagicMock()
    connection.bind.return_value = bind
    connection.result = {"result": 49 if not bind else 0}

    def search(base, *args, **kwargs):
        if not base:
            connection.entries = [
                SimpleNamespace(
                    entry_attributes_as_dict={"namingContexts": list(contexts)}
                )
            ]
            connection.result = {"result": 0}
            return True
        else:
            connection.entries = (
                [
                    SimpleNamespace(
                        entry_dn=f"cn=public,{base}",
                        entry_attributes_as_dict={"objectClass": ["person"]},
                    )
                ]
                if entry
                else []
            )
            connection.result = {"result": code}
        return code == 0

    connection.search.side_effect = search
    server = MagicMock()
    monkeypatch.setattr(ldap3, "Server", server)
    monkeypatch.setattr(ldap3, "Connection", lambda *a, **kw: connection)
    return connection, server


@pytest.mark.parametrize(
    "contexts,entry,code,expected,status",
    [
        ((), False, 0, None, "unsupported"),
        (("dc=example,dc=test",), False, 50, False, "completed_with_no_findings"),
        (("dc=example,dc=test",), True, 0, True, "completed_with_findings"),
        (("dc=example,dc=test",), False, 80, None, "failed"),
    ],
)
def test_d07_bind_and_rootdse_do_not_prove_directory_disclosure(
    monkeypatch, contexts, entry, code, expected, status
):
    ldap_connection(monkeypatch, contexts=contexts, entry=entry, code=code)
    result = ldap_probe._check_anonymous_bind("192.0.2.1", 389)
    assert result["directory_readable"] is expected
    assert result["status"] == status
    promoted = ldap_probe.run("192.0.2.1", [389])
    assert bool(promoted["cves"]) is (expected is True)


def test_d07_ldaps_uses_tls_and_refused_bind_is_negative(monkeypatch):
    connection, server = ldap_connection(monkeypatch, bind=False)
    assert (
        ldap_probe._check_anonymous_bind("192.0.2.1", 636)["directory_readable"]
        is False
    )
    assert server.call_args.kwargs["use_ssl"] is True
    connection.search.assert_not_called()


@pytest.mark.parametrize(
    "response,expected,status",
    [
        ({"ok": 0, "errmsg": "authentication required"}, None, "failed"),
        ({"ok": 1}, None, "failed"),
        ({"ok": 1, "databases": "invalid"}, None, "failed"),
        ({"ok": 1, "databases": [{"name": "public"}]}, True, "completed_with_findings"),
    ],
)
def test_d08_command_success_and_decoded_database_list_are_required(
    monkeypatch, response, expected, status
):
    import pymongo

    client = MagicMock()
    client.admin.command.return_value = response
    monkeypatch.setattr(pymongo, "MongoClient", lambda *a, **kw: client)
    result = default_creds._check_mongo_noauth("192.0.2.1")
    assert result["vulnerable"] is expected
    assert result["status"] == status
    assert client.admin.command.call_args.args[0] == {
        "listDatabases": 1,
        "nameOnly": True,
        "authorizedDatabases": False,
    }


@pytest.mark.parametrize(
    "exc,status,verdict",
    [("denied", "completed_with_no_findings", False), ("timeout", "timed_out", None)],
)
def test_d08_driver_errors_do_not_become_clean_or_vulnerable(
    monkeypatch, exc, status, verdict
):
    import pymongo
    from pymongo.errors import NetworkTimeout, OperationFailure

    client = MagicMock()
    client.admin.command.side_effect = (
        OperationFailure("denied", 13) if exc == "denied" else NetworkTimeout("timeout")
    )
    monkeypatch.setattr(pymongo, "MongoClient", lambda *a, **kw: client)
    result = default_creds._check_mongo_noauth("192.0.2.1")
    assert result["status"] == status
    assert result["vulnerable"] is verdict


@pytest.mark.parametrize("authorized", [False, True])
def test_d08_real_driver_uses_valid_modern_op_msg_against_local_fixture(authorized):
    from bson import BSON

    seen = []

    def exact(sock, count):
        data = b""
        while len(data) < count:
            chunk = sock.recv(count - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            try:
                while True:
                    length, request_id, _, opcode = struct.unpack(
                        "<iiii", exact(self.request, 16)
                    )
                    assert 16 <= length <= 100000
                    body = exact(self.request, length - 16)
                    if opcode == 2004:
                        offset = body.index(b"\x00", 4) + 9
                        command = BSON(body[offset:]).decode()
                    else:
                        assert opcode == 2013 and body[4] == 0
                        command = BSON(body[5:]).decode()
                    if "listDatabases" in command:
                        seen.append((opcode, command))
                        response = (
                            {"ok": 0, "code": 13, "errmsg": "Unauthorized"}
                            if authorized
                            else {"ok": 1, "databases": [{"name": "public"}]}
                        )
                    else:
                        response = {
                            "ok": 1,
                            "ismaster": True,
                            "isWritablePrimary": True,
                            "minWireVersion": 0,
                            "maxWireVersion": 25,
                            "maxBsonObjectSize": 16777216,
                            "maxMessageSizeBytes": 48000000,
                        }
                    encoded = BSON.encode(response)
                    payload = (
                        struct.pack("<iqii", 0, 0, 0, 1) + encoded
                        if opcode == 2004
                        else bytes(5) + encoded
                    )
                    frame = (
                        struct.pack(
                            "<iiii",
                            len(payload) + 16,
                            1,
                            request_id,
                            1 if opcode == 2004 else 2013,
                        )
                        + payload
                    )
                    self.request.sendall(frame)
            except (EOFError, ConnectionError, TimeoutError):
                pass

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    with Server(("127.0.0.1", 0), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            result = default_creds._check_mongo_noauth(
                "127.0.0.1", server.server_address[1]
            )
        finally:
            server.shutdown()
            worker.join(timeout=3)
    assert result["vulnerable"] is (not authorized)
    assert seen and seen[0][0] == 2013
    assert seen[0][1]["authorizedDatabases"] is False


@pytest.mark.parametrize(
    "exc,status",
    [
        (RuntimeError("fixture"), "failed"),
        (TimeoutError(), "timed_out"),
        (ImportError(), "unsupported"),
    ],
)
def test_d09_errors_have_outcomes_and_cannot_assert_clean(monkeypatch, exc, status):
    plugin = SimpleNamespace(__name__="fixture", run=MagicMock(side_effect=exc))
    result = VulnerabilityEngine._run_single_plugin(plugin, "192.0.2.1", [])
    assert result["_plugin_outcome"]["status"] == status
    assert result["_plugin_outcome"]["coverage_complete"] is False


def test_d09_completed_empty_partial_and_skipped_remain_distinct():
    engine = VulnerabilityEngine()
    host = {"ip_address": "192.0.2.1"}
    for name, result in [
        ("clean", result_with_outcome()),
        ("partial", {"cves": [{"id": "fixture"}]}),
        ("skip", result_with_outcome(status="skipped")),
    ]:
        engine._record_result(host, SimpleNamespace(__name__=name), result)
    assert [o["status"] for o in host["plugin_outcomes"]] == [
        "completed_with_no_findings",
        "completed_with_findings",
        "skipped",
    ]
    assert coverage_summary([host])["complete"] is False
    assert "_plugin_outcome" not in host
    assert host["cves"] == [{"id": "fixture", "execution_plugin": "partial"}]


@pytest.mark.parametrize("result", [None, [], {"cves": "invalid"}])
def test_d09_invalid_plugin_result_is_a_failed_assessment(result):
    plugin = SimpleNamespace(run=lambda *a: result)
    outcome = VulnerabilityEngine._run_single_plugin(plugin, "192.0.2.1", [])
    assert outcome["_plugin_outcome"]["status"] == "failed"


@pytest.mark.parametrize(
    "target", [None, "invalid", "192.0.2.1/24", "192.0.2.1\r\nHost: injected"]
)
def test_d09_invalid_targets_fail_before_any_plugin_dispatch(monkeypatch, target):
    import engines.vulnerability.vulnerability_engine as engine_module

    select = MagicMock()
    monkeypatch.setattr(engine_module, "select_plugins", select)
    host = {"ip_address": target}
    VulnerabilityEngine()._run_plugins(host)
    select.assert_not_called()
    assert host["plugin_coverage"]["complete"] is False
    assert host["plugin_outcomes"][0]["status"] == "failed"


@pytest.mark.parametrize(
    "targets",
    [
        ["invalid"],
        ["192.0.2.0/24", "invalid"],
        [],
        None,
        "192.0.2.1",
        ["192.0.2.1/24"],
        [1],
    ],
)
def test_d13_supplied_invalid_scope_is_rejected_before_secrets(monkeypatch, targets):
    from routers.phase_scans import HostDiscoveryRequest
    from scans.tasks import credentialed as tasks  # the module reading the resolver

    raw = [{"credential_id": "fixture", "targets": targets}]
    with pytest.raises(ValueError):
        credential_plan_entries(raw)
    resolve = MagicMock()
    monkeypatch.setattr(tasks, "_resolve_stored_credential", resolve)
    scan = SimpleNamespace(id="fixture", options={"credentials": raw})
    assert tasks._credentialed_plan_for_scan(None, scan) == []
    resolve.assert_not_called()
    with pytest.raises(ValidationError):
        HostDiscoveryRequest(targets=["192.0.2.1"], options=scan.options)


def test_d13_valid_and_omitted_scopes_preserve_intended_matching(monkeypatch):
    from scans.tasks import credentialed as tasks  # the module reading the resolver

    monkeypatch.setattr(
        tasks, "_resolve_stored_credential", lambda *a: {"username": "fixture"}
    )
    for entry, allowed in [
        ({"credential_id": "fixture", "targets": ["192.0.2.0/24"]}, False),
        ({"credential_id": "fixture"}, True),
    ]:
        plan = tasks._credentialed_plan_for_scan(
            None, SimpleNamespace(id="fixture", options={"credentials": [entry]})
        )
        assert tasks._credential_for_host(plan, "192.0.2.7") is not None
        assert (tasks._credential_for_host(plan, "198.51.100.8") is not None) is allowed
        assert tasks._credential_for_host(plan, "invalid-target") is None
    assert (
        tasks._credential_for_host([{"material": {}, "networks": []}], "192.0.2.1")
        is None
    )


@pytest.mark.parametrize("field", ["target", "scope", "networks"])
def test_d13_unknown_scope_keys_cannot_be_misread_as_omitted_scope(field):
    with pytest.raises(ValueError):
        credential_plan_entries([{"credential_id": "fixture", field: ["192.0.2.0/24"]}])


def test_d15_fresh_import_failure_affects_only_requested_plugin():
    code = """
import importlib.abc, sys
class RejectLDAP(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "engines.vulnerability.plugins.ldap_probe":
            raise ModuleNotFoundError("synthetic LDAP-only failure")
sys.meta_path.insert(0, RejectLDAP())
from engines.vulnerability import plugin_selector
assert plugin_selector._load("ssh_probe") is not None
assert plugin_selector._load("ldap_probe") is None
assert plugin_selector._load("http_analyzer") is not None
"""
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=20
    )
    assert result.returncode == 0, result.stderr
