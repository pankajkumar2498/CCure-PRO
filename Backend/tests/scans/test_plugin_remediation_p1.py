"""Corrected P1 assertions; responses are local fixtures, never external targets."""

import io
import json
import socketserver
import struct
import subprocess
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from core.checks.plugin_outcomes import result_with_outcome
from core.checks.probe_endpoints import ProbePorts
from core.risk import deduplicate_cves
from engines.vulnerability import plugin_selector as selector
from engines.vulnerability.network_checks import network_finding
from engines.vulnerability.plugins import (
    default_creds,
    heartbleed_probe,
    http_analyzer,
    nuclei_probe,
    smb_probe,
    ssh_probe,
)
from engines.vulnerability.vulnerability_engine import VulnerabilityEngine


def selected(port, protocol="tcp", service=""):
    host = {"open_ports": [{"port": port, "protocol": protocol, "service": service}]}
    return selector.selected_plugin_names(host)


@pytest.mark.parametrize("port", [443, 8443])
def test_d01_https_only_selects_http_analysis(port):
    assert "http_analyzer" in selected(port)


@pytest.mark.parametrize("port", [80, 8080, 8000, 8888, 443, 8443])
def test_d02_web_only_selects_authentication_check(port):
    assert "default_creds" in selected(port)


def test_d01_d02_all_http_and_https_endpoints_are_probed(monkeypatch):
    seen = []

    def analyze(ip, port, tls):
        seen.append((port, tls))
        return {"http_audit": {"status_code": 200}, "cves": []}

    monkeypatch.setattr(http_analyzer, "_run_endpoint", analyze)
    result = http_analyzer.run("192.0.2.1", [80, 443, 8080, 8443])
    assert set(seen) == {(80, False), (443, True), (8080, False), (8443, True)}
    assert len(result["http_endpoints"]) == 4
    check = MagicMock(
        return_value={"found": False, "status": "completed_with_no_findings"}
    )
    monkeypatch.setattr(default_creds, "_check_http_default_creds", check)
    result = default_creds.run("192.0.2.1", [80, 443, 8443])
    assert [(c.args[1], c.kwargs["use_tls"]) for c in check.call_args_list] == [
        (80, False),
        (443, True),
        (8443, True),
    ]
    assert result["_plugin_outcome"]["status"] == "completed_with_no_findings"


@pytest.mark.parametrize(
    "accept,challenge,expected,status",
    [
        (True, "Basic realm=fixture", True, "completed_with_findings"),
        (False, "Basic realm=fixture", False, "completed_with_no_findings"),
        (True, "Digest realm=fixture", None, "unsupported"),
    ],
)
def test_d02_real_basic_auth_positive_negative_and_unsupported(
    accept, challenge, expected, status
):
    credentials = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            auth = self.headers.get("Authorization")
            if auth:
                credentials.append(auth)
            code = 200 if accept and auth == "Basic YWRtaW46YWRtaW4=" else 401
            self.send_response(code)
            self.send_header("WWW-Authenticate", challenge)
            self.send_header("Content-Length", "0")
            self.end_headers()

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            result = default_creds._check_http_default_creds(
                "127.0.0.1", server.server_address[1]
            )
        finally:
            server.shutdown()
            worker.join(timeout=3)
    assert result["found"] is expected
    assert result["status"] == status
    assert bool(credentials) is challenge.startswith("Basic")


@pytest.mark.parametrize(
    "port,plugin",
    [
        (22, "ssh_probe"),
        (443, "tls_scanner"),
        (389, "ldap_probe"),
        (27017, "default_creds"),
    ],
)
def test_d03_udp_numbers_do_not_dispatch_tcp_probes(port, plugin):
    assert plugin not in selected(port, "udp")
    assert plugin in selected(port, "tcp")


def test_d03_service_identity_overrides_number_and_reaches_custom_port(monkeypatch):
    assert "ssh_probe" not in selected(22, service="https")
    assert "http_analyzer" in selected(22, service="https")
    assert "ssh_probe" in selected(2222, service="ssh")
    ports = ProbePorts(
        {
            "open_ports": [
                {"port": 2222, "service": "ssh", "protocol": "tcp"},
                {"port": 22, "protocol": "udp"},
            ]
        }
    )
    check = MagicMock(
        return_value={"weak_algos": [], "status": "completed_with_no_findings"}
    )
    monkeypatch.setattr(ssh_probe, "_probe_ssh", check)
    result = ssh_probe.run("192.0.2.1", ports)
    check.assert_called_once_with("192.0.2.1", 2222)
    assert result["_plugin_outcome"]["endpoints"][0]["protocol"] == "tcp"
    assert result["_plugin_outcome"]["endpoints"][0]["service"] == "ssh"


@pytest.mark.parametrize("tls", [False, True])
def test_d03_nmap_xml_retains_tls_service_identity(tls):
    from core.nmap.wrapper import NmapScanner

    tunnel = ' tunnel="ssl"' if tls else ""
    xml = f'<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="9443"><state state="open"/><service name="http"{tunnel}/></port></ports></host></nmaprun>'
    scanner = NmapScanner.__new__(NmapScanner)
    result = scanner._parse_xml(xml, 0)
    assert result.ports[0].service == ("ssl/http" if tls else "http")
    assert "http_analyzer" in selected(9443, service=result.ports[0].service)
    assert ("tls_scanner" in selected(9443, service=result.ports[0].service)) is tls


@pytest.mark.parametrize("tls", [False, True])
def test_d03_python_nmap_retains_tls_service_identity(tls):
    from core.nmap.wrapper import NmapScanner

    host = MagicMock()
    host.state.return_value = "up"
    host.hostnames.return_value = []
    host.all_protocols.return_value = ["tcp"]
    host.__getitem__.return_value = {
        9443: {"name": "http", "state": "open", "tunnel": "ssl" if tls else ""}
    }
    host.get.side_effect = lambda key, default=None: default
    result = NmapScanner.__new__(NmapScanner)._parse_python_nmap(
        {"192.0.2.1": host}, "192.0.2.1", 0
    )
    assert result.ports[0].service == ("ssl/http" if tls else "http")


@pytest.mark.parametrize(
    "banner,expected", [("220 fixture", True), ("HTTP/1.1 200 OK", False)]
)
def test_d03_ftp_custom_endpoints_require_ftp_evidence(monkeypatch, banner, expected):
    from engines.vulnerability.plugins import ftp_checker

    probe = MagicMock(return_value={"banner": banner, "anonymous_login": True})
    monkeypatch.setattr(ftp_checker, "_probe_ftp", probe)
    ports = ProbePorts(
        {
            "open_ports": [
                {"port": port, "protocol": "tcp", "service": "ftp"}
                for port in (21, 2121)
            ]
        }
    )
    result = ftp_checker.run("192.0.2.1", ports)
    assert probe.call_count == 2
    assert bool(result["cves"]) is expected
    if expected:
        assert {f["port"] for f in result["cves"]} == {21, 2121}
    else:
        assert result["_plugin_outcome"]["status"] == "failed"


@pytest.mark.parametrize("initial_dns", [False, True])
def test_d04_late_udp_discovery_dispatches_dns_once(monkeypatch, initial_dns):
    calls = []

    def plugin(name):
        def run(ip, ports, *details):
            calls.append(name)
            if name == "udp_scanner":
                return result_with_outcome(
                    {"udp_services": [{"port": 53, "service": "DNS"}]}
                )
            if name == "dns_probe":
                assert any(e["port"] == 53 for e in ports.endpoints)
            return result_with_outcome()

        return SimpleNamespace(__name__=name, run=run)

    monkeypatch.setattr(selector, "_load", plugin)
    host = {
        "ip_address": "192.0.2.1",
        "open_ports": [{"port": 53, "protocol": "tcp"}] if initial_dns else [],
    }
    VulnerabilityEngine()._run_plugins(host)
    assert calls.count("dns_probe") == 1
    assert calls.count("udp_scanner") == 1
    assert len(calls) <= 6


class FragmentSocket:
    def __init__(self, data, chunk=1):
        self.data = data
        self.chunk = chunk
        self.sent = []

    def recv(self, count):
        size = min(count, self.chunk)
        data, self.data = self.data[:size], self.data[size:]
        return data

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, timeout):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def ssh_frame(mac_c2s=b"hmac-sha2-256", mac_s2c=b"hmac-md5", cipher_s2c=b"aes256-ctr"):
    lists = [
        b"curve25519-sha256",
        b"ssh-ed25519",
        b"aes256-ctr",
        cipher_s2c,
        mac_c2s,
        mac_s2c,
        b"none",
        b"none",
        b"",
        b"",
    ]
    payload = (
        b"\x14"
        + bytes(16)
        + b"".join(struct.pack("!I", len(value)) + value for value in lists)
        + bytes(5)
    )
    padding = 8 - (5 + len(payload)) % 8
    if padding < 4:
        padding += 8
    return (
        struct.pack("!I", 1 + len(payload) + padding)
        + bytes([padding])
        + payload
        + bytes(padding)
    )


@pytest.mark.parametrize("chunk", [1, 3, 8192])
@pytest.mark.parametrize("weak", [False, True])
def test_d05_correct_directional_mac_lists_and_fragmented_reads(
    monkeypatch, chunk, weak
):
    frame = ssh_frame(mac_s2c=b"hmac-md5" if weak else b"hmac-sha2-256")
    sock = FragmentSocket(b"SSH-2.0-fixture\r\n" + frame, chunk)
    monkeypatch.setattr(ssh_probe.socket, "create_connection", lambda *a, **kw: sock)
    info = ssh_probe._probe_ssh("192.0.2.1")
    assert info["status"] == (
        "completed_with_findings" if weak else "completed_with_no_findings"
    )
    assert ("Weak MAC: hmac-md5" in info["weak_algos"]) is weak
    assert info["enc_algos"] == ["aes256-ctr"]
    assert info["mac_algos_s2c"] == (["hmac-md5"] if weak else ["hmac-sha2-256"])


@pytest.mark.parametrize(
    "data",
    [
        b"SSH-1.5-fixture\r\n",
        b"SSH-2.0-fixture\r\n" + struct.pack("!I", 40000),
        b"SSH-2.0-fixture\r\n" + ssh_frame()[:-1],
    ],
)
def test_d05_unsupported_or_truncated_ssh_does_not_assert_clean(monkeypatch, data):
    sock = FragmentSocket(data)
    monkeypatch.setattr(ssh_probe.socket, "create_connection", lambda *a, **kw: sock)
    assert ssh_probe._probe_ssh("192.0.2.1")["status"] in {"failed", "unsupported"}


def test_d10_dedup_retains_both_endpoint_evidence_and_paths():
    records = [
        network_finding(
            "tls.certificate_expired",
            f"certificate-{port}",
            target=f"192.0.2.1:{port}",
            port=port,
        )
        for port in (443, 8443)
    ]
    merged = deduplicate_cves(records)
    assert len(merged) == 1
    assert {o["port"] for o in merged[0]["endpoint_observations"]} == {443, 8443}
    assert (
        "certificate-443" in merged[0]["evidence"]
        and "certificate-8443" in merged[0]["evidence"]
    )
    assert len(deduplicate_cves(records, by_endpoint=True)) == 2
    assert len(deduplicate_cves(merged)) == 1


def test_d10_each_endpoint_is_verified_before_logical_aggregation():
    affected = [
        {
            "vendor": "nginx",
            "product": "nginx",
            "versionEndExcluding": "1.27.0",
            "cpe23Uri": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
        }
    ]
    host = {
        "ip_address": "192.0.2.1",
        "is_active": True,
        "open_ports": [
            {
                "port": port,
                "protocol": "tcp",
                "service": "http",
                "product": "nginx",
                "version": version,
            }
            for port, version in [(80, "1.26.0"), (8080, "1.28.0")]
        ],
        "cves": [
            {
                "cve_id": "CVE-9999-1010",
                "port": port,
                "affected": affected,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
            for port in (80, 8080)
        ],
    }
    VulnerabilityEngine._verify_host(host)
    assert len(host["cves"]) == 1
    assert {o["port"] for o in host["cves"][0]["endpoint_observations"]} == {80}
    assert len(host["suppressed_cves"]) == 1


def test_d10_aggregation_does_not_relabel_derived_evidence_as_captured():
    from core.checks.finding_normalizer import _build_evidence, DetectionMethod

    finding = deduplicate_cves(
        [
            {
                "cve_id": "CVE-9999-1010",
                "port": 80,
                "evidence": "Derived version observation",
                "evidence_captured": False,
            }
        ]
    )[0]
    _, captured = _build_evidence(
        finding, None, "", DetectionMethod.UNVERIFIED, "CVE-9999-1010"
    )
    assert captured is False


@pytest.mark.parametrize("port", [465, 993, 995, 8000, 8888])
def test_d11_supported_active_probe_ports_are_selected(port):
    assert "heartbleed_probe" in selected(port)


def test_d11_first_negative_does_not_hide_second_affected_endpoint(monkeypatch):
    monkeypatch.setattr(
        heartbleed_probe,
        "_check_heartbleed",
        lambda ip, port: {
            "vulnerable": port == 8443,
            "status": (
                "completed_with_findings"
                if port == 8443
                else "completed_with_no_findings"
            ),
        },
    )
    monkeypatch.setattr(
        heartbleed_probe,
        "_check_shellshock",
        lambda ip, port, **kw: {
            "vulnerable": port == 8080,
            "status": (
                "completed_with_findings"
                if port == 8080
                else "completed_with_no_findings"
            ),
        },
    )
    result = heartbleed_probe.run("192.0.2.1", [443, 8443, 80, 8080])
    assert {(f["cve_id"], f["port"]) for f in result["cves"]} == {
        ("CVE-2014-0160", 8443),
        ("CVE-2014-6271", 8080),
    }


def tls_record(kind, body):
    return bytes([kind]) + b"\x03\x03" + struct.pack("!H", len(body)) + body


def tls_handshake(heartbeat=True):
    extensions = b"\x00\x0f\x00\x01\x01" if heartbeat else b""
    hello = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00\x00\x2f\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    return tls_record(
        22, b"\x02" + len(hello).to_bytes(3, "big") + hello + b"\x0e\x00\x00\x00"
    )


@pytest.mark.parametrize(
    "payload,expected,status",
    [
        (b"\x02\x00\x08" + b"leakdata" + bytes(16), True, "completed_with_findings"),
        (b"\x02\x00\x00" + bytes(16), False, "completed_with_no_findings"),
        (b"\x02\x40\x00xx", None, "failed"),
    ],
)
def test_d11_coalesced_handshake_fragmented_tls_and_actual_heartbeat_payload(
    monkeypatch, payload, expected, status
):
    sock = FragmentSocket(tls_handshake() + tls_record(24, payload))
    monkeypatch.setattr(
        heartbleed_probe.socket, "create_connection", lambda *a, **kw: sock
    )
    result = heartbleed_probe._check_heartbleed("192.0.2.1", 443)
    assert result["vulnerable"] is expected
    assert result["status"] == status
    assert len(sock.sent) == 2


def test_d11_no_heartbeat_negotiation_means_no_active_request(monkeypatch):
    sock = FragmentSocket(tls_handshake(False))
    monkeypatch.setattr(
        heartbleed_probe.socket, "create_connection", lambda *a, **kw: sock
    )
    assert (
        heartbleed_probe._check_heartbleed("192.0.2.1", 443)["status"] == "unsupported"
    )
    assert len(sock.sent) == 1


@pytest.mark.parametrize(
    "mode,expected", [("execute", True), ("reflect", False), ("clean", False)]
)
def test_d11_shellshock_requires_execution_and_negative_reflection_control(
    monkeypatch, mode, expected
):
    def open_request(request, **kw):
        value = request.get_header("User-agent")
        body = (
            value
            if mode == "reflect"
            else (
                value.rsplit(" ", 1)[-1]
                if mode == "execute" and value.startswith("()")
                else "healthy"
            )
        )
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = body.encode()
        return response

    opener = SimpleNamespace(open=open_request)
    monkeypatch.setattr(
        heartbleed_probe.urllib.request, "build_opener", lambda *a: opener
    )
    assert heartbleed_probe._check_shellshock("192.0.2.1", 80)["vulnerable"] is expected


def smb_response(version="v1", status=0):
    if version == "v1":
        body = bytearray(69)
        body[:4] = b"\xffSMB"
        body[4], body[9], body[32] = 0x72, 0x80, 17
        struct.pack_into("<I", body, 5, status)
    else:
        body = bytearray(128)
        body[:4] = b"\xfeSMB"
        struct.pack_into("<H", body, 4, 64)
        struct.pack_into("<I", body, 8, status)
        struct.pack_into("<I", body, 16, 1)
        struct.pack_into("<H", body, 64, 65)
        struct.pack_into("<H", body, 68, 0x0202)
    return bytes(1) + len(body).to_bytes(3, "big") + body


@pytest.mark.parametrize("version", ["v1", "v2"])
def test_d12_correct_request_is_accepted_by_length_aware_local_smb_fixture(version):
    seen = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            header = bytearray()
            while len(header) < 4:
                header.extend(self.request.recv(4 - len(header)))
            count = int.from_bytes(header[1:], "big")
            payload = bytearray()
            while len(payload) < count:
                chunk = self.request.recv(count - len(payload))
                if not chunk:
                    break
                payload.extend(chunk)
            assert payload[:4] == b"\xffSMB" and payload[32] == 0
            assert struct.unpack_from("<H", payload, 33)[0] == len(payload) - 35
            assert payload[35:] == b"\x02NT LM 0.12\x00\x02SMB 2.002\x00"
            seen.append(bytes(payload))
            for byte in smb_response(version):
                self.request.sendall(bytes([byte]))

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        worker = threading.Thread(target=server.handle_request, daemon=True)
        worker.start()
        result = smb_probe._probe_smb("127.0.0.1", server.server_address[1])
        worker.join(timeout=3)
    assert seen
    assert result["version"] == ("SMBv1" if version == "v1" else "SMBv2/3")
    assert result["null_session"] is None


@pytest.mark.parametrize(
    "response",
    [
        b"\x00\x00\x00\x40\xffSMB",
        smb_response(status=0xC0000022),
        b"\x00\x00\x00\x04oops",
    ],
)
def test_d12_malformed_or_error_reply_does_not_claim_smbv1(monkeypatch, response):
    sock = FragmentSocket(response)
    monkeypatch.setattr(smb_probe.socket, "create_connection", lambda *a, **kw: sock)
    info = smb_probe._probe_smb("192.0.2.1", 445)
    assert info["version"] == ""
    assert info["status"] in {"failed", "unsupported"}


def test_d12_netbios_session_must_be_established_first(monkeypatch):
    sock = FragmentSocket(b"\x82\x00\x00\x00" + smb_response())
    monkeypatch.setattr(smb_probe.socket, "create_connection", lambda *a, **kw: sock)
    assert smb_probe._probe_smb("192.0.2.1", 139)["version"] == "SMBv1"
    assert sock.sent[0][0] == 0x81 and len(sock.sent[0]) - 4 == int.from_bytes(
        sock.sent[0][1:4], "big"
    )
    assert sock.sent[1] == smb_probe._negotiate_request()


@pytest.mark.parametrize(
    "exitcode,timeout,expected",
    [
        (0, False, "completed_with_findings"),
        (1, False, "failed"),
        (2, False, "failed"),
        (0, True, "timed_out"),
    ],
)
def test_d14_partial_nuclei_matches_survive_error_and_timeout(
    monkeypatch, tmp_path, exitcode, timeout, expected
):
    monkeypatch.setattr(nuclei_probe, "_resolve_binary", lambda: "fixture")
    monkeypatch.setattr(nuclei_probe, "_TEMPLATE_DIR", str(tmp_path))

    def execute(argv, **kw):
        output = Path(argv[argv.index("-output") + 1])
        output.write_text(
            json.dumps(
                {
                    "template-id": "fixture",
                    "info": {
                        "name": "Fixture",
                        "severity": "high",
                        "classification": {"cve-id": ["CVE-9999-1414"]},
                    },
                    "matched-at": "http://192.0.2.1:80/affected",
                }
            )
            + "\n"
        )
        if timeout:
            raise subprocess.TimeoutExpired(argv, 1)
        return SimpleNamespace(
            returncode=exitcode, stderr="fixture error" if exitcode else ""
        )

    monkeypatch.setattr(nuclei_probe.subprocess, "run", execute)
    result = nuclei_probe.run("192.0.2.1", [80])
    assert result["_plugin_outcome"]["status"] == expected
    assert result["cves"][0]["cve_id"] == "CVE-9999-1414"
    assert result["_plugin_outcome"]["coverage_complete"] is (
        exitcode == 0 and not timeout
    )


@pytest.mark.parametrize(
    "code,expected", [(0, "completed_with_no_findings"), (1, "failed")]
)
def test_d14_empty_result_requires_successful_execution(
    monkeypatch, tmp_path, code, expected
):
    monkeypatch.setattr(nuclei_probe, "_resolve_binary", lambda: "fixture")
    monkeypatch.setattr(nuclei_probe, "_TEMPLATE_DIR", str(tmp_path))
    monkeypatch.setattr(
        nuclei_probe.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=code, stderr="fixture"),
    )
    result = nuclei_probe.run("192.0.2.1", [80])
    assert result["_plugin_outcome"]["status"] == expected
    assert result["nuclei_templates_run"] is (code == 0)


def test_d14_malformed_lines_do_not_discard_valid_partial_matches(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(nuclei_probe, "_resolve_binary", lambda: "fixture")
    monkeypatch.setattr(nuclei_probe, "_TEMPLATE_DIR", str(tmp_path))

    def execute(argv, **kw):
        Path(argv[argv.index("-output") + 1]).write_text(
            "broken JSON\n"
            + json.dumps(
                {
                    "template-id": "fixture",
                    "info": {"name": "Fixture", "severity": "high"},
                    "matched-at": "http://192.0.2.1:80/exposed",
                }
            )
            + "\n[]\n"
        )
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(nuclei_probe.subprocess, "run", execute)
    result = nuclei_probe.run("192.0.2.1", [80])
    assert len(result["cves"]) == 1
    assert result["_plugin_outcome"]["status"] == "failed"
    assert result["nuclei_execution"]["malformed_records"] == 2
