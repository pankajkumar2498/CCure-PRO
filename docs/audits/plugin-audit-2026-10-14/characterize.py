"""Non-network audit characterizations; assertions describe the current defects.

These are evidence, not release acceptance tests. After a fix, invert the relevant
assertion and move it to Backend/tests/scans. No database or target is contacted.
Run with Backend on PYTHONPATH and SKIP_DOTENV_LOAD=1.
"""

import json
import struct
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from core.risk import deduplicate_cves
from engines.vulnerability import plugin_selector as selector
from engines.vulnerability.plugins import (
    default_creds, dns_probe, eternalblue_probe, heartbleed_probe,
    ldap_probe, nuclei_probe, smb_probe, ssh_probe,
)
from engines.vulnerability.network_checks import network_finding
from engines.vulnerability.vulnerability_engine import VulnerabilityEngine


class CurrentBehavior(unittest.TestCase):
    def selected(self, ports):
        host = {"open_ports": [{"port": p, "protocol": proto} for p, proto in ports]}
        return selector.plugin_names(selector.select_plugins_flat(host))

    def socket(self, responses):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.side_effect = responses
        return sock

    def test_D01_https_analyzer_not_dispatched(self):
        for port in (443, 8443):
            self.assertNotIn("http_analyzer", self.selected([(port, "tcp")]))

    def test_D02_default_auth_not_dispatched_for_http(self):
        for port in (80, 443, 8080, 8443):
            self.assertNotIn("default_creds", self.selected([(port, "tcp")]))
        with patch.object(default_creds, "_check_http_default_creds") as check:
            default_creds.run("192.0.2.1", [443])
            check.assert_not_called()

    def test_D03_port_selection_ignores_protocol(self):
        self.assertIn("ssh_probe", self.selected([(22, "udp")]))
        self.assertIn("tls_scanner", self.selected([(443, "udp")]))
        # A selector can see UDP evidence the invoked plugin cannot see.
        host = {"open_ports": [], "udp_services": [{"port": 53}]}
        self.assertIn("dns_probe", selector.plugin_names(selector.select_plugins_flat(host)))
        self.assertEqual(dns_probe.run("192.0.2.1", []), {})

    def test_D04_late_udp_discovery_does_not_trigger_dns(self):
        host = {"ip_address": "192.0.2.1", "is_active": True, "open_ports": []}
        with patch("engines.vulnerability.plugins.snmp_probe.run", return_value={}), \
             patch("engines.vulnerability.plugins.icmp_probe.run", return_value={}), \
             patch("engines.vulnerability.plugins.udp_scanner.run", return_value={"udp_services": [{"port": 53, "service": "DNS"}]}), \
             patch.object(nuclei_probe, "run", return_value={}), \
             patch("engines.vulnerability.plugins.cve_engine.run", return_value={}), \
             patch.object(dns_probe, "run") as dns:
            VulnerabilityEngine()._run_plugins(host)
            dns.assert_not_called()
            self.assertEqual(host["udp_services"][0]["port"], 53)

    def test_D05_ssh_mac_is_wrong_name_list(self):
        lists = [b"curve25519-sha256", b"ssh-ed25519", b"aes256-ctr", b"aes256-ctr", b"hmac-md5", b"hmac-md5", b"none", b"none", b"", b""]
        payload = b"\x14" + bytes(16) + b"".join(struct.pack(">I", len(s)) + s for s in lists) + bytes(5)
        padding = 8 - ((5 + len(payload)) % 8)
        if padding < 4:
            padding += 8
        frame = struct.pack(">I", 1 + len(payload) + padding) + bytes([padding]) + payload + bytes(padding)
        sock = self.socket([b"SSH-2.0-fixture\r\n", frame])
        with patch.object(ssh_probe.socket, "create_connection", return_value=sock):
            info = ssh_probe._probe_ssh("192.0.2.1")
        self.assertEqual(info["mac_algos"], ["aes256-ctr"])
        self.assertEqual(info["weak_algos"], [])

    def test_D06_dns_success_without_zone_is_vulnerable(self):
        # Valid DNS header and root AXFR question; NOERROR, no answers.
        response = struct.pack("!6H", 1, 0x8000, 1, 0, 0, 0) + b"\x00\x00\xfc\x00\x01"
        sock = self.socket([struct.pack("!H", len(response)), response])
        with patch.object(dns_probe.socket, "create_connection", return_value=sock):
            result = dns_probe._check_zone_transfer("192.0.2.1")
        self.assertTrue(result["vulnerable"])

    def test_D07_ldap_claims_content_without_search_result(self):
        with patch.object(ldap_probe, "_check_anonymous_bind", return_value={"allowed": True}), \
             patch.object(ldap_probe, "_query_root_dse", return_value=None):
            result = ldap_probe.run("192.0.2.1", [389])
        self.assertEqual(len(result["cves"]), 1)
        self.assertIn("returned directory content", result["cves"][0]["evidence"])

    def test_D07_ldaps_uses_plain_socket(self):
        sock = self.socket([b""])
        with patch.object(ldap_probe.socket, "create_connection", return_value=sock):
            ldap_probe._check_anonymous_bind("192.0.2.1", 636)
        sent = sock.sendall.call_args.args[0]
        self.assertEqual(sent[0], 0x30)  # LDAP BER, not a TLS record.

    def test_D08_mongodb_error_with_ok_field_claims_no_auth(self):
        # OP_REPLY-like header followed by a BSON error {ok: 0, errmsg: ...}.
        body = b"\x01ok\x00" + struct.pack("<d", 0.0) + b"\x02errmsg\x00" + b"authentication required\x00"
        sock = self.socket([bytes(36) + body])
        with patch.object(default_creds.socket, "create_connection", return_value=sock):
            result = default_creds._check_mongo_noauth("192.0.2.1")
        self.assertTrue(result["vulnerable"])
        query = sock.sendall.call_args.args[0]
        bson_at = 16 + 4 + len(b"admin.$cmd\x00") + 8
        declared = struct.unpack_from("<i", query, bson_at)[0]
        self.assertNotEqual(declared, len(query) - bson_at)

    def test_D09_parallel_exception_is_empty_success_shape(self):
        plugin = SimpleNamespace(run=MagicMock(side_effect=RuntimeError("fixture failure")))
        self.assertEqual(VulnerabilityEngine._run_single_plugin(plugin, "192.0.2.1", []), {})

    def test_D10_endpoint_evidence_is_lost_in_dedup(self):
        records = [network_finding("tls.certificate_expired", f"expired on {port}", target=f"192.0.2.1:{port}", port=port) for port in (443, 8443)]
        merged = deduplicate_cves(records)
        self.assertEqual(len(merged), 1)
        self.assertNotIn("8443", merged[0]["evidence"])
        self.assertEqual(merged[0]["port"], 443)

    def test_D11_heartbleed_skips_supported_ports(self):
        for port in (465, 993, 995, 8000, 8888):
            self.assertNotIn("heartbleed_probe", self.selected([(port, "tcp")]))
        with patch.object(heartbleed_probe, "_check_heartbleed", return_value={"vulnerable": False}), \
             patch.object(heartbleed_probe, "_check_shellshock", return_value={"vulnerable": False}) as check:
            heartbleed_probe.run("192.0.2.1", [80, 8080])
            self.assertEqual(check.call_count, 1)

    def test_D12_smb_probe_bad_frame_eternalblue_control_valid(self):
        # The server must wait for the declared NBSS payload before parsing.
        sock = self.socket([b""])
        with patch.object(smb_probe.socket, "create_connection", return_value=sock):
            smb_probe._probe_smb("192.0.2.1", 445)
        frame = sock.sendall.call_args.args[0]
        self.assertNotEqual(int.from_bytes(frame[1:4], "big"), len(frame) - 4)
        frame = eternalblue_probe._SMB_NEG_REQ
        self.assertEqual(int.from_bytes(frame[1:4], "big"), len(frame) - 4)

    def test_D13_invalid_credential_scope_becomes_global(self):
        from core import tasks
        scan = SimpleNamespace(id="fixture", options={"credentials": [{"credential_id": "fixture", "targets": ["not-a-network"]}]})
        with patch.object(tasks, "_resolve_stored_credential", return_value={"username": "fixture"}):
            plan = tasks._credentialed_plan_for_scan(None, scan)
        self.assertIsNone(plan[0]["networks"])
        self.assertIsNotNone(tasks._credential_for_host(plan, "198.51.100.8"))

    def test_D14_nuclei_exit_one_can_be_marked_complete(self):
        with patch.object(nuclei_probe, "_resolve_binary", return_value="fixture"), \
             patch.object(nuclei_probe.Path, "is_dir", return_value=True), \
             patch.object(nuclei_probe.subprocess, "run", return_value=SimpleNamespace(returncode=1, stderr="fixture fatal error")):
            result = nuclei_probe.run("192.0.2.1", [80])
        self.assertEqual(result, {"nuclei_templates_run": True, "cves": []})

    def test_D15_eager_package_failure_blocks_unrelated_plugin(self):
        code = '''
import importlib.abc, sys
class RejectLDAP(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "engines.vulnerability.plugins.ldap_probe":
            raise ModuleNotFoundError("synthetic LDAP-only import failure")
sys.meta_path.insert(0, RejectLDAP())
from engines.vulnerability import plugin_selector
result = plugin_selector._load("ssh_probe")
assert result is None
assert plugin_selector._plugin_cache["ssh_probe"] is None
print("SSH withheld and negatively cached after LDAP-only import failure")
'''
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SSH withheld", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
