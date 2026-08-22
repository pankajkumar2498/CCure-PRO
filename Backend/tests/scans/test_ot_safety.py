import ipaddress
import logging
import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

# Configure logging to capture audit logs during tests
logging.basicConfig(level=logging.INFO)


class TestOTSafetyAndStability(unittest.TestCase):
    """Test suite verifying OT/ICS safety and stability enhancements."""

    def setUp(self):
        self.ip = "192.168.1.100"
        self.ot_ports = {
            502,
            102,
            44818,
            47808,
            20000,
            4840,
            2404,
            18245,
            9600,
            5007,
            2455,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # 1. Socket Option Configuration Tests
    # ─────────────────────────────────────────────────────────────────────────

    def test_configure_safe_socket_tcp(self):
        """Verify that _configure_safe_socket sets SO_LINGER and SO_BROADCAST on TCP sockets."""
        from core.discovery.techniques.ot_probes import _configure_safe_socket

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            _configure_safe_socket(s)

            # Verify SO_BROADCAST is disabled (0)
            try:
                broadcast = s.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST)
                self.assertEqual(broadcast, 0)
            except OSError as e:
                # Windows (Winsock) throws WSAENOPROTOOPT (10042) on TCP stream sockets
                if getattr(e, "winerror", None) != 10042:
                    raise

            # Verify SO_LINGER is enabled with timeout=0 (sends TCP RST on close)
            linger_opt = s.getsockopt(socket.SOL_SOCKET, socket.SO_LINGER, 8)
            if len(linger_opt) == 4:
                onoff, linger = struct.unpack("hh", linger_opt)
            else:
                onoff, linger = struct.unpack("ii", linger_opt)
            self.assertEqual(onoff, 1)
            self.assertEqual(linger, 0)
        finally:
            s.close()

    def test_configure_safe_socket_udp(self):
        """Verify that _configure_safe_socket disables SO_BROADCAST and doesn't crash on UDP (no SO_LINGER)."""
        from core.discovery.techniques.ot_probes import _configure_safe_socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Should not raise OSError: [Errno 10022] (Protocol not available)
            _configure_safe_socket(s)

            broadcast = s.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST)
            self.assertEqual(broadcast, 0)
        finally:
            s.close()

    # ─────────────────────────────────────────────────────────────────────────
    # 2. IP Blacklisting & Exclusions Tests
    # ─────────────────────────────────────────────────────────────────────────

    @patch("config.AppConfig.SCAN_IP_BLACKLIST", [ipaddress.ip_network("10.0.0.0/8")])
    def test_is_blacklisted_global(self):
        """Verify that IPs in the global blacklist are detected."""
        from orchestrator.scan_orchestrator import ScanOrchestrator

        self.assertTrue(ScanOrchestrator._is_blacklisted("10.1.2.3"))
        self.assertFalse(ScanOrchestrator._is_blacklisted("192.168.1.1"))

    def test_is_blacklisted_custom(self):
        """Verify that IPs in the per-scan exclude list are detected."""
        from orchestrator.scan_orchestrator import ScanOrchestrator

        custom_exclude = ScanOrchestrator._parse_exclude_ips(
            "192.168.0.0/16,172.16.0.5"
        )

        self.assertTrue(
            ScanOrchestrator._is_blacklisted("192.168.1.50", custom_exclude)
        )
        self.assertTrue(ScanOrchestrator._is_blacklisted("172.16.0.5", custom_exclude))
        self.assertFalse(ScanOrchestrator._is_blacklisted("172.16.0.6", custom_exclude))

    @patch("config.AppConfig.SCAN_IP_BLACKLIST", [ipaddress.ip_network("10.0.0.0/8")])
    def test_expand_targets_filtering(self):
        """Verify target expansion filters out blacklisted and custom excluded IPs."""
        from orchestrator.scan_orchestrator import ScanOrchestrator

        targets = ["10.1.1.1", "192.168.1.1-192.168.1.3", "172.16.0.1"]
        custom_exclude = ScanOrchestrator._parse_exclude_ips("172.16.0.1,192.168.1.2")

        expanded = ScanOrchestrator._expand_targets(targets, custom_exclude)

        # 10.1.1.1 is globally blacklisted
        # 172.16.0.1 is custom excluded
        # 192.168.1.2 is custom excluded
        # Remaining should only be 192.168.1.1 and 192.168.1.3
        self.assertEqual(expanded, ["192.168.1.1", "192.168.1.3"])

    # ─────────────────────────────────────────────────────────────────────────
    # 3. Sequential Probing & Auditing Tests
    # ─────────────────────────────────────────────────────────────────────────

    @patch("core.discovery.enrichment._is_port_connectable", return_value=True)
    @patch("core.discovery.techniques.ot_probes.probe_modbus")
    @patch("core.discovery.techniques.ot_probes.probe_s7")
    def test_ot_probes_sequential_execution(
        self, mock_s7, mock_modbus, mock_connectable
    ):
        """Verify that OT probes execute sequentially and break early on successful match."""
        from core.discovery.enrichment import _ot_protocol_probes

        # Configure mock_modbus to return a valid match
        mock_modbus.return_value = {"protocol": "modbus", "vendor": "Schneider"}
        # Configure mock_s7 (which would run after Modbus in candidate list)
        mock_s7.return_value = {"protocol": "s7", "vendor": "Siemens"}

        result = {
            "port_states": {502: "open", 102: "open"},
            "confirmations": [],
            "open_ports": [],
        }

        with self.assertLogs("ccure.audit", level="INFO") as log_capture:
            _ot_protocol_probes(self.ip, result)

            # Assert Modbus was initiated
            self.assertTrue(
                any(
                    "INITIATING MODBUS PROBE" in line.upper()
                    for line in log_capture.output
                )
            )
            # Assert Modbus matched successfully
            self.assertTrue(
                any(
                    "SUCCESSFULLY IDENTIFIED MODBUS" in line.upper()
                    for line in log_capture.output
                )
            )
            # Assert early break (S7 should NOT have been initiated because Modbus matched)
            self.assertFalse(
                any(
                    "INITIATING S7_OR_MMS PROBE" in line.upper()
                    for line in log_capture.output
                )
            )
            mock_s7.assert_not_called()

    # ─────────────────────────────────────────────────────────────────────────
    # 4. Passive-First Bypass Tests
    # ─────────────────────────────────────────────────────────────────────────

    @patch("orchestrator.scan_orchestrator.PortEngine")
    def test_passive_first_bypass(self, mock_port_engine_class):
        """Verify that passive-first bypasses active port scanning for pre-resolved hosts."""
        from unittest.mock import AsyncMock

        from orchestrator.scan_orchestrator import ScanOrchestrator

        mock_port_engine = MagicMock()
        mock_port_engine.run = AsyncMock()
        mock_port_engine_class.return_value = mock_port_engine

        hosts = [
            # Host 1: Already resolved passively (has device category)
            {
                "ip_address": "192.168.1.10",
                "is_active": True,
                "device_category": "plc",
                "vendor": "Rockwell",
            },
            # Host 2: Not resolved (unknown/N/A)
            {
                "ip_address": "192.168.1.11",
                "is_active": True,
                "device_category": "unknown",
                "vendor": "N/A",
            },
        ]

        orchestrator = ScanOrchestrator()
        import asyncio

        loop = asyncio.get_event_loop()

        loop.run_until_complete(
            orchestrator.run_asset_discovery_only(
                hosts=hosts, passive_first=True, exclude_ot_from_nmap=False
            )
        )

        # Verify PortEngine was called
        mock_port_engine.run.assert_called_once()
        # Verify only Host 2 (unresolved) was passed to the PortEngine active scan
        called_hosts = mock_port_engine.run.call_args[0][0]
        self.assertEqual(len(called_hosts), 1)
        self.assertEqual(called_hosts[0]["ip_address"], "192.168.1.11")

    # ─────────────────────────────────────────────────────────────────────────
    # 5. Nmap OT Port Exclusion Tests
    # ─────────────────────────────────────────────────────────────────────────

    def test_port_engine_excludes_ot_ports(self):
        """Verify that PortEngine excludes OT ports from Nmap scan list when enabled."""
        from core.models import ScanIntensity
        from engines.port.port_engine import PortEngine

        engine_exclude = PortEngine(
            intensity=ScanIntensity.NORMAL, exclude_ot_from_nmap=True
        )
        ports_exclude = engine_exclude._port_list()

        # None of the OT ports should be in the Nmap scan list
        for ot_port in self.ot_ports:
            self.assertNotIn(ot_port, ports_exclude)

        engine_include = PortEngine(
            intensity=ScanIntensity.NORMAL, exclude_ot_from_nmap=False
        )
        ports_include = engine_include._port_list()

        # At least port 102 and 502 should be in the default system scan list (1-1024)
        self.assertIn(102, ports_include)
        self.assertIn(502, ports_include)

    # ─────────────────────────────────────────────────────────────────────────
    # 6. OS Inference Gating Tests
    # ─────────────────────────────────────────────────────────────────────────

    @patch("core.discovery.enrichment._ot_protocol_probes")
    def test_apply_os_inference_gating(self, mock_ot_probes):
        """Verify that _apply_os_inference gates OT probing using the ot_enrichment parameter."""
        from orchestrator.scan_orchestrator import ScanOrchestrator

        hosts = [{"ip_address": "192.168.1.20", "is_active": True}]

        # Case 1: ot_enrichment = False (e.g. Basic Discovery or Phase 1 Asset Discovery)
        ScanOrchestrator._apply_os_inference(hosts, ot_enrichment=False)
        mock_ot_probes.assert_not_called()

        # Case 2: ot_enrichment = True (e.g. Phase 2 Port Scan or Vulnerability Audit)
        ScanOrchestrator._apply_os_inference(hosts, ot_enrichment=True)
        mock_ot_probes.assert_called_once_with("192.168.1.20", hosts[0])

    # ─────────────────────────────────────────────────────────────────────────
    # 7. Static Payload Analysis (Write Prevention)
    # ─────────────────────────────────────────────────────────────────────────

    def test_static_analysis_prevent_write_commands(self):
        """Analyze ot_probes.py source code to verify no write/control payloads are defined."""
        import os

        probes_file_path = os.path.join(
            os.path.dirname(__file__), "../core/discovery/techniques/ot_probes.py"
        )

        # Ensure the file exists
        self.assertTrue(os.path.exists(probes_file_path))

        with open(probes_file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # 1. Check for Modbus Write Function Codes:
        # FC 5 (Write Single Coil), FC 6 (Write Single Register), FC 15 (Write Multiple Coils), FC 16 (Write Multiple Registers)
        # In Modbus TCP request headers, the function code is at byte 7.
        # Ensure no byte literals contain write FCs in Modbus sections.
        # FC 5: \x05, FC 6: \x06, FC 15: \x0f, FC 16: \x10
        # A Modbus request typically starts with transaction ID, protocol ID, length, unit ID, function code.
        # Example Modbus read request: b"\x00\x01\x00\x00\x00\x05\x01\x2b..." (FC 2B/43 is Read ID)
        # We search for hex bytes corresponding to write FCs right after unit ID (usually \x01).
        self.assertNotIn(r"\x01\x05", content)
        self.assertNotIn(r"\x01\x06", content)
        self.assertNotIn(r"\x01\x0f", content)
        self.assertNotIn(r"\x01\x10", content)

        # 2. Check for S7 Write commands:
        # S7 Communication write parameter starts with 0x05 (Write) instead of 0x04 (Read).
        # S7 Job request header has ROSCTR 0x01 (Job).
        # Parameter group for Write is 0x05.
        # Check that there are no hex bytes representing S7 Write parameters.
        self.assertNotIn(
            r"\x12\x04\x11\x45", content
        )  # 0x45 is S7 Write (0x44 is Read)

        # 3. Check for general write keywords in comments or variable names
        # (excluding explanatory comments about read-only safety).
        # We check that no variable names contain "write" or "force" or "control".
        # We can scan the AST if needed, but a simple string check is highly effective.
        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):
            clean_line = line.strip()
            # Ignore comments
            if (
                clean_line.startswith("#")
                or clean_line.startswith('"""')
                or clean_line.startswith("'''")
            ):
                continue

            # Ensure no active write/control function or payload is defined
            self.assertFalse(
                "write_single" in clean_line
                or "write_multiple" in clean_line
                or "force_coil" in clean_line,
                f"Line {line_num} contains a potential write payload definition: {clean_line}",
            )


if __name__ == "__main__":
    unittest.main()
