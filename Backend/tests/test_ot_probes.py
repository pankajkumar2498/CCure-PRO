import socket
from unittest.mock import MagicMock, patch
import pytest

from core.discovery.techniques.ot_probes import (
    probe_modbus, probe_s7, probe_ethernetip, probe_bacnet, probe_dnp3,
    probe_opcua, probe_iec104, probe_ge_srtp, probe_fins, probe_melsec,
    probe_codesys, probe_mms
)

class MockSocket:
    def __init__(self, responses=None):
        self.responses = responses or []
        self.sent_data = []

    def sendall(self, data):
        self.sent_data.append(data)

    def sendto(self, data, addr):
        self.sent_data.append((data, addr))

    def recv(self, limit):
        if self.responses:
            return self.responses.pop(0)
        return b""

    def recvfrom(self, limit):
        if self.responses:
            return self.responses.pop(0), ("127.0.0.1", 12345)
        return b"", ("127.0.0.1", 12345)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def close(self):
        pass


@patch("socket.create_connection")
def test_probe_modbus(mock_connect):
    # Mock Modbus FC 43 response
    # Transaction ID (2B), Proto ID (2B), Len (2B), Unit ID (1B), FC (1B), MEI (1B), ReadID (1B), Conformity (1B), More (1B), Next (1B), NumObjs=2
    # Obj0: ID=0, Len=7, "Siemens"
    # Obj1: ID=1, Len=7, "S7-1200"
    mock_resp = b"\x00\x01\x00\x00\x00\x16\x01\x2b\x0e\x01\x01\x00\x00\x02\x00\x07Siemens\x01\x07S7-1200"
    mock_sock = MockSocket(responses=[mock_resp])
    mock_connect.return_value = mock_sock

    info = probe_modbus("10.0.0.1")
    assert info is not None
    assert info["protocol"] == "modbus"
    assert info["vendor"] == "Siemens"
    assert info["model"] == "S7-1200"


@patch("socket.create_connection")
def test_probe_s7(mock_connect):
    # Mock Siemens S7 sequence responses
    # 1. COTP CC TPDU
    resp_cotp = b"\x03\x00\x00\x16\x11\xd0\x00\x01\x00\x02\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02"
    # 2. S7 Setup Comm Confirm
    resp_setup = b"\x03\x00\x00\x1b\x02\xf0\x80\x32\x03\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\xf0\x00\x00\x01\x00\x01\x03\xc0"
    # 3. Read SZL System Identification (contains "CPU 1214C")
    resp_szl = b"\x03\x00\x00\x35\x02\xf0\x80\x32\x07\x00\x00\x00\x01\x00\x08\x00\x08\x00\x01\x12\x04\x11\x44\x01\x00\xff\x09\x00\x18\x00\x1c\x00\x00\x00\x01\x00\x01\x00\x14\x05\x01\x43\x50\x55\x20\x31\x32\x31\x34\x43"
    
    mock_sock = MockSocket(responses=[resp_cotp, resp_setup, resp_szl])
    mock_connect.return_value = mock_sock

    info = probe_s7("10.0.0.1")
    assert info is not None
    assert info["protocol"] == "s7"
    assert info["vendor"] == "Siemens"
    assert "1214C" in info["model"]


@patch("socket.socket")
def test_probe_ethernetip(mock_socket):
    # Mock EtherNet/IP CIP ListIdentity response
    mock_resp = bytearray(80)
    mock_resp[0:2] = b"\x63\x00"
    mock_resp[48:50] = b"\x01\x00"  # Rockwell Automation
    mock_resp[50:52] = b"\x0e\x00"  # PLC Device Type
    mock_resp[62] = 12               # Name length
    mock_resp[63:75] = b"ControlLogix"
    
    mock_sock = MockSocket(responses=[bytes(mock_resp)])
    mock_socket.return_value = mock_sock

    info = probe_ethernetip("10.0.0.1")
    assert info is not None
    assert info["protocol"] == "ethernetip"
    assert "Rockwell" in info["vendor"]
    assert info["model"] == "ControlLogix"


@patch("socket.socket")
def test_probe_bacnet(mock_socket):
    # Mock BACnet Who-Is response
    mock_resp = bytearray(30)
    mock_resp[0:2] = b"\x81\x0a"
    mock_resp[10] = 0x91  # Segmentation tag
    mock_resp[11] = 0x00
    mock_resp[12] = 0x21  # 1-byte integer tag
    mock_resp[13] = 15    # Vendor: Honeywell
    
    mock_sock = MockSocket(responses=[bytes(mock_resp)])
    mock_socket.return_value = mock_sock

    info = probe_bacnet("10.0.0.1")
    assert info is not None
    assert info["protocol"] == "bacnet"
    assert info["vendor"] == "Honeywell"


@patch("socket.create_connection")
def test_probe_dnp3(mock_connect):
    # Mock DNP3 link status reply
    mock_resp = b"\x05\x64\x05\x0b\x00\x01\x64\x00\x11\x22"
    mock_sock = MockSocket(responses=[mock_resp])
    mock_connect.return_value = mock_sock

    info = probe_dnp3("10.0.0.1")
    assert info is not None
    assert info["protocol"] == "dnp3"
    assert info["vendor"] == "DNP3 Controller"


@patch("socket.create_connection")
def test_probe_opcua(mock_connect):
    mock_resp = b"ACKF\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00"
    mock_sock = MockSocket(responses=[mock_resp])
    mock_connect.return_value = mock_sock

    info = probe_opcua("10.0.0.1")
    assert info is not None
    assert info["protocol"] == "opcua"


@patch("socket.create_connection")
def test_probe_iec104(mock_connect):
    mock_resp = b"\x68\x04\x83\x00\x00\x00"
    mock_sock = MockSocket(responses=[mock_resp])
    mock_connect.return_value = mock_sock

    info = probe_iec104("10.0.0.1")
    assert info is not None
    assert info["protocol"] == "iec104"


@patch("socket.create_connection")
def test_probe_ge_srtp(mock_connect):
    mock_resp = b"\x03\x00\x00\x00\x00\x00"
    mock_sock = MockSocket(responses=[mock_resp])
    mock_connect.return_value = mock_sock

    info = probe_ge_srtp("10.0.0.1")
    assert info is not None
    assert info["protocol"] == "ge_srtp"
    assert info["vendor"] == "GE Fanuc"


@patch("socket.create_connection")
def test_probe_fins(mock_connect):
    mock_resp = b"FINS\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
    mock_sock = MockSocket(responses=[mock_resp])
    mock_connect.return_value = mock_sock

    info = probe_fins("10.0.0.1")
    assert info is not None
    assert info["protocol"] == "fins"
    assert info["vendor"] == "Omron"


@patch("socket.create_connection")
def test_probe_melsec(mock_connect):
    mock_resp = b"\xd0\x00\x00\xff\xff\x03\x00\x10\x00\x00\x00Q06HCPU"
    mock_sock = MockSocket(responses=[mock_resp])
    mock_connect.return_value = mock_sock

    info = probe_melsec("10.0.0.1")
    assert info is not None
    assert info["protocol"] == "melsec"
    assert info["vendor"] == "Mitsubishi"
    assert "Q06HCPU" in info["model"]


@patch("socket.create_connection")
def test_probe_codesys(mock_connect):
    mock_resp = b"\xbb\xbb\x00\x00"
    mock_sock = MockSocket(responses=[mock_resp])
    mock_connect.return_value = mock_sock

    info = probe_codesys("10.0.0.1")
    assert info is not None
    assert info["protocol"] == "codesys"


@patch("socket.create_connection")
def test_probe_mms(mock_connect):
    mock_resp = b"\x03\x00\x00\x1f\x02\xf0\x80\xa2\x17\x00\x00"
    mock_sock = MockSocket(responses=[mock_resp])
    mock_connect.return_value = mock_sock

    info = probe_mms("10.0.0.1")
    assert info is not None
    assert info["protocol"] == "mms"


@patch("socket.create_connection")
def test_probe_modbus_fallback(mock_connect):
    # Mock socket throws exception on sendall/recv (e.g. timeout or closed connection)
    mock_sock = MagicMock()
    mock_sock.sendall.side_effect = socket.error("Closed")
    mock_connect.return_value = mock_sock

    info = probe_modbus("10.0.0.1")
    assert info is not None
    assert info["protocol"] == "modbus"
    assert info["vendor"] == "Modbus Device"
    assert info["model"] == "Modbus TCP Controller"


@patch("socket.create_connection")
def test_probe_s7_fallback(mock_connect):
    # Mock S7 sequence: COTP CC works, but Setup Comm throws exception
    resp_cotp = b"\x03\x00\x00\x16\x11\xd0\x00\x01\x00\x02\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02"
    mock_sock = MagicMock()
    # First recv returns COTP CC, second recv throws exception
    mock_sock.recv.side_effect = [resp_cotp, socket.error("Timeout")]
    mock_connect.return_value = mock_sock

    info = probe_s7("10.0.0.1")
    assert info is not None
    assert info["protocol"] == "s7"
    assert info["vendor"] == "Siemens"
    assert info["model"] == "S7 PLC"
