"""
core/discovery/techniques/ot_probes.py
────────────────────────────────────────────────────────────────────────────
OT (Operational Technology) / SCADA Protocol Fingerprinting Library

Pure Python, socket-based, lightweight, non-intrusive identity probes
for the 12 most widely used industrial and building automation protocols.

Safe Design Constraint:
  - Strict Port-Gating: Probes are ONLY executed on their default ports.
  - Non-intrusive: Only sends read-only status or identity queries.
  - Safe Timeouts: Strict socket timeouts of 1.0 second.
"""

import socket
import struct
import re
import logging
from typing import Dict, Optional

log = logging.getLogger("ccure.discovery.ot_probes")


def _configure_safe_socket(s: socket.socket) -> None:
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 0)
    except Exception:
        pass
    if s.type == socket.SOCK_STREAM:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# 1. Modbus TCP (Port 502 TCP)
# ─────────────────────────────────────────────────────────────────────────────


def probe_modbus(ip: str, timeout: float = 1.0) -> Optional[Dict]:
    """Send Modbus Read Device Identification (FC 43/14) and parse response."""
    try:
        with socket.create_connection((ip, 502), timeout=timeout) as s:
            _configure_safe_socket(s)
            # TransID=0x0001, ProtoID=0x0000, Len=0x0005, UnitID=0x01, FC=0x2b (43), MEI=0x0e (14), ReadIDCode=0x01, ObjID=0x00
            req = b"\x00\x01\x00\x00\x00\x05\x01\x2b\x0e\x01\x00"
            s.sendall(req)
            resp = s.recv(1024)

            # Check for standard Modbus TCP response header protocol ID (0x0000)
            # and either Function Code 43 (0x2b) or Exception (0xab)
            if (
                len(resp) >= 9
                and resp[2] == 0x00
                and resp[3] == 0x00
                and (resp[7] == 0x2B or resp[7] == 0xAB)
            ):
                info = {
                    "protocol": "modbus",
                    "vendor": "Modbus Device",
                    "model": "Modbus TCP Controller",
                }
                if resp[7] == 0x2B and len(resp) > 13:
                    try:
                        num_objects = resp[13]
                        idx = 14
                        for _ in range(num_objects):
                            if idx + 2 > len(resp):
                                break
                            obj_id = resp[idx]
                            obj_len = resp[idx + 1]
                            if idx + 2 + obj_len > len(resp):
                                break
                            obj_val = (
                                resp[idx + 2 : idx + 2 + obj_len]
                                .decode("utf-8", errors="ignore")
                                .strip()
                            )
                            idx += 2 + obj_len

                            if obj_id == 0:
                                info["vendor"] = obj_val
                            elif obj_id == 1:
                                info["model"] = obj_val
                            elif obj_id == 2:
                                info["revision"] = obj_val
                    except Exception:
                        pass
                return info
    except Exception as exc:
        log.debug("probe_modbus(%s) error: %s", ip, exc)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 2. Siemens S7 (Port 102 TCP)
# ─────────────────────────────────────────────────────────────────────────────


def probe_s7(ip: str, timeout: float = 1.0) -> Optional[Dict]:
    """Perform COTP CR, Setup Comm PDU, and Read SZL 0x001C to parse S7 PLC model."""
    try:
        with socket.create_connection((ip, 102), timeout=timeout) as s:
            _configure_safe_socket(s)
            # 1. COTP Connection Request (CR TPDU)
            cotp_cr = b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a"
            s.sendall(cotp_cr)
            resp = s.recv(1024)
            if not (len(resp) > 5 and resp[4] == 0x11 and resp[5] == 0xD0):
                return None

            # If COTP CC succeeds, we know it's a Siemens S7 device
            info = {"protocol": "s7", "vendor": "Siemens", "model": "S7 PLC"}
            try:
                # 2. S7 Setup Communication
                s7_setup = b"\x03\x00\x00\x19\x02\xf0\x80\x32\x01\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\xf0\x00\x00\x01\x00\x01\x03\xc0"
                s.sendall(s7_setup)
                resp = s.recv(1024)
                if len(resp) > 10 and resp[7] == 0x32:
                    # 3. Read SZL ID 0x001c (System Identification)
                    s7_read_szl = b"\x03\x00\x00\x21\x02\xf0\x80\x32\x07\x00\x00\x00\x00\x00\x08\x00\x08\x00\x01\x12\x04\x11\x44\x01\x00\xff\x09\x00\x04\x00\x1c\x00\x00"
                    s.sendall(s7_read_szl)
                    resp = s.recv(2048)

                    strings = re.findall(b"[a-zA-Z0-9_\\-\\.\\/ ]{4,}", resp)
                    valid_strings = [s.decode(errors="ignore").strip() for s in strings]
                    valid_strings = [
                        s
                        for s in valid_strings
                        if s
                        and not any(
                            noise in s.lower() for noise in ["sub", "pdu", "system"]
                        )
                    ]
                    if valid_strings:
                        cpu_match = None
                        for s in valid_strings:
                            if "cpu" in s.lower() or "s7-" in s.lower():
                                cpu_match = s
                                break
                        info["model"] = cpu_match or valid_strings[0]
                    else:
                        info["model"] = "S7-Compatible PLC"
            except Exception:
                pass
            return info
    except Exception as exc:
        log.debug("probe_s7(%s) error: %s", ip, exc)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 3. EtherNet/IP / CIP (Port 44818 UDP)
# ─────────────────────────────────────────────────────────────────────────────


def probe_ethernetip(ip: str, timeout: float = 1.0) -> Optional[Dict]:
    """Send CIP ListIdentity command and parse Vendor ID and Product Name."""
    try:
        # Encapsulation Header with Command 0x0063 (ListIdentity)
        req = b"\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            _configure_safe_socket(s)
            s.settimeout(timeout)
            s.sendto(req, (ip, 44818))
            resp, _ = s.recvfrom(2048)

            if len(resp) >= 63 and resp[0] == 0x63:
                vendor_id = int.from_bytes(resp[48:50], byteorder="little")
                device_type = int.from_bytes(resp[50:52], byteorder="little")
                prod_name_len = resp[62]

                prod_name = "CIP Device"
                if 63 + prod_name_len <= len(resp):
                    prod_name = (
                        resp[63 : 63 + prod_name_len]
                        .decode("utf-8", errors="ignore")
                        .strip()
                    )

                cip_vendors = {
                    1: "Rockwell Automation/Allen-Bradley",
                    2: "Wago",
                    45: "Omron",
                    59: "HMS Industrial Networks",
                    125: "Moxa Technologies",
                    288: "Phoenix Contact",
                }
                vendor_name = cip_vendors.get(vendor_id, f"CIP Vendor {vendor_id}")

                return {
                    "protocol": "ethernetip",
                    "vendor": vendor_name,
                    "model": prod_name,
                    "device_type_id": device_type,
                }
    except Exception as exc:
        log.debug("probe_ethernetip(%s) error: %s", ip, exc)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 4. BACnet/IP (Port 47808 UDP)
# ─────────────────────────────────────────────────────────────────────────────


def probe_bacnet(ip: str, timeout: float = 1.0) -> Optional[Dict]:
    """Send BACnet Who-Is request and parse the Vendor ID from I-Am response."""
    try:
        # BACnet Who-Is APDU payload
        req = b"\x81\x0a\x00\x11\x01\x04\x00\x05\x01\x0c\x0c\x02\x3f\xff\xff\x19\x50"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            _configure_safe_socket(s)
            s.settimeout(timeout)
            s.sendto(req, (ip, 47808))
            resp, _ = s.recvfrom(2048)

            if len(resp) >= 10 and resp[0] == 0x81 and resp[1] == 0x0A:
                info = {
                    "protocol": "bacnet",
                    "vendor": "BACnet Device",
                    "model": "BACnet Hvac/Sensor",
                }

                # Simple parsing of Vendor ID tag (Application Tag 2 - Unsigned Integer)
                # Look for Segmentation Tag (0x91 followed by value) or search for tags after index 9
                idx = resp.find(b"\x91")
                if idx != -1 and idx + 2 < len(resp):
                    # Next tag should be Vendor ID (typically 0x21 for 1-byte or 0x22 for 2-byte integer)
                    tag_idx = idx + 2
                    if tag_idx < len(resp):
                        tag = resp[tag_idx]
                        if tag == 0x21 and tag_idx + 1 < len(resp):
                            vendor_id = resp[tag_idx + 1]
                        elif tag == 0x22 and tag_idx + 2 < len(resp):
                            vendor_id = int.from_bytes(
                                resp[tag_idx + 1 : tag_idx + 3], byteorder="big"
                            )
                        else:
                            vendor_id = 0

                        bacnet_vendors = {
                            1: "Siemens Building Technologies",
                            15: "Honeywell",
                            37: "Johnson Controls",
                            24: "Delta Controls",
                            8: "Alerton",
                        }
                        if vendor_id > 0:
                            info["vendor"] = bacnet_vendors.get(
                                vendor_id, f"BACnet Vendor {vendor_id}"
                            )
                return info
    except Exception as exc:
        log.debug("probe_bacnet(%s) error: %s", ip, exc)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 5. DNP3 (Port 20000 TCP/UDP)
# ─────────────────────────────────────────────────────────────────────────────


def probe_dnp3(ip: str, timeout: float = 1.0) -> Optional[Dict]:
    """Send DNP3 Request Link Status and verify response frame format."""
    # First try TCP
    try:
        with socket.create_connection((ip, 20000), timeout=timeout) as s:
            _configure_safe_socket(s)
            # Request Link Status: Start=0x0564, Len=0x05, Ctrl=0xc9, Dst=0x0100, Src=0x6400, CRC=0xe23d
            req = b"\x05\x64\x05\xc9\x01\x00\x64\x00\xe2\x3d"
            s.sendall(req)
            resp = s.recv(1024)
            if len(resp) >= 10 and resp[0] == 0x05 and resp[1] == 0x64:
                return {
                    "protocol": "dnp3",
                    "vendor": "DNP3 Controller",
                    "model": "DNP3 Outstation",
                }
    except Exception:
        pass

    # Fallback to UDP
    try:
        req = b"\x05\x64\x05\xc9\x01\x00\x64\x00\xe2\x3d"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            _configure_safe_socket(s)
            s.settimeout(timeout)
            s.sendto(req, (ip, 20000))
            resp, _ = s.recvfrom(1024)
            if len(resp) >= 10 and resp[0] == 0x05 and resp[1] == 0x64:
                return {
                    "protocol": "dnp3",
                    "vendor": "DNP3 Controller",
                    "model": "DNP3 Outstation",
                }
    except Exception as exc:
        log.debug("probe_dnp3(%s) error: %s", ip, exc)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 6. OPC UA (Port 4840 TCP)
# ─────────────────────────────────────────────────────────────────────────────


def probe_opcua(ip: str, timeout: float = 1.0) -> Optional[Dict]:
    """Send OPC UA HEL (Hello) packet and verify ACKF/ERRF response."""
    try:
        with socket.create_connection((ip, 4840), timeout=timeout) as s:
            _configure_safe_socket(s)
            # Hello packet: type=HELF, size=54, version=0, buffer sizes, URL length=22, URL=opc.tcp://127.0.0.1:4840
            req = b"HELF\x36\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16\x00\x00\x00opc.tcp://127.0.0.1:4840"
            s.sendall(req)
            resp = s.recv(1024)
            if len(resp) >= 8 and (resp[0:4] == b"ACKF" or resp[0:4] == b"ERRF"):
                return {
                    "protocol": "opcua",
                    "vendor": "OPC UA Device",
                    "model": "OPC UA Server",
                }
    except Exception as exc:
        log.debug("probe_opcua(%s) error: %s", ip, exc)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 7. IEC 60870-5-104 (Port 2404 TCP)
# ─────────────────────────────────────────────────────────────────────────────


def probe_iec104(ip: str, timeout: float = 1.0) -> Optional[Dict]:
    """Send IEC 104 TESTFR Activation U-Frame and verify response."""
    try:
        with socket.create_connection((ip, 2404), timeout=timeout) as s:
            _configure_safe_socket(s)
            # TESTFR activation: Start=0x68, Len=0x04, Control=0x43000000
            req = b"\x68\x04\x43\x00\x00\x00"
            s.sendall(req)
            resp = s.recv(1024)
            if len(resp) >= 6 and resp[0] == 0x68 and resp[1] == 0x04:
                return {
                    "protocol": "iec104",
                    "vendor": "IEC-104 Controller",
                    "model": "IEC 60870-5-104 Device",
                }
    except Exception as exc:
        log.debug("probe_iec104(%s) error: %s", ip, exc)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 8. GE SRTP (Port 18245 TCP)
# ─────────────────────────────────────────────────────────────────────────────


def probe_ge_srtp(ip: str, timeout: float = 1.0) -> Optional[Dict]:
    """Send GE SRTP System Request status query and confirm response format."""
    try:
        with socket.create_connection((ip, 18245), timeout=timeout) as s:
            _configure_safe_socket(s)
            # 56-byte System Request block
            req = b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            s.sendall(req)
            resp = s.recv(1024)
            if len(resp) >= 4 and (resp[0] == 0x03 or resp[0] == 0x02):
                return {
                    "protocol": "ge_srtp",
                    "vendor": "GE Fanuc",
                    "model": "GE Series PLC",
                }
    except Exception as exc:
        log.debug("probe_ge_srtp(%s) error: %s", ip, exc)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 9. Omron FINS (Port 9600 TCP)
# ─────────────────────────────────────────────────────────────────────────────


def probe_fins(ip: str, timeout: float = 1.0) -> Optional[Dict]:
    """Send FINS TCP connection request and parse confirmation header."""
    try:
        with socket.create_connection((ip, 9600), timeout=timeout) as s:
            _configure_safe_socket(s)
            # FINS TCP Connection Request: Header "FINS", length 12, command 0, error 0
            req = (
                b"FINS\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            s.sendall(req)
            resp = s.recv(1024)
            if len(resp) >= 16 and resp[0:4] == b"FINS":
                return {
                    "protocol": "fins",
                    "vendor": "Omron",
                    "model": "Omron Sysmac PLC",
                }
    except Exception as exc:
        log.debug("probe_fins(%s) error: %s", ip, exc)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 10. Mitsubishi MELSEC (Port 5007 TCP)
# ─────────────────────────────────────────────────────────────────────────────


def probe_melsec(ip: str, timeout: float = 1.0) -> Optional[Dict]:
    """Send MELSEC MC 3E frame CPU Type read and check response."""
    try:
        with socket.create_connection((ip, 5007), timeout=timeout) as s:
            _configure_safe_socket(s)
            # 3E frame CPU read
            req = b"\x50\x00\x00\xff\xff\x03\x00\x0c\x00\x10\x00\x01\x04\x00\x00\x00\x00\x00\x00\x00\x00"
            s.sendall(req)
            resp = s.recv(1024)
            # Response starts with subheader D000
            if len(resp) >= 11 and resp[0] == 0xD0 and resp[1] == 0x00:
                info = {
                    "protocol": "melsec",
                    "vendor": "Mitsubishi",
                    "model": "MELSEC Q-Series CPU",
                }
                # Try to extract MELSEC model string
                strings = re.findall(b"[a-zA-Z0-9_\\-\\.\\/]{3,10}", resp[11:])
                if strings:
                    info["model"] = (
                        f"MELSEC ({strings[0].decode(errors='ignore').strip()})"
                    )
                return info
    except Exception as exc:
        log.debug("probe_melsec(%s) error: %s", ip, exc)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 11. CoDeSys (Port 2455 TCP)
# ─────────────────────────────────────────────────────────────────────────────


def probe_codesys(ip: str, timeout: float = 1.0) -> Optional[Dict]:
    """Send CoDeSys V2 connection handshake to verify CoDeSys presence."""
    try:
        with socket.create_connection((ip, 2455), timeout=timeout) as s:
            _configure_safe_socket(s)
            req = b"\xbb\xbb\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            s.sendall(req)
            resp = s.recv(1024)
            # Response validation for CoDeSys handshake returns \xbb\xbb
            if len(resp) >= 2 and resp[0] == 0xBB and resp[1] == 0xBB:
                return {
                    "protocol": "codesys",
                    "vendor": "CoDeSys Compatible",
                    "model": "CoDeSys PLC Runtime",
                }
    except Exception as exc:
        log.debug("probe_codesys(%s) error: %s", ip, exc)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 12. IEC 61850 MMS (Port 102 TCP)
# ─────────────────────────────────────────────────────────────────────────────


def probe_mms(ip: str, timeout: float = 1.0) -> Optional[Dict]:
    """Send ISO ACSE MMS Initiate Request to identify substation utility relays."""
    try:
        with socket.create_connection((ip, 102), timeout=timeout) as s:
            _configure_safe_socket(s)
            # ACSE MMS Initiate Request
            req = b"\x03\x00\x00\x2f\x02\xf0\x80\xa1\x27\x88\x02\x07\x80\xa0\x21\xa0\x03\x80\x01\x01\xa1\x0f\x06\x0c\x2b\x06\x01\x04\x01\x82\x37\x01\x01\x01\x02\x01\xa2\x0b\x02\x01\x01\x02\x01\x01\x02\x03\x00\xfa\x00"
            s.sendall(req)
            resp = s.recv(1024)
            # Response starts with COTP and ACSE response tag (0xa2 is Initiate Response)
            if len(resp) >= 10 and resp[0] == 0x03 and resp[7] == 0xA2:
                return {
                    "protocol": "mms",
                    "vendor": "IEC 61850 Substation Device",
                    "model": "MMS Telecontrol",
                }
    except Exception as exc:
        log.debug("probe_mms(%s) error: %s", ip, exc)
    return None
