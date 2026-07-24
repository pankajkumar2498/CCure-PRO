"""
verify_install.py
-----------------
Run this script to confirm every layer of the project imports and
functions correctly after install.

Usage:
    python verify_install.py

Expected: All checks passed! (all checks)
"""

import io
import os
import sys

# Ensure UTF-8 output on Windows (fixes Unicode arrow/box-drawing crash on cp1252 consoles)
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Add Backend directory to path (works whether run from Backend/ or Backend/scripts/)
backend_dir = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, backend_dir)

CHECKS = []


def check(name: str, fn):
    try:
        fn()
        print(f"  [PASS] {name}")
        CHECKS.append(True)
    except Exception as e:
        print(f"  [FAIL] {name}: {e}")
        CHECKS.append(False)


print("\n" + "=" * 60)
print("  Ccure Audit - Install Verification")
print("=" * 60 + "\n")

# -- Layer 1: core --
check(
    "core.constants imports",
    lambda: __import__("core.constants", fromlist=["CVE_HINTS", "PORT_DB"]),
)

check(
    "core.models imports",
    lambda: __import__("core.models", fromlist=["HostResult", "PortResult", "TLSInfo"]),
)

check(
    "core.utils imports",
    lambda: __import__(
        "core.utils", fromlist=["lookup_cve", "extract_version", "InputValidator"]
    ),
)

check(
    "core.risk imports",
    lambda: __import__(
        "core.risk", fromlist=["calculate_risk", "fingerprint_os", "deduplicate_cves"]
    ),
)

# -- Layer 2: engines --
check(
    "engines.discovery imports",
    lambda: __import__(
        "engines.discovery.discovery_engine", fromlist=["DiscoveryEngine"]
    ),
)

check(
    "engines.port imports",
    lambda: __import__("engines.port.port_engine", fromlist=["PortEngine"]),
)

check(
    "engines.vulnerability imports",
    lambda: __import__(
        "engines.vulnerability.vulnerability_engine", fromlist=["VulnerabilityEngine"]
    ),
)

# -- Layer 3: plugins --
check(
    "all plugins import",
    lambda: __import__(
        "engines.vulnerability.plugins",
        fromlist=[
            "tls_scanner",
            "http_analyzer",
            "ssh_probe",
            "smb_probe",
            "snmp_probe",
            "udp_scanner",
            "icmp_probe",
            "cve_engine",
        ],
    ),
)

# -- Layer 4: orchestrator + api --
check(
    "orchestrator imports",
    lambda: __import__("orchestrator.scan_orchestrator", fromlist=["ScanOrchestrator"]),
)

check(
    "api imports",
    lambda: __import__("api.host_discovery_api", fromlist=["HostDiscoveryAPI"]),
)

# -- Functional checks --
check(
    "HostDiscoveryAPI instantiates cleanly",
    lambda: (
        __import__(
            "api.host_discovery_api", fromlist=["HostDiscoveryAPI"]
        ).HostDiscoveryAPI(silent=True)
    ),
)

check(
    "CVE lookup returns results for known banner",
    lambda: (
        __import__("core.utils", fromlist=["lookup_cve"])
        .lookup_cve("vsftpd 2.3.4")
        .__len__()
        > 0
    ),
)

check(
    "Version extraction works",
    lambda: (
        "Apache"
        in __import__("core.utils", fromlist=["extract_version"]).extract_version(
            "Server: Apache/2.4.51 (Ubuntu)"
        )
    ),
)

check(
    "OS fingerprint: TTL=64+window=29200 -> Linux",
    lambda: (
        "Linux"
        in __import__("core.risk", fromlist=["fingerprint_os"]).fingerprint_os(
            64, 29200
        )[0]
    ),
)

check(
    "Risk score calculation returns non-zero for critical ports",
    lambda: (
        __import__("core.risk", fromlist=["calculate_risk"]).calculate_risk(
            [{"risk": "Critical"}], [{"cvss": 9.8}], {}, {}
        )[0]
        > 0
    ),
)

check(
    "InputValidator rejects unsafe input",
    lambda: (
        not __import__(
            "core.utils", fromlist=["InputValidator"]
        ).InputValidator.is_safe("10.180.6.14; rm -rf /")
    ),
)

check(
    "deduplicate_cves removes duplicates",
    lambda: (
        len(
            __import__("core.risk", fromlist=["deduplicate_cves"]).deduplicate_cves(
                [{"cve": "CVE-2017-0144"}, {"cve": "CVE-2017-0144"}]
            )
        )
        == 1
    ),
)

check(
    "get_system_info returns expected keys",
    lambda: (
        all(
            k
            in __import__("api.host_discovery_api", fromlist=["HostDiscoveryAPI"])
            .HostDiscoveryAPI(silent=True)
            .get_system_info()
            for k in (
                "platform",
                "version",
                "scan_types",
                "intensities",
                "pro_features",
            )
        )
    ),
)

# -- Optional dependency check --
print()
try:
    import scapy

    print("  [INFO] Scapy     : installed - ARP / ICMP / SYN / stealth modes available")
except ImportError:
    print(
        "  [INFO] Scapy     : not installed - TCP mode only (pip install scapy to enable raw-packet scans)"
    )

try:
    import reportlab

    print("  [INFO] reportlab : installed - PDF report generation available")
except ImportError:
    print(
        "  [INFO] reportlab : not installed - PDF reports disabled (pip install reportlab to enable)"
    )

try:
    import fastapi
    import uvicorn

    print(
        "  [INFO] FastAPI   : installed - API server available (uvicorn main:app --reload)"
    )
except ImportError:
    print(
        "  [INFO] FastAPI   : not installed - API server disabled (pip install fastapi uvicorn to enable)"
    )

# -- Result --
print()
passed = sum(CHECKS)
total = len(CHECKS)
status = (
    "All checks passed!" if passed == total else f"{total - passed} check(s) FAILED"
)
print(f"{status} ({passed}/{total})")
print()
sys.exit(0 if passed == total else 1)
