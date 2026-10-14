"""
An SNMP sysDescr maps to the platform it names, or to nothing.

The string describes the device, not the SNMP agent. Recognised formats become
an exact vendor/product the host-scope CVE search can use; anything else maps
to None rather than being name-matched (see test_cve_engine_candidates).
"""

import pytest
from engines.vulnerability.snmp_platform import platform_from_sysdescr


@pytest.mark.parametrize(
    "sysdescr,cpe_product,version",
    [
        (
            "Linux superusr-HP3 6.8.0-146-generic #146-Ubuntu SMP PREEMPT_DYNAMIC "
            "Thu Sep  3 16:12:30 UTC 2026 x86_64",
            "linux:linux_kernel",
            "6.8.0",
        ),
        (
            "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version "
            "15.0(2)SE4, RELEASE SOFTWARE (fc1)\r\nTechnical Support: "
            "http://www.cisco.com/techsupport",
            "cisco:ios",
            "15.0(2)se4",
        ),
        (
            "Cisco IOS XE Software, Version 16.09.04 - Extended Support Release",
            "cisco:ios_xe",
            "16.09.04",
        ),
        (
            "Cisco IOS Software [Fuji], Catalyst L3 Switch Software (CAT9K_IOSXE), "
            "Version 16.9.4, RELEASE SOFTWARE (fc2)",
            "cisco:ios_xe",
            "16.9.4",
        ),
        (
            "Cisco NX-OS(tm) n9000, Software (n9000-dk9), Version 9.3(5), "
            "RELEASE SOFTWARE",
            "cisco:nx-os",
            "9.3(5)",
        ),
        (
            "Juniper Networks, Inc. ex2200-24t-4g Ethernet Switch, kernel JUNOS "
            "12.3R6.6, Build date: 2014-03-13 06:57:06 UTC",
            "juniper:junos",
            "12.3r6.6",
        ),
        (
            "FreeBSD fw01 13.2-RELEASE FreeBSD 13.2-RELEASE releng/13.2-n254617 amd64",
            "freebsd:freebsd",
            "13.2",
        ),
        ("RouterOS RB750Gr3", "mikrotik:routeros", ""),
    ],
)
def test_a_recognised_description_names_its_platform(sysdescr, cpe_product, version):
    platform = platform_from_sysdescr(sysdescr)
    assert platform is not None
    assert f":{cpe_product}:" in platform.cpe
    assert platform.version == version


@pytest.mark.parametrize(
    "sysdescr",
    [
        "",
        None,
        "HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT,JD153",
        "Hardware: Intel64 Family 6 Model 154 - Software: Windows Version 6.3 "
        "(Build 26100 Multiprocessor Free)",
        "Palo Alto Networks PA-220 series firewall",
    ],
)
def test_anything_else_names_no_platform(sysdescr):
    assert platform_from_sysdescr(sysdescr) is None
