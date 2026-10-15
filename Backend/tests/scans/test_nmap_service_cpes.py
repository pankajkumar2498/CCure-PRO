"""
Every CPE nmap reports for a service reaches the scan, not only the last one.

Measured on 14 Oct 2026 against an Ubuntu 24.04 host's OpenSSH: nmap's XML
carried ``cpe:/a:openbsd:openssh:9.6p1`` and then ``cpe:/o:linux:linux_kernel``,
and python-nmap 0.7.1 stores only the last ``<cpe>`` of a service. The port
reached the CVE engine as the kernel alone, so an unauthenticated scan never
searched OpenSSH's CVEs on that host. The engine already searches an
application CPE when a port carries one (``test_cve_engine_candidates``); the
identity was being dropped before it got there.

These tests run nmap's own XML through the real python-nmap parser, so a later
python-nmap that keeps every CPE leaves them passing and one that keeps fewer
fails them.
"""

from __future__ import annotations

import pytest

nmap = pytest.importorskip("nmap")

from core.nmap import wrapper  # noqa: E402

# CI's MOCK_SCANNERS=true replaces nmap.PortScanner for the session.
pytestmark = pytest.mark.usefixtures("real_nmap_port_scanner")

OPENSSH = "cpe:/a:openbsd:openssh:9.6p1"
KERNEL = "cpe:/o:linux:linux_kernel"


def _host(addr: str, ports: str) -> str:
    return f"""
<host starttime="1" endtime="2"><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="{addr}" addrtype="ipv4"/><hostnames></hostnames>
<ports>{ports}</ports></host>"""


SSH_UBUNTU = """<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="63"/>
<service name="ssh" product="OpenSSH" version="9.6p1 Ubuntu 3ubuntu13.19"
 extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10">
<cpe>cpe:/a:openbsd:openssh:9.6p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>"""

HTTP_ONE_CPE = """<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="63"/>
<service name="http" product="nginx" version="1.24.0" method="probed" conf="10">
<cpe>cpe:/a:igor_sysoev:nginx:1.24.0</cpe></service></port>"""


def _scanner(*hosts: str) -> "nmap.PortScanner":
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV" start="1" version="7.95" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="2" services="22,80"/>
{"".join(hosts)}
<runstats><finished time="2" timestr="now" elapsed="1.00" summary="" exit="success"/>
<hosts up="{len(hosts)}" down="0" total="{len(hosts)}"/></runstats></nmaprun>"""
    # PortScanner() looks for the nmap binary, which a test runner need not
    # have; parsing XML needs none of what the constructor sets up.
    nm = nmap.PortScanner.__new__(nmap.PortScanner)
    nm._scan_result = {}
    nm._nmap_version_number, nm._nmap_subversion_number = 7, 95
    nm.analyse_nmap_xml_scan(nmap_xml_output=xml)
    nm._nmap_last_output = xml  # what scan() leaves behind
    return nm


def _ports(result):
    return {p.port: p.cpe for p in result.ports}


def test_python_nmap_alone_keeps_only_the_last_cpe():
    # The premise. If this starts failing, python-nmap was fixed upstream and
    # the recovery below has become a no-op rather than wrong.
    nm = _scanner(_host("192.0.2.45", SSH_UBUNTU))
    assert nm["192.0.2.45"]["tcp"][22]["cpe"] == KERNEL


def test_an_application_cpe_listed_before_the_os_is_kept():
    nm = _scanner(_host("192.0.2.45", SSH_UBUNTU))
    result = wrapper.NmapScanner()._parse_python_nmap(
        nm, "192.0.2.45", 1.0, service_cpes=wrapper._service_cpes_by_port(nm)
    )
    assert _ports(result)[22] == [OPENSSH, KERNEL]


def test_each_host_keeps_its_own_cpes_in_a_multi_host_scan():
    nm = _scanner(
        _host("192.0.2.45", SSH_UBUNTU + HTTP_ONE_CPE),
        _host("192.0.2.46", HTTP_ONE_CPE),
    )
    cpes = wrapper._service_cpes_by_port(nm)
    scanner = wrapper.NmapScanner()
    first = _ports(scanner._parse_python_nmap(nm, "192.0.2.45", 1.0, cpes))
    second = _ports(scanner._parse_python_nmap(nm, "192.0.2.46", 1.0, cpes))
    assert first == {22: [OPENSSH, KERNEL], 80: ["cpe:/a:igor_sysoev:nginx:1.24.0"]}
    assert second == {80: ["cpe:/a:igor_sysoev:nginx:1.24.0"]}


@pytest.mark.parametrize("raw", ["", "<not-xml", None])
def test_unreadable_raw_output_falls_back_to_python_nmaps_value(raw):
    nm = _scanner(_host("192.0.2.45", SSH_UBUNTU))
    nm._nmap_last_output = raw
    cpes = wrapper._service_cpes_by_port(nm)
    assert cpes == {}
    result = wrapper.NmapScanner()._parse_python_nmap(nm, "192.0.2.45", 1.0, cpes)
    assert _ports(result)[22] == [KERNEL]


def test_both_python_nmap_call_sites_pass_the_recovered_cpes():
    # A static guard: the single-target and the multi-target runners are the
    # only two places python-nmap results are parsed, and each must hand the
    # parser the CPEs recovered from the same scan.
    import inspect

    for runner in (wrapper.NmapScanner._run, wrapper.NmapScanner._run_multi):
        source = inspect.getsource(runner)
        assert "_service_cpes_by_port(nm)" in source, runner.__name__
        assert "service_cpes=" in source, runner.__name__
