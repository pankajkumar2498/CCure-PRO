"""
How unauthenticated CVE candidates are searched, and what a capped search says.

Measured on 13 Oct 2026 against 10.180.6.45 and 10.180.6.30:

* Nmap tags an Ubuntu OpenSSH service with ``cpe:/o:linux:linux_kernel``. The
  kernel's ~14,000 CVEs were searched as that port's identity, stopped at the
  2,000-row cap, and the only trace was a WARNING in the worker log. Where a
  service carries both its own CPE and the kernel's, 20 of OpenSSH's 133 CVEs
  ranked below the cap and were never evaluated.
* The SNMP agent's banner is the device's sysDescr ("Linux superusr-HP3
  6.8.0-146-generic #146-Ubuntu SMP …"); name-matched as a search term it
  returned 200 rows of whatever ranked highest, all bound to port 161.
* ``lookup_cve`` is lru_cached and the engine bound ports onto the cached dicts,
  so a later host or scan with the same banner inherited the first one's port.

Replaying both hosts' stored services through candidate generation and
verification, old code and new, reported identical findings with identical
port bindings; only the candidate pool and the truncation record changed.
"""

from __future__ import annotations

import pytest
from engines.vulnerability.plugins import cve_engine

KERNEL_22 = "cpe:/o:linux:linux_kernel"
SYSDESCR = (
    "Linux superusr-HP3 6.8.0-146-generic #146-Ubuntu SMP PREEMPT_DYNAMIC "
    "Thu Sep  3 16:12:30 UTC 2026 x86_64"
)


@pytest.fixture()
def lookups(monkeypatch):
    """A fake lookup_cve that, like the real one, returns cached objects."""
    calls: list[tuple] = []
    cache: dict = {}

    def fake(query, version="", cpes=()):
        calls.append((query, version, tuple(cpes)))
        key = (query, version, tuple(cpes))
        if key not in cache:
            truncated = any("linux_kernel" in c for c in cpes)
            cache[key] = [
                {
                    "cve_id": f"CVE-2026-{len(cache):04d}",
                    "candidate_source": "cpe_exact" if cpes else "name_match",
                    **(
                        {"enumeration_truncated": True, "enumeration_cap": 2000}
                        if truncated
                        else {}
                    ),
                }
            ]
        return cache[key]

    monkeypatch.setattr(cve_engine, "lookup_cve", fake)
    return calls, cache


def _port(port, service, cpe=(), banner="", version="", protocol="tcp"):
    return {
        "port": port,
        "service": service,
        "cpe": list(cpe),
        "banner": banner,
        "version": version,
        "protocol": protocol,
    }


def test_an_os_cpe_is_searched_once_for_the_host_not_with_the_service(lookups):
    calls, _ = lookups
    result = cve_engine.run(
        "10.0.0.1",
        [22, 2222],
        [
            _port(
                22, "ssh", ["cpe:/a:openbsd:openssh:9.6p1", KERNEL_22], version="9.6p1"
            ),
            _port(
                2222,
                "ssh",
                ["cpe:/a:openbsd:openssh:9.6p1", KERNEL_22],
                version="9.6p1",
            ),
        ],
    )
    service_calls = [c for c in calls if "cpe:/a:openbsd:openssh:9.6p1" in c[2]]
    kernel_calls = [c for c in calls if KERNEL_22 in c[2]]
    assert all(KERNEL_22 not in c[2] for c in service_calls)
    assert len(kernel_calls) == 1  # once per host, however many ports name it
    kernel = [
        c
        for c in result["cves"]
        if c["candidate_source"] == "cpe_exact" and c["port"] is None
    ]
    assert kernel, "the platform's candidates are scoped to the host"


def test_a_port_known_only_by_its_os_cpe_gets_no_search_of_its_own(lookups):
    calls, _ = lookups
    cve_engine.run("10.0.0.1", [22], [_port(22, "ssh", [KERNEL_22], version="9.6p1")])
    assert calls == [(KERNEL_22, "", (KERNEL_22,))]


def test_a_truncated_search_is_recorded_with_its_cap(lookups):
    result = cve_engine.run("10.0.0.1", [22], [_port(22, "ssh", [KERNEL_22])])
    record = result["candidate_enumeration"]
    assert record["searches"] == 1
    assert record["truncated"] == [
        {
            "scope": "host",
            "port": None,
            "protocol": None,
            "search": KERNEL_22,
            "source": "cpe_exact",
            "cap": 2000,
        }
    ]


def test_every_search_completing_is_recorded_as_none_truncated(lookups):
    result = cve_engine.run(
        "10.0.0.1", [80], [_port(80, "http", ["cpe:/a:igor_sysoev:nginx"])]
    )
    assert result["candidate_enumeration"] == {"searches": 1, "truncated": []}


def test_cached_candidates_are_never_bound_to_a_port(lookups):
    _calls, cache = lookups
    first = cve_engine.run(
        "10.0.0.1", [8080], [_port(8080, "http", banner="nginx/1.18.0")]
    )
    second = cve_engine.run(
        "10.0.0.2", [9090], [_port(9090, "http", banner="nginx/1.18.0")]
    )
    assert first["cves"][0]["port"] == 8080
    assert second["cves"][0]["port"] == 9090
    assert all("port" not in record for records in cache.values() for record in records)


def test_an_snmp_sysdescr_is_never_a_search_term(lookups):
    calls, _ = lookups
    cve_engine.run(
        "10.0.0.1", [161], [_port(161, "snmp", banner=SYSDESCR, protocol="udp")]
    )
    assert all("superusr" not in str(query).lower() for query, _v, _c in calls)
    # The agent is searched by its service name, like any unfingerprinted
    # service, and the kernel the description names is searched for the host.
    assert ("snmp", "", ()) in calls
    kernel = [c for c in calls if any("linux_kernel" in cpe for cpe in c[2])]
    assert kernel and kernel[0][1] == "6.8.0"


def test_an_unrecognised_sysdescr_adds_no_platform_search(lookups):
    calls, _ = lookups
    cve_engine.run(
        "10.0.0.1",
        [161],
        [_port(161, "snmp", banner="HP ETHERNET MULTI-ENVIRONMENT", protocol="udp")],
    )
    assert calls == [("snmp", "", ())]


def test_one_platform_named_two_ways_is_searched_once(lookups):
    calls, _ = lookups
    cve_engine.run(
        "10.0.0.1",
        [22, 161],
        [
            _port(22, "ssh", [KERNEL_22]),
            _port(161, "snmp", banner=SYSDESCR, protocol="udp"),
        ],
    )
    kernel = [c for c in calls if any("linux_kernel" in cpe for cpe in c[2])]
    assert len(kernel) == 1
    assert kernel[0][1] == "6.8.0", "the spelling that carries a version wins"
