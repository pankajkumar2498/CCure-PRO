"""
Where an authenticated scan opens its session, and why.

The regression these exist for: ``compliance_credentials.port`` is NOT NULL with
a model default of 22, and until this was fixed it was the *only* thing that
decided where to authenticate. A host running sshd on 2222 was skipped with
"port 22/tcp not open" on a scan that had already identified sshd on 2222, and
the enrichment path additionally dropped the transport entirely — so a Windows
credential opened an SSH handshake against a WinRM listener.

Two safety properties are asserted as hard as the capability itself:

* a credential is never offered to a port that is neither stated on it nor
  positively identified as that transport's service, and
* selection is by TCP reachability, so exactly one authentication attempt is
  made however many candidates were considered.
"""

import pytest
from engines.credentialed.transport_resolver import (
    DEFAULT_PORT,
    TransportEndpoint,
    candidate_endpoints,
    resolve_endpoint,
)


def _port(port, **kw):
    record = {"port": port, "protocol": "tcp", "state": "open"}
    record.update(kw)
    return record


def _ports(endpoints):
    return [e.port for e in endpoints]


# ─────────────────────────────────────────────────────────────────────────────
# Identifying a transport from what the port scan saw
# ─────────────────────────────────────────────────────────────────────────────


def test_stated_port_leads_when_discovery_agrees():
    endpoints = candidate_endpoints(
        transport="ssh", stated_port=22, open_ports=[_port(22, service="ssh")]
    )
    assert _ports(endpoints) == [22]
    assert endpoints[0].source == "credential"


def test_ssh_identified_on_a_non_standard_port_by_service_name():
    endpoints = candidate_endpoints(
        transport="ssh", stated_port=22, open_ports=[_port(2222, service="ssh")]
    )
    assert _ports(endpoints) == [22, 2222]
    assert endpoints[1].source == "discovered"
    assert "2222" not in endpoints[1].evidence  # evidence names the service
    assert "ssh" in endpoints[1].evidence


def test_ssh_identified_by_its_protocol_banner_when_the_service_name_is_wrong():
    """
    RFC 4253's identification string settles it. A listener that opens with
    ``SSH-2.0-...`` is sshd whatever nmap decided to call the service, and this
    is the case that makes a genuinely odd port reachable.
    """
    endpoints = candidate_endpoints(
        transport="ssh",
        stated_port=22,
        open_ports=[_port(8022, service="unknown", banner="SSH-2.0-OpenSSH_9.6")],
    )
    assert 8022 in _ports(endpoints)


def test_ssh_identified_by_product_string():
    endpoints = candidate_endpoints(
        transport="ssh",
        stated_port=22,
        open_ports=[_port(9022, service="tcpwrapped", product="OpenSSH")],
    )
    assert 9022 in _ports(endpoints)


def test_port_db_label_for_2222_identifies_as_ssh():
    """
    This product's own PORT_DB names 2222 ``SSH-Alt`` when nmap did not run a
    version scan. Tokenising rather than substring-matching is what makes that
    label qualify while ``ssl`` does not.
    """
    endpoints = candidate_endpoints(
        transport="ssh", stated_port=22, open_ports=[_port(2222, service="SSH-Alt")]
    )
    assert 2222 in _ports(endpoints)


@pytest.mark.parametrize("service", ["ssl", "https", "ssl/http", "sslh"])
def test_tls_service_names_are_not_read_as_ssh(service):
    endpoints = candidate_endpoints(
        transport="ssh", stated_port=22, open_ports=[_port(443, service=service)]
    )
    assert 443 not in _ports(endpoints)


@pytest.mark.parametrize("service", ["wsman", "WinRM-HTTP", "winrm"])
def test_winrm_identified_by_service_name(service):
    endpoints = candidate_endpoints(
        transport="winrm", stated_port=5985, open_ports=[_port(5985, service=service)]
    )
    assert _ports(endpoints) == [5985]


def test_winrm_identified_on_a_non_standard_port_by_product():
    """
    A WinRM listener moved off 5985 is reported by nmap as ``http`` with the
    product ``Microsoft HTTPAPI httpd`` — the product is the only thing that
    identifies it, and without this the port is invisible to resolution.
    """
    endpoints = candidate_endpoints(
        transport="winrm",
        stated_port=5985,
        open_ports=[
            _port(47001, service="http", product="Microsoft HTTPAPI httpd 2.0")
        ],
    )
    assert 47001 in _ports(endpoints)


def test_plain_http_is_not_read_as_winrm():
    endpoints = candidate_endpoints(
        transport="winrm",
        stated_port=5985,
        open_ports=[_port(8080, service="http", product="nginx")],
    )
    assert 8080 not in _ports(endpoints)


# ─────────────────────────────────────────────────────────────────────────────
# Never spray a credential across open ports
# ─────────────────────────────────────────────────────────────────────────────


def test_an_unidentified_open_port_never_becomes_a_candidate():
    """
    The whole difference between resolution and credential spraying. Every port
    below is open; none is identified as SSH; none may be authenticated to.
    """
    open_ports = [
        _port(80, service="http"),
        _port(443, service="https"),
        _port(3306, service="mysql"),
        _port(8443, service="https-alt"),
        _port(9999),  # open, no identification at all
    ]
    endpoints = candidate_endpoints(
        transport="ssh", stated_port=22, open_ports=open_ports
    )
    assert _ports(endpoints) == [22]


def test_closed_and_filtered_ports_are_never_candidates():
    open_ports = [
        _port(2222, service="ssh", state="closed"),
        _port(2223, service="ssh", state="filtered"),
    ]
    endpoints = candidate_endpoints(
        transport="ssh", stated_port=22, open_ports=open_ports
    )
    assert _ports(endpoints) == [22]


def test_udp_ports_are_never_candidates():
    endpoints = candidate_endpoints(
        transport="ssh",
        stated_port=22,
        open_ports=[dict(_port(2222, service="ssh"), protocol="udp")],
    )
    assert _ports(endpoints) == [22]


def test_a_port_appearing_twice_yields_one_candidate():
    endpoints = candidate_endpoints(
        transport="ssh",
        stated_port=2222,
        open_ports=[_port(2222, service="ssh"), _port(2222, service="ssh")],
    )
    assert _ports(endpoints) == [2222]


@pytest.mark.parametrize("bad", [0, -1, 70000, "", None, "twenty-two"])
def test_an_unusable_stated_port_falls_back_to_the_transport_default(bad):
    endpoints = candidate_endpoints(transport="ssh", stated_port=bad)
    assert _ports(endpoints) == [DEFAULT_PORT["ssh"]]


def test_no_stated_port_uses_the_transports_own_default_not_ssh():
    assert _ports(candidate_endpoints(transport="winrm")) == [5985]
    assert _ports(candidate_endpoints(transport="ssh")) == [22]


# ─────────────────────────────────────────────────────────────────────────────
# The stated port is outranked only by evidence, and never dropped
# ─────────────────────────────────────────────────────────────────────────────


def test_a_stated_port_discovery_names_as_another_service_is_demoted():
    """
    A Windows credential can carry port 22 without anyone having chosen it —
    that is the model default. On a host running both sshd and WinRM, leading
    with 22 sends a WS-Management request to sshd while the real listener sits
    identified two entries away.
    """
    open_ports = [_port(22, service="ssh"), _port(5985, service="wsman")]
    endpoints = candidate_endpoints(
        transport="winrm", stated_port=22, open_ports=open_ports
    )
    assert _ports(endpoints) == [5985, 22]


def test_a_demoted_stated_port_is_still_offered_last():
    """Service detection can be wrong; the operator's choice is never dropped."""
    open_ports = [_port(22, service="ssh"), _port(5985, service="wsman")]
    endpoints = candidate_endpoints(
        transport="winrm", stated_port=22, open_ports=open_ports
    )
    assert 22 in _ports(endpoints)
    assert endpoints[-1].source == "credential"


def test_a_stated_port_discovery_cannot_identify_still_leads():
    """No evidence against it is not evidence against it."""
    open_ports = [_port(2022, service=""), _port(2222, service="ssh")]
    endpoints = candidate_endpoints(
        transport="ssh", stated_port=2022, open_ports=open_ports
    )
    assert _ports(endpoints) == [2022, 2222]


def test_an_unknown_service_on_the_stated_port_does_not_demote_it():
    open_ports = [_port(2022, service="unknown"), _port(2222, service="ssh")]
    endpoints = candidate_endpoints(
        transport="ssh", stated_port=2022, open_ports=open_ports
    )
    assert _ports(endpoints)[0] == 2022


# ─────────────────────────────────────────────────────────────────────────────
# TLS is carried, not re-derived
# ─────────────────────────────────────────────────────────────────────────────


def test_winrm_tls_is_settled_by_convention_on_the_two_standard_ports():
    https = candidate_endpoints(
        transport="winrm", stated_port=None, open_ports=[_port(5986, service="wsman")]
    )
    assert https[0].use_tls is True

    http = candidate_endpoints(
        transport="winrm", stated_port=None, open_ports=[_port(5985, service="wsman")]
    )
    assert http[0].use_tls is False


def test_winrm_tls_is_unknown_on_a_non_standard_port_rather_than_guessed():
    """
    ``None`` is a real answer. nmap carries the TLS fact in a ``tunnel``
    attribute this product does not parse, so anything here would be a guess —
    and a wrong one addresses an HTTPS listener as ``http://``.
    """
    endpoints = candidate_endpoints(
        transport="winrm",
        stated_port=None,
        open_ports=[_port(47001, service="http", product="Microsoft HTTPAPI httpd")],
    )
    assert endpoints[0].use_tls is None


def test_an_explicit_use_tls_on_the_credential_overrides_the_port_convention():
    endpoints = candidate_endpoints(
        transport="winrm",
        stated_port=5985,
        use_tls=True,
        open_ports=[_port(5985, service="wsman")],
    )
    assert endpoints[0].use_tls is True


def test_ssh_endpoints_never_carry_a_tls_flag():
    endpoints = candidate_endpoints(
        transport="ssh", stated_port=22, open_ports=[_port(22, service="ssh")]
    )
    assert endpoints[0].use_tls is None


# ─────────────────────────────────────────────────────────────────────────────
# Choosing one endpoint — discovery is authoritative where it exists
# ─────────────────────────────────────────────────────────────────────────────


def test_no_socket_is_opened_when_the_port_scan_already_answered():
    """
    A 5-second connect per host is minutes across a large scan, and the answer
    is already known. This rule predates resolution and is kept deliberately.
    """
    probed = []

    def probe(ip, port, timeout):
        probed.append(port)
        return True

    result = resolve_endpoint(
        ip="10.0.0.5",
        transport="ssh",
        stated_port=22,
        open_ports=[_port(2222, service="ssh")],
        probe=probe,
    )
    assert result.endpoint.port == 2222
    assert probed == []


def test_nothing_open_for_the_transport_is_refused_with_what_was_considered():
    result = resolve_endpoint(
        ip="10.0.0.5",
        transport="ssh",
        stated_port=22,
        open_ports=[_port(443, service="https")],
    )
    assert not result.resolved
    assert "22/tcp" in result.reason
    assert "no authenticated session attempted" in result.reason


def test_the_reason_names_every_candidate_that_was_rejected():
    result = resolve_endpoint(
        ip="10.0.0.5",
        transport="winrm",
        stated_port=5985,
        open_ports=[_port(80, service="http")],
    )
    assert "5985/tcp" in result.reason
    assert "WINRM" in result.reason


# ─────────────────────────────────────────────────────────────────────────────
# Choosing one endpoint — a TCP probe where there is no discovery
# ─────────────────────────────────────────────────────────────────────────────


def test_the_stated_port_is_probed_before_any_alternate():
    probed = []

    def probe(ip, port, timeout):
        probed.append(port)
        return True

    result = resolve_endpoint(
        ip="10.0.0.5",
        transport="ssh",
        stated_port=2222,
        include_fallbacks=True,
        probe=probe,
    )
    assert probed == [2222]
    assert result.endpoint.port == 2222


def test_a_conventional_alternate_is_reached_when_the_stated_port_is_silent():
    def probe(ip, port, timeout):
        return port == 2222

    result = resolve_endpoint(
        ip="10.0.0.5",
        transport="ssh",
        stated_port=22,
        include_fallbacks=True,
        probe=probe,
    )
    assert result.endpoint.port == 2222
    assert result.endpoint.source == "fallback"


def test_winrm_https_is_reached_when_the_http_listener_is_silent():
    def probe(ip, port, timeout):
        return port == 5986

    result = resolve_endpoint(
        ip="10.0.0.5",
        transport="winrm",
        stated_port=5985,
        include_fallbacks=True,
        probe=probe,
    )
    assert result.endpoint.port == 5986
    assert result.endpoint.use_tls is True


def test_fallbacks_are_bounded_to_the_conventional_alternates():
    """
    A long alternate list turns every unreachable host into a minute of connect
    timeouts. This is a courtesy, not a port scan.
    """
    probed = []

    def probe(ip, port, timeout):
        probed.append(port)
        return False

    resolve_endpoint(
        ip="10.0.0.5",
        transport="ssh",
        stated_port=22,
        include_fallbacks=True,
        probe=probe,
    )
    assert probed == [22, 2222]


def test_fallbacks_are_off_unless_asked_for():
    probed = []

    def probe(ip, port, timeout):
        probed.append(port)
        return False

    resolve_endpoint(ip="10.0.0.5", transport="ssh", stated_port=22, probe=probe)
    assert probed == [22]


def test_a_probe_that_raises_is_read_as_closed_not_as_reachable():
    def probe(ip, port, timeout):
        if port == 22:
            raise OSError("network unreachable")
        return True

    result = resolve_endpoint(
        ip="10.0.0.5",
        transport="ssh",
        stated_port=22,
        include_fallbacks=True,
        probe=probe,
    )
    assert result.endpoint.port == 2222


def test_nothing_reachable_is_refused_rather_than_attempted():
    result = resolve_endpoint(
        ip="10.0.0.5",
        transport="ssh",
        stated_port=22,
        include_fallbacks=True,
        probe=lambda ip, port, timeout: False,
    )
    assert not result.resolved
    assert result.endpoint is None


def test_the_default_probe_is_a_socket_test_not_an_authentication_attempt():
    """
    Selection must never generate a failed-logon event. Both defaults are the
    executors' own ``test_connectivity``, which opens a socket and closes it.
    """
    from engines.credentialed.ssh_scanner import SSHScanner
    from engines.credentialed.transport_resolver import _default_probe
    from engines.credentialed.winrm_executor import WinRMExecutor

    assert _default_probe("ssh") is SSHScanner.test_connectivity
    assert _default_probe("winrm") is WinRMExecutor.test_connectivity


# ─────────────────────────────────────────────────────────────────────────────
# The behaviour matrix this fix was asked for
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "transport,stated,listening,service",
    [
        ("ssh", 22, 22, "ssh"),
        ("ssh", 2222, 2222, "ssh"),
        ("ssh", 22, 2222, "ssh"),  # discovered, credential not updated
        ("ssh", 8022, 8022, "ssh"),  # configured, non-conventional
        ("winrm", 5985, 5985, "wsman"),
        ("winrm", 5986, 5986, "wsman"),
        ("winrm", 5985, 5986, "wsman"),  # discovered on the other standard port
        ("winrm", 15985, 15985, "wsman"),  # configured, non-conventional
        ("winrm", 5985, 47001, "http"),  # discovered, non-conventional
    ],
)
def test_every_required_port_arrangement_resolves(
    transport, stated, listening, service
):
    record = _port(listening, service=service)
    if service == "http":
        record["product"] = "Microsoft HTTPAPI httpd"
    result = resolve_endpoint(
        ip="10.0.0.5",
        transport=transport,
        stated_port=stated,
        open_ports=[record],
    )
    assert result.resolved, result.reason
    assert result.endpoint.port == listening


def test_endpoint_description_is_readable_in_a_skip_reason():
    endpoint = TransportEndpoint(port=5986, use_tls=True, source="discovered")
    assert endpoint.describe() == "5986/tcp TLS [discovered]"
    assert TransportEndpoint(port=22).describe() == "22/tcp [credential]"
