"""
The TLS test listener itself (Phase 10.4): handshake, certificate and SANs,
protocol versions, and that nothing plaintext is served on it. Runs both
through the published 127.0.0.1:8443 (host runner) and in-network.
"""

from __future__ import annotations

import socket
import ssl

import pytest
from cryptography import x509

from conftest import CA, EDGE, EDGE_HOST, tls_context


def _handshake(context, server_hostname=EDGE_HOST):
    with socket.create_connection(EDGE, timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=server_hostname) as tls:
            return tls.version(), tls.cipher()[0], tls.getpeercert(binary_form=True)


def test_the_handshake_verifies_against_the_test_ca():
    version, cipher, der = _handshake(tls_context())
    assert version in ("TLSv1.2", "TLSv1.3")
    cert = x509.load_der_x509_certificate(der)
    assert "THROWAWAY" in cert.issuer.rfc4514_string()


def test_the_certificate_names_exactly_the_test_hosts():
    _, _, der = _handshake(tls_context())
    san = x509.load_der_x509_certificate(der).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sorted(san.get_values_for_type(x509.DNSName)) == ["ccurepro.cdac.in", "edge-tls", "localhost"]
    assert [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] == ["127.0.0.1"]


def test_a_name_outside_the_certificate_fails_verification():
    with pytest.raises(ssl.SSLCertVerificationError):
        _handshake(tls_context(), server_hostname="evil.example")


def test_an_untrusted_client_trust_store_fails_verification():
    with pytest.raises(ssl.SSLCertVerificationError):
        _handshake(ssl.create_default_context())  # the system store does not know the test CA


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
def test_tls_1_2_and_1_3_are_offered(version):
    negotiated, cipher, _ = _handshake(tls_context(minimum=version, maximum=version))
    assert negotiated == {ssl.TLSVersion.TLSv1_2: "TLSv1.2", ssl.TLSVersion.TLSv1_3: "TLSv1.3"}[version]
    if version == ssl.TLSVersion.TLSv1_2:
        assert cipher.startswith("ECDHE-")  # forward secrecy only


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1])
def test_tls_1_0_and_1_1_are_refused(version):
    context = tls_context(maximum=version)
    context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    with pytest.raises((ssl.SSLError, ConnectionResetError, OSError)):
        _handshake(context)


def test_plain_http_on_the_tls_port_serves_nothing_from_the_application():
    with socket.create_connection(EDGE, timeout=10) as raw:
        raw.sendall(b"GET /api/ HTTP/1.1\r\nHost: ccurepro.cdac.in\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            chunk = raw.recv(4096)
            if not chunk:
                break
            data += chunk
    status_line = data.split(b"\r\n", 1)[0]
    assert b" 400 " in status_line
    assert b"plain HTTP request was sent to HTTPS port" in data
    assert b"x-request-id" not in data.lower() and b"platform" not in data


def test_the_ca_file_is_a_certificate_only():
    text = open(CA).read()
    assert "BEGIN CERTIFICATE" in text and "PRIVATE KEY" not in text
