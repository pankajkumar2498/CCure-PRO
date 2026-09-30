"""
Generate the throwaway TLS material for the Phase 10.4 test edge.
ALONGSIDE ONLY — never a production certificate or key.

    python make_test_tls.py OUT_DIR

Writes, all under OUT_DIR (run.sh puts it in the run's scratch directory,
outside the repository, and deletes it at teardown):

* ``ca.pem``          — a one-day test CA certificate (public; clients trust it)
* ``edge/server.pem`` — the edge's leaf certificate, signed by that CA
* ``edge/server.key`` — the leaf's private key (mode 0600)

The CA's private key exists only in this process's memory and is never
written, so nothing can sign another certificate with it after the run.
SANs: ccurepro.cdac.in, localhost, edge-tls, 127.0.0.1 — the names the
tests dial; anything else fails hostname verification, which a test checks.
"""

from __future__ import annotations

import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import ipaddress

SANS_DNS = ("ccurepro.cdac.in", "localhost", "edge-tls")
SANS_IP = ("127.0.0.1",)


def main(out: str) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CCure Phase 10.4 THROWAWAY test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                     crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ccurepro.cdac.in (Phase 10.4 test)")]))
        .issuer_name(ca_name).public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName(n) for n in SANS_DNS] + [x509.IPAddress(ipaddress.ip_address(i)) for i in SANS_IP]),
            critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    os.makedirs(os.path.join(out, "edge"), exist_ok=True)
    with open(os.path.join(out, "ca.pem"), "wb") as fh:
        fh.write(ca.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(out, "edge", "server.pem"), "wb") as fh:
        fh.write(leaf.public_bytes(serialization.Encoding.PEM))
    key_path = os.path.join(out, "edge", "server.key")
    with open(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as fh:
        fh.write(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    print("test TLS material written (CA private key not kept)")


if __name__ == "__main__":
    main(sys.argv[1])
