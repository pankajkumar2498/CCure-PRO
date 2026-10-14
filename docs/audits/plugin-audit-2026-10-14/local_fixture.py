"""Controlled loopback HTTP/TLS + real Nuclei execution; no external targets.

Does not exercise API dispatch or database persistence. Unrelated probes and
feed queries are replaced explicitly to prevent outbound traffic.
"""

import json
import ssl
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from engines.vulnerability.plugins import http_analyzer, nuclei_probe, tls_scanner
from engines.vulnerability.vulnerability_engine import VulnerabilityEngine


class Handler(BaseHTTPRequestHandler):
    weak = True
    server_version = "Fixture"
    sys_version = ""

    def log_message(self, *_):
        pass

    def do_HEAD(self):
        self.answer(False)

    def do_GET(self):
        self.answer(True)

    def answer(self, body):
        content = b"DB_PASSWORD=synthetic-audit-fixture\n" if self.weak and self.path == "/.env" else b"fixture"
        status = 200 if self.path == "/" or (self.weak and self.path == "/.env") else 404
        self.send_response(status)
        if not self.weak:
            for k, v in {"strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'none'", "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "no-referrer", "permissions-policy": "geolocation=()"}.items():
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        if body:
            self.wfile.write(content)


with tempfile.TemporaryDirectory(prefix="ccure-audit-fixture-") as folder:
    root = Path(folder)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    (root / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    (root / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (root / "audit-fixture.yaml").write_text("""id: ccure-audit-synthetic-env
info:
  name: Synthetic CCure audit fixture
  author: ccure-audit-fixture
  severity: high
http:
  - method: GET
    path:
      - '{{BaseURL}}/.env'
    matchers:
      - type: word
        words:
          - 'DB_PASSWORD=synthetic-audit-fixture'
""")
    http = ThreadingHTTPServer(("127.0.0.1", 8080), Handler)
    tls = ThreadingHTTPServer(("127.0.0.1", 8443), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(root / "cert.pem", root / "key.pem")
    tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
    for server in (http, tls):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with patch.object(nuclei_probe, "_TEMPLATE_DIR", str(root)), \
             patch.object(nuclei_probe, "_TIMEOUT_SECONDS", 40), \
             patch("engines.vulnerability.plugins.snmp_probe.run", return_value={}), \
             patch("engines.vulnerability.plugins.udp_scanner.run", return_value={}), \
             patch("engines.vulnerability.plugins.icmp_probe.run", return_value={}), \
             patch("engines.vulnerability.plugins.heartbleed_probe.run", return_value={}), \
             patch("engines.vulnerability.plugins.cve_engine.run", return_value={}):
            output = {}
            for mode in ("weak", "hardened"):
                Handler.weak = mode == "weak"
                host = {"ip_address": "127.0.0.1", "is_active": True, "open_ports": [
                    {"port": 8080, "protocol": "tcp", "service": "http"},
                    {"port": 8443, "protocol": "tcp", "service": "https"},
                ]}
                VulnerabilityEngine().run([host])
                findings = host.get("cves", [])
                http_ids = [f.get("cve_id") for f in findings if "HTTP-" in str(f.get("cve_id"))]
                nuclei_ids = [f.get("cve_id") for f in findings if "NUCLEI-" in str(f.get("cve_id"))]
                output[mode] = {"finding_ids": [f.get("cve_id") for f in findings], "http_findings": http_ids, "nuclei_findings": nuclei_ids, "nuclei_templates_run": host.get("nuclei_templates_run"), "tls_endpoints": len(host.get("tls_endpoints", [])), "risk": host.get("host_risk_level"), "verified_count": len(findings)}
                assert host.get("nuclei_templates_run") is True
                assert len(host.get("tls_endpoints", [])) == 1
                if mode == "weak":
                    assert http_ids and nuclei_ids
                else:
                    assert not http_ids and not nuclei_ids
            print(json.dumps(output, indent=2))
    finally:
        for server in (http, tls):
            server.shutdown()
            server.server_close()
