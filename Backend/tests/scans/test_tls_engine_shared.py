"""
B9: the network scan's TLS assessment runs without the web module.

The network checks' TLS plugin ran its deep assessment through the sslyze
wrapper in ``core/web/sslyze/``, so the network scan could not run without the
web scanner's package. The wrapper is the TLS engine both paths use; it moved
to ``engines/tls/wrapper.py``, below both, and the old path is an alias of the
same module.

These pin the purpose (no network-check import of the web module, statically
and at run time, with the web module made unimportable), that the engine
imports no application code, that both callers use its own path, and that the
alias is the same module. B9's golden capture, the plugin and the web path
against a live listener byte-identical, is recorded in the refactoring log
(§6).
"""

import ast
import json
import subprocess
import sys

import pytest

from scripts.architecture import capability_map
from scripts.architecture.import_graph import collect_edges, discover_modules
from testpaths import BACKEND_ROOT


def test_the_network_checks_import_nothing_from_the_web_module():
    """Lazy imports count; the TLS plugin's import of the wrapper was one."""
    _, edges = collect_edges()
    reaching = sorted(
        (e.src, e.dst)
        for e in edges
        if capability_map.capability_of(e.src) == "network_checks"
        and capability_map.capability_of(e.dst) == "web_dast"
    )
    assert reaching == []


def test_the_tls_engine_imports_no_application_code():
    modules, edges = collect_edges()
    assert "engines.tls.wrapper" in modules
    beyond = sorted(
        (e.src, e.dst)
        for e in edges
        if e.src.startswith("engines.tls") and not e.dst.startswith("engines.tls")
    )
    assert beyond == []
    assert capability_map.capability_of("engines.tls.wrapper") == "tls"
    # Below both of its users, so neither edge into it is lateral or upward.
    layer = capability_map.CAPABILITIES
    assert layer["tls"][0] < layer["network_checks"][0]
    assert layer["tls"][0] < layer["web_dast"][0]


def test_production_code_imports_the_engine_by_its_own_path():
    """The alias is for tests, patch targets and scripts, not new code."""
    importers = {}
    for module, path in discover_modules().items():
        if module.split(".")[0] in ("tests", "scripts", "alembic"):
            continue
        if module == "core.web.sslyze.wrapper":
            continue  # the alias itself
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module:
                importers.setdefault(node.module, set()).add(module)
    assert "core.web.sslyze.wrapper" not in importers
    assert "core.web.sslyze" not in importers
    assert importers["engines.tls.wrapper"] == {
        "engines.vulnerability.plugins.tls_scanner",
        "orchestrator.web_orchestrator",
    }


def test_the_old_path_is_the_same_module():
    import core.web.sslyze.wrapper as old
    import engines.tls.wrapper as new

    assert old is new
    assert old.SSLyzeWrapper is new.SSLyzeWrapper
    # Log filters match on the logger's name; the move does not change it.
    assert new.log.name == "ccure.web.sslyze"


_WITHOUT_WEB = r"""
import datetime, http.server, json, ssl, sys, threading, tempfile, pathlib


class NoWebModule:
    # The network scan must run on a host where core.web cannot be imported.
    def find_spec(self, name, path=None, target=None):
        if name == "core.web" or name.startswith("core.web."):
            raise ModuleNotFoundError(f"blocked for the test: {name}")
        return None


sys.meta_path.insert(0, NoWebModule())

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "b9.invalid")])
utc = datetime.timezone.utc
cert = (
    x509.CertificateBuilder().subject_name(name).issuer_name(name)
    .public_key(key.public_key()).serial_number(0xB9)
    .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=utc))
    .not_valid_after(datetime.datetime(2021, 1, 1, tzinfo=utc))
    .sign(key, hashes.SHA256())
)
tmp = pathlib.Path(tempfile.mkdtemp())
(tmp / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
(tmp / "key.pem").write_bytes(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption()))
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(str(tmp / "cert.pem"), str(tmp / "key.pem"))


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def finish_request(self, request, address):
        try:
            super().finish_request(context.wrap_socket(request, server_side=True), address)
        except (ssl.SSLError, OSError):
            pass

    def handle_error(self, request, address):
        pass


server = Server(("127.0.0.1", 0), Handler)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()

from core.checks.probe_endpoints import ProbePorts
from engines.vulnerability.plugins import tls_scanner

host = {"open_ports": [{"port": port, "protocol": "tcp", "service": "https"}]}
result = tls_scanner.run("127.0.0.1", ProbePorts(host))
endpoint = result["tls_endpoints"][0]
print(json.dumps({
    "deep_assessed": endpoint["deep_assessed"],
    "protocols": sorted(p for p, v in endpoint.get("protocols", {}).items() if v.get("supported")),
    "findings": sorted(f.get("title", "") for f in result.get("cves", [])),
    "web_loaded": sorted(m for m in sys.modules if m.startswith("core.web")),
}))
"""


def _sslyze_available():
    try:
        from engines.tls.wrapper import SSLyzeWrapper

        return SSLyzeWrapper().is_available()
    except Exception:
        return False


@pytest.mark.skipif(not _sslyze_available(), reason="sslyze is not installed")
def test_the_network_tls_assessment_runs_with_the_web_module_unavailable():
    """
    The plan's target, run: a fresh interpreter in which core.web cannot be
    imported runs the TLS plugin against a local listener serving an expired
    certificate, and the sslyze deep assessment still happens. On the parent
    the plugin's import failed, was swallowed as "sslyze unavailable", and the
    endpoint was assessed by the handshake probe alone.
    """
    done = subprocess.run(
        [sys.executable, "-c", _WITHOUT_WEB],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    seen = json.loads(done.stdout.strip().splitlines()[-1])
    assert seen["web_loaded"] == []
    assert seen["deep_assessed"] is True
    assert "tls_1_2" in seen["protocols"]
    assert any("xpired" in title for title in seen["findings"]), seen["findings"]
