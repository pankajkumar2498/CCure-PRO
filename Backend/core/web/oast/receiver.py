"""
core/web/oast/receiver.py
────────────────────────────────────────────────────────────────────────────
Self-hosted OAST collaborator (Phase 9).

A minimal server the scanner controls, so out-of-band detection works with no
outbound internet and without sending interaction metadata to a third party
(ProjectDiscovery's public interact.sh). It records every inbound HTTP request
and DNS query it receives, keyed by the interaction token the payload carried,
and exposes them to the poll client over a reserved, authenticated endpoint.

  • **HTTP** — a threaded HTTP server. Any request is an interaction; the token
    is read from the Host subdomain, then the first path segment. The one
    exception is the reserved ``/_ccure_oast/`` control path (poll + health),
    which is never treated as a callback (a real token is hex and cannot begin
    with ``_``).

  • **DNS** — an optional UDP responder that parses the query name, records the
    leading label as the token, and answers so the target's resolver does not
    hang. It binds whatever port it is given (53 in production behind a
    delegated zone; an ephemeral high port in tests).

The record keeps only what the callback exposes anyway — protocol, source
address, timestamp, method/path/host or query name. It never stores request
bodies or credentials, because a correlation callback is not supposed to carry
any (the token is the whole message).
"""

from __future__ import annotations

import json
import logging
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Optional

from core.web.oast.session import token_from_host, token_from_path

log = logging.getLogger("ccure.web.oast.receiver")

_CONTROL_PREFIX = "/_ccure_oast/"


class _Inbox:
    """Thread-safe append-only interaction store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: List[dict] = []

    def add(self, item: dict) -> None:
        with self._lock:
            self._items.append(item)

    def since(self, ts: float = 0.0) -> List[dict]:
        with self._lock:
            return [dict(i) for i in self._items if i.get("timestamp", 0) > ts]

    def all(self) -> List[dict]:
        with self._lock:
            return [dict(i) for i in self._items]

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


class OastReceiver:
    """
    Self-hosted HTTP (+ optional DNS) OAST collaborator.

    Args:
        base_domain: the zone whose subdomain carries the token.
        host: bind address for both listeners.
        http_port: 0 for an ephemeral port (tests); a fixed port in production.
        dns_port: DNS UDP port, or 0 to disable the DNS listener.
        auth_token: bearer required on the poll endpoint, so interactions are
            not world-readable. Empty disables the check (loopback-only use).
    """

    def __init__(
        self,
        base_domain: str = "oast.ccure.internal",
        *,
        host: str = "127.0.0.1",
        http_port: int = 0,
        dns_port: int = 0,
        auth_token: str = "",
    ) -> None:
        self.base_domain = base_domain.strip().strip(".").lower()
        self.host = host
        self._req_http_port = http_port
        self._req_dns_port = dns_port
        self.auth_token = auth_token or ""
        self.inbox = _Inbox()

        self._httpd: Optional[ThreadingHTTPServer] = None
        self._http_thread: Optional[threading.Thread] = None
        self.http_port = 0

        self._dns_sock: Optional[socket.socket] = None
        self._dns_thread: Optional[threading.Thread] = None
        self._dns_running = False
        self.dns_port = 0

    # ── lifecycle ─────────────────────────────────────────────────────────────
    def start(self) -> "OastReceiver":
        self._start_http()
        # dns_port == 0 means the DNS listener is off; a caller wanting an
        # ephemeral DNS port asks for it explicitly with start_dns(0).
        if self._req_dns_port:
            self._start_dns(self._req_dns_port)
        return self

    def __enter__(self) -> "OastReceiver":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def stop(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None
        self._dns_running = False
        if self._dns_sock is not None:
            try:
                self._dns_sock.close()
            except Exception:
                pass
            self._dns_sock = None

    def clear(self) -> None:
        self.inbox.clear()

    # ── HTTP listener ─────────────────────────────────────────────────────────
    def _start_http(self) -> None:
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # silence
                pass

            def _empty(self, code: int):
                # A bodyless response still needs Content-Length: 0 under
                # HTTP/1.1 keep-alive, or the client waits for a body that never
                # comes and eventually times out.
                self.send_response(code)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _record(self):
                path = self.path or "/"
                if path.startswith(_CONTROL_PREFIX):
                    return self._control(path)
                host = self.headers.get("Host", "")
                token = token_from_host(host, receiver.base_domain) or token_from_path(
                    path
                )
                receiver.inbox.add(
                    {
                        "token": token,
                        "protocol": "http",
                        "remote_addr": self.client_address[0],
                        "timestamp": time.time(),
                        "method": self.command,
                        "path": path,
                        "host": host.split(":")[0],
                        "user_agent": self.headers.get("User-Agent", ""),
                    }
                )
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except Exception:
                    pass

            # Any verb is a valid interaction.
            do_GET = _record
            do_POST = _record
            do_PUT = _record
            do_HEAD = _record
            do_OPTIONS = _record
            do_DELETE = _record

            def _control(self, path: str):
                # Poll / health. Bearer-gated so interactions are not
                # world-readable.
                if receiver.auth_token:
                    auth = self.headers.get("Authorization", "")
                    if auth != f"Bearer {receiver.auth_token}":
                        self._empty(401)
                        return
                if path.startswith(_CONTROL_PREFIX + "health"):
                    payload = {"status": "ok", "now": time.time()}
                elif path.startswith(_CONTROL_PREFIX + "interactions"):
                    since = 0.0
                    if "?" in path:
                        from urllib.parse import parse_qs, urlparse

                        q = parse_qs(urlparse(path).query)
                        try:
                            since = float(q.get("since", ["0"])[0])
                        except (ValueError, TypeError):
                            since = 0.0
                    payload = {
                        "interactions": receiver.inbox.since(since),
                        "now": time.time(),
                    }
                else:
                    self._empty(404)
                    return
                data = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except Exception:
                    pass

        self._httpd = ThreadingHTTPServer((self.host, self._req_http_port), Handler)
        self._httpd.daemon_threads = True
        self.http_port = self._httpd.server_address[1]
        self._http_thread = threading.Thread(
            target=self._httpd.serve_forever, daemon=True
        )
        self._http_thread.start()
        log.info("OAST HTTP collaborator on %s:%s", self.host, self.http_port)

    @property
    def http_base_url(self) -> str:
        return f"http://{self.host}:{self.http_port}"

    @property
    def control_url(self) -> str:
        return f"{self.http_base_url}{_CONTROL_PREFIX}"

    # ── DNS listener (optional) ───────────────────────────────────────────────
    def start_dns(self, port: int = 0) -> int:
        """Start the UDP DNS responder on ``port`` (0 = ephemeral). Returns the port."""
        self._start_dns(port)
        return self.dns_port

    def _start_dns(self, port: int) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, port))
        sock.settimeout(0.5)
        self._dns_sock = sock
        self.dns_port = sock.getsockname()[1]
        self._dns_running = True
        self._dns_thread = threading.Thread(target=self._dns_loop, daemon=True)
        self._dns_thread.start()
        log.info("OAST DNS collaborator on %s:%s", self.host, self.dns_port)

    def _dns_loop(self) -> None:
        while self._dns_running and self._dns_sock is not None:
            try:
                data, addr = self._dns_sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                qname = _parse_dns_qname(data)
            except Exception:
                qname = ""
            token = token_from_host(qname, self.base_domain)
            self.inbox.add(
                {
                    "token": token,
                    "protocol": "dns",
                    "remote_addr": addr[0],
                    "timestamp": time.time(),
                    "qname": qname,
                }
            )
            try:
                resp = _build_dns_response(data)
                if resp:
                    self._dns_sock.sendto(resp, addr)
            except Exception:
                pass


# ── minimal DNS wire parsing (no dnspython at scan time) ──────────────────────
def _parse_dns_qname(data: bytes) -> str:
    """Return the query name from a DNS request packet (labels joined by '.')."""
    if len(data) < 13:
        return ""
    idx = 12  # skip the 12-byte header
    labels = []
    while idx < len(data):
        length = data[idx]
        if length == 0:
            break
        if length & 0xC0:  # compression pointer — not expected in a question
            break
        idx += 1
        labels.append(data[idx : idx + length].decode("ascii", "ignore"))
        idx += length
    return ".".join(labels).lower()


def _build_dns_response(query: bytes) -> bytes:
    """
    Build a tiny A-record answer (127.0.0.1) for the query, so the target's
    resolver completes rather than retrying. Best-effort; correctness of the
    answer does not matter, only that we reply.
    """
    if len(query) < 12:
        return b""
    txn_id = query[:2]
    # Response flags: QR=1, standard query, no error.
    flags = struct.pack(">H", 0x8180)
    counts = struct.pack(">HHHH", 1, 1, 0, 0)  # QD=1, AN=1
    # Copy the question section verbatim.
    idx = 12
    while idx < len(query) and query[idx] != 0:
        if query[idx] & 0xC0:
            break
        idx += query[idx] + 1
    idx += 1  # null label
    qsection = query[12 : idx + 4]  # name + qtype + qclass
    answer = (
        b"\xc0\x0c"  # pointer to the question name
        + struct.pack(">HH", 1, 1)  # type A, class IN
        + struct.pack(">I", 30)  # TTL
        + struct.pack(">H", 4)  # RDLENGTH
        + socket.inet_aton("127.0.0.1")
    )
    return txn_id + flags + counts + qsection + answer
