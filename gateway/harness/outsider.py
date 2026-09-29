"""
An UNTRUSTED client for the harness trust-boundary tests. LOCAL HARNESS ONLY.

The test runner plays the trusted edge (host nginx) at 10.254.10.10. This
relay runs at another address, 10.254.10.20, which the gateway does not trust:
the runner asks it to send a request to the gateway with whatever forwarding
headers it likes, and it answers with the gateway's response. The tests then
check the gateway forwarded this peer's own address, not the claimed one.

    POST /relay  {"method": "GET", "path": "/api/...", "headers": {...}}
"""

from __future__ import annotations

import http.client
import http.server
import json


class Relay(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        if self.path != "/relay":
            self.send_error(404)
            return
        spec = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        conn = http.client.HTTPConnection("gateway", 8080, timeout=10)
        conn.request(spec.get("method", "GET"), spec["path"], headers=spec.get("headers") or {})
        response = conn.getresponse()
        body = response.read().decode("utf-8", "replace")
        conn.close()
        out = json.dumps({"status": response.status, "headers": response.getheaders(), "body": body}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("0.0.0.0", 9000), Relay).serve_forever()
