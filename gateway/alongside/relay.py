"""
An UNTRUSTED in-network caller for the alongside validation. ALONGSIDE ONLY.

It sits on the alongside network at 10.254.20.50 — a container peer, like the
frontend container or a worker on the live compose network — and forwards one
request, with whatever forwarding headers the test asks for, to the target the
test names (the gateway, or either API directly). The tests then check that no
application trusted what it claimed.

    POST /relay  {"target": ["api", 8000], "method": "GET", "path": "/", "headers": {...}}

With ``"tls": true`` it connects over HTTPS, verifying the edge against the
run's throwaway test CA (Phase 10.4).
"""

from __future__ import annotations

import http.client
import http.server
import json
import ssl


class Relay(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        spec = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        host, port = spec["target"]
        if spec.get("tls"):
            context = ssl.create_default_context(cafile="/tls/ca.pem")
            conn = http.client.HTTPSConnection(host, int(port), timeout=10, context=context)
        else:
            conn = http.client.HTTPConnection(host, int(port), timeout=10)
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
