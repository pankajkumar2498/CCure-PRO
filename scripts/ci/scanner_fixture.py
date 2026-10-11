"""Exercise scanner HTTP detection and JSON output against a loopback fixture.

Run inside the backend image with --network none. No real target, feed, API,
credential or application database is involved.
"""

import json
import re
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        found = self.path == "/ccure-marker"
        body = b"ccure-controlled-marker" if found else b"missing"
        self.send_response(200 if found else 404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=90)


def main():
    versions = dict(
        re.findall(
            r"^ARG (NUCLEI_VERSION|FFUF_VERSION|SUBFINDER_VERSION)=v(.+)$",
            Path(sys.argv[1]).read_text(),
            re.MULTILINE,
        )
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="ccure-scanner-fixture-") as tmp:
            root = Path(tmp)
            url = f"http://127.0.0.1:{server.server_port}"
            template = root / "fixture.yaml"
            template.write_text(
                """id: ccure-dependency-smoke
info:
  name: CCure controlled scanner fixture
  author: ccure
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/ccure-marker"
    matchers:
      - type: word
        part: body
        words:
          - ccure-controlled-marker
"""
            )
            nuclei_output = root / "nuclei.jsonl"
            nuclei_result = run(
                "nuclei",
                "-u",
                url,
                "-t",
                str(template),
                "-jsonl",
                "-o",
                str(nuclei_output),
                "-duc",
                "-ni",
                "-silent",
                "-nc",
                "-timeout",
                "3",
                "-retries",
                "0",
            )
            findings = [
                json.loads(line) for line in nuclei_output.read_text().splitlines()
            ]
            assert len(findings) == 1, (findings, nuclei_result.stderr)
            assert findings[0]["template-id"] == "ccure-dependency-smoke"
            assert findings[0]["matched-at"] == url + "/ccure-marker"

            wordlist = root / "words.txt"
            wordlist.write_text("ccure-marker\nnot-found\n")
            ffuf_output = root / "ffuf.json"
            run(
                "ffuf",
                "-u",
                url + "/FUZZ",
                "-w",
                str(wordlist),
                "-o",
                str(ffuf_output),
                "-of",
                "json",
                "-mc",
                "200",
                "-t",
                "1",
                "-timeout",
                "3",
                "-noninteractive",
                "-s",
            )
            results = json.loads(ffuf_output.read_text())["results"]
            assert len(results) == 1, results
            assert results[0]["input"]["FUZZ"] == "ccure-marker"
            assert results[0]["status"] == 200

            for tool, flag, pin in (
                ("nuclei", "-version", "NUCLEI_VERSION"),
                ("ffuf", "-V", "FFUF_VERSION"),
                ("subfinder", "-version", "SUBFINDER_VERSION"),
            ):
                result = run(tool, flag)
                assert versions[pin] in result.stdout + result.stderr, (tool, result)
            print(
                "PASS: pinned scanner versions, Nuclei detection and ffuf JSON discovery"
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
