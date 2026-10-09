"""
Log redaction proof for the harness (Phase 10.2d). Reads the gateway and
gateway-auth logs of a harness run and the list of every token the runner
minted, and fails if any token, any fragment of one, a query string, or a
credential-bearing header appears in any log line.

    python3 scan_logs.py LOGS TOKENS
"""

from __future__ import annotations

import json
import re
import sys

FORBIDDEN = [
    (re.compile(r"ticket="), "a ticket query parameter"),
    (re.compile(r"token="), "a token query parameter"),
    (re.compile(r"eyJ[\w-]{6,}"), "a JWT-shaped string"),
    # The credential form ("Bearer <value>"), case-sensitive as the scheme is
    # sent; gateway-auth's own "policy=bearer" field is not a credential.
    (re.compile(r"\bBearer\s+\S"), "a Bearer credential"),
    (re.compile(r"authorization", re.I), "the Authorization header"),
    (re.compile(r"\bcookie", re.I), "a cookie"),
    (re.compile(r"referer", re.I), "the Referer"),
]


def main(logs_path: str, tokens_path: str) -> int:
    logs = open(logs_path, encoding="utf-8", errors="replace").read().splitlines()
    tokens = [t for t in open(tokens_path).read().split() if t]
    fragments = {part for t in tokens for part in t.split(".") if len(part) >= 16}
    problems = []
    access_lines = 0
    for number, line in enumerate(logs, 1):
        for pattern, what in FORBIDDEN:
            if pattern.search(line):
                problems.append(f"line {number}: {what}")
        for fragment in fragments:
            if fragment in line:
                problems.append(f"line {number}: a fragment of a minted token")
                break
        payload = line.split("|", 1)[1].strip() if "|" in line else line
        if payload.startswith("{"):
            record = json.loads(payload)
            access_lines += 1
            if "?" in record.get("uri", ""):
                problems.append(f"line {number}: a query string in the logged uri")
    print(f"scanned {len(logs)} log lines ({access_lines} gateway access records) "
          f"for {len(tokens)} minted tokens: {len(problems)} problem(s)")
    for problem in problems[:20]:
        print("  " + problem)
    if access_lines == 0 or not tokens:
        print("  nothing was scanned — the run did not produce logs or tokens")
        return 1
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
