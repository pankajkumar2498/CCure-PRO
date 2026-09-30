#!/usr/bin/env python3
"""
Phase 10.6 — summarise the M3/M6 connection sampler's log.

The sampler (Phase 10 M3, read-only, /proc only) wrote one line per observed
ESTABLISHED socket every 10 s:

    T <ts>                        a sample was taken
    H <ts> <local> <uid>          a HOST socket dialling 127.0.0.1:8000, with its uid
    C <ts> <remote>               a socket inside ccure-api's netns on :8000, with the peer

This prints, per period (before the cut-over, gateway over TCP, gateway over
the socket), who dialled the published :8000 and whom the api heard from —
the evidence 10.7 needs before :8000 is closed. Counts only.

    python3 scripts/gateway/cutover/m3_summary.py <samples.log> [--json out.json]
"""
from __future__ import annotations

import argparse
import collections
import json
import pwd
import socket
import struct
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))
# boundaries (IST): 10.5 cut-over and 10.6 socket migration, from the switch log
CUTOVER = datetime(2026, 9, 30, 11, 26, 44, tzinfo=IST).timestamp()
HARDEN = datetime(2026, 9, 30, 12, 34, 54, tzinfo=IST).timestamp()


def period(ts: float) -> str:
    if ts < CUTOVER:
        return "1 before cut-over (443 -> :8000)"
    if ts < HARDEN:
        return "2 gateway over TCP (10.5)"
    return "3 gateway over the unix socket (10.6)"


def hexip(h: str) -> str:
    addr = h.split(":")[0]
    return socket.inet_ntoa(struct.pack("<I", int(addr, 16)))


def who(uid: str) -> str:
    try:
        return f"{pwd.getpwuid(int(uid)).pw_name} ({uid})"
    except (KeyError, ValueError):
        return uid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--json")
    args = ap.parse_args()
    samples = collections.Counter()
    host = collections.defaultdict(collections.Counter)
    api = collections.defaultdict(collections.Counter)
    first = last = None
    for line in open(args.log):
        parts = line.split()
        if not parts:
            continue
        ts = float(parts[1])
        first = ts if first is None else first
        last = ts
        p = period(ts)
        if parts[0] == "T":
            samples[p] += 1
        elif parts[0] == "H":
            host[p][who(parts[3])] += 1
        elif parts[0] == "C":
            api[p][hexip(parts[2])] += 1
    out = {
        "from": datetime.fromtimestamp(first, IST).isoformat() if first else None,
        "to": datetime.fromtimestamp(last, IST).isoformat() if last else None,
        "periods": {p: {"samples": samples[p], "hours": round(samples[p] * 10 / 3600, 2),
                        "host_dialers_of_127.0.0.1:8000": dict(host[p]),
                        "api_peers_on_8000": dict(api[p])} for p in sorted(samples)},
    }
    print(json.dumps(out, indent=1))
    if args.json:
        json.dump(out, open(args.json, "w"), indent=1)


if __name__ == "__main__":
    main()
