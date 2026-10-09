"""
Gateway overhead against the direct path (Phase 10.3), measured, not asserted:
the design's budget is +5 ms at p95, and exceeding it is reported rather than
failed, so a slow run does not hide behind a red test. Results go to
$ALONGSIDE_OUT/latency.json for run.sh to print.

Each request opens its own connection on both paths, as host nginx does today.
"""

from __future__ import annotations

import json
import os
import statistics
import time

from conftest import API, GATEWAY, OUT, bearer, request

N = 250


def _measure(target, path, headers):
    samples = []
    for _ in range(N):
        started = time.perf_counter()
        resp = request(target, "GET", path, headers)
        samples.append((time.perf_counter() - started) * 1000)
        assert resp.status == 200
    samples.sort()
    return {"p50": round(statistics.median(samples), 2), "p95": round(samples[int(0.95 * N) - 1], 2),
            "n": N}


def test_gateway_overhead(session):
    results = {}
    for label, path, headers in (
        ("public (no auth_request)", "/", {}),
        ("bearer (auth_request)", "/scans?limit=1", bearer(session["access"])),
    ):
        request(API, "GET", path, headers), request(GATEWAY, "GET", path, headers)  # warm up
        direct = _measure(API, path, headers)
        via = _measure(GATEWAY, path, headers)
        results[label] = {"direct": direct, "gateway": via,
                          "overhead_p50_ms": round(via["p50"] - direct["p50"], 2),
                          "overhead_p95_ms": round(via["p95"] - direct["p95"], 2),
                          "within_5ms_p95": via["p95"] - direct["p95"] <= 5.0}
    with open(os.path.join(OUT, "latency.json"), "w") as fh:
        json.dump(results, fh, indent=1)
    assert results  # measured; the budget is reported, not enforced here
