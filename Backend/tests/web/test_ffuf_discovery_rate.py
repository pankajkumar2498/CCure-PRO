"""
Phase 21 — ffuf content-discovery rate is decoupled from the fuzzing ceiling.

Phase 20 measured the standard-tier ffuf run dominating the CRAWL phase because
content discovery inherited the conservative WEB_SCAN_RATE_LIMIT (5 req/s).
Content discovery is directory brute-forcing (plain GETs), so it now runs at a
dedicated FFUF_RATE — the SAME wordlist, no coverage reduction, just a higher
request rate. These tests pin the decoupling and that the wrapper honours the
rate it is handed (so the orchestrator's value reaches ffuf's -rate flag).
"""

from config import WebScanConfig
from core.web.ffuf.wrapper import FfufWrapper


def test_ffuf_rate_is_decoupled_from_fuzzing_ceiling():
    # A dedicated discovery rate, higher than the conservative fuzzing ceiling,
    # so the same wordlist is not throttled to injection-probe speed.
    assert WebScanConfig.FFUF_RATE > WebScanConfig.SCAN_RATE_LIMIT


def test_wrapper_passes_rate_to_ffuf(monkeypatch, tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("a\nb\nc\n")
    captured = {}

    def _fake_run(self, args, **k):
        captured["args"] = args

        class _R:
            returncode = 0

        # ffuf writes JSON to the -o path; emit an empty result set.
        out = args[args.index("-o") + 1]
        with open(out, "w", encoding="utf-8") as fh:
            fh.write('{"results": []}')
        return _R()

    monkeypatch.setattr(FfufWrapper, "require_available", lambda self: None)
    monkeypatch.setattr(FfufWrapper, "_run_subprocess", _fake_run)

    FfufWrapper().run(target="http://t/", wordlist=str(wl), rate_limit=30)
    args = captured["args"]
    assert "-rate" in args
    assert args[args.index("-rate") + 1] == "30"  # the passed rate reaches ffuf


def test_wrapper_falls_back_when_no_rate(monkeypatch, tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("a\n")
    captured = {}

    def _fake_run(self, args, **k):
        captured["args"] = args

        class _R:
            returncode = 0

        out = args[args.index("-o") + 1]
        with open(out, "w", encoding="utf-8") as fh:
            fh.write('{"results": []}')
        return _R()

    monkeypatch.setattr(FfufWrapper, "require_available", lambda self: None)
    monkeypatch.setattr(FfufWrapper, "_run_subprocess", _fake_run)

    FfufWrapper().run(target="http://t/", wordlist=str(wl))  # no rate → default
    args = captured["args"]
    assert "-rate" in args
    assert int(args[args.index("-rate") + 1]) == WebScanConfig.SCAN_RATE_LIMIT
