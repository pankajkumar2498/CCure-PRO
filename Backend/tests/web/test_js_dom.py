"""
Phase 22 — static DOM source→sink analysis (Codex item 9).

Complements the browser XSS engine (which confirms DOM XSS by execution) with
Burp-style passive source-code analysis: a tainted source flowing into a
dangerous sink in the same statement is a high-signal DOM-XSS indicator. These
tests pin that behaviour and its low-false-positive design.
"""

from core.web.js_dom import analyze_dom_flows

URL = "http://t/app.js"


def test_flags_source_to_sink_on_same_statement():
    js = "document.getElementById('o').innerHTML = location.hash.slice(1);"
    f = analyze_dom_flows(js, URL)
    assert len(f) == 1
    assert f[0]["finding_type"] == "dom_xss"
    assert f[0]["cwe_id"] == "CWE-79"
    assert f[0]["severity"] == "low"
    assert f[0]["is_verified"] is False
    assert "innerHTML" in f[0]["title"] and "location.hash" in f[0]["title"]


def test_flags_eval_and_document_write():
    assert analyze_dom_flows("eval(location.search)", URL)
    assert analyze_dom_flows("document.write(document.referrer)", URL)


def test_no_finding_without_a_source():
    # innerHTML with a static/constant value is not a DOM-XSS flow.
    assert analyze_dom_flows("el.innerHTML = '<b>hello</b>';", URL) == []
    assert analyze_dom_flows("el.innerHTML = template;", URL) == []


def test_no_finding_for_source_without_sink():
    assert analyze_dom_flows("var h = location.hash; console.log(h);", URL) == []


def test_dedupes_repeated_flows():
    js = (
        "a.innerHTML = location.hash;\n"
        "b.innerHTML = location.hash;\n"  # same (sink, source) → one finding
    )
    assert len(analyze_dom_flows(js, URL)) == 1


def test_minified_single_line_is_chunked():
    # a source and sink in one statement of a minified bundle still co-occur
    js = "var x=1;" * 60 + "root.innerHTML=location.hash;" + "var y=2;" * 60
    f = analyze_dom_flows(js, URL)
    assert len(f) == 1 and "innerHTML" in f[0]["title"]
