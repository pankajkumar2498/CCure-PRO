"""
core/web/js_dom.py
────────────────────────────────────────────────────────────────────────────
Static DOM source→sink flow analysis (Phase 22, Codex item 9).

The browser-driven XSS engine already *confirms* DOM XSS by execution. This is
the complementary passive analysis Burp/Acunetix also do: reading the JS source
for a tainted **source** (location.hash, document.referrer, window.name, …)
flowing into a dangerous **sink** (innerHTML, document.write, eval, …). It is a
review signal, not a confirmed exploit, so findings are low-severity and marked
unverified — the execution engine is what proves an actual bug.

To keep false positives low it only flags a source and a sink appearing in the
*same statement/line* (e.g. ``el.innerHTML = location.hash``), which is a strong
DOM-XSS indicator, rather than the mere presence of an innerHTML anywhere (which
every framework uses internally).
"""

from __future__ import annotations

import re
from typing import List

# Tainted sources — attacker-controllable client-side inputs.
_SOURCES = [
    r"location\.hash",
    r"location\.search",
    r"location\.href",
    r"location\.pathname",
    r"document\.URL",
    r"document\.documentURI",
    r"document\.referrer",
    r"window\.name",
    r"document\.cookie",
    r"\.postMessage\b",
    r"event\.data\b",
    r"URLSearchParams\b",
]
_SOURCE_RE = re.compile("|".join(_SOURCES))

# Dangerous sinks — where a tainted value becomes markup/code/navigation.
_SINKS = {
    "innerHTML": r"\.innerHTML\s*=",
    "outerHTML": r"\.outerHTML\s*=",
    "insertAdjacentHTML": r"\.insertAdjacentHTML\s*\(",
    "document.write": r"document\.write(?:ln)?\s*\(",
    "eval": r"\beval\s*\(",
    "Function": r"\bnew\s+Function\s*\(",
    "setTimeout-string": r"\bsetTimeout\s*\(\s*['\"]",
    "jQuery.html": r"\.html\s*\(",
    "location-assign": r"(?:location\s*=|location\.href\s*=|location\.assign\s*\()",
}
_SINK_RES = {name: re.compile(pat) for name, pat in _SINKS.items()}


def analyze_dom_flows(js_text: str, url: str, max_findings: int = 20) -> List[dict]:
    """
    Findings for source→sink flows in JavaScript source. One finding per
    (sink, source) pair per file; low severity, unverified — a review signal.
    """
    if not js_text:
        return []
    findings: List[dict] = []
    seen: set = set()
    # Line-scoped: a source and a sink on the same statement is the high-signal
    # case. Long minified "lines" are chunked so one giant line is still useful.
    for raw_line in _iter_statements(js_text):
        if not _SOURCE_RE.search(raw_line):
            continue
        source = _SOURCE_RE.search(raw_line).group(0)
        for sink_name, sink_re in _SINK_RES.items():
            if not sink_re.search(raw_line):
                continue
            key = (sink_name, source)
            if key in seen:
                continue
            seen.add(key)
            snippet = raw_line.strip()[:240]
            findings.append(
                {
                    "finding_type": "dom_xss",
                    "title": f"Potential DOM-based XSS: {source} → {sink_name}",
                    "severity": "low",
                    "cwe_id": "CWE-79",
                    "detected_by": "ccure-js-dom",
                    "matched_at": url,
                    "is_verified": False,
                    "description": (
                        f"Static analysis found a client-side data flow from the "
                        f"attacker-controllable source '{source}' into the "
                        f"dangerous sink '{sink_name}' in JavaScript served by "
                        f"{url}. If the source reaches the sink without sanitising "
                        f"the value, this is DOM-based cross-site scripting. This "
                        f"is a review signal from source inspection, not a "
                        f"confirmed exploit — verify with a payload."
                    ),
                    "payload_used": snippet,
                    "remediation": (
                        "Do not pass untrusted client-side input to HTML/JS sinks. "
                        "Use textContent instead of innerHTML, sanitise with a "
                        "trusted library (e.g. DOMPurify), and avoid eval / the "
                        "Function constructor / string setTimeout."
                    ),
                }
            )
            if len(findings) >= max_findings:
                return findings
    return findings


def _iter_statements(js_text: str):
    """Yield statement-ish chunks. Real newlines first; a minified single line
    is split on ';' so a source and sink in one statement still co-occur."""
    for line in js_text.splitlines():
        if len(line) <= 400:
            yield line
        else:
            for chunk in line.split(";"):
                if chunk:
                    yield chunk
