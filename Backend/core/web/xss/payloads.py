"""
core/web/xss/payloads.py
────────────────────────────────────────────────────────────────────────────
Payload catalogue and constants for the active XSS engine.

Design constraints, all safety-driven:

* **Proof of execution, not reflection.** Every payload calls a single injected
  sentinel — ``window.<SENTINEL>('<token>')`` — rather than doing anything
  observable to a human or destructive to the target. A finding is only raised
  when that sentinel actually fires in a real browser, so a string that is
  reflected but correctly encoded (and therefore inert) is never reported.

* **Auto-firing only.** Each payload executes on load with no human
  interaction (``<script>``, ``onerror``, ``onload``, ``javascript:`` URIs), so
  the execution oracle is deterministic. Payloads that need a mouse event are
  deliberately excluded — they cannot be proven in an automated pass and would
  invite guessing.

* **Unique per request.** The ``{token}`` is a fresh random marker per test, so
  a sentinel call is attributable to exactly one (endpoint, parameter, payload)
  and cannot be confused with the application's own behaviour.

No payload exfiltrates data, sets cookies, calls out to any external host, or
writes to the target. This is the safe-mode contract and there is no other mode.
"""

from __future__ import annotations

#: The JS symbol the engine exposes into every page (via context binding). A
#: payload proves execution by calling it with its token. Distinctive so it
#: cannot collide with an application global.
SENTINEL = "__ccure_xss_probe"


#: Reflected / stored payloads. Each entry is (context_label, template). The
#: template carries ``{sentinel}`` and ``{token}`` placeholders. ``context_label``
#: records which output context the payload is shaped for, so a finding can say
#: *how* the value was reflected — HTML body, an attribute, or a JS string.
#:
#: Ordered cheapest-and-most-common first; the engine stops a parameter at the
#: first payload that fires, so ordering bounds work on a vulnerable parameter.
PAYLOAD_TEMPLATES: list[tuple[str, str]] = [
    # Raw HTML body context — value lands between tags.
    ("html_body", '<script>{sentinel}("{token}")</script>'),
    ("html_body", '<img src=x onerror={sentinel}("{token}")>'),
    ("html_body", '<svg onload={sentinel}("{token}")>'),
    # Attribute context — value lands inside a double/single quoted attribute
    # and must break out first.
    ("attribute_double", '"><img src=x onerror={sentinel}("{token}")>'),
    ("attribute_single", '\'><img src=x onerror={sentinel}("{token}")>'),
    # Inside an existing <script> block — close it, or break the string.
    ("script_block", '</script><script>{sentinel}("{token}")</script>'),
    ("js_string_single", "';{sentinel}('{token}');//"),
    ("js_string_double", '";{sentinel}("{token}");//'),
]


#: DOM payloads delivered through the URL *fragment* (``#…``). The fragment is
#: never sent to the server, so execution proves a purely client-side
#: (DOM-based) sink — this is what separates a DOM finding from a reflected one
#: by construction rather than by guesswork.
DOM_PAYLOAD_TEMPLATES: list[tuple[str, str]] = [
    ("dom_fragment", '<img src=x onerror={sentinel}("{token}")>'),
    ("dom_fragment", '<svg onload={sentinel}("{token}")>'),
    ("dom_fragment", "javascript:{sentinel}('{token}')"),
]


#: Init script installed before any page script runs. It wraps the dangerous
#: client-side sinks and, when a value carrying the active token reaches one,
#: reports ``SINK:<name>`` through the sentinel. This does not decide the
#: verdict — execution does — but it captures *which sink* the data flowed into,
#: which is the DOM-location evidence a triager needs. Wrapping is best-effort
#: and never throws into the page.
SINK_INSTRUMENTATION_JS = """
(() => {
  const report = (name) => { try { window.%(sentinel)s('SINK:' + name); } catch (e) {} };
  // Every payload contains the sentinel symbol, so a value flowing into a sink
  // that carries it is our injected data — no per-test token plumbing needed.
  const tainted = (v) => {
    try { return String(v).indexOf('%(sentinel)s') !== -1; } catch (e) { return false; }
  };
  try {
    const d = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (d && d.set) {
      Object.defineProperty(Element.prototype, 'innerHTML', {
        configurable: true, enumerable: d.enumerable, get: d.get,
        set(v) { if (tainted(v)) report('innerHTML'); return d.set.call(this, v); }
      });
    }
  } catch (e) {}
  try {
    const w = document.write.bind(document);
    document.write = function (v) { if (tainted(v)) report('document.write'); return w(v); };
  } catch (e) {}
  try {
    const oe = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (oe && oe.set) {
      Object.defineProperty(Element.prototype, 'outerHTML', {
        configurable: true, enumerable: oe.enumerable, get: oe.get,
        set(v) { if (tainted(v)) report('outerHTML'); return oe.set.call(this, v); }
      });
    }
  } catch (e) {}
})();
""" % {
    "sentinel": SENTINEL
}


#: One CWE covers reflected, DOM and stored — they are the same weakness class
#: differing by delivery. CWE-79: Improper Neutralization of Input During Web
#: Page Generation ('Cross-site Scripting').
CWE_ID = "CWE-79"

#: OWASP mapping is resolved centrally from finding_type by
#: core/web/standards_mapping.py; "xss" already maps to A03:2021 – Injection.
FINDING_TYPE = "xss"

#: Per-variant static remediation. Kept here so the engine stays about detection.
REMEDIATION = {
    "reflected": (
        "Encode all user-controlled data on output using a context-aware "
        "encoder (HTML entity, attribute, JavaScript-string or URL encoding to "
        "match where the value is placed). Prefer a framework's auto-escaping "
        "templating and validate input server-side. Add a restrictive "
        "Content-Security-Policy as defence in depth."
    ),
    "dom": (
        "Avoid passing untrusted data (location.hash/search, referrer, "
        "postMessage) into dangerous sinks (innerHTML, outerHTML, "
        "document.write, eval, Function, setTimeout/setInterval with strings, "
        "or location). Use textContent / safe DOM APIs, sanitise with a vetted "
        "library (e.g. DOMPurify) and deploy Trusted Types where available."
    ),
    "stored": (
        "Encode user-controlled data on output in every context it is rendered, "
        "not only on input. Validate and sanitise on the way in as defence in "
        "depth, and apply a restrictive Content-Security-Policy. Stored XSS "
        "affects every viewer of the persisted content, so treat it as higher "
        "impact than reflected."
    ),
}

#: Severity by variant. Stored is the most impactful (persists, hits every
#: viewer); reflected and DOM are high. These are proven-execution findings, so
#: they are not discounted for uncertainty.
SEVERITY = {"reflected": "high", "dom": "high", "stored": "critical"}
