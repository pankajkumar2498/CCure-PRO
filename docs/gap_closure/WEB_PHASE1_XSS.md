# Web Application Gap-Closure — Phase 1: Active XSS Engine

Closes the reflected/DOM/stored XSS gap. The existing pipeline relied on nuclei
templates for XSS, which — measured against OWASP Juice Shop — misses reflected
and DOM XSS a browser-driven active test catches. This phase adds that engine
**inside the existing architecture**; it is not a parallel scanner.

## Objective

A dedicated active XSS capability covering **reflected**, **DOM** and **stored**
XSS, detecting by **proof of execution in a real browser** rather than by
reflection — so a value that is reflected but correctly encoded (the safe case)
is inert and never reported.

## Architecture integration (no parallel framework)

| Concern                     | Existing mechanism reused                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------------------------- |
| Discovered endpoints/params | `endpoints` + `forms` from the CRAWL phase (same input `build_injection_targets` uses for sqlmap)       |
| Browser contexts            | Playwright async, the pattern `core/web/crawling/browser.py` established                                |
| Auth/session                | `_authenticate` → `(headers, cookies, status)` reused for the XSS browser context                       |
| Orchestration               | invoked in `WebScanOrchestrator.run_detect`, beside nuclei and sqlmap, via the `ToolCoverage` pattern   |
| Findings                    | emitted in the finding-dict shape `_persist_web_findings` reads → `WebFinding`                          |
| Severity/OWASP              | existing severity ranks + `standards_mapping` (`xss` → A03:2021 – Injection)                            |
| Progress/cancellation       | `_emit_web_progress` on the Redis channel the WebSocket consumes; cancellation via `_scan_is_cancelled` |
| CWE                         | `_persist_web_findings` now maps `cwe_id` (previously dropped) → CWE-79 persists                        |

New code: `core/web/xss/` (`engine.py`, `payloads.py`, `__init__.py`). One
finding-model change (`cwe_id` mapping) and config knobs (`XSS_*`). No new
table, no new route, no new scan kind.

## Detection methodology

A single injected sentinel `window.__ccure_xss_probe(<token>)`; a finding is
raised only when that call actually reaches the browser. The three variants
differ by **delivery vector**, which is what lets the engine label them without
guessing:

- **Reflected** — payload sent to the server in a query/form parameter,
  executed in the rendered response (GET navigation, or an auto-submitting form
  for POST so the response is rendered).
- **DOM** — payload placed in the URL **fragment** (`#…`), which never leaves
  the browser, so execution proves a purely client-side sink. Delivered both at
  navigation and via `location.hash` + `hashchange`. Sinks (`innerHTML`,
  `outerHTML`, `document.write`) are instrumented to record which sink the data
  reached, as DOM-location evidence.
- **Stored** — payload submitted through a form, then found executing on a
  _later, fresh_ page load (execution on the revisit, not merely on submit).

Payloads are context-shaped (HTML body, attribute breakout, JS-string breakout)
and **auto-firing only** (`<script>`, `onerror`, `onload`, `javascript:`), so
the oracle is deterministic and needs no human interaction.

## Safety

Same-origin by default; bounded `XSS_MAX_TARGETS` × `XSS_MAX_PARAMS_PER_TARGET`
× `XSS_MAX_PAYLOADS_PER_PARAM`; shares the scan's rate limit; per-navigation
timeout; cancellation honoured; duplicate-prevented (one finding per parameter,
stops at first firing payload); auth/session reused; payloads never exfiltrate,
never call an external host, and (except the single stored submission) never
write to the target. There is no unsafe mode.

## Finding model

`finding_type=xss`, `detected_by=ccure-xss`, `cwe_id=CWE-79`,
`is_verified=True`, severity high (reflected/DOM) / critical (stored), with
payload, parameter, HTTP method, output context, browser-execution evidence and
per-variant remediation. The variant (reflected/DOM/stored) is stated in the
title and description. No CVE identifier is invented.

## Tests

`tests/web/test_xss_engine.py` — 13 tests against an in-process controlled
vulnerable app (reflected HTML/attribute/JS contexts, encoded-safe true
negative, encoded-payload detection, non-vulnerable parameter, DOM via hash,
stored, auth-protected via cookie reuse, duplicate behaviour, cancellation,
timeout handling, same-origin scope). Skips cleanly where no browser is present.

## Results, performance, limitations

### Automated tests

`tests/web/test_xss_engine.py` — **13 passed**; `test_web_finding_persistence.py`
(CWE round-trip) — **1 passed**. Full web suite **100 passed**, reports **160**,
security **175** (no regressions).

### End-to-end scan (controlled target, full RECON→CRAWL→DETECT→AUDIT pipeline)

A standalone reflected/DOM/stored/safe app was crawled and scanned like any
other target. **11 findings**, of which **6 XSS** proven by execution:

| Variant   | Severity | Location                                     |
| --------- | -------- | -------------------------------------------- |
| Stored    | critical | `comment` at `/stored`                       |
| DOM       | high     | `#fragment` at `/dom` (hash → innerHTML)     |
| Reflected | high     | `q` at `/reflect` (HTML body)                |
| Reflected | high     | `q` at `/reflect_attr` (attribute)           |
| Reflected | high     | `q` at `/reflect_js` (JS string)             |
| Reflected | high     | `comment` at `/stored` (reflected on submit) |

The remaining 5 are the pre-existing header/misconfig checks. Findings carry
`cwe_id=CWE-79`, `detected_by=ccure-xss`, payload, parameter, method, context and
browser-execution evidence, and render in the PDF (CWE row added).

### False positives / negatives

- **No false positive** on `/safe` (HTML-encoded output): 0 findings — the
  reflection-is-not-execution design holds.
- The `/stored` `comment` field is reported **twice** — once reflected (it echoes
  on submit) and once stored (it persists). Both are real but overlap; a future
  refinement could collapse a reflected finding subsumed by a stored one on the
  same parameter. Recorded, not a false positive.
- Known limit: frameworks that sanitise on output (Angular's DomSanitizer) defeat
  the generic payload set; a targeted bypass corpus is a later increment. This is
  why the engine reports only what executes rather than guessing.

### Performance

XSS engine: **5 parameters, 40 payloads, 59 requests, 32.7 s** on 8 endpoints —
bounded and same-origin. Whole scan 837 s, dominated by the ffuf crawl (~8 min)
and sqlmap, not by XSS. Worst-case navigation count is capped by the three
`XSS_*` bounds and rate-limited, so a small app cannot be turned into an
hours-long scan.

### Remaining limitations

- No output-sanitiser bypass corpus (Angular/React escaping defeats generic
  payloads) — deliberate; execution-proof avoids false positives.
- DOM coverage is fragment/hash-driven; sources such as `postMessage` and
  `document.referrer` are instrumented as sinks but not yet actively driven.
- Stored XSS revisits the submitting form's page, not an arbitrary rendering
  location elsewhere in the app.
- No screenshot column in the finding model, so execution evidence is textual.
