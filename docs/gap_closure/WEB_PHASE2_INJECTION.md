# Web Application Gap-Closure — Phase 2: Active Server-Side Injection

Extends active injection testing beyond the existing sqlmap SQLi capability
(which is untouched) with five server-side classes: **OS command injection,
SSTI, XXE, LDAP injection, XPath injection**. Integrated into the existing DAST
pipeline, not a parallel scanner.

## Architecture integration (reuse, not rebuild)

| Concern                                        | Existing mechanism reused                                                      |
| ---------------------------------------------- | ------------------------------------------------------------------------------ |
| Endpoints / parameters                         | `endpoints` + `forms` from CRAWL (same as sqlmap/XSS)                          |
| HTTP client                                    | `httpx.AsyncClient` — the orchestrator's own client                            |
| Auth / session                                 | `_authenticate` headers **and** cookies                                        |
| Orchestration                                  | `run_detect`, beside nuclei/sqlmap/XSS, via `ToolCoverage`                     |
| Findings / evidence                            | the finding-dict shape `_persist_web_findings` reads; `cwe_id` (Phase 1)       |
| Severity / OWASP / CWE                         | `standards_mapping` (all classes → A03 Injection) + per-class CWE              |
| Progress / cancellation / timeout / rate limit | `_emit_web_progress`, `_scan_is_cancelled`, `httpx` timeout, shared rate limit |

New code: `core/web/injection/` (`engine.py`, `payloads.py`, `__init__.py`),
`XSS`-sibling. `standards_mapping` gains `ssti`/`ldap_injection`/`xpath_injection`;
`config` gains `INJECTION_*`. No new table, route or scan kind. sqlmap is not
touched.

## Detection methodology — evidence, never reflection

- **OS command injection (CWE-78)** — controlled **differential timing**: a
  `sleep`/`ping` payload must delay the response, a zero-delay control must stay
  fast, and a _second, larger_ delay must be tracked. A merely slow endpoint
  fails all three, so it is not reported. Non-destructive (sleep/ping only).
- **SSTI (CWE-1336)** — a unique arithmetic expression is injected in seven
  engine syntaxes; a finding requires the **computed product** to appear while
  the **literal expression** does not (evaluation, not reflection). The syntax
  that fired names the likely engine.
- **XXE (CWE-611)** — an **internal** canary entity is defined and referenced;
  a finding requires it to come back **expanded**, proving DTD/entity
  processing. No external or file entity is ever sent (no local file access).
- **LDAP (CWE-90) / XPath (CWE-643)** — a broken filter must provoke a specific
  **parser-error signature** absent from the baseline; a boolean differential is
  recorded as supporting evidence, never as the sole basis.

## Safety

Same-origin by default; bounded targets/params; shared rate limit; per-request
timeout that exceeds the command-injection delay; cancellation honoured;
duplicate-prevented (one finding per parameter per class). No payload modifies
or deletes data, runs a destructive command, reads a file, or calls an external
host. There is no unsafe mode.

## Finding model

`finding_type` ∈ {command_injection, ssti, xxe, ldap_injection, xpath_injection},
`detected_by=ccure-injection`, per-class `cwe_id`, severity (critical for CMDI/
SSTI, high for the rest), payload, parameter, method, technique, response
evidence, per-class remediation, `is_verified=True`, confidence. No CVE invented.

## Tests

`tests/web/test_injection_engine.py` — 16 tests against an in-process app that
emulates each class through the exact side-channel the engine keys on (a real
sleep, real arithmetic, real entity expansion, real parser errors): one per
class, safe-endpoint true negative, **slow-endpoint false-positive guard**,
combined scan, duplicate, cancellation, timeout, server error, malformed
response, auth cookie reuse, same-origin scope, rate limiting.

## Results, performance, limitations

## Results, performance, limitations

### Automated tests

`tests/web/test_injection_engine.py` — **16 passed**. Regression: web suite
passes after fixing one fragile index assumption in `test_web_scan_coverage.py`
(the new `injection` tool sorts ahead of `nuclei`; the test now selects nuclei
by name). reports **160**, security **175**.

### End-to-end scan (full RECON→CRAWL→DETECT→AUDIT against a genuine target)

A standalone target with **real** command injection (subprocess), **real** SSTI
(Jinja2), **real** XXE and XPath (lxml), and an emulated LDAP endpoint was
crawled and scanned like any target. **All five classes detected**, one each:

| Class                | Severity | CWE      | Evidence                                                              |
| -------------------- | -------- | -------- | --------------------------------------------------------------------- |
| OS command injection | critical | CWE-78   | `sleep 5→5.01s, control 0→0.01s, sleep 8→8.01s` (differential timing) |
| SSTI                 | critical | CWE-1336 | computed product returned, literal absent (Jinja2)                    |
| XXE                  | high     | CWE-611  | internal canary entity expanded                                       |
| LDAP injection       | high     | CWE-90   | `InvalidSearchFilterException` signature                              |
| XPath injection      | high     | CWE-643  | `XPathEvalError` signature                                            |

Injection engine: **6 parameters, 158 requests, 28.65 s, 5 findings**. Findings
carry `detected_by=ccure-injection`, per-class CWE, payload, technique and
evidence, and render in the PDF.

### False positives / negatives

- **No false positive** on the inert `/safe` endpoint (0 injection findings) —
  the evidence-not-reflection design holds across all five classes.
- **No false positive** on the always-slow endpoint — the differential-timing
  guard (fast zero-delay control + two tracked delays) is what prevents it.
- Known false negatives: blind/out-of-band-only variants are not covered here
  (no OAST — the deployment is egress-restricted); XXE is confirmed via internal
  entities, so a parser that blocks internal entities but allows blind external
  OOB would be missed; SSTI/LDAP/XPath rely on evaluation/error side-channels, so
  a fully blind sink with no observable difference is not reported (by design —
  strong evidence is required).

### Performance

Injection adds ~29 s on this target (mostly the two command-injection sleeps on
the one vulnerable parameter; every clean parameter is fast because no sleep
executes). Whole scan 771 s, dominated by the ffuf crawl, not injection. Cost is
bounded by `INJECTION_MAX_TARGETS × INJECTION_MAX_PARAMS_PER_TARGET` and the
shared rate limit.

### Architectural changes

New `core/web/injection/` package; `run_detect` gains a `2c` injection stage via
`ToolCoverage`; `standards_mapping` gains three finding types; `config` gains
`INJECTION_*`. sqlmap and every existing capability are untouched. No new table,
route or scan kind.

### Remaining limitations

- No blind/OOB detection (no OAST in this egress-restricted deployment).
- LDAP/XPath boolean-differential is supporting evidence only; a target with no
  error signature and no observable boolean difference is not reported.
- Command injection uses a timing side-channel, so a target that serialises
  requests or has very high jitter could need delay tuning (`INJECTION_CMDI_*`).
- XXE tests POST endpoints that accept an XML body; SOAP/complex content types
  beyond `application/xml` and `text/xml` are a later increment.
