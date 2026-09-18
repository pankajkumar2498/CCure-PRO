# Web Application Gap-Closure — Phase 6: HTTP Method Security Testing

Systematic HTTP method/verb testing over the existing endpoint inventory,
integrated into DETECT (`core/web/http_methods`). Read-only and safe by default.

## Safe by default

Only non-mutating verbs are sent by default — **OPTIONS, HEAD, GET, TRACE**.
Nothing is created, modified or deleted. State-changing verbs (PUT/PATCH/DELETE)
are sent **only** when `allow_write_testing` is explicitly enabled, and even then
merely to observe whether they are accepted.

## What it determines per endpoint

- supported vs advertised methods (OPTIONS `Allow`);
- authentication requirement for GET (owner-in / anon-out);
- whether that requirement holds across verbs.

## Confirmed findings (existing model, OWASP-mapped)

- **Cross-Site Tracing / TRACE enabled** — `insecure_http_method`, CWE-693,
  medium. Proven: a TRACE request answered 200 and echoed a marker header the
  scanner sent. Origin-level, one probe.
- **Method-based authentication bypass** — `http_method_auth_bypass`, CWE-288,
  high. Proven: the authenticated session receives 200 for GET, an anonymous
  GET is denied (so the endpoint requires auth), yet an anonymous **HEAD**
  returns 200 — the check is tied to the verb. HEAD is used because it is safe.
- **Unauthenticated write verb accepted** — `insecure_http_method`, CWE-650,
  high — only when write testing is enabled.

An advisory OPTIONS `Allow` enumeration is gathered but a dangerous verb being
_advertised_ is never reported as a finding on its own (it is not proof).

## Reuse

Runs as a DETECT stage beside the other engines, over the endpoints the crawl
and the Phase 5 API import already discovered, using the main authenticated
session as the baseline. Findings flow through the existing severity/CWE/
reporting path.

## Tests

`tests/web/test_http_method_engine.py` — 6 tests against a controlled app
(TRACE echo, a GET-gated/HEAD-ungated endpoint, a correctly-protected endpoint,
an open one): TRACE enabled detected, TRACE disabled → nothing, method auth
bypass detected, properly-protected endpoint not flagged, no-owner-session
skips the bypass check (no guessing), cancellation.

## Regression

web + reports + security re-run green.
