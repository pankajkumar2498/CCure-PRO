# Web Application Gap-Closure — Phase 3: Authenticated Scanning

Upgrades authenticated scanning from basic session handling (form login,
bearer, cookie) to reliable authenticated assessment: CSRF/token logins,
session verification, expiry detection, bounded re-authentication,
authenticated crawling and multi-step workflows. The existing mechanisms are
extended, not replaced.

## Architecture (reuse, not rebuild)

All work lives in the existing auth layer — `core/web/auth/session_manager.py`
(`WebSessionManager`/`WebSession`) and `core/web/auth/secrets.py` — and the
existing Redis-backed session sharing. `_authenticate` in the orchestrator
still returns `(headers, cookies, status)`, so the crawler, API discovery,
XSS, SQLi, nuclei and the Phase 2 injection engine consume the authenticated
session unchanged. No new table, route or scan kind.

## Capabilities

| #   | Capability                   | How                                                                                                                     |
| --- | ---------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| 1   | Username/password login      | existing `form_login`, hardened below                                                                                   |
| 2   | CSRF token extraction        | login page pre-fetched on the _same_ client; token read from `csrf_field` or auto-detected, bound to the session cookie |
| 3   | Hidden form-token extraction | all hidden inputs (and the submit button) carried into the login                                                        |
| 4   | Cookie sessions              | existing `cookie` type (unchanged)                                                                                      |
| 5   | Bearer tokens                | existing `bearer_token` type (unchanged)                                                                                |
| 6   | Custom auth headers          | `headers` merged into the session for _any_ auth type                                                                   |
| 7   | Session verification         | `verify_url` fetched post-login; confirmed by indicator or "not a login page"                                           |
| 8   | Session-expiry detection     | `WebSession.looks_unauthenticated` — 401/403, redirect to login, failure indicator, login markers                       |
| 9   | Re-authentication            | `reauthenticate`, bounded by `max_reauth` (default 2), never looping                                                    |
| 10  | Authenticated crawling       | crawler applies the session, detects session loss per page, re-authenticates and re-crawls                              |
| 11  | Multi-step workflows         | `login_steps` run on one client with `{{var}}` carry-over between steps                                                 |

## Login success is decided by evidence

A 200 is not a login. Each body encoding (`auto` → json then form) is judged by
`_login_succeeded`: a configured `success_indicator` / `failure_indicator`, an
issued token, or a redirect away from a login page that no longer looks like
one. The anti-CSRF token is re-fetched before every attempt (it binds to the
session cookie and a failed login can rotate it), which is what made the
JSON-first "auto" attempt stop masking the real form login.

## Session loss during crawling

The crawler watches every navigated page while it holds a session. A page that
is a 401/403, a redirect to the login URL, or carries a configured failure
indicator means the session dropped: the crawler calls the bounded re-auth
callback, re-applies fresh cookies and re-crawls that URL, recording a
`reauthenticated` event. When re-auth is exhausted it records
`session_lost_unrecovered` once and finishes the crawl anonymously rather than
looping. Only the decrypted config lives in the re-auth closure; the crawler is
handed a secret-free detection config (login_url + failure_indicator only).

## Secret handling

Credentials are AES-256-GCM encrypted at rest via `secrets.py` (the project's
existing crypto), now including credentials inside `login_steps` fields.
`redact_auth_config` masks every secret (top-level, cookie/header maps and step
fields) for logs. `auth_config` is not returned over the API. The decrypted
config exists only transiently in the worker during authentication/re-auth.
Credentials never appear in findings, reports, WebSocket messages or errors.

## Tests

`tests/web/test_web_auth_phase3.py` — 15 tests against a stateful CSRF-login app
and a browser: token extraction, CSRF login success, wrong-password clean
failure, wrong-csrf-field safety net, known-CSRF-name auto-capture, session
verification (pass + bad-session), expiry/loss detection, bounded re-auth,
multi-step login, bearer/cookie types unchanged, custom-header merge, credential
non-exposure, authenticated crawl reaching protected pages, and session-loss →
re-auth → recovery during a crawl.

## Before/after coverage (DVWA, genuine CSRF `user_token` login)

Two full RECON→CRAWL→DETECT→AUDIT scans of the same DVWA host, one anonymous
and one with a CSRF `user_token` form login (`admin`/`password`, verified
against `/index.php`):

```
Unauthenticated surface:  10 endpoints   5 findings   (0 vulnerabilities; all missing-header misconfigurations)
Authenticated surface:    34 endpoints   6 findings
Authenticated findings:    1 reflected XSS on /vulnerabilities/xss_r/ (?name=), unreachable without login
                           + the 5 missing-header findings
```

Authentication unlocked **24 endpoints** the anonymous scan never saw — the
entire `/vulnerabilities/*` tree (sqli, sqli_blind, exec, fi, upload, csrf,
brute, captcha, weak_id, javascript, csp, xss_r, xss_s, xss_d) plus
`security.php`, `setup.php`, `instructions.php`, `about.php`. The reflected XSS
on `/vulnerabilities/xss_r/` was found only in the authenticated scan (the
anonymous scan reported **0** XSS), which is the concrete proof that findings
behind authentication are now reached and reported. The verified session
stayed valid for the whole crawl (no session-loss events). The password was
stored AES-256-GCM encrypted (`enc:v1:…`) and appeared in **0** findings.

## Application types still unsupported

- Interactive OAuth2/OIDC / SSO / SAML redirect flows through an external IdP
  and consent screens (needs full browser-driven login automation).
- MFA / 2FA / one-time-code and CAPTCHA-gated logins.
- WebAuthn / passkeys.
- Client-certificate (mTLS) authentication.
- Logins performed entirely by a client-side SDK that never issues an
  observable form POST or token response (many are covered by `login_steps`,
  but not those with no HTTP-visible credential exchange).

## Regression

Existing auth/secrets tests (14), crawl-scope (30) and the 15 new Phase 3 tests
pass; full web/reports/security suites green. Bearer, cookie, custom-header and
the original form-login paths are unchanged.
