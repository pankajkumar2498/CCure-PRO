---
paths:
  - "Backend/routers/**"
  - "Backend/main.py"
  - "Backend/scan_helpers.py"
  - "Backend/config.py"
  - "Backend/core/rate_limiter.py"
  - "Backend/core/rate_limit_middleware.py"
  - "Backend/core/rate_limit_audit.py"
  - "Backend/core/ip_resolver.py"
  - "Backend/core/trusted_proxy.py"
  - "Backend/core/throttle.py"
  - "Backend/core/user_agent.py"
  - "Backend/core/celery_app.py"
  - "Backend/ccure_platform/identity/**"
  - "Backend/auth/**"
  - "Backend/tests/security/**"
---

# Authentication, rate limiting, sessions, email screening, beat and CORS

> Scoped instructions. Claude Code loads this file when it reads or edits a file matching the `paths` above; every other agent is routed here by `AGENTS.md`. The text was moved verbatim from `CLAUDE.md` at `9bb84d9` (lines 1471–1585, 1613–1643, 1694–1916, 1974–1981) and is maintained here. Frozen original: `docs/archive/engineering-record/runtime-architecture-and-edge-security.md`. The repository-wide rules in `CLAUDE.md` still apply.

- **Auth** — `POST /auth/login` takes `{"email": ..., "password": ...}` (the
  field is `email`, not `username`). Access tokens last 30 minutes; the refresh
  token is an HttpOnly, **Secure** cookie valid 7 days.

  Login checks account state **after** the password verifies, not before.
  Checking `is_deleted` / `is_verified` / `approved_at` / `is_active` first made
  each one an account-existence oracle: any password at all returned a 403 that
  distinguished "disabled" from "no such account". Only the lockout check
  precedes the password, because stopping the in-progress brute force is its
  entire purpose. Do not reorder these.

  Self-registration is **off** by default (`ALLOW_SELF_REGISTRATION`). When on,
  `POST /auth/register` returns 202 with **no tokens**: the account is created
  unverified, inactive, unapproved, in the `viewer` role, and needs both a
  confirmed mailbox and `POST /admin/users/{id}/approve`. It used to return
  working tokens for an `analyst`, which carries `scans:execute`.

  **Registration policy:** Docker receives its default from the root `.env`,
  explicitly passed to the api by Compose. Administration → User Management →
  Registration settings opens a dialog that persists a platform-wide override
  in `platform_registration_policy`; there is no separate sidebar item.
  **Use deployment default** clears it. `/auth/config` and all signup gates
  read this same singleton on every request, without process-local caching.
  The platform-scope `platform.registration.read` / `.manage` permissions
  govern the page/API; saves use authenticator step-up, row locking, revision
  checks and an atomic platform audit event. They do not change verification
  or approval. A UI save takes effect immediately; editing the deployment
  default requires recreating the api with its existing Compose overrides.

- **Token signing keys (Phase 9.3, 9.4)** — the API verifies ES256 tokens
  signed by the keyset in `CCURE_TOKEN_KEYS_HOST_DIR` (`/home/cdac/ccure-keys`,
  mounted read-only into **api only**) and publishes it at `/auth/jwks.json`.
  It issues ES256 with the `active` key `7jKp…` (live since 29 Sep 2026). There are
  no signing-algorithm settings any more (Phase 9.6c). See Phase 9 doc §15.3 and
  §17.5 (history).
  - **Key management.** Keys are managed only with
    `scripts/security/manage_token_keys.py`, run in the backend image as root —
    never by hand.
  - **Tests never use these keys.** The suite signs with a throwaway keyset
    that `conftest.py` generates.
  - **The directory must stay inside `/home/cdac`.** The private key files are
    owned by uid 1000, which on this VM is also the `monitor` login account.
  - **The compose variable is required.** An unset one stops `docker compose`
    rather than mounting an empty directory.
  - **Runbook and as-built record:**
    `docs/architecture/PHASE9_TOKENS_AND_SERVICE_IDENTITIES.md` §14–15.

- **Rate limiting** — two layers in the application plus one at the edge, and
  they answer different questions. Reviewed against OWASP/NIST guidance in
  August 2026; the findings and their fixes are below.

  **Per-endpoint limits** are `@limiter.limit` decorators (slowapi, counters in
  the Celery Redis so they are not multiplied by the worker count). The key is
  `core.ip_resolver.get_client_ip`, never the socket peer — behind nginx that
  would put every user in one bucket.

  **A per-IP limit alone does not protect login.** It stops one source
  hammering many accounts; it does nothing about many sources hammering one,
  which is what credential stuffing is. The account-side control is the
  `failed_login_count` / `locked_until` lockout (5 attempts, 15 minutes) and it
  is why the lockout check precedes the password check. Both are needed; say
  "layered authentication throttling, source-IP _and_ account", not "we have
  rate limiting".

  **`/auth/reset-password` carried no limit at all** — the one unauthenticated
  write path in the API that could be driven without bound. Worse, a comment in
  `tests/security/test_rbac_routes.py` asserted in prose that it _was_ limited,
  which is how it survived review. `tests/security/test_rate_limiting.py` now
  asserts the whole credential set in code against `Limiter._route_limits`.

  Three more things about password recovery, each of which was wrong:

  - **Completing a reset must retire _every_ outstanding token for the account,
    not just the one redeemed.** Clicking "forgot password" three times left
    three live links; one was consumed and the other two stayed valid against a
    password that had already been changed. `/auth/forgot-password` likewise
    deletes prior tokens before issuing a new one.
  - **The per-account ceiling must never answer 429.** It exists because the
    per-IP limit does nothing about a caller who rotates addresses while the
    mail goes to an address they chose. But only a real account can exceed a
    per-account ceiling, so a distinct status code there is an account-existence
    oracle — exactly what the uniform 200 exists to prevent. It falls through
    to the same 200 having sent nothing.
  - **"User not found." was a fourth distinct failure message** on the reset
    path. All three failure branches now answer identically.

  **A baseline ceiling covers everything else** —
  `core/rate_limit_middleware.py`, `API_DEFAULT_RATE_LIMIT`, 600/minute per IP.
  Deliberately generous: it exists so a route added next month is not
  _entirely_ unbounded, not to be the control that stops abuse. Three things
  about it:

  - **It is registered before `CORSMiddleware`, which in Starlette means it
    runs inside it.** A browser cannot read a response without CORS headers, so
    a 429 emitted outside CORS surfaces in the SPA as a network error rather
    than "slow down"; and the request-ID middleware further out is what stamps
    `X-Request-ID` onto it.
  - **It never wraps `send`.** slowapi's own `SlowAPIASGIMiddleware` re-emits
    the buffered `http.response.start` on every body message, so any
    multi-chunk response sends its headers repeatedly — and this API streams
    (`FileResponse` report downloads, SSE notifications, scan progress).
  - **Exempt paths are matched exactly** unless the entry ends in `*`. The
    health endpoint here is `/`, and as a prefix that exempts the entire
    application — a rate limit that is installed, logged at startup and covers
    nothing. The first version of the list also named `/health`, `/healthz` and
    `/metrics`, none of which this API serves.

  **A Redis outage used to break authentication outright.** slowapi is built
  with `swallow_errors=False`, so a storage failure propagated out of the
  decorator and login, registration and every scan endpoint answered 500 — not
  fail-closed, an outage, and one anyone able to disrupt Redis could cause.
  `RATE_LIMIT_MEMORY_FALLBACK` switches to process-local counters instead:
  degraded (per worker, and it replaces the per-route limit while active) but
  never absent.


  **`TRUSTED_PROXIES` must name reverse proxies, never a user network.** It
  decides which hop may _speak about_ the client address, and that address is
  the rate-limit bucket key and the audit-trail entry. The default used to
  include `10.0.0.0/8` while this deployment's clients live at `10.180.6.0/24`,
  so every real client was classified as a proxy; the right answer still came
  back, but only through the "all hops trusted, take the leftmost" fallback,
  which reads the one field a client controls. It is now loopback plus the
  Docker bridge pool, and `core/ip_resolver.py` warns at import about any range
  wider than /12. Two related fixes there: forwarding headers are read **only
  when the immediate peer is a trusted proxy** (`X-Real-IP` was previously an
  unconditional override — any direct caller could name its own bucket), and a
  value that does not parse as an address never becomes a key.

  **Since Phase 10.3 (finding F10-1) the default is exact peers:
  `127.0.0.1,::1,172.18.0.1`.**
  - **Why `172.18.0.1`:** it is the compose network's gateway, the one peer host
    nginx arrives as through docker-proxy.
  - **What was wrong:** the old default, the whole Docker pool `172.16.0.0/12`,
    trusted every _container_. That included the frontend's `/api/` proxy on
    `:3200`, which appends `X-Forwarded-For`.
  - **The mechanism:** uvicorn now runs with `--no-proxy-headers` (`start.sh`).
    `core/trusted_proxy.py`, the outermost middleware, resolves the client
    address _and_ scheme, and only for a peer in this list.
  - **The old flag was the real hole:** with `--forwarded-allow-ips='*'`, any
    caller of `:8000` chose its own rate-limit key and scheme, whatever this
    list said. uvicorn had already rewritten the peer before
    `get_client_ip` ran.
  - **HSTS** follows the resolved scheme, never the raw header.
  - **Residual:** every host process arrived as `172.18.0.1` too. Phase 10.7
    unpublished `:8000` and removed `172.18.0.1` from the api's list (below).


  **If Docker recreates the network on a different subnet, set
  `TRUSTED_PROXIES` to its gateway.** Until then the peer is not trusted,
  X-Forwarded-For is ignored, and every client collapses into one bucket keyed
  on the gateway, while the audit trail records the gateway instead of the
  user. That fails safe rather than open, but it fails silently;
  `log_trust_boundary()` prints the ranges in force at startup so it is
  visible.

  That function is called **from the lifespan, not at import**, and the reason
  generalises: `main.py` imports every router before it reaches
  `logging.basicConfig`, so anything a module logs at import time is emitted
  with no handlers installed. INFO vanishes entirely; WARNING survives only via
  `logging.lastResort`, unformatted and without the logger name. A safety
  warning nobody can see is not a safety warning.

  **Every unauthenticated or expensive route needs a recorded decision**, and
  `tests/security/test_endpoint_limit_inventory.py` enforces it. The by-hand
  audit that found `/auth/reset-password` unlimited found it exactly once; the
  route added next month would not have been in it. The test walks
  `app.routes`, resolves each route's auth dependencies and its entry in
  `Limiter._route_limits`, and fails on anything unauthenticated or expensive
  that has neither a limit nor a name in one of its two allowlists. **Adding an
  allowlist entry with a reason is a legitimate answer** — the goal is a
  decision on the record, not a limiter everywhere.

  What that audit turned up beyond reset-password: `POST /web-scans` was the
  only scan-dispatch route with no limit while its eight siblings all carried
  5/minute, and it sends ffuf and nuclei at a caller-named target — an
  unbounded loop there is an unbounded outbound attack wearing this host's
  address. All **thirteen** `/compliance/reports/*` endpoints rendered a PDF or
  DOCX synchronously inside the request with no limit, which is CPU and memory
  exhaustion behind nothing more than `compliance:export_report`. And
  `/auth/refresh` and `/auth/logout`, both unauthenticated in the FastAPI sense
  because the refresh cookie is what identifies the session, had none either.
  42 routes carry explicit limits now, up from 21.

  **Adding `@limiter.limit` to a route means adding `response: Response` to its
  signature.** The limiter is built `headers_enabled=True`, so slowapi writes
  X-RateLimit-* after the handler returns, and it finds the response only two
  ways: the handler returned a `Response`, or it declared a `response: Response`
  parameter for FastAPI to fill in. A handler that returns a dict and declares
  neither hands slowapi `None`, and upstream `_inject_headers` answers with a
  bare `raise Exception` ("parameter response must be an instance of …") from
  inside the endpoint call — **a 500 on every request to that route**.

  All 21 routes the audit above added limits to shipped in exactly that state,
  `/scan/host-discovery` and `/auth/reset-password` among them. The original 21
  were unaffected only by luck: five auth routes already took `response` to set
  the refresh cookie, and the sixteen report downloads return a `FileResponse`.

  Nothing caught it, and the reason matters: `conftest` sets
  `limiter.enabled = False` for the suite, and a disabled limiter skips header
  injection entirely, so the tests asserting the limits are _registered_ pass
  whether or not the route can serve a single request. This is only observable
  on a live server. `tests/security/test_rate_limit_headers.py` now checks the
  signature of every limited route statically, which does not depend on the
  limiter being enabled.

  `scan_helpers._HeaderSafeLimiter` is the backstop: no response to write to is
  a logged warning naming the endpoint and a missing advisory header, never an
  exception. Same trade as the Redis fallback above — degrade, log, keep
  answering. `_route_limits` is untouched, so the limit is still enforced. Do
  not read that as licence to skip the parameter; the test is what catches it.

  Beware the inventory's own false-positive mode: the first pass flagged four
  routes as unauthenticated that were not, because it did not know about
  `get_current_user_flexible` (the ticket-or-bearer dependency the report
  downloads use). An auth marker missing from that set reads as a
  vulnerability. Check the dependency before believing the finding.

  **429s are logged, and the log is the point.** `core/rate_limit_audit.py`
  records layer, method, path, resolved IP, authenticated user and org, the
  limit breached and the request id — enough to see one address making a
  thousand login attempts, which a bare counter cannot show. It deliberately
  omits the account named in a failed login: writing it there rebuilds, in the
  log file, exactly the account-existence oracle `/auth/forgot-password`
  refuses to create in its response. `Retry-After` is read from the breached
  limit rather than hardcoded — a wrong value is worse than none, because
  clients act on it.

  **`RATE_LIMIT_DEGRADED` is the alert to key on.** The fallback path is
  invisible by design: when Redis goes away the limiter keeps answering, and
  nothing in any response says the counters are now per-worker and the
  effective ceiling has been multiplied by the worker count. It is logged on
  _transition_ only, so an outage produces two lines rather than one per
  request, and it covers slowapi's own `_storage_dead` as well as the
  baseline's.

  **Do not treat the 600/minute baseline as an authentication control.** It is
  10 requests a second; it exists so that no route is _entirely_ unbounded, and
  it is deliberately not consulted by the inventory test. Sensitive endpoints
  need their own number.

  **Three volume ceilings are disabled for the test session** in
  `conftest.relax_registration_volume_limits`: the registration daily cap and
  both password-reset ceilings. Every request in the suite comes from one
  TestClient address and the counters live in Redis for hours, so they are
  shared across the whole run _and survive between runs_ — a later `pytest` on
  the same day starts returning 429 in tests that have nothing to do with rate
  limiting. A test that wants to exercise a ceiling patches `core.throttle.hit`
  rather than restoring a real number, which would leak into whatever runs next.

- **Concurrent sessions are unlimited, deliberately.** Each login inserts a
  `refresh_token_sessions` row and nothing displaces an earlier one; logout
  revokes only the token presented. Capping it would push people into sharing a
  browser or logging each other out and makes nothing safer — so do not "fix"
  this. What the choice _requires_ is that the owner can see where the account
  is signed in and end any of it: `GET /user/sessions`,
  `DELETE /user/sessions/{id}`, and `DELETE /user/sessions` (everything except
  the caller's own). Password reset, admin reset and any MFA change still
  revoke every session.

  Two things that made the session list useless and are now fixed:
  `is_current` was hardcoded `False` behind a TODO — it cannot be answered from
  the access token, which identifies the user rather than the session, so it is
  read from the refresh cookie; and `device_info` had never been written, so
  every row rendered as `{}`. A list of rows a person cannot tell apart is
  worse than no list — it invites revoking the wrong one. `core/user_agent.py`
  fills it in on a best-effort basis and keeps `raw` beside the labels because
  the parse is approximate. The User-Agent is client-supplied, so it is a
  memory aid, never evidence.

  **`refresh_token_sessions` was append-only and nothing ever swept it.** A row
  per login _and_ one per rotation, which at 30-minute access tokens is roughly
  48 a day per signed-in session; the table already held 506 rows on a
  development install. `ccure.tasks.purge_expired_refresh_sessions` runs daily
  on beat and removes rows that are **both** past `expires_at` and older than
  `REFRESH_SESSION_RETENTION_DAYS` (90) — so it can never end a session that
  still works. Revoked-but-recent rows are kept on purpose: the revocation is
  the audit record of somebody signing a device out, and deleting it the moment
  it stopped being usable would erase the evidence of the event an
  investigation is looking for.

- **Email domain screening** — `auth/email_domain_guard.py`. Two halves, and the
  split is not a performance decision.

  The **inline** half decides the request from memory: normalize → registrable
  domain → ALLOW rule → DENY rule → merged blocklist corpus → canonical-mailbox
  collision. The **deferred** half (`ccure.tasks.enrich_email_risk`) does MX and
  RDAP lookups on a worker and can only ever raise a flag. `/auth/register`
  accepts a domain chosen by an unauthenticated caller, so resolving it in-request
  would let a stranger aim DNS and HTTPS lookups from this host at a target of
  their choosing and time them.

  **Enforced at**: `/auth/register`, `POST /admin/users`, email change,
  `/auth/check-email` (advisory). **Deliberately not at login, forgot-password,
  resend-verification or reset-password** — login resolves
  `or_(email_matches, username_matches)`, so a check there is bypassed by typing
  a username, and when it does fire it locks out an existing customer whose
  domain landed on a list after they joined, with no self-service recovery.

  Four things measured on 18 Aug 2026, each of which changes the design:

  - **One blocklist is not enough.** Of the two temp-mail domains that reached
    the approval queue, the canonical `disposable-email-domains` list (8,310
    entries) contained **neither**. Merging three lists (75,170 unique) catches
    `hutdot.com` and still misses `radiant-flow.org`.
  - **`radiant-flow.org` must be accepted.** Valid MX, Cloudflare nameservers,
    registered 2025-03-23 — 17 months old, so a domain-age rule passes it too.
    Nothing separates it from a small real company except human judgement, which
    is why the load-bearing deliverable is the **risk badge in the approval
    queue**, not the blocklist. Both suites assert this direction; a guard that
    refuses unfamiliar domains passes the "blocks disposables" test and costs
    real customers.
  - **`test.com` is on a real published blocklist** and 106 test registrations
    use it. `tests/conftest.py` seeds it as ALLOW _and_ leaves it in the test
    corpus, so ALLOW-beats-corpus stays continuously proven.
  - **The per-IP daily cap will break the suite** if left on: every request comes
    from one TestClient address and the counter lives in Redis for 48 hours, so
    the third `pytest` of the day starts returning 429. `conftest` sets
    `REGISTRATION_DAILY_IP_LIMIT = 0` for the session.

  `EMAIL_DOMAIN_GUARD_MODE` is `off | flag | enforce` (default `enforce`).
  `flag` computes and records the same verdict without refusing anything, which
  is the staged-rollout path. **Everything fails open** — an unreachable rules
  table or an empty corpus lets registration through and logs loudly, because
  refusing every signup over a blocklist that did not load is a worse outage
  than the abuse it prevents.

  Two tables, and they must stay separate: `email_domain_rules` (~100 rows, each
  a human decision, ALLOW always wins) and `disposable_domains` (~75k rows,
  rebuilt weekly). Merged, a sync would be writing to the rows an administrator
  edits.

  Managed at **`/admin/email-domains`** (`routers/admin_email_domains.py`,
  `Frontend/src/shell/admin/pages/EmailDomainRules.jsx`) — list, add, flip, remove,
  plus a lookup that runs an address through the live guard and names the rule
  or list that matched. **Platform-scope permissions
  (`platform.email_domain.read` / `.manage`), held only by the superadmin role — never a role name.** The rules are platform-wide, so an org_admin reaching them could
  block another tenant's customers, which is why the keys are platform-scope
  rather than organisation-scope. (Before native RBAC this was a
  `superadminOnly` navigation flag; RBAC-6 removed it, and the sidebar asks for
  `platform.email_domain.read` like every other item in `shell/admin/adminNav.js`.)

  `POST /admin/users/{id}/approve` is the deliberate exception: it can create an
  ALLOW rule under `users:update`, but only ever allows, and only the domain of
  an account already in front of the reviewer.

  `scripts/security/sync_disposable_domains.py` **merges, never replaces**. A
  source below `DISPOSABLE_SYNC_MIN_ROWS_PER_SOURCE` is rejected outright: an
  error page parses to zero domains and would silently empty the corpus, which
  reads as a clean run — the same failure shape as the Siemens 403 below.

  `email_canonical` (UNIQUE on `users`) closes the one hole no blocklist can:
  `p.kumar+1@gmail.com` and `pkumar@gmail.com` are one mailbox. Dots are folded
  **only** for Gmail and subaddressing **only** for providers that document it —
  folding `sales+web@acme.com` into `sales@acme.com` would collide two unrelated
  colleagues at a company whose mail system has no subaddressing, and the user
  has no way to work around a false "already registered".

- **Celery beat** — `celery_app.conf.beat_schedule` had defined periodic tasks
  since before this feature and **nothing ran them**. No service started a beat
  process; the command existed only as a line in `DEVELOPER_SETUP_GUIDE.md`.
  Compliance scheduling and the stale-account purge were silently dead. There is
  now a `beat` service in `docker-compose.yml`, deliberately _not_ behind the
  `container-scanner` profile. Exactly one beat process may run at a time —
  two schedulers publish every task twice.

  Note that `purge_stale_unverified_accounts` filters `is_verified=False` and so
  can never reach a throwaway account: temp-mail users _do_ click the
  verification link. `purge_stale_unapproved_accounts` covers verified-but-never-
  approved accounts on a separate, longer TTL.


- **CORS** — `main.py` had `allow_origin_regex="https?://.*"` alongside the
  allow-list, which matched every origin on the web with
  `allow_credentials=True`; `Frontend/nginx.conf` separately added
  `Access-Control-Allow-Origin: *` on its `/api/` proxy. Both are gone. The
  allow-list in `CORS_ALLOW_ORIGINS` is now the only thing that grants an
  origin, and Nginx adds no CORS headers — it cannot know which origins are
  legitimate.
