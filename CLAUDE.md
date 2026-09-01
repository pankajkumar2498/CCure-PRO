# CCure-Audit-PRO — working notes for agents

## ⚠️ Running the test suite

**`Backend/tests/` is destructive.** It `TRUNCATE`s `organizations` and `users`
`CASCADE`, which reaches `scans`, `scan_phases`, `assets`, `services`,
`asset_change_log`, `audit_logs` and `notifications`.

The live application database is named **`ccure_test`**. That name looks
disposable and is not. On 10 Aug 2026 a full-suite run inherited the API
container's `DATABASE_URL`, was accepted by a guard that matched `_test$`, and
destroyed all users, orgs, scans and assets. There was no recovery:
`archive_mode` is `off`.

Three layers now prevent a repeat, in `Backend/tests/conftest.py`:

1. `TEST_DB_NAME_PATTERN` only accepts `^pytest_`, `_pytest`, `_pytest_db`.
2. `FORBIDDEN_DB_NAMES` rejects `ccure_test`, `ccure_db`, `vuln_intel`, … even
   if renamed into the pattern.
3. `_assert_database_is_disposable()` refuses any database holding rows in
   `users` / `scans` / `assets` / `services` unless it carries the
   `_pytest_scratch_marker` sentinel table.

`docker-compose.yml` also pins `TEST_DATABASE_URL` to `ccure_pytest_db` on the
`api`, `worker` and `web-worker` services, so `docker exec … pytest` cannot
inherit the live URL.

**Before any destructive operation** (test run, migration, bulk delete):

```powershell
$env:PGPASSWORD = '<password>'
.\scripts\backup_db.ps1 -SkipReferenceData   # fast: operational data only
```

Restore with `pg_restore --clean --if-exists -d ccure_test <file>.dump`.

A scheduled task **CCure DB Backup** already dumps operational data every 6
hours into `backups/` and prunes after 30 days (registered by
`scripts/install_backup_schedule.ps1`). Check it with:

```powershell
Get-ScheduledTask -TaskName 'CCure DB Backup' | Get-ScheduledTaskInfo
```

`archive_mode` is still `off`, so recovery granularity is "since the last
dump", not point-in-time. Ad-hoc dumps before risky work are still worth taking.

### Known test-suite failures

None. The three entries that used to sit here are all resolved, and two of them
were not what they looked like:

- `test_scans.py::test_host_discovery_endpoint` was recorded as needing
  `CELERY_TASK_ALWAYS_EAGER=True`. It asserts on rows the Celery task writes, so
  the task has to run before the assertions do — but whether it did was decided
  by a deployment setting this machine deliberately sets to `False` so the host
  worker can perform live scans. The test now enables eager execution for itself
  and restores the previous value afterwards, so it passes under either setting.
  A test should not depend on how the machine it runs on is configured.

- `test_docs_integrity.py` (3 tests) was recorded as documentation drift. It was
  not: `docs/` was never mounted into the container, so the test could not find
  any of the three files it checks and failed on all of them. `docker-compose.yml`
  now mounts `./docs:/docs:ro` on the `api` service. With the mount in place the
  test found exactly one genuinely undocumented route, which is now documented.
  If this fails again, it means a route, table or permission really was added
  without updating `docs/`.
- `test_schema_drift.py::test_models_have_no_unmigrated_changes` was recorded as
  uncommitted model edits. Migration `z9e0f1g2h3i4` brought the schema and the
  models back into agreement and it passes.

Baseline as of 11 Aug 2026: the suites touching scans, findings, reports,
credentialed scanning, compliance and schema run clean apart from the eager-mode
test above.

## Test layout

`Backend/tests/` is grouped by module: `auth/`, `security/`, `compliance/`,
`scans/`, `assets/`, `topology/`, `credentialed/`, `web/`, `reports/`, `repo/`.
[`Backend/tests/README.md`](Backend/tests/README.md) says what belongs where.

Two rules the layout depends on, both of which fail loudly if broken:

- **The group directories carry no `__init__.py`, and must not gain one.** As
  packages, `tests/auth` and `tests/scans` collide with Backend's own `auth` and
  `scans` packages — pytest names the module `auth.test_auth`, Python resolves
  `auth` to the application package, and every test in the group fails to import
  with `ModuleNotFoundError`. Without the markers pytest imports each file under
  its bare basename, so **test file basenames must stay unique across groups**.
  One test imports another (`test_compliance_iso27001` reads
  `test_compliance_rule_wiring`) and does so by bare name for the same reason.

- **Never spell a path as `os.path.dirname(os.path.dirname(__file__))`.** A
  module's depth below `tests/` is no longer a constant, and that expression now
  resolves to `tests/` rather than `Backend/` — which surfaces as a confusing
  "no such file" from a seed lookup, not as an import error. Import the anchors
  from `testpaths` (`BACKEND_ROOT`, `REPO_ROOT`, `SCRIPTS_DIR`, `CORE_DIR`,
  `MAIN_PY`); `conftest.py` puts `tests/` on `sys.path` so it resolves from any
  group.

## Where things live

- **Compliance catalogues** — the thirteen `*_controls_seed.json` files are in
  `Backend/data/compliance_seeds/`, not `Backend/scripts/`. Resolve the
  directory through `core/compliance_seeds.py` (`SEEDS_DIR`, `seed_path()`,
  `all_seed_paths()`) rather than joining a path by hand. `main.py`'s bootstrap
  condition names all thirteen, so a catalogue it cannot find makes the
  condition permanently true and re-runs the whole seeder on every container
  start without ever satisfying itself — a slow boot, not an error.

- **Scan report generators** — `pdf_generator.py`, `csv_generator.py`,
  `web_pdf_generator.py` and `report_helpers.py` are in `Backend/reporting/`.
  Note the name: `Backend/reports/` already exists and is the *runtime output
  directory* for generated PDFs, bind-mounted into the API container. Code in
  `reporting/`, artefacts in `reports/`. Compliance keeps its own DOCX/PDF
  generators inside `routers/compliance.py`.

## Architecture

- **API** — `ccure-api` container, `127.0.0.1:8000`, mounts `./Backend` (restart
  picks up Python changes; no rebuild needed).
- **Frontend** — `ccure-frontend`, `localhost:3200`. Assets are **baked at build
  time**; JSX changes need `docker compose build frontend && docker compose up -d
  --no-deps frontend`.
- **Scanner worker** — Celery on the **Windows host**, not in Docker, so Nmap and
  Scapy get raw-socket access to the physical network. Start with
  `.\Backend\scripts\scan\start_host_scanner_worker.ps1`. Restart it after
  changing anything under `core/`, `scans/` or `orchestrator/`.
- **Database** — PostgreSQL 18 on the host, `ccure_test`. The `ccure-db`
  container runs but is unused; both API and worker point at the host server.

  **TLS is required and the server certificate is verified.** `pg_hba.conf` is
  `hostssl` only, scoped to loopback plus the Docker ranges — `0.0.0.0/0` used to
  be there, and with `listen_addresses='*'` the only thing keeping the LAN out
  was a missing firewall rule. Every connection string carries
  `sslmode=verify-full&sslrootcert=…`; `require` alone would encrypt but accept
  any certificate. Certificate issued by `scripts/tls/new_postgres_cert.ps1`.

  Three things that will bite:

  - **Backslashes in a libpq URI are escapes.** `sslrootcert=D:\PostgreSQL\…`
    becomes `D:PostgreSQL…`. Use forward slashes.
  - **The cert must carry every hostname any client dials** —
    `host.docker.internal` (containers), `127.0.0.1` (host worker) and
    `localhost` (vuln_intel scripts). libpq matches the string in the connection
    URI, not the resolved address.
  - Enable `ssl`, verify with
    `SELECT ssl,version,cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()`,
    *then* switch to `hostssl`. libpq's default `prefer` silently falls back to
    plaintext, so "it still works" proves nothing until you check that view.
  The cluster's data directory was moved to **`D:\PostgreSQL\18\data`** on
  11 Aug 2026 (C had 61 GB free and the feeds needed room). The service's
  `ImagePath` in `HKLM:\SYSTEM\CurrentControlSet\Services\postgresql-x64-18`
  points there. The old directory is kept as
  `C:\Program Files\PostgreSQL\18\data.old-premove-20260811` — deleting it
  reclaims 8.4 GB. `D:\` grants `Authenticated Users:(F)` by inheritance, so
  inheritance is disabled on both `D:\PostgreSQL` and the data directory; do
  not re-enable it.
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
  "layered authentication throttling, source-IP *and* account", not "we have
  rate limiting".

  **`/auth/reset-password` carried no limit at all** — the one unauthenticated
  write path in the API that could be driven without bound. Worse, a comment in
  `tests/security/test_rbac_routes.py` asserted in prose that it *was* limited,
  which is how it survived review. `tests/security/test_rate_limiting.py` now
  asserts the whole credential set in code against `Limiter._route_limits`.

  Three more things about password recovery, each of which was wrong:

  - **Completing a reset must retire *every* outstanding token for the account,
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
  *entirely* unbounded, not to be the control that stops abuse. Three things
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

  **Nginx carries a second layer** (`scripts/host-nginx/nginx-host.conf`:
  `ccure_auth` 30r/m on `/api/auth/`, `ccure_api` 20r/s on `/api/`). Not
  redundant with the application: Argon2 is deliberately expensive, so a login
  flood is CPU exhaustion on the API host whether or not any credential is
  guessed, and the process doing the hashing cannot defend against that. Keyed
  on `$binary_remote_addr` — at that hop the socket peer *is* the client.
  `limit_req_status 429`, because nginx's default 503 reads as "this server is
  broken". **The `/api/auth/` block duplicates `/api/` in every other respect;
  change the two together.**

  Deploying it: copy to `C:\nginx\conf\nginx.conf`, `nginx -t`, then
  **restart the `CCureNginx` service** — `nginx -s reload` fails with
  `OpenEvent(...) failed (5: Access is denied)` because the service runs under
  a different account than an interactive shell. `Restart-Service CCureNginx`
  works. A validated config file is not a deployed one; verify by driving a
  zone to 429 and checking the response has **no `X-Request-ID`**, which is
  what distinguishes a refusal by nginx from one by the application.

  `Retry-After` on nginx's own 429s comes from a `map $status`, not a literal:
  `add_header` with an empty value emits nothing, whereas a literal with
  `always` would put `Retry-After` on every 200 as well. `X-Content-Type-Options`
  is emitted here with a matching `proxy_hide_header`, because an nginx-generated
  429 never passes through the application and so carries none of the headers
  the API sets on its own responses.

  **`TRUSTED_PROXIES` must name reverse proxies, never a user network.** It
  decides which hop may *speak about* the client address, and that address is
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

  `Backend/.env` now sets it explicitly to `127.0.0.1,::1,172.18.0.0/16` —
  the compose network host nginx reaches the published port through — so the
  trust boundary is a recorded decision for this deployment rather than a
  library default. **If Docker recreates the network on a different subnet the
  peer stops being trusted, X-Forwarded-For is ignored, and every client
  collapses into one bucket keyed on the gateway while the audit trail records
  the gateway instead of the user.** That fails safe rather than open, but it
  fails silently; `log_trust_boundary()` prints the ranges in force at startup
  so it is visible.

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
  injection entirely, so the tests asserting the limits are *registered* pass
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
  *transition* only, so an outage produces two lines rather than one per
  request, and it covers slowapi's own `_storage_dead` as well as the
  baseline's.

  **Do not treat the 600/minute baseline as an authentication control.** It is
  10 requests a second; it exists so that no route is *entirely* unbounded, and
  it is deliberately not consulted by the inventory test. Sensitive endpoints
  need their own number.

  **Three volume ceilings are disabled for the test session** in
  `conftest.relax_registration_volume_limits`: the registration daily cap and
  both password-reset ceilings. Every request in the suite comes from one
  TestClient address and the counters live in Redis for hours, so they are
  shared across the whole run *and survive between runs* — a later `pytest` on
  the same day starts returning 429 in tests that have nothing to do with rate
  limiting. A test that wants to exercise a ceiling patches `core.throttle.hit`
  rather than restoring a real number, which would leak into whatever runs next.

- **Concurrent sessions are unlimited, deliberately.** Each login inserts a
  `refresh_token_sessions` row and nothing displaces an earlier one; logout
  revokes only the token presented. Capping it would push people into sharing a
  browser or logging each other out and makes nothing safer — so do not "fix"
  this. What the choice *requires* is that the owner can see where the account
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
  per login *and* one per rotation, which at 30-minute access tokens is roughly
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
    use it. `tests/conftest.py` seeds it as ALLOW *and* leaves it in the test
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
  `Frontend/src/pages/admin/EmailDomainRules.jsx`) — list, add, flip, remove,
  plus a lookup that runs an address through the live guard and names the rule
  or list that matched. **Superadmin only, via `require_role`, not a
  permission.** The rules are platform-wide, so an org_admin reaching them could
  block another tenant's customers; and a permission check cannot express this
  anyway, because superadmin holds every permission and any permission an
  org_admin also has would let them through. `AppLayout`'s `canSeeNavItem` grew
  a `superadminOnly` flag for the same reason.

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
  now a `beat` service in `docker-compose.yml`, deliberately *not* behind the
  `container-scanner` profile. Exactly one beat process may run at a time —
  two schedulers publish every task twice.

  Note that `purge_stale_unverified_accounts` filters `is_verified=False` and so
  can never reach a throwaway account: temp-mail users *do* click the
  verification link. `purge_stale_unapproved_accounts` covers verified-but-never-
  approved accounts on a separate, longer TTL.

- **TLS** — host Nginx terminates TLS on **443** and 301-redirects 80. Reached
  at **`https://ccurepro.cdacb.in`**; the Docker published ports are bound to
  127.0.0.1 only, so this is the sole listener on a routable interface and the
  only hop that needs a certificate.

  Certificates come from a **private CA** — `scripts/tls/new_internal_ca.ps1`.
  A public CA is impossible here, not merely inconvenient: the app is reached at
  10.180.6.14 and CA/Browser Forum rules forbid certificates for reserved IP
  ranges. Clients run `scripts/tls/install_client_trust.ps1` once. See
  [docs/TLS_SETUP.md](docs/TLS_SETUP.md).

  Two things that look like faults and are not:

  - **`curl` on Windows fails with `CRYPT_E_NO_REVOCATION_CHECK`.** Schannel
    hard-fails when it cannot check revocation, and a private CA publishes no
    CRL. Browsers soft-fail this. Use `curl --ssl-no-revoke`, or verify with
    OpenSSL, which validates the chain properly.
  - **HSTS is ignored on `https://10.180.6.14`.** RFC 6797 §8.1.1 requires
    browsers to discard the header when the host is an IP literal. The IP form
    still gets encryption; only the hostname can be pinned. This is why
    `FRONTEND_URL` is the hostname.

  `max-age` is **300** in both Nginx and `main.py`. Raise them **together** and
  only after every client is confirmed working — HSTS is a one-way door, and a
  client that cached HTTPS-only for a year cannot reach a broken deployment to
  be told why. `tests/security/test_cors_and_headers.py` asserts the low value.

- **The `gateway` service in `docker-compose.yml` is not part of this
  deployment**, and two things now stop it becoming part of one by accident: it
  sits behind the `alt-gateway` profile, so `docker compose up` cannot start it,
  and its mapping is `127.0.0.1:${GATEWAY_PORT:-8082}:80`, so if it is started
  it is reachable from this host only. It previously carried no bind address —
  Docker published it on `0.0.0.0`, the one port in the file that was not
  loopback bound.

  It duplicates host Nginx's routing (`/api/` → api:8000, `/` → frontend:80)
  but over plain HTTP, which would not merely expose sessions but break them:
  `REFRESH_COOKIE_SECURE` is set statically in `.env` rather than derived from
  `X-Forwarded-Proto`, so over HTTP the browser refuses to store the refresh
  cookie and every session dies at the 30-minute access-token expiry.

  The default port is `8082` because that is what `.env` already sets, so the
  value is the same with or without `.env`. It is deliberately not `80`, the
  previous default, which collides with host Nginx's `0.0.0.0:80` redirect
  listener; and not `8080`, which on this host is the Oracle XE TNS listener.

- **`add_header` in Nginx does not merge.** A `location` containing any
  `add_header` replaces the parent's whole set. This silently disabled the SPA's
  Content-Security-Policy for months: `location = /index.html` declared a
  `Cache-Control` header, and `location /` resolves through it via `try_files`,
  so the HTML document — the only response CSP protects — carried none of the
  server-level headers. Check with:

  ```bash
  curl -sD - -o /dev/null http://127.0.0.1:3200/ | grep -i content-security
  ```

  If you add a header at server level in `Frontend/nginx.conf`, add it to the
  `= /index.html` block too. Where both host Nginx and a container set the same
  header, host Nginx wins by `proxy_hide_header` — a UA processes only the
  *first* `Strict-Transport-Security`, so duplicates make ordering decide.

- **CORS** — `main.py` had `allow_origin_regex="https?://.*"` alongside the
  allow-list, which matched every origin on the web with
  `allow_credentials=True`; `Frontend/nginx.conf` separately added
  `Access-Control-Allow-Origin: *` on its `/api/` proxy. Both are gone. The
  allow-list in `CORS_ALLOW_ORIGINS` is now the only thing that grants an
  origin, and Nginx adds no CORS headers — it cannot know which origins are
  legitimate.

## Scan pipeline

`pipeline_mode` selects the phases: `basic` = 1, `asset` = 1+2,
`vulnerability_audit` = 1+2+3. The UI posts to `/scan/host-discovery` and the
backend auto-chains the later phases.

- **Phase 1** — `core/discovery/engine.py`, Scapy only (ARP/ICMP/TCP/UDP). No
  Nmap, no port scanning.
- **Phase 2** — `core/nmap/wrapper.py` via `engines/port/port_engine.py`. Normal
  intensity scans ports 1-1024 plus a curated high-port list from
  `PORT_DB` (~1,127 ports), with OT ports excluded by default.
- **Enrichment** — `core/discovery/enrichment.py`. When adding a probe, pass the
  real transport to `_register_open_port(..., protocol="udp")`. SNMP, mDNS and
  NetBIOS-NS are UDP; recording them as TCP claims an open TCP port that is
  usually filtered, and that claim reaches the asset registry and the reports.

## Windows credentialed collection (`engines/credentialed/winrm_executor.py`)

Native WinRM, added in Phase 2. **Windows targets no longer need OpenSSH
Server installed.**

- **It is a transport, not a collector.** `ssh_scanner.py` already declared a
  `BaseExecutor` protocol, so `WinRMExecutor` drops in and `WindowsCollector`
  is unchanged — the same ~970 lines of PowerShell commands and parsers drive
  either transport, and Windows findings flow through the existing evidence →
  matching → finding → risk → reporting path. If you add a Windows capability,
  add a command to the catalogue; do not add a collector.

- **A pywinrm NTLM session is not thread-safe, and `collect_all` is parallel.**
  Sessions are therefore thread-local. Sharing one corrupts the NTLM security
  context and fails *every* section with `SpnegoError (6): invalid Message
  Integrity Check`, HTTP 400, and — most misleadingly — "the specified
  credentials were rejected by the server" on a credential that just
  authenticated. Measured against a real host: sequential 10/10, concurrent
  shared 0/8, concurrent per-thread 8/8. Do not "simplify" this to one session.

- **Errors are classified into four types and must stay that way.** A refused
  password, an unprivileged account, nothing listening, and a bad certificate
  need four different actions; collapsing them is how a fixable firewall rule
  becomes "host unreachable". Note that pywinrm's literal rejection string
  contains none of `401`, "unauthorized" or "authentication", so it is matched
  explicitly — without that it classified as a connection error.

- **`shell_type` resolves to "powershell" over WinRM and that matters.**
  pywinrm's `run_ps` already base64-encodes UTF-16-LE, which is the same trick
  `_wrap_ps` applies by hand for cmd.exe over SSH. Wrapping twice feeds the
  encoder its own output.

- **Basic auth over plain HTTP is refused.** NTLM encrypts the payload even on
  5985, so there is no reason to send a password in base64. The validation host
  had `AllowUnencrypted=false` and `Basic=false`, which is the normal posture.

- **Nessus's primary Windows transport is SMB + Remote Registry + WMI, not
  WinRM.** WinRM is on by default on Server 2012+ but **off by default on
  client SKUs**, so on a workstation estate this product currently reaches
  fewer hosts out of the box than Nessus does. That is a recorded coverage gap
  needing a second transport, not a defect in this one.

- **Patch assessment does not read installed KBs**, and the real host confirms
  why: `Get-HotFix` returned **4** entries on a fully patched Windows 11
  machine, because cumulative updates supersede one another.
  `windows_patch.py` compares the host's build — UBR included — against MSRC's
  published fixed builds. `os_assessed` distinguishes "no missing patches" from
  "could not assess"; never collapse them.

## Credentialed transport and port resolution (`engines/credentialed/transport_resolver.py`)

Where an authenticated session is opened. Until this existed the answer was
`compliance_credentials.port`, which is **NOT NULL with a model default of 22** —
so "the operator chose 22" and "nobody said anything" are the same row.

- **The port scan's service identification is evidence, and the resolver reads
  it.** Candidates are the stated port plus every open TCP port positively
  identified as that transport's service. A host running sshd on 2222 used to be
  skipped with "Port 22/tcp not open" on a scan that had already identified sshd
  on 2222 — the evidence was in the same dictionary the guard was reading.

- **A credential is only ever offered a port that is stated on it or identified
  as that transport.** Walking every open port until something authenticates is
  credential spraying against the customer's own estate, and it is what a "try
  harder" resolver becomes the moment identification is dropped. `ssh` is
  matched by service *token* (so `SSH-Alt` qualifies and `ssl` does not), by the
  RFC 4253 banner, or by product; WinRM by `wsman`/`winrm` or the
  `Microsoft HTTPAPI` product string — which is the only thing identifying a
  listener moved off 5985.

- **Selection is by TCP reachability, never by attempting authentication.** Both
  executors already expose `test_connectivity`. Exactly one authentication
  attempt is made however many candidates were considered. A **rejected**
  credential is never retried on another port; only a transport failure —
  nothing answered — advances, which is what `_is_transport_failure` in
  `core/tasks.py` decides. Retrying a rejection turns one failed logon into
  three against an account the lockout control must not trip.

- **Discovery is authoritative where it exists; a TCP probe is the fallback
  where it does not.** The phase-3.5 enrichment path has the port scan's view
  and opens no socket — a 5-second connect per host is minutes across a large
  scan. The standalone `/scan/credentialed` runs no discovery, so it attempts
  the stated port directly and probes the conventional alternates *only after a
  transport failure*. `FALLBACK_PORTS` is deliberately two entries per
  transport, not a port scan.

- **`use_tls` is carried, not re-derived.** `WinRMExecutor` infers TLS from
  `port == 5986` when it is not told, which is right for the conventional layout
  and wrong for every other one. 5985/5986 are settled by convention; anything
  else carries `None`, because nmap keeps the TLS fact in a `tunnel` attribute
  this product does not parse and a guess addresses an HTTPS listener as
  `http://`.

- **The stated port leads, except when discovery contradicts it.** Since 22 can
  sit on a Windows credential without anyone having chosen it, a stated port the
  scan identified as *some other* service goes second. It is never dropped —
  service detection can be wrong. Validated against a real host running sshd on
  22 **and** WinRM on 5985 at once.

- **`_apply_credentialed_enrichment` must pass `transport`, `auth_method`,
  `domain` and `credential_options`.** It resolved all four from the stored
  credential and then called the auditor with none of them, so the auditor's
  `transport="ssh"` default applied to every credential on the main scan path
  and a Windows credential opened an SSH handshake against a WinRM listener. The
  standalone route passed them correctly, which is why the defect was invisible
  to anyone testing that route.

- **That path must also skip `credential_type == database`.** A database
  credential names an instance, not a host; the standalone task branches on this
  and the enrichment path did not.

## Elevation on the credentialed path

- **The sudo password goes on the remote command's stdin, never in the
  command.** `SSHScanner.run_sudo()` owns this and the secret never leaves that
  class. `LinuxCollector._run` previously built
  ``echo 'PASSWORD' | sudo -S …`` and passed it to `exec_command`, which puts
  the customer's password in the argv of the shell sshd spawns — visible in
  `ps` to every local user on the target, captured permanently by any `execve`
  audit rule, and from there into this scanner's own debug log, which logged
  the full command string on failure.

  `run_sudo` rewrites each `sudo` to `sudo -S -p ''` and writes **one password
  line per invocation**. `-S` reads the password from stdin and `-p ''`
  suppresses the prompt, which would otherwise land in stderr and be read as
  command output. `-n` is stripped wherever it appears, bundled forms such as
  `-ln` included: it means "never prompt" and sudo honours it over `-S`, so
  leaving it makes sudo refuse the password and the failure reads on the target
  as a permissions problem rather than as a scanner bug. One line *per
  invocation* because `sudo -l || sudo -l` runs at most one of them but which
  is decided on the target, and relying on sudo's credential cache instead
  breaks wherever `timestamp_timeout=0` is set.

  A collector must never read `ssh._password`. `has_password` answers whether
  elevation is worth attempting without exposing the secret, and
  `tests/credentialed/test_sudo_password_safety.py` pins both — including a
  source-level guard against the `echo … | sudo` shape returning.

- **`SSHScanner._redact()` masks the session password in anything logged.**
  With the stdin fix the command no longer carries it, so this is defence in
  depth: a log line is the one place a regression here would be written to disk
  and kept.

- **The configuration-audit collectors do not elevate at all.** `ShellRunner`
  has no sudo path, so every Phase 3+ Linux check reads what the scanning
  account can read. That is a recorded limitation, not an oversight — adding
  elevation there widens what a compromised scanner credential can do on every
  host in the estate, and it needs its own decision.

- **There is no elevation mechanism on the Windows path and none may be
  invented.** WinRM and OpenSSH both run as whoever authenticated; escalating
  by creating a service or a scheduled task changes a host this product is only
  meant to read. `test_windows_privilege_context.py` guards the absence by
  name (`New-Service`, `Register-ScheduledTask`, `schtasks`, `psexec`,
  `runas`, …).

  What is recorded instead is **which token the session held** —
  `system_data["privilege_context"]` carries `account`, `is_administrator` and
  `is_system`, read via `WindowsBuiltInRole.Administrator` (which resolves to
  S-1-5-32-544, so it works on a non-English install where matching the group
  *name* fails). A probe that could not be read yields `None`, not `False`:
  reading it as "not an administrator" would attribute a complete audit's
  findings to a partial one.

  **Measured, not assumed:** against a real Windows 11 Pro host over WinRM as a
  member of Administrators, all 20 Windows built-in checks completed with
  **zero errors** and no check in the current set needs SYSTEM. The three empty
  fields in the Windows collector — `arp_table_raw`, `env_vars_summary`,
  `login_history_raw` — are hardcoded placeholders in `_collect_network` and
  `_collect_login_history`, not privilege failures.

- **`credentialed_status` has one writer**, `asset_syncer.set_credentialed_status`.
  The standalone audit set the literal inline and the Vulnerability Audit's
  credentialed pass did not, so a host that was authenticated to, collected
  from and configuration-audited still read as `unknown` — and
  `core/compliance_tasks.py` routes every rule in
  `CREDENTIALED_EVIDENCE_SOURCES` to `manual_review` unless it says `success`.
  Measured on the live database: **zero** assets carried the attribute despite
  that path having written eight configuration and privilege findings against a
  real Windows host. `success` and `failed` are both written; a host nothing
  was attempted against is left **unset**, because "no credential was in scope"
  and "the credential was refused" are different facts.

## Scan scheduling (`core/scheduling/`)

Recurring network and credentialed scans. Phase 1 of the gap-closure
programme; tracker in [`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

- **Scheduling adds no scan engine.** `core/scheduling/dispatcher.py` calls
  `run_host_discovery_task.delay(...)` and `run_credentialed_scan_task.delay(...)`
  — the same tasks the manual routes call. A scheduled run is an ordinary
  `Scan` row and shows up in Scan History, reports and the dashboard like any
  other, marked `options.origin = "schedule"`. If you add a scan kind, add a
  dispatch branch; do not add a pipeline.

- **`scan_schedules` is deliberately not `compliance_scan_schedules`.** That
  table's `framework_id` and `policy_id` are NOT NULL FKs into the compliance
  catalogue and a network scan has no framework. Six of its behaviours are
  defects this table does not repeat, each documented at the point of the
  decision: no time zones, `monthly` as a 30-day `timedelta`, a
  `cron_expression` nothing reads, no duplicate-execution guard, no execution
  history, and a bare `except` reporting `success: False`.

- **A schedule stores a credential *reference*, never a secret.**
  `run_credentialed_scan_task` already resolved `credential_id` worker-side, so
  nothing had to change to make this true. `POST /scan/credentialed` still
  accepts a plaintext password and puts it in the task arguments; a schedule
  doing that would put it in the database, in every backup, and in the broker
  payload on every run.

- **Scope and quota are re-checked at every dispatch, never inherited.** A
  schedule written in March and firing in November is a stored intent, not a
  standing authorisation — narrowing an org's `scan_scope_cidrs` must take
  effect on the next run.

- **`next_run_at IS NULL` means dormant, not due.** The compliance scheduler
  treats NULL as due (`or_(next_run_at.is_(None), ...)`), so any row written
  without a computed next run fires on the very next tick regardless of the
  time the user chose. Here NULL is a one-time schedule that has fired, or a
  custom recurrence nothing can place yet.

- **Wall-clock time is preserved across DST, and the awkward hours have
  defined answers.** `core/scheduling/recurrence.py` computes in the schedule's
  IANA zone: a skipped hour (spring forward) is pushed to the first instant
  that exists rather than skipping the day; a repeated hour (autumn back) fires
  once, at the earlier instant; day 31 clamps to the month's last day. Zones
  are IANA names only — a fixed offset cannot express daylight saving and is
  refused.

- **Next run is computed from *now*, not from the previous `next_run_at`.** A
  worker down for a week comes back and runs once, not seven times.

- **Duplicate dispatch is prevented by `pg_try_advisory_xact_lock`**, not by
  assuming one beat process. Transaction-scoped, never session-scoped —
  `pg_advisory_lock` releases when the *connection* closes and SQLAlchemy pools
  connections, so a session-scoped lock leaks onto the next unrelated request.

- **`custom` (cron) is stored but not yet placed.** `compute_next_run` returns
  None for it, so such a schedule stays dormant rather than firing at an
  arbitrary time. Parsing cron needs a dependency decision that has not been
  taken.

- **Body models are prefixed `ScanSchedule` and must stay that way.** FastAPI
  keys OpenAPI component schemas by class name; a `ScheduleCreate` here
  silently replaced `routers/compliance.py`'s in the generated contract. The CI
  contract gate caught it — a regeneration showing *deletions* is the signal.

## Configuration audit engine (`core/config_audit/`)

The generic engine for configuration and hardening assessment. Phase 3 of the
gap-closure programme; tracker in
[`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

    Configuration Rule → Collector → Expected State → Actual State
        → PASS / FAIL / MANUAL / N/A → Finding → Risk → Remediation → Reporting

**No benchmark name appears anywhere in this package, and none may.** CIS
(Phase 4), STIG (Phase 5), application, database, network-device and cloud
content are all just sets of `ConfigCheck` records. The moment the engine knows
which benchmark it is running, adding the next one means editing the engine.

- **Rules live in `compliance_rules`, not a new table.** It already carries
  `check_type`, a JSONB `check_definition`, `target_platform`, `severity`,
  versioning and a junction to every framework control. A second rule table
  would need all of that again, and a second finding table, a second score and
  a second report generator come along behind it — which is exactly why Phase 0
  widened `vulnerability_definitions` rather than adding one.
  `ConfigCheck.to_check_definition()` / `.from_rule()` are the adapter.
  Migration `b4c5d6e7f8a9` widens the two CHECK constraints; the seven
  pre-existing `check_type` names are kept verbatim, and the two rule kinds are
  told apart by `check_definition.config_check`, not by the type name.

- **Four collection states, and collapsing any two is the whole class of bug
  this engine exists to prevent.** `COLLECTED` (a value was read) → compared.
  `ABSENT` (the collector ran and the thing is genuinely not there) → the
  *rule's* policy. `UNSUPPORTED` (out of scope for this target) →
  NOT_APPLICABLE. `UNAVAILABLE` (collection failed) → **ERROR, never a
  verdict**. "The registry value does not exist" and "the registry value is
  empty" routinely mean opposite things, and a collector returning `""` for
  both has lost the distinction before the engine sees it.

- **`AbsencePolicy` has no default, deliberately.** Absence is a PASS for
  "SMBv1 must not be installed", a FAIL for "auditd must be installed", and
  NOT_APPLICABLE for "if IIS is present it must be configured thus". A default
  would silently pick whichever answer flatters the score, so a rule that does
  not choose is refused at construction. Most Windows rules are
  `MANUAL_REVIEW`: a security setting absent from the registry is at a platform
  default that varies by build and SKU, and neither PASS nor FAIL can be
  asserted from the absence alone.

- **`ShellRunner` keeps the exit code; the collectors' own `_run` does not.**
  `WindowsCollector._run` and `LinuxCollector._run` both end
  `return _clean_output(result.stdout) if result.stdout else ""`. For bulk
  inventory that is defensible. For a check it means a failed command returns
  `""`, the comparison reads `""` as the host's setting, and a verdict is
  reported about a machine that never answered. There is no method on
  `ShellRunner` that returns a bare string.

- **Commands print a sentinel, and a value runs to the end of the output.**
  `CCURE::VALUE::` / `CCURE::ABSENT::`, with a non-zero exit meaning the read
  failed. Only the *first* line carries the prefix — the first parser returned
  that line alone, so every configuration file was read as its first directive
  and every other directive reported as absent, which surfaces as a fleet-wide
  configuration gap rather than as a parser bug. Output carrying no sentinel is
  UNAVAILABLE, never an empty reading.

- **`grep` exiting 1 is a successful read of "no match", and so is
  `systemctl is-active` on a stopped unit.** The Linux commands are written to
  exit 0 for all three normal outcomes. Exit **97** is the reserved sentinel for
  "the tool I needed is not installed" — a host with no `dpkg-query`, no `rpm`,
  no `ss` or no `systemctl` reports UNAVAILABLE, not ABSENT: nothing was
  established about the package, only about the package manager.

- **Rule parameters are data.** Every one goes through `ps_quote` (doubling
  single quotes) or `shlex.quote`. The rules are administrator-editable, so this
  is an injection boundary inside the product, not defensive style.

- **A FAIL becomes an ordinary `StandardizedFinding`** in the same `cve_list` as
  the CVE findings, minted `CCURE-CFG-…` and filed as
  `definition_type = config_check` with `cve_id` NULL. Only a FAIL: a PASS is a
  compliance verdict, not a vulnerability, and the other three are not verdicts.
  `RemediationConfidence.CONFIGURATION_GUIDANCE` exists because
  `NONE_PUBLISHED` renders as "no published fix — compensating controls only",
  which is true of an unpatched CVE and false of a hardening control.
  **Every `RemediationConfidence` member needs a label in
  `pdf_generator.REMEDIATION_PROVENANCE`**; that lookup used to be a dict
  subscript and a missing member raised KeyError inside PDF generation.

- **The audit runs inside the credentialed scan**, on the session the collectors
  already opened — `core/tasks.audit_credentialed_host`, inside the `with
  connection` block. Moving it after that block leaves every check reporting "no
  authenticated session". There is deliberately **no HTTP endpoint that runs
  one**: that would be a second way to start a scan against a caller-named
  target, needing its own scope check, quota check, rate limit and audit entry.
  An audit that could not run is recorded as
  `MISC-CREDENTIALED-CONFIG-NOT-ASSESSED`, because a crashed audit leaves no
  failing checks and that is byte-identical to a host that passed every one.

- **`core/config_audit/operators.py` is the single comparison vocabulary.**
  `core/compliance_tasks._evaluate_operator` delegates to it and
  `_evaluate_operator_legacy` is the pre-Phase-3 implementation, kept as the
  reference `tests/scans/test_config_audit_operators.py` compares against over
  a truth table. Do not add a second evaluator. The shared operators' semantics
  are frozen by the seeded rule catalogue, quirks included. `evaluate_detailed`
  adds a third state, `UNKNOWN_OPERATOR`: the old bare `return False` meant a
  misspelled operator evaluated False and was recorded as a **fail** against
  every host it ran on.

- **`api` is reserved and has no collector.** (`database_query` and the
  `database` platform were reserved here until Phase 7 implemented them;
  Phase 8 added `structured_config` for nested and structured
  configuration files; Phase 9 added `container` for enumerating live
  runtime state; Phase 10 added `scap_rule` for a compiled OVAL definition
  — see the database, middleware, container and SCAP sections below. The `container` *platform* is still reserved and unused: the
  Phase 9 rules target `linux`, because a runtime is assessed over its
  host's session.) Naming them now means Phases
  9–17 need no CHECK migration on a table holding customer rules. A rule using
  one reports ERROR — "this product cannot perform that check" is a product gap,
  not a property of the host, and must never render as NOT_APPLICABLE or PASS.
  `GET /config-audit/capabilities` reports the gap from the live registry.

- **The built-in pack (`builtin/`) is 20 rules and is not a benchmark.** It
  exists so the engine ships exercised. Growing it does not grow capability.

## Benchmark content (`core/benchmarks/`)

Hardening benchmarks as loadable data on top of the Phase 3 engine. Phase 4 of
the gap-closure programme; tracker in
[`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

    pack.json → compliance_frameworks/_controls/_rules → ConfigAuditEngine
      → evidence → verdict → compliance_findings → risk → remediation → report

Format and authoring guide: [`Backend/data/benchmarks/README.md`](Backend/data/benchmarks/README.md).

- **No CIS Benchmark ships in this repository and none may be committed.** CIS
  Benchmark recommendation text, rationale and remediation are the Center for
  Internet Security's, distributed under licence. A customer with a SecureSuite
  membership converts their own export into a pack; nothing in the code changes.
  **Do not write benchmark content from memory** — a rule labelled `2.3.1.1`
  carrying a recalled expected value is a false compliance claim in a
  customer's audit report and is indistinguishable from a correct one until an
  auditor checks. What *does* ship is `data/benchmarks/*.benchmark.json`, two
  CCURE-authored baselines generated from `core/config_audit/builtin/`, whose
  `licence` says in words that they are not CIS Benchmarks.

- **`assessment` is declared, never inferred** — `automated` (has a check),
  `manual` (the benchmark itself wants a human), `unimplemented` (the benchmark
  automates it, this product does not yet, and it must say why). Reading "has a
  check" as "is automated" is the inference the format refuses; it is the same
  defect as the eighteen ISO controls that claimed `semi_auto` with nothing
  behind them. `unimplemented` is what keeps the coverage figures honest — a
  benchmark that omits what it cannot do reports better coverage than it has.

- **A benchmark *is* a framework.** No new table. Recommendations are controls,
  automated recommendations are rules, and the register, score, findings queue
  and report all work the moment the rows exist. Framework ids carry the
  `cfw_bm_` prefix, which is load-bearing: `compliance_frameworks.is_active`
  uses it to tell loaded content from a *shipped but parked* catalogue. Without
  it a loaded benchmark can never appear in the hardcoded active tuple and
  scores nothing. A prefix rather than "anything unknown is active", because
  that reading would make a misspelled framework id active and the guard could
  no longer answer 404.

- **`run_scan_task` skips configuration rules, and must keep skipping them.**
  A benchmark rule has no evidence `key` — it is evaluated against a live host
  by the configuration audit and synced afterwards by
  `core/config_audit/compliance_sync.py`. If the compliance scan also evaluated
  it, it would read the missing key as missing evidence and write
  `manual_review` **over the real verdict**, silently blanking every benchmark
  result the last credentialed scan established.

- **`platforms` is windows-or-linux and that is not enough for benchmarks.**
  A CIS Ubuntu 22.04 benchmark and a CIS RHEL 9 benchmark are both `linux`;
  running one against the other's host checks paths and package names that
  distribution does not use and reads their absence as a verdict. A pack
  declares `applies_to` once (`os_name_contains`, `os_version_prefix`) and it
  flows onto every check. **An unidentified OS is an ERROR, not
  NOT_APPLICABLE** — "we could not tell what this host runs" and "this host is
  not what the benchmark is for" are different facts, and only the second is a
  legitimate reason for a control to leave the score.

- **Profiles are data on the control**, not engine behaviour:
  `compliance_controls.profiles` (JSONB, GIN-indexed, migration `c5d6e7f8a9b0`).
  Empty means in scope whatever profile was selected, which is what every
  pre-Phase-4 control is. `saq_profiles` expresses the same idea for PCI-DSS
  and is deliberately left alone — the PCI scoping queries read it — so **new
  content uses `profiles`**, pinned by a test. Choosing a profile per
  organisation is a scan-policy question and belongs to Phase 12; the filter
  exists and is tested.

- **One theme list, in `db/models/compliance.CONTROL_THEMES`.** It was
  previously copied five ways — the model twice (`ck_control_theme`,
  `ck_score_theme`), every framework migration, and `tests/conftest.py` — and
  the conftest copy silently won, because it rewrites the constraint on every
  session. A theme added to the model and its migration was still rejected by
  the test database with nothing saying why. Benchmarks use one generic
  `BENCHMARK` theme; minting one per benchmark section would add ~80 values for
  four platforms alone. The section travels in `tags`.

- **`_build_test_schema` bootstraps from the models and stamps head**, so a
  migration written *after* a database was bootstrapped never runs against it.
  Column changes are gap-filled; **CHECK constraint changes are not**. If a
  constraint change seems not to have applied, check
  `SELECT pg_get_constraintdef(...)` before assuming the migration is wrong.

- **CIS Controls v8.1 is active as of Phase 4** and is the framework benchmark
  crosswalks target. Note it is the *Controls* (153 governance safeguards), not
  the *Benchmarks* — separate publications. It shipped as a seed file, a theme
  migration and an `ALL_FRAMEWORK_IDS` entry since before Phase 4 and
  **`main.py` never seeded it**: parked *and* unseeded, so the omission was
  invisible. It is in the bootstrap now.

## Local privilege checks (`core/config_audit/collectors/privilege_*.py`)

Local privilege-escalation and host-exposure enumeration. Phase 5 of the
gap-closure programme, closing GAP-08; tracker in
[`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

**No new engine.** These are Phase 3 `ConfigCheck` records with a new check
type, `privilege`, executed by the same `ConfigAuditEngine` and reaching the
same finding, risk, remediation and report paths.

- **The shape is "which items are offending", not "read one value".** A probe
  returns one offender per line; the rule asserts the list is empty. So a clean
  host produces an ABSENT reading and `AbsencePolicy.PASS` makes it a pass,
  while a breached one produces a FAIL naming exactly what to fix. That is why
  these use `absent = PASS` where the Phase 3 Windows rules use
  `MANUAL_REVIEW`: a missing registry value tells you nothing, but a *search*
  that returned nothing is a real result.

- **`privilege` is its own check type, not a `command` rule.** Service-ACL
  parsing is not a shell one-liner and a rule author should not be pasting one.
  Migration `d6e7f8a9b0c1` adds the type; the probes live in code, are tested
  against captured output, and a rule just names one.

- **`ConfigCheck.finding_type` decides the identifier.** `config_check` mints
  `CCURE-CFG-…`, `privilege_check` mints `CCURE-PRV-…`, and they group into
  different report families. "Deviates from a baseline" and "has a path to
  SYSTEM" are different piles to a triager. The engine carries `finding_type`
  on every result, because `core/tasks._run_configuration_audit` builds findings
  from the *result* and would otherwise file every privilege finding as CFG.
  `cve` is refused at construction.

- **Three false positives were found by real-target validation, and each is the
  reason to do it.** All three would have shipped looking correct:

  - **`NT SERVICE\*` virtual accounts.** The service-ACL probe reported seven
    services on a stock Windows 11 workstation, because TrustedInstaller
    (`S-1-5-80-956008885-…`) legitimately holds full control over service
    configuration and each service's own account holds ChangeConfig over
    itself. `S-1-5-80-*` is now trusted.
  - **`stat` does not dereference symlinks.** `/bin`, `/sbin` and `/lib` are
    symlinks into `/usr` on every modern distribution, and a symlink's own mode
    is always 777 — so the writable-PATH probe reported them as world-writable
    on every host. It uses `stat -L` now. **The Phase 3
    `LinuxPermissionCollector` has the same `stat -c` without `-L`**; it is only
    pointed at regular files today, so it is not currently wrong, but a symlink
    target would fool it.
  - **`ssh-keysign` is legitimately SUID** on Debian and Ubuntu.

- **A count is not a check.** "37 SUID binaries found" says nothing — a stock
  distribution ships about thirty. `EXPECTED_SUID` is the allow-list and the
  probe reports the *difference*. The list is deliberately generous: a missing
  legitimate binary is a false positive, and a check that cries wolf is worse
  than one that misses, because the reader stops looking.

- **Exit 97 means "the tool I needed is not installed".** A host with no `find`
  has established nothing about its SUID binaries, and `getcap` is absent on
  many images. That is UNAVAILABLE → ERROR, never "none found". Proven on a real
  target, where `file_capabilities` correctly reported not-assessed.

- **These replace prose, and the prose stays.**
  `LinuxCollector._collect_security_audit` still emits its `security_issues`
  sentences — the report's posture section reads them and nothing should change
  what an existing report says. The *finding* is now the authoritative form,
  because a sentence in a PDF has no severity, no risk score, no remediation, no
  lifecycle and cannot be triaged or exported.

- **The account-file probe is scoped around the Phase 3 checks.**
  `ccure.linux.passwd.permissions` and `.shadow.permissions` already assert
  those two files' modes, so the probe checks *ownership* of all four and the
  *modes* of `/etc/group` and `/etc/gshadow` only. Repeating them would report
  one condition twice and make the remediation look twice as large.

- **Coverage is measured by `scripts/measure_privilege_coverage.py`, and its
  denominator deliberately includes eight areas this build does not implement.**
  The first version listed twenty areas, all of which the phase then
  implemented, and reported 100% — a tautology wearing a percentage. The
  headline figure is *implemented and tested*: an area whose test is deleted
  loses its coverage credit, because the script reads the test sources rather
  than a hand-maintained list.

## Middleware configuration assessment (`core/config_audit/structured.py`)

Authenticated assessment of nginx, Apache httpd, Tomcat and the Docker daemon's
own configuration. Phase 8 of the gap-closure programme, closing GAP-09;
tracker in [`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

**No new engine, no new scan kind, no new route.** These are Phase 3
`ConfigCheck` records at `platform = linux|windows`, so they run inside the
credentialed host audit alongside the OS hardening rules — a web server's
configuration is part of the host's posture, not a separate scan. 40 checks.

- **`config_file` could not have been extended to cover this, and that is the
  phase's main engineering.** It reads one directive out of a flat
  `key<separator>value` file. All four products keep their settings inside a
  structure, and there was no XML or JSON reading anywhere in
  `core/config_audit/`. The failure a flat reader produces is not "misses the
  setting" — `AllowOverride None` under `<Directory />` and under a document
  root are different statements, and a reader that cannot say which it found
  returns whichever it saw last, confidently.

- **One check type, `structured_config`, with `format` as a parameter.** From
  the engine's point of view nginx, Apache, XML and JSON are one shape: name a
  file and an address, get COLLECTED / ABSENT / UNAVAILABLE. Four check types
  would have been four CHECK-constraint values on a table holding customer
  rules for a distinction the engine cannot act on. Migration `a9b0c1d2e3f4`.

- **Scope is matched exactly, never by suffix.** `scope: None` means any depth,
  `[]` means top level only, `["http","server"]` means that exact path. An
  "ends with" rule would let a directive in `http > server > location` satisfy
  a rule about `http > server`, and telling those apart is the entire reason to
  parse structure.

- **A missing configuration file is UNSUPPORTED, not ABSENT.** A Linux host
  that does not run Apache is not *failing* Apache's rules. Get this wrong and
  every host in the estate acquires findings about software it does not have,
  which is how a configuration report gets ignored wholesale.

  **The Docker daemon is the deliberate exception** (`missing_file: absent`).
  Most installations have no `daemon.json` at all, and that means every setting
  is at its built-in default — a real state. Those defaults are a mixture, so
  each rule declares what its own absence means: no `hosts` entry is secure
  (PASS), no `icc` entry means inter-container traffic is on (MANUAL_REVIEW,
  because failing it would fire on every Docker host there is).

- **An unresolved include poisons an absence.** nginx and Apache both ship the
  interesting settings in *included* files, so a directive missing from the
  named file may be somewhere the collector did not look. Incomplete expansion
  makes an absent reading UNAVAILABLE; only a *found* value is trusted.
  Expansion is one level deep, which covers every default layout these products
  ship.

- **Include globs never reach a shell.** They come out of the *target's own
  configuration*, so they are attacker-influenced in a way rule parameters are
  not. Directories are listed and matched with `fnmatch` in Python; a glob
  handed to a shell for expansion would be command execution on the target
  during an audit.

- **Any DOCTYPE is refused before the XML parser sees it.** ElementTree *does*
  expand internal entities — measured, not assumed — and the XML here comes off
  a host being audited, so an entity bomb in a `server.xml` is a
  denial-of-service route into the scanner. No configuration file assessed here
  carries a DTD, so the ban costs nothing.

### Five things real containers settled, each of which had shipped looking right

- **Included files lost their enclosing scope.** nginx ships `server` blocks in
  `conf.d/*.conf`, included from inside `http`; parsed alone they scope as
  `server`, so every rule about `http > server` found nothing and reported it
  as not configured. `rescope()` grafts a child onto the branch its `include`
  sat on.
- **Apache resolves a relative `Include` against `ServerRoot`**, not the config
  file's directory. Assuming the latter left the include unexpanded, which
  downgraded *every* absent directive in the file to "could not assess". The
  collector reads `ServerRoot` out of the configuration itself.
- **A default XML namespace made every Tomcat selection return nothing.**
  Tomcat 10 declares `xmlns` on `tomcat-users.xml`, so a plain `.//user`
  matches nothing — the parse succeeds, the selection is empty, the collector
  reports ABSENT and the rule's `AbsencePolicy.PASS` **declares the server
  clean**. Namespaces are stripped on parse; pinning rules to the URI would
  break on the next version, which is the same failure with a longer fuse.
- **`not_contains` on a list is membership, not substring.** `["apache-coyote"]`
  against `['Apache-Coyote/1.1']` found no equal element and passed — a server
  advertising itself, reported clean. Use the scalar path and a regex.
- **`User` is not a top-level Apache directive.** The stock layout puts it
  inside `<IfModule unixd_module>`; a rule pinned to the top level reports
  ABSENT on an entirely normal server.

### Content

**No CIS or STIG content, and none may be added from memory** — same position
as Phases 4 and 7. These are CCURE-authored rules written from vendor
documentation, and every directive was read off a live container before its
rule was written.

**Nothing here duplicates GAP-06.** Missing security headers, dangerous HTTP
methods, directory listing, banner version disclosure, cookie flags and TLS
endpoint assessment are observed over the wire and validated there.
`test_no_rule_duplicates_a_check_gap06_already_makes` enforces the boundary in
code. GAP-06 answers "what does this server *show* an anonymous client";
GAP-09 answers "what does its configuration *say*".

**A directive missing from a config file means the compiled-in default**, and
those differ between builds and distributions — so those rules are
MANUAL_REVIEW, following the Phase 3 `sshd_config` precedent. Each one must
name the vendor default in its description, which a test enforces, so the
reviewer settles it in one step instead of going to look it up.

### Test targets

Disposable containers, destroyed after use:

```powershell
docker run -d --name ccure-nginx-target   nginx:1.27-alpine
docker run -d --name ccure-httpd-target   httpd:2.4
docker run -d --name ccure-tomcat-target  tomcat:10.1-jdk17
docker run -d --name ccure-dockerd-target --privileged docker:27-dind
```

Measured weak → hardened: nginx **11 → 0**, Apache **8 → 0**, Tomcat
**10 → 0**, Docker **10 → 0**. A run returning zero against a *weakened*
target is a regression, not a clean server.

Two things worth knowing about the stock images:

- **Tomcat's official image is already hardened on two checks.** `webapps/` is
  empty (the bundled applications live in `webapps.dist/`) and
  `tomcat-users.xml` defines no users, so proving those checks *fire* needs the
  applications copied back deliberately.
- **`shutdown="SHUTDOWN"` on `<Server>` is a real finding on a stock Tomcat.**
  It is what the image ships and what Tomcat's own documentation tells you to
  change; anyone who can reach port 8005 and send that word stops the server.

### Coverage

`scripts/measure_middleware_coverage.py`, denominator frozen at 36 areas before
implementation and including **twelve areas this build does not implement** —
six of them IIS, which needs a Windows Server target that is not available
here. **~3% → 66.7%** (24/36), implemented *and* tested. Product breadth is
reported separately and never folded in.

## Container and Kubernetes assessment (`core/config_audit/containers.py`)

Authenticated assessment of what a container runtime is *running* and what a
Kubernetes cluster *allows*. Phase 9 of the gap-closure programme, closing
GAP-17; tracker in
[`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

**No new engine, no new scan kind, no new route.** 24 checks at
`platform = linux`, running inside the credentialed host audit — a container
runtime is assessed over the *host's* session.

- **The Docker daemon configuration belongs to GAP-09, not here.**
  `daemon.json`, the TCP socket, `icc`, `userns-remap`, insecure registries and
  the log driver are ten checks built and validated in Phase 8. GAP-17 is about
  what the daemon is *running*. Two tests enforce the boundary in code, because
  counting them twice would have inflated this phase by a quarter.

- **`container` is its own check type, for the Phase 5 reason.**
  `structured_config` reads a document and addresses a value; this enumerates
  live state and filters it. The rule names a probe, the command is fixed in
  code, and the filtering happens **in Python** — putting a pipeline of
  `docker inspect` text-munging into administrator-editable rule data is what
  Phase 5 refused for service-ACL enumeration. Migration `b0c1d2e3f4a5`.

- **The reserved `container` platform is deliberately unused.** These rules
  target `linux`. That reservation describes a container as a target in its own
  right, which is a different idea.

- **Two exit statuses where one would have done, and this is the phase's main
  design decision.** `97` = the tool is not installed → UNSUPPORTED →
  NOT_APPLICABLE. `96` = installed but not answering → UNAVAILABLE → ERROR.

  This differs deliberately from Phases 3 and 5, where exit 97 is an *error*.
  Every Linux host has SUID binaries, so failing to list them is a gap; **most
  hosts run no Kubernetes**, so not finding it is an answer. Treating it as an
  error would hand every host in an estate eight findings-shaped errors about
  software it does not have.

  The second status is what keeps that safe: the probes require `docker info`
  and `kubectl version` to *succeed*, not merely that a binary exists, because
  `docker ps` against an unreachable daemon returns an empty container list
  byte-identical to a clean host.

- **`structured_config` gained `yaml` and `toml` rather than a new collector.**
  kubelet configuration is YAML, containerd's is TOML, and all three mapping
  formats parse to the same Python shapes — so `navigate()` is one
  implementation, not three. `tomllib` is stdlib from 3.11; **PyYAML is
  declared explicitly** in `requirements.txt` even though it arrives
  transitively via bandit and pre-commit, which are *development* tooling. That
  is the dnspython trap: the import is reached at scan time.

- **Only `yaml.safe_load` is ever called.** The full loader constructs
  arbitrary Python objects from tags such as `!!python/object/apply`, which is
  remote code execution in the scanner reading a file off a host it audits —
  the same threat the XML DOCTYPE ban addresses, one format over.

- **A dotted pointer cannot address containerd's keys.**
  `[plugins."io.containerd.grpc.v1.cri"]` parses to a key literally *named*
  `io.containerd.grpc.v1.cri`; splitting on dots yields five segments matching
  nothing, and "matches nothing" is ABSENT, which for these rules means "at the
  product default". `navigate()` therefore accepts a **list** of segments, and
  the collector must pass it through without `str()` — see below.

### Three things real targets settled

- **`str(pointer)` silently defeated list pointers.** `_from_mapping` called
  `str()` on the address, turning `["plugins", "io.containerd…"]` into its repr,
  which then split on dots into nothing. containerd reported **clean however it
  was configured**. Found only because a deliberately weakened `config.toml`
  failed to produce the finding it should have.
- **`cluster-admin` was reported on every cluster.** The wildcard-role probe
  excluded roles named `system:*`, but `cluster-admin` is not one and is *the*
  role that legitimately holds `*` on `*`. The filter is now the
  `kubernetes.io/bootstrapping: rbac-defaults` label, which 65 of the 69
  ClusterRoles on a stock k3s carry.
- **Kubernetes' own components are legitimately privileged.** kube-proxy runs
  privileged and CNI pods share the host network, so the workload probes skip
  `kube-system`, `kube-public` and `kube-node-lease`. Without that, every
  cluster produces a page of findings.

### Content

**No CIS Benchmark content** — same licensing position as Phases 4, 7 and 8.
These are CCURE-authored rules written from vendor documentation, and every
probe was run against a live Docker host and a live k3s cluster before its rule
was written.

**Image scanning, registry scanning and managed-cloud Kubernetes are out of the
denominator entirely**, not merely unimplemented. They are a different product
shape needing a Trivy/Grype-class toolchain and cloud credentials.

### Test targets

Disposable containers, destroyed after use:

```powershell
docker run -d --name ccure-ctr-target --privileged docker:27-dind
docker run -d --name ccure-k3s-target --privileged -e K3S_KUBECONFIG_MODE=644 `
  rancher/k3s:v1.31.4-k3s1 server --disable=traefik --disable=metrics-server
```

Measured weak → hardened: Docker **9 → 0**, Kubernetes **7 → 0**, kubelet
**4 → 0**, containerd **1 → 0**. The hardened Docker run keeps one deliberately
well-configured container running (`--user 1000 --read-only --security-opt
no-new-privileges --cap-drop ALL`), so a clean result proves the probes stay
silent on a real container rather than on an empty host.

Three things worth knowing:

- **k3s bundles `kubectl` at `/bin/kubectl`.** `k3s kubectl` is not a valid
  invocation *inside* the image; the guard tries `kubectl` first for that
  reason.
- **k3s does not use a kubelet configuration file** — it passes flags. The
  kubelet rules therefore report NOT_APPLICABLE against it and were validated
  against a kubeadm-shaped `config.yaml` written to the kubeadm path. That
  proves the rule, path, parser and verdict; it does not prove a kubeadm
  kubelet reads the file as assumed.
- **k3s's containerd config lives at
  `/var/lib/rancher/k3s/agent/etc/containerd/config.toml`**, not `/etc`.

### Coverage

`scripts/measure_container_coverage.py`, denominator frozen at 42 areas before
implementation and including **eighteen areas this build does not implement** —
five of them the Kubernetes control plane, which needs a kubeadm-style static
manifest that k3s does not have. **~4% → 57.1%** (24/42), implemented *and*
tested. Runtime breadth is reported separately and never folded in.

## STIG and SCAP content (`core/scap/`)

Reading published SCAP content — an XCCDF benchmark and the OVAL definitions
its rules check through — and evaluating it against a credentialed host.
Phase 10 of the gap-closure programme, closing GAP-05; tracker in
[`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

    datastream → XCCDF rules + OVAL definitions → compiled definition
      → ConfigCheck(check_type="scap_rule") → BenchmarkPack
      → compliance_frameworks/_controls/_rules → ConfigAuditEngine
      → PASS / FAIL / NOT_APPLICABLE / ERROR → finding → risk → report

**No new engine, no new finding model, no new scan kind, no new route.** The
persistence cost of the whole phase is one value on one CHECK constraint
(migration `c1d2e3f4a5b6`). A benchmark *is* a framework (Phase 4), a rule *is*
a `ConfigCheck` (Phase 3), a failed check *is* a finding (Phase 0).

- **What ships is the reader, not the content.** No STIG is committed and none
  needs to be — this is the one content gap where licensing is not the blocker.
  DISA publishes its SCAP benchmarks as US Government works; SCAP Security
  Guide publishes an `xccdf_org.ssgproject.content_profile_stig` profile per OS
  under **BSD-3-Clause** (verified against the project's `LICENSE`, not
  recalled). `scripts/benchmarks/load_stig.py` converts and loads it.

  **An SSG result is not a DISA certification.** SSG renders the STIG's
  requirements as its own automated content. `--publisher` and `--licence` are
  required with no defaults, and both land on the framework record, because
  that distinction has to survive into a report.

- **A definition is compiled, not referenced.** The rule row carries the tests,
  objects, states and *resolved* variables it needs. The datastream is a 28 MB
  file on an operator's workstation and the rule runs on a Celery worker months
  later; a rule that had to reach back to its source content would be
  unevaluable in exactly the situation it exists for.

- **`UnsupportedConstruct` is the phase's whole honesty mechanism.** OVAL 5.11
  defines well over a hundred tests and this build evaluates ten, chosen by
  measuring which ones the available content actually uses (five test types are
  92.2% of 1,318 test elements). Anything else fails to compile and the
  converter records the control as `unimplemented` **with the reason** — so it
  appears in the register, counts against coverage, and can never be mistaken
  for a control that passed.

- **A refusal knowable from the content belongs at load time, not scan time.**
  Every shape check — unsupported test type, an entity selected by an operation
  that cannot be resolved, a path pattern with no literal root — was moved from
  the probe into the compiler as it was found. The result is that a converted
  benchmark produces **zero scan-time errors** on a real host: a refusal is
  reported once, in the load tally, instead of on every host the benchmark ever
  runs against.

- **Namespaces are read, never stripped** — the opposite of Phase 8. `file_test`
  exists in the OVAL `unix` schema *and* the `windows` schema; stripping merges
  them and hands a Windows registry rule to a Unix probe. Every element is keyed
  `schema:local_name`.

- **Polarity is asserted.** A `compliance`-class definition is TRUE when the
  host is hardened; a `vulnerability`-class one is TRUE when it is *affected*.
  Scoring the second with the first's polarity reports every vulnerable host as
  compliant, so anything but `compliance` is refused rather than negated on a
  guess.

- **Matching happens in Python, not in the shell.** `textfilecontent54` is 68%
  of the corpus and its object carries a regex with capture groups plus
  behaviour flags. Handing that to `grep` means translating one regex dialect
  into another, on the target, with the rule's own text as input.

### Applicability is not optional, and the measurement says so

A STIG rule is frequently conditional: "if PAM is installed", "if this is a
real system with a kernel rather than a container". Those are XCCDF
`<platform>` elements resolving to CPE 2.0 logical tests over OVAL *inventory*
definitions, and `core/scap/evaluate.evaluate_applicability` runs them with the
same three-valued logic as everything else.

It was originally declared **not planned**, on the reasoning that
benchmark-level `applies_to` targeting already answered it. Cross-checking
against `oscap` on the same host proved that wrong: **without applicability,
128 rules produced verdicts `oscap` correctly skipped, 102 of them failures** —
findings about a kernel, a display manager and a PAM stack the target does not
have.

**The nesting is the semantics, and it was wrong twice.** Platforms declared
side by side are alternatives; platforms inherited from different levels
(Benchmark → Group → Rule) are cumulative. Reading the second as the first left
17 rules applicable that `oscap` skipped — each a Group saying "a system with a
kernel" and a Rule saying "and PAM is installed", which in a container are
false and true. `XccdfRule.platform_levels` keeps the structure; `platforms`
is the flat form and is for tags only.

An applicability that cannot be established is **UNKNOWN → ERROR**, never
"applies". Reading it as applicable puts the verdict back into the
false-positive class; reading it as not-applicable silently drops a control
from the score.

### Six defects real content found, and one a warning found

Every one produced a plausible result and none raised.

- **`<Value>` was read only from the Benchmark's direct children.** XCCDF
  permits it inside a `<Group>` and SSG puts nearly all of them there, so the
  real RHEL 9 datastream yielded **zero values** — every parameterised rule then
  failed to compile for want of a binding and loaded as `unimplemented` with a
  plausible reason.
- **Reference *values* were discarded in favour of their href.** SSG writes
  `<reference href="…/cci/">CCI-000366</reference>`; the href names the
  catalogue and the **text** is the identifier. Keeping only the href throws
  away every CCI and NIST control in the benchmark.
- **No SSG rule carries `<version>`**, so control ids fell back to the full
  XCCDF rule URI and dozens exceeded the catalogue-key ceiling. Stripping the
  XCCDF 1.2 identifier scaffolding is defined by the specification.
- **The NIST crosswalk emitted controls that do not exist** — `PR.DS-01`, a
  CSF identifier, yielded `DS-1`, and its href says "nist" so a source filter
  let it through. Entries are now validated against the seeded 800-53
  catalogue, so a dangling crosswalk is structurally impossible.
- **`seed_path` returns a `str`.** Calling `.read_text()` on it raised into a
  broad `except` and every crosswalk vanished while the load reported success.
  Failing open is right; failing open *quietly* is not.
- **An empty `<filename/>` selects the directory itself.** Dropping it made a
  rule about `/var/log/journal` collect nothing, and `check_existence="none_exist"`
  read "no offending directory" off an empty set — a vacuous truth and a false
  **negative**. It was the only rule `oscap` and this build ever disagreed on.
- **Python's `re` does not support POSIX bracket expressions and does not say
  so.** `[[:blank:]]` parses as a set of the literal characters `[ : b l a n k`,
  so a pattern written to match whitespace matches punctuation. Found only
  because a `FutureWarning` about a nested set appeared in scan output nobody
  would normally read. Unknown class names are refused rather than left in
  place, which would reproduce the same silent mis-parse.

Two dialect differences are translated rather than declined, each to the
escape's documented meaning: **inline global flags must lead** in Python
(`^\s*(?i)X` raises), and **`\N` and `\h` do not exist** — `\N` is read as the
start of a named-Unicode escape. Scoped pairs `(?i)X(?-i)` become `(?i:X)`;
handling only the opening half would silently widen the match, which is what
the content wrote `(?-i)` to prevent.

### Validation

Two disposable containers, destroyed after use. The root credential is
generated at run time and never written to source, configuration, logs, Celery
arguments or Git.

```powershell
docker run -d --name ccure-rocky-target  -p 127.0.0.1:2222:22 rockylinux/rockylinux:9 sleep infinity
docker run -d --name ccure-ubuntu-target -p 127.0.0.1:2223:22 ubuntu:24.04           sleep infinity
```

RHEL 9 STIG → Rocky 9: **257 automated, 0 errors**. Ubuntu 24.04 STIG →
Ubuntu: **144 automated, 0 errors**. Nine rules were proven in both directions
across all four probe families, including a three-state demonstration: the
`auditd` rules report NOT_APPLICABLE with the `audit` package absent, FAIL with
a weak `auditd.conf` once installed, PASS when hardened. Writing the config
file by hand does not make the rule apply, and it did not.

**`oscap` 1.3.9 agrees on 144 of 144 rules** — same datastream, same profile,
same host, nothing changed in between. No previous phase has had an independent
implementation of the same standard to check against.

Two things worth knowing before repeating this:

- **`oscap` will not evaluate RHEL content on Rocky.** The first cross-check
  returned `notapplicable` for all 1,532 rules, correctly: the benchmark's CPE
  is `cpe:/o:redhat:enterprise_linux:9`. Running the RHEL STIG against a
  rebuild is a deliberate operator decision, supplied through
  `--applies-to-name`; nothing in the code infers that two distributions are
  interchangeable.
- **A container satisfies few platforms.** Most SSG rules are gated on
  `system_with_kernel`, so a stock container reports them NOT_APPLICABLE —
  correctly. Installing `kernel-core` (Rocky) or `linux-base` (Ubuntu) is what
  makes the rules behind it reachable for validation.

### Coverage

`scripts/measure_scap_coverage.py`, denominator frozen at 52 areas before
implementation with **nineteen** declared unimplemented. **0% → 63.5%** (33/52),
implemented *and* tested. Two areas were found after the freeze —
`systemdunitdependency` and the OpenSCAP Script Check Engine — and are reported
separately against a corrected denominator of 54, giving **61.1%**; the frozen
list is what was predicted beforehand and editing it afterwards destroys the
only thing it is for.

The converter's own tally is the remaining gap list, produced from real content:
`local_variable` (111 RHEL 9 rules) and object `<set>` (52) are one problem
wearing two hats — both need a second collection pass whose results feed the
first. That is the single change that would move the figure most.


## Assessment framework (`core/checks/`)

The common contract every new assessment speaks. Added in Phase 0 of the
Nessus gap-closure programme; the tracker is
[`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

**It does not replace the fifteen vulnerability plugins and is not meant to.**
Those are stable and produce real findings; rewriting them onto this contract
would be a large refactor with no capability gained. New capabilities —
configuration audit, local privilege checks, database and network-device
assessment — register here. What the plugins gained instead is the guard they
never had (below).

- **`CheckOutcome` reuses the compliance vocabulary, deliberately.** `pass`,
  `fail`, `not_applicable`, `manual_review` are spelled exactly as
  `compliance_findings.status` spells them, so a check result stores as a
  compliance verdict with no translation table — and a translation table is how
  two vocabularies for one idea begin. `error` is the one addition, and it is
  deliberately *not* storable as a verdict: it is a scan-time condition, and
  writing it as a status would assert something about a host that nothing
  established.

- **`is_verdict` is True for exactly PASS and FAIL, and every roll-up must gate
  on it.** Treating NOT_APPLICABLE, MANUAL_REVIEW or ERROR as a pass inflates a
  compliance score; treating any of them as a fail invents findings on hosts
  nobody could reach. ISO A.8.2 was once reported as *failed* on hosts the
  scanner could not authenticate to — that is this bug.

- **A FAIL with no evidence is rejected at construction.** Not a lint, not a
  review checklist — `CheckResult.__post_init__` raises. It is the mirror image
  of the synthesised `password_policy` that once made every rule reading it pass
  unconditionally on every host, and it is the direction that reaches a customer
  as a false positive.

- **A check that raises yields an ERROR result**, never a swallowed log line and
  never a FAIL. Swallowing makes a broken check indistinguishable from a clean
  host; returning FAIL invents a finding out of a bug in our own code.

- **Severity has one vocabulary.** `normalize_severity()` maps
  `compliance_rules`' `info` onto `scans.cvss.CANONICAL_SEVERITIES`' `none`.
  Unrecognised input becomes `unscored`, not `none` — no rating published is a
  different fact from a published rating of zero.

- **`tests/scans/test_plugin_contract.py` is the guard the legacy plugins never
  had.** `VulnerabilityEngine` calls serial plugins with three arguments and
  parallel plugins with two, and catches plugin exceptions at DEBUG. A plugin
  with the wrong arity raises `TypeError` on every host, is swallowed, and stays
  in `plugin_names()` and `select_plugins()` while producing **zero findings
  indefinitely**. The test reads `plugin_selector`'s own dispatch tables — not
  `plugins.__all__`, which is the import list and says nothing about arity — and
  checks each signature statically. Verified by mutation: reducing
  `nuclei_probe.run` to two arguments fails it with a message naming the plugin,
  the arity and the call site.

## Data model notes

- **`compliance_credentials` is the platform credential store, not a
  compliance table.** The name is a misnomer kept deliberately — it has been
  the store for credentialed scans since before Phase 1 and
  `scan_schedules.credential_id` points at it, so renaming means an ALTER on
  live encrypted credentials for a cosmetic gain. It is discriminated by
  `credential_type` (`ssh`, `windows`, `database`; `network_device` and
  `snmp` reserved) and `transport` (`ssh`, `winrm`, plus one per database
  engine — `postgresql`, `mysql`, `mssql`, with `oracle` and `mongodb`
  reserved). `domain` is a column rather than
  a prefix on `username` because NTLM wants `DOMAIN\user` and Kerberos wants
  `user@REALM`; `principal()` owns that mapping. Never put a secret in
  `options` — it is returned to clients and logged.

- **The catalogue holds checks as well as CVEs.** `vulnerability_definitions`
  gained `definition_type` (`cve` | `config_check` | `plugin_check` |
  `privilege_check`) in migration `e1f2a3b4c5d6`, and both `id` and
  `asset_vulnerabilities.vuln_id` widened from 30 to 120 characters. Before
  that, `vuln_id` was a NOT NULL foreign key into a CVE-only catalogue, so
  **every finding the product could record had to be a CVE** — and a CIS
  control, a STIG rule, a weak service ACL or a database privilege finding had
  nowhere to go except its own findings table, which is where a second finding
  model, a second risk model and a second report generator come from.

  Mint non-CVE identifiers with `core.checks.definitions.definition_id_for_check`
  — never by hand. It emits the `CCURE-` vendor prefix (so a reader knows the
  identifier is ours and that NVD has never heard of it), folds dots and
  underscores to one spelling (so `2.3.1.1` and `2_3_1_1` cannot become two
  catalogue rows for one control), and refuses rather than truncating an
  over-long id, because a truncated key silently merges two sibling controls.

  `ck_vuln_def_cve_id_matches_type` enforces that a `cve` row carries `cve_id`
  and a check row does not. Without it a check filed as `cve` inherits KEV
  lookups, EPSS scores, CVSS bands and an NVD link that resolves to nothing.

  The live catalogue used to hold 23 rows keyed `CVE-9999-<hex>` — test residue
  from `tests/scans/test_scans.py`, predating the conftest database guards.
  **They are gone**: measured at 0 on 30 Aug 2026, alongside 0 `cve` rows with
  a NULL `cve_id` and 0 non-CVE rows carrying one, across 263,938 rows. The
  episode is kept here because it is exactly the confusion the `CCURE-` prefix
  exists to prevent, and because nothing stops a future test writing more.

- `services` is a **current-state projection**, not per-scan history. The row id
  is `gen_service_id(asset, port, protocol)`, so re-scanning re-points rows
  rather than adding a generation. Point-in-time results live in
  `scan_phases.summary`, which the scan-detail API and reports read back.
- `assets` is keyed by `(org_id, ip_address)` and `(org_id, mac_address)`.
  Re-scans update in place; `first_seen_at` is preserved and per-field
  provenance is tracked in `custom_attributes.provenance`.
- Timestamps in scan payloads are timezone-aware UTC. Do not introduce naive
  `datetime.now()` — it renders as local time beside UTC siblings.

## Vulnerability feeds (`vuln_intel`)

`vuln_intel` is a separate database with its own schema, and it is **not under
this repo's alembic control** — its `alembic_version` names a revision that
exists nowhere in the tree. Each sync script asserts the tables it needs, so
the feeds can be rebuilt onto an empty server.

- `Backend/scripts/vuln/sync_osv.py` — osv.dev advisories. Written 11 Aug 2026
  because **there was no ingest path at all**: 3.1M rows existed with nothing
  able to refresh or rebuild them. Stages under `CCURE_FEED_DIR` (see `Backend/.env.example`). Default set
  covers 22 ecosystems; `--list` shows what osv.dev publishes.
- `Backend/scripts/vuln/sync_msrc.py` — Microsoft Security Update Guide
  (CVRF v3.0, no API key). Populates `msrc_document`, `msrc_product`,
  `msrc_remediation` and the `msrc_product_build` view. Caches raw JSON in
  `CCURE_FEED_DIR`; re-runs only fetch months whose `CurrentReleaseDate`
  moved.
- `Backend/scripts/vuln/sync_exploit_intel.py` — exploit availability from
  ExploitDB, Metasploit (read from ExploitDB's tags) and Nuclei templates,
  merged with CISA KEV. Before it, the `exploits` table held 1,647 rows all
  sourced from KEV, so `has_exploit` was an exact synonym for `in_kev` and both
  `has_exploit` branches in `compute_priority` were unreachable. Now 29,287
  rows, 27,640 of them outside KEV. `verified_exploit` marks the subset
  ExploitDB confirmed reproducible.
- `Backend/scans/nvd_sync.py` — NVD, pre-existing. Needs the API key in `.env`.

- `Backend/scripts/vuln/sync_csaf.py` — CSAF 2.0 vendor and government
  advisories: **Siemens ProductCERT**, **CISA ICS/OT and IT**, Red Hat. Adding
  a provider is one entry in `PROVIDERS`, because discovery follows the
  standard — `provider-metadata.json` names ROLIE feeds, the feed lists
  advisories. Documents cache in `CCURE_FEED_DIR`.

  Two things to know before extending it:

  - **The `.well-known/csaf/` path does not work for these providers.** Both
    Siemens and CISA return HTTP 403 there and it looks exactly like a network
    block — it is not. Siemens publishes at
    `/productcert/csaf/provider-metadata.json` and CISA at
    `/sites/default/files/csaf/provider-metadata.json`. Always start from the
    provider's documented metadata URL, never a guessed well-known path.
  - Red Hat publishes a `directory_url` distribution rather than ROLIE, so it
    has no machine-readable index. The script warns and skips it instead of
    scraping HTML.

  Stored data is advisories, their CVEs, affected product names, the vendor's
  own remediation wording, and — in `csaf_affected.version_constraint` — the
  machine-readable version range.

  **Read `version_constraint`, never `product_name`, when matching.** The two
  live side by side and only one is parseable. `product_name` is prose for a
  human: "TIA Portal v15: All versions prior to v15.1 Update 7", "SIMATIC
  STEP 7 (TIA Portal) and WinCC (TIA Portal) V15" (two products in one row),
  "Siemens SIMATIC WinCC 7.3: <Update_10". Measured across 107,747 rows, only
  **11.4%** of those yield a constraint a parser can act on, which makes the
  corpus look unmatchable. The branch name beside it carries the structured
  form — the OpenSSF `vers` spec (54%) or a plain operator and version (43%),
  **97.6% machine-readable**. The first version of this ingest stored only the
  prose and discarded the branch name, and the conclusion drawn from that
  measurement — that CSAF matching could not be built safely — was an artefact
  of measuring the wrong column.

  `engines/credentialed/csaf_matcher.py` matches installed software against
  these. It is the only path that reaches OT software at all: TIA Portal,
  WinCC and SIMATIC either have no CPE or none anyone publishes against, so
  the CPE path sees nothing on an engineering station. On the audited host it
  produced 14 findings nothing else could.

  **Two conditions, both required, both derived from measurement.** Token
  containment — the rule the Microsoft application matcher uses — was tried
  first and produced **1,901 matches from 191 packages**, mostly wrong:

      Google Cloud SDK                    ->  TIA Portal Cloud V16
      SIMATIC WinCC Runtime Advanced V17  ->  SIMATIC WinCC 7.2

  Stripping vendor and family noise from an OT name removes the words that
  distinguish the products — "Runtime", "Advanced", "Professional" — leaving a
  generic token like `wincc` that matches half the catalogue. So:

  1. **Normalised whole-name equality**, not containment.
  2. **Release-line agreement.** An advisory for "SIMATIC ProSave V18" with
     `vers:all/*` means every version *of the V18 line*. Without this rule an
     installed V19 inherits V18's and V20's advisories — the same failure as
     the Windows servicing-line bug. It correctly withheld WinCC Runtime
     Advanced V11–V16 advisories from an installed V17.

  A constraint the matcher cannot order (`<V19_Update_4`, "All versions prior
  to the latest build") yields **no finding** and is counted as unassessed.
  Seven such constraints were skipped on the audited host rather than guessed.

  Enrichment by exact CVE match is separate and also safe
  (`core.vuln_intel.csaf_advisories_for`).

  **Pace it politely.** Fetched with eight threads and no delay, Siemens'
  portal began returning 403 with "You made too many requests in a short time
  for our system… please contact productcert@siemens.com", and 137 of 831
  documents were lost — which looks exactly like corrupt data in the log. At
  1 worker with a 0.4s delay all 831 fetch cleanly. Per-provider `workers` and
  `delay` live in `PROVIDERS`; do not raise Siemens'.

  An enriched advisory covers the same **CVE**, not necessarily the same
  **product**. A Chrome CVE appears in a CISA ICS advisory because an ICS
  product embeds Chrome, and that advisory's mitigation is written for the ICS
  context. `vendor_remediation` is therefore always prefixed with the advisory
  id, so ICS guidance can never read as the desktop vendor's own advice.

- `Backend/scripts/vuln/sync_vulncheck.py` — VulnCheck KEV, 5,117 entries
  against CISA's 1,647: **3,470 exploited CVEs CISA does not list**. Needs
  `VULNCHECK_API_TOKEN` in `Backend/.env` (free tier, vulncheck.com). Note the
  API caps pagination at **6 pages regardless of page size**, so `_PAGE_SIZE`
  must stay large enough that 6 pages covers the catalogue — a smaller page
  size truncates the feed silently. The script warns if it retrieved fewer
  entries than the API reports.

  **Stored in its own table, not merged into `kev`.** CISA KEV drives BOD 22-01
  remediation deadlines and every entry carries a `due_date`; a report showing
  "in KEV" is read as "there is a mandated fix-by date". VulnCheck KEV is
  threat intelligence with no deadline and no compliance duty. Merging them
  would attach an imaginary federal deadline to 3,470 vulnerabilities, and a
  compliance report built on that would be wrong invisibly. `in_kev` keeps
  meaning exactly CISA KEV.

  `vulncheck_kev.canary_confirmed` marks the 481 CVEs observed being exploited
  against VulnCheck's own honeypots — direct observation rather than a report
  of one, and the strongest exploitation evidence in any feed here. It is the
  only VulnCheck signal allowed to set `verified_exploit`.

Secrets live in `Backend/.env` (gitignored), which is what `config.py` loads —
**not** the repository-root `.env`, which is for docker-compose. A token placed
in the root file is silently ignored by every script here.

`has_exploit` means a public exploit exists for the CVE. It does **not** mean
the scanned host is exploitable, which depends on configuration and
reachability this feed knows nothing about. Do not render it as proof of
exploitability.

Things about OSV worth knowing before trusting a query against it. Each of
these was a silent false negative found by scanning a real target, not a
theoretical concern — all four produced a confidently clean report:

- OSV **does** carry `Red Hat`, `Rocky Linux`, `AlmaLinux`, `SUSE` and
  `openSUSE` now. Separate OVAL/CSAF parsers are not needed for RHEL-family
  coverage.
- **Ecosystem names are not uniform.** Rocky and Alma are `Rocky Linux:9` /
  `AlmaLinux:9`, but Red Hat splits a release across repository modules
  (`Red Hat:enterprise_linux:9::appstream`, `::baseos`, `::crb`) and SUSE names
  products (`SUSE:Linux Enterprise Server 15 SP5`). `osv_ecosystems_for()`
  returns **LIKE patterns**, and both OSV queries use `LIKE ANY`. The earlier
  `Red Hat:9` form matched zero rows.
- **RHEL-family and SUSE advisories carry no `aliases` field.** They put CVE
  references in `upstream` and `related` — 0 of 3,846 Rocky records have
  `aliases`. The matcher reaches findings through an inner join on
  `osv_aliases.cve_id`, so ingesting only `aliases` left every RHEL-family
  advisory unreachable. `sync_osv.py` reads all three fields.
- **Distribution versions need distribution comparison.** `_parse_version`
  strips everything from `el9`/`ubuntu` onward, which is right for upstream CPE
  ranges and catastrophic for OSV: a backported fix (`2.34-274.el9_8` against
  installed `2.34-266.el9_8`) compares equal, and backports are how
  distributions fix nearly everything. Use `compare_distro_versions()` —
  rpmvercmp ordering with epoch and `~` handling — on the OSV path.
- **RPM epochs must be collected.** `linux_collector` emits
  `%|EPOCH?{%{EPOCH}}:{0}|` so the epoch is always present. Without it Rocky's
  openssl (epoch 1) defaulted to epoch 0 and matched every advisory fixed in
  `1:3.0.1-…`, reporting a 3.5.5 install as vulnerable to a flaw fixed four
  releases earlier.
- `osv_ranges` now carries `ecosystem` and `package_name`, and both matcher
  queries join on them. Before that, an advisory covering several packages or
  releases had its ranges applied to all of them — an Ubuntu 24.04 package was
  reported as fixed in a 25.10 version that cannot be installed on it. Rows
  predating the columns are NULL and still match, so a partial re-sync degrades
  to the old behaviour rather than dropping ranges.

## Network checks (`engines/vulnerability/network_checks.py`)

The catalogue every unauthenticated network plugin turns an observation into a
finding through. Phase 6 of the gap-closure programme, closing GAP-06; tracker
in [`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

**No new engine.** `VulnerabilityEngine`, `plugin_selector` and the fifteen
probes' own detection logic are unchanged. What changed is that a probe which
has established something now has one correct way to say so.

- **`VulnerabilityEngine._merge` promotes a *top-level* `cves` key and nothing
  else.** This is the single most important fact about writing a network
  plugin. Six of fifteen returned their findings nested inside `http_audit`,
  `ftp_info` or `smb_info` and every condition they detected was discarded —
  weak SSH algorithms, SMBv1, a `public` SNMP community, an expired
  certificate, anonymous FTP write access. A finding that is not at the top
  level does not exist.

- **`ssh_probe` is the shape to watch for.** It initialised `info["cves"] = []`,
  promoted it with `if info.get("cves")`, and nothing ever appended to it: the
  CVE lookup had been removed and the plumbing left behind. An AST pass over
  the fifteen modules answers "8 plugins emit"; the truth was 7. That is why
  `scripts/measure_network_check_coverage.py` reads a catalogue rather than the
  sources — a measurement fooled by dead plumbing reports the starting point
  too high and every later number inherits the error.

- **A network condition must never become a fabricated CVE.** `asset_syncer`
  set neither `definition_type` nor a NULL `cve_id`, so `MISC-FTP-ANON` and its
  eleven siblings were filed as `cve` rows carrying their own invented string
  in `cve_id` — inheriting KEV lookups, EPSS scores, CVSS bands and an NVD link
  that resolves to nothing. `ck_vuln_def_cve_id_matches_type` could not catch
  it, because the row *did* carry a `cve_id`, just not a real one. The write
  path now calls `definition_type_for_id`, and `_enrich_findings_with_intel`
  skips anything that is not a real CVE.

- **`cve_id` is `varchar(30)` and the catalogue insert is not inside a
  try/except.** So a fabricated identifier longer than thirty characters raised
  `StringDataRightTruncation` and **aborted the finding sync for the whole
  scan**. All three `MISC-CREDENTIALED-*` markers are over the limit (33, 37,
  39) and so are most Nuclei template ids —
  `MISC-NUCLEI-WORDPRESS-DIRECTORY-LISTING` is 39. Minted identifiers go in
  `id`, which is `varchar(120)`, and `cve_id` stays NULL, so the limit no
  longer applies. Do not put a non-CVE string in `cve_id`.

- **A real CVE stays a real CVE.** Heartbleed, Shellshock and EternalBlue keep
  their published identifiers, `definition_type = cve`, their NVD links and
  their KEV and EPSS enrichment, because all of it means something for them.
  `NetworkCheck` refuses a `cve_id` that is not well-formed at construction.

- **Two probes that detect one condition emit one identifier.**
  `default_creds` and `ftp_checker` both test anonymous FTP; both report
  `ftp.anonymous_login`, so `deduplicate_cves` collapses them. Promoting the
  second without matching the first would have started showing the reader the
  same problem twice.

- **`detection_method` must be `active_check`.** It maps to
  `DetectionMethod.CONFIG_CHECK` — QoD 99, Confirmed — and is in the
  normalizer's `AUTHORITATIVE` set, which lets the finding bypass the CPE
  version-range test. These checks observed the condition rather than inferring
  it from a version, so there is no version to range-check and anything else
  would be withheld as unverified.

- **Three detections are deliberately not promoted**, each because it would
  fire on ordinary hosts. They stay in the metadata, so no existing report
  changes:
  - **`smb_probe.null_session`** is the negotiate response's NT status being
    zero — STATUS_SUCCESS, which every reachable SMB server returns. Nothing
    attempts a session setup with an empty username.
  - **`http.admin_interface_exposed`** matches on path plus a 200/401/403
    status with no body check, and a single-page application answers every
    unknown route with 200 and its index document, so all thirteen fingerprints
    match at once.
  - **SMBv1 as CVE-2017-0144.** EternalBlue needs SMBv1 *and* an unpatched
    implementation. SMBv1 alone is `smb.v1_enabled`; only the MS17-010
    fingerprint claims the CVE. The old companion `CVE-2017-0144-ACTIVE` was a
    CVE-shaped string that is not a CVE.

- **`_http_request` returned an empty body on every request.** It stopped
  reading at `\r\n\r\n` — the end of the *headers* — so directory-listing
  detection tested `"index of /"` against `""` and could never fire, and
  sensitive-path exposure was decided by status code alone. Pass
  `read_body=True` when you need the body; it stays opt-in because HEAD has no
  body and the method probe only needs a status.

- **`http.sensitive_path_exposed` requires a body fingerprint.**
  `_SENSITIVE_PATHS` probes `/login`, `/admin/`, `/dashboard` and `/console`,
  which an SPA answers with 200 — so a status match alone reports four exposed
  files on every SPA, this product's own frontend included.

## Database assessment (`engines/credentialed/database_executor.py`)

Authenticated configuration and privilege assessment of database instances.
Phase 7 of the gap-closure programme, closing GAP-10; tracker in
[`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

**No new engine, and no new finding model.** A database check is an ordinary
Phase 3 `ConfigCheck` with `check_type = database_query` and
`target_platform = database`, run by the same `ConfigAuditEngine`, reaching the
same evidence → finding → risk → remediation → report path. 49 checks across
PostgreSQL, MySQL/MariaDB and Microsoft SQL Server.

- **The whole persistence cost was one CHECK constraint.** `credential_type`
  has admitted `database` since Phase 2 and `compliance_rules` has admitted
  `database_query` and `target_platform = 'database'` since Phase 3's
  `b4c5d6e7f8a9`. Migration `f8a9b0c1d2e3` adds five `transport` values and
  nothing else. That is what the reservations were for — keep making them.

- **Engine targeting reuses `os_match`; do not add a second mechanism.** The
  instance's product string becomes `os_name` and its version
  `os_version_id`, so the Phase 4 targeting written for "Ubuntu 22.04 versus
  RHEL 9" places "PostgreSQL 16 versus MySQL 8" unchanged.

- **`product_name` is not the version banner, and that distinction was load
  bearing.** `SELECT version()` answers `PostgreSQL 16.15 on x86_64…` on
  PostgreSQL but a bare `8.0.46` on MySQL. Targeting on the raw banner made
  **all fifteen MySQL rules NOT_APPLICABLE** — a complete rule set that
  silently never ran, and which looked perfect on PostgreSQL alone. MariaDB is
  labelled separately even though PyMySQL drives it and it normalises to the
  `mysql` engine: its version series is its own, and a "MySQL 8.0 or later"
  rule would read MariaDB 10.11 as ancient.

- **`sslrootcert` is passed explicitly on every PostgreSQL connection, and
  must stay that way.** `Backend/.env` sets `PGSSLROOTCERT` to this
  deployment's private CA for the *application* database; loading config puts
  it in the environment, and libpq applies it to any connection that does not
  set it. Every PostgreSQL **target** was therefore verified against our own CA
  and failed with "certificate verify failed", which reads as a fault on the
  target. Note the asymmetry that hid it: passing `sslmode` explicitly *does*
  override `PGSSLMODE`, so the mode was right and only the trust anchor was
  wrong — and under `prefer` libpq still verifies once a root certificate is
  configured.

- **TLS is preferred, never required, and both halves matter.** Requiring it
  makes the scanner unable to assess a correctly hardened MySQL
  (`require_secure_transport = ON`); refusing to fall back makes it unable to
  assess the instance whose *missing* TLS is the finding most worth reporting.
  PyMySQL has no `prefer` mode, so it is implemented by hand — TLS first, then
  plaintext, and **never a retry after an authentication failure**, which would
  only produce a second identical rejection and a second entry in the server's
  failed-login log.

- **Read-only is enforced in three layers, and every shipped rule is tested
  against the guard.** `assert_read_only` admits one statement beginning
  SELECT/SHOW/WITH/VALUES with comments and literals stripped first; rule
  values are bound parameters, never interpolated; and the session itself is
  opened read-only. A refused statement is UNAVAILABLE → **ERROR**, never a
  verdict — a defect in a rule must not manufacture a finding about a
  customer's database. The guard is also why SQL Server login auditing is
  unassessed: the conventional read is `EXEC xp_instance_regread`, and the
  guard is worth more than the check.

- **An empty result set is the most dangerous value in this package.** A
  hardened instance answers "which accounts have an empty password" with no
  rows; so does a refused query, and so does a catalogue view this engine
  version does not have. Only `QueryResult.ok` separates them, and there is
  deliberately no method that returns a bare list of rows. Reading the rows
  instead reports a clean bill of health for an instance nobody was allowed to
  inspect.

- **Four error types, and they must stay four.** A refused password, an
  authenticated account without the privilege, nothing listening, and a driver
  that is not installed need four different actions. Two collapses were found
  and fixed: an ordinary SQL error on a *healthy* session was reported as an
  unreachable database (the classifier's fallback is now context-dependent —
  only a positive connectivity match becomes a transport error), and
  PostgreSQL's `no pg_hba.conf entry` was reported as a connection failure when
  the instance had answered and declined.

- **Findings mint `CCURE-CFG-…`, including the privilege and grant rules.**
  `privilege_check` was considered and rejected: it files under the report
  family "Local Privilege", and an over-granted role on a remote database
  server is not a local privilege-escalation condition on the scanning host.

- **Dispatch adds no route and no task.** `run_credentialed_scan_task` branches
  on the credential's type and calls `audit_database_target`. So
  `POST /scan/credentialed` and `core/scheduling/dispatcher.py` are unchanged,
  and a recurring database audit works today through the existing
  `credentialed` schedule kind. `SCAN_KIND_DATABASE` stays reserved.

- **A database target is excluded from the asset-registry sync, deliberately.**
  Both sync helpers write an OS, a package inventory and a MAC-based identity
  onto an `Asset` row. Letting a database audit through would overwrite the
  record of the machine hosting it with an audit that never looked at the
  machine.

- **`coverage.scope` says what was not assessed.** A database audit examines
  the instance's configuration and says nothing about the operating system
  underneath it. A report that does not say so reads as a complete audit of the
  machine.

### Content, and the false positives real targets caught

**No CIS Benchmark content here either** — same licensing position as Phase 4.
These are CCURE-authored rules written from vendor documentation, and every
statement was run against a live instance before its rule was written. Five
conditions were dropped or rescoped because they are *stock defaults* and a
check that fires on every host is worse than one that misses:

| Would have reported                            | Reality                                            |
| ---------------------------------------------- | -------------------------------------------------- |
| PUBLIC holds CONNECT on `postgres`/`template0`  | The default on every PostgreSQL installation       |
| `trust` on `local` and `127.0.0.1`             | The postgres image default; how `docker exec psql` works |
| `guest` holds CONNECT in SQL Server             | Mandatory in `master`; cannot be revoked there     |
| `BUILTIN\*` and `NT AUTHORITY\*` are sysadmin   | Provisioned by SQL Server itself                   |
| `VIEW ANY DATABASE` granted to `public`         | A default grant on every instance                  |

Two more worth knowing:

- **`information_schema.user_privileges` returns 132 `is_grantable` rows on a
  stock MySQL**, all root's. That measurement is why `db.priv.grant_option` is
  excluded from the coverage denominator rather than implemented badly.
- **`secure_file_priv` inverted its own verdict.** `not_empty` treats SQL NULL
  as empty, and NULL is the *most* hardened state — file access disabled
  outright. A locked-down instance and a wide-open one (`''`) failed
  identically until NULL was folded to a token first.

Three PostgreSQL rules also read `pg_hba_file_rules` with overlapping
predicates, so one permissive line produced three findings and made the
remediation look three times larger than it was.

**Version-currency boundaries have a shelf life and say so.** PostgreSQL 14,
MySQL 8.0 and SQL Server 2017 were the oldest supported releases as at
29 August 2026; each rule states that date and links the vendor's lifecycle
page.

### Test targets

Disposable containers only. Credentials are generated at run time and
destroyed with the container — never in source, configuration, logs, Celery
arguments or git.

```powershell
docker run -d --name ccure-pg-target    -p 127.0.0.1:15432:5432 -e POSTGRES_PASSWORD=... postgres:16-alpine
docker run -d --name ccure-mysql-target -p 127.0.0.1:13306:3306 -e MYSQL_ROOT_PASSWORD=... mysql:8.0
docker run -d --name ccure-mssql-target -p 127.0.0.1:11433:1433 -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD=... mcr.microsoft.com/mssql/server:2022-latest
```

Measured weak → hardened: PostgreSQL **12 → 0**, MySQL **11 → 0**, SQL Server
**12 → 0**. A run returning zero against a *weakened* instance is a regression,
not a clean database.

Two things that cost time and will again:

- **`mysqladmin ping` succeeds against MySQL's temporary init server**, which
  then shuts down before the real one starts. Wait for
  `ready for connections.*port: 3306` in the container log; `port: 0` is the
  temporary server.
- **SQL Server on Linux refuses to start if it cannot read its TLS
  certificate**, and `/etc/ssl/private` is not traversable by the `mssql` user.
  Put the certificate and key under `/var/opt/mssql/`. `xp_cmdshell` and OLE
  Automation are also unsupported on Linux, so the dangerous-features rule is
  exercised through `clr enabled`, `cross db ownership chaining` and
  `Ad Hoc Distributed Queries`.

### Coverage

`scripts/measure_database_coverage.py`, denominator frozen at 31 areas before
implementation and including **eight areas this build does not implement**,
each with a recorded reason. **0% → 74.2%** (23/31), implemented *and* tested.
Engine breadth is reported separately and never folded in: an area answered on
one engine is implemented, and answering it on three does not make it three
areas.

**Oracle and MongoDB are reserved, not shipped.** Drivers exist for both
(`oracledb` thin mode needs no Instant Client), and the transport vocabulary
names them so the phase that adds them adds a collector rather than a
migration. Neither could be stood up as a disposable target here, so neither
was validated, and `USABLE_TRANSPORTS` stops the API creating such a
credential.

## Deep TLS on the network path

`engines/vulnerability/plugins/tls_scanner.py` runs the **existing** sslyze
wrapper (`core/web/sslyze/wrapper.py`), which had driven full TLS audits on the
`/web-scans` path since before Phase 6 while the main network scan got a
140-line socket probe. There is one TLS engine; do not add a second.

- **`tls_scanner` used `log` and never imported it.** Four exception handlers
  called `log.debug(...)`, so any TLS error path raised `NameError` *inside the
  except block*, and `VulnerabilityEngine` catches plugin exceptions at DEBUG.
  Same failure mode as `nuclei_probe`'s arity, reached from the other side.

- **It assessed only the first TLS port.** `for port in _TLS_PORTS: if port in
  open_ports: … return`. A host serving 443 and 8443 was assessed on 443 alone.
  It now assesses every endpoint, and `_PORT_MAP` names the same ports the
  plugin does — a port in one list and not the other means the plugin is never
  selected for a host exposing only that port.

- **`"VULNERABLE" in robot_enum.name` matched `NOT_VULNERABLE_NO_ORACLE`.**
  sslyze's ROBOT enum has five members and the substring test passed three of
  them, so **every server sslyze positively cleared was reported vulnerable**,
  including any TLS 1.3-only listener where RSA key exchange does not exist.
  It is `startswith("VULNERABLE_")` now, and `UNKNOWN_INCONSISTENT_RESULTS` is
  deliberately not a finding — "could not determine" is not a verdict.

- **The handshake and the deep engine see different things, and both are
  needed.** A single handshake reports the suite it negotiated, which on a
  modern client is the *strongest* the server offers; every weak suite the
  server would also accept is invisible to it. Measured on a deliberately weak
  listener: negotiated `ECDHE-RSA-AES256-GCM-SHA384` while the deep engine
  found three weak suites across TLS 1.0, 1.1 and 1.2. The socket probe is kept
  because it is fast and produces the `TLSInfo` shape `asset_syncer` and
  `core/risk.py` already read.

- **Deep assessment is bounded.** It enumerates cipher suites across six
  protocol versions, so it costs many handshakes per endpoint where the socket
  probe costs one. `TLS_DEEP_MAX_ENDPOINTS` (4) and `TLS_DEEP_SCAN` exist
  because this product scans OT segments. Measured at 2.2s per endpoint.

- **STARTTLS is reached through the same wrapper** (Phase 11, GAP-07).
  `STARTTLS_SERVICES` maps six services to their ports — SMTP, IMAP, POP3,
  LDAP, PostgreSQL, FTP — and sslyze performs the negotiation, so no second TLS
  transport exists. The names are looked up against sslyze's own
  `ProtocolWithOpportunisticTlsEnum`, so a service it cannot negotiate is
  impossible to add by mistake: MySQL has no handler in 6.3.1 and is declared
  unimplemented rather than silently producing connection errors.

  **A port in `STARTTLS_SERVICES` must also be in `plugin_selector._PORT_MAP`**,
  or a host exposing only that port never runs the plugin at all. PostgreSQL hit
  exactly this: 5432 already had an entry for `default_creds`, and a second dict
  key for it kept only the last value. A test now asserts selection for every
  port in the table and refuses any duplicate key in the map.

  **A STARTTLS endpoint never becomes `tls_info`.** That key means the first
  *implicit*-TLS endpoint that answered; `asset_syncer` and `core/risk.py` read
  it, and a mail server's certificate appearing there would rewrite an asset's
  TLS identity with something no browser negotiates. They go to
  `tls_endpoints` with a `starttls` marker, and one budget covers both kinds.

- **Three sslyze commands were requested and their results discarded.**
  `TLS_FALLBACK_SCSV` and `SESSION_RENEGOTIATION` since before Phase 6, and
  `path_validation_results` was parsed into a `chain_trusted` boolean nothing
  read. Phase 11 reads them, which is why fourteen findings arrived for very
  little extra time on the wire. Each reading is **tri-state**: True, False, or
  absent because the command did not complete. Every guard is `is True` /
  `is False`, never truthiness — an absent command has established nothing, and
  reading it either way invents a verdict.

- **Classify a public key by type, not by class name.** `_describe_public_key`
  tested `"EllipticCurve" in type(key).__name__`; this build of `cryptography`
  returns `ECPublicKey`, so every EC certificate went unclassified and the
  key-strength check was silently withheld for the whole algorithm. It is
  `isinstance` against the abstract types now. An algorithm it does not
  recognise returns `{}` and the check is withheld rather than compared against
  the wrong floor.

- **`/web-scans` output is deliberately unchanged.** The wrapper's own
  `findings` list was not extended; that path renders it and altering an
  existing report was not Phase 11's business. The network path builds its own
  findings from the structured data the wrapper now returns.

- **`tls_info` keeps its meaning** — the first TLS endpoint that answered.
  `tls_endpoints` is additive and carries the rest. Nothing downstream should
  change because a host happens to expose a second TLS port.

### Active template verification (Nuclei)

`engines/vulnerability/plugins/nuclei_probe.py` runs ProjectDiscovery's
templates and produces the only findings in this product that are *proven*
rather than inferred — a template matched a live response, so the
vulnerability is present and reachable now. They grade as `active_check` →
`CONFIG_CHECK`, QoD 99, Confirmed.

A template with no CVE now mints `CCURE-CHK-NUCLEI-<template>` rather than
`MISC-NUCLEI-<template>` — see the network-checks section above for why the
old form aborted the finding sync outright on any template id over eighteen
characters.

Binary and templates are located via `NUCLEI_BINARY` and
`NUCLEI_TEMPLATES`; the defaults are `nuclei` on PATH and
`~/nuclei-templates`. This repository is shared, so no absolute path is
hardcoded — a machine-specific default silently disables the plugin for
everyone else. ~13,510 templates when fully installed.
and logs it; an unavailable optional probe is a coverage gap, not an error.

Four things measured the hard way, all of which produced *zero findings*
before they were fixed:

- **Serial plugins are called with three arguments** (`ip, open_ports,
  port_details`). A two-argument `run` raises TypeError, the engine catches
  plugin exceptions at debug level, and the plugin looks registered while
  never executing.
- **Do not allow-list web ports.** An allow-list gave a web server on 8099
  only a bare `host:port` target, so the HTTP templates — most of the corpus —
  never engaged. Everything not in `_NON_HTTP_PORTS` now gets a URL target too.
- **Do not run the full corpus.** 13,510 templates exceeded 600s against one
  host and returned nothing, which reads as "verified, nothing found". Default
  is `critical,high,medium` (7,460 templates); most of the excluded mass is
  `info`, which is technology *detection*, and grading "nginx present" as
  Confirmed at QoD 99 would bury the real findings.
- **`-exclude-tags dos,fuzz,intrusive,brute-force` and `-no-interactsh` are
  not optional.** This scans production and OT hosts: an audit that causes an
  outage is worse than the finding it would have produced, and out-of-band
  callbacks leak target identity off-site and need egress OT segments lack.

Measured: 129s for one web port, 289s for three ports at `critical,high`.
Nuclei ships overlapping templates, so one exposed `.env` legitimately matches
`generic-env`, `laravel-env` and `codeigniter-env` — three rows for one
problem. They are not false positives; the file really is exposed.

### Test targets

Two disposable containers exist for validating credentialed collection. Both
are deliberately **not** updated after build — an up-to-date target cannot tell
"matching works and the host is clean" apart from "matching is broken", which
is how five separate false negatives survived until they were scanned.

```powershell
docker start ccure-rocky-target    # Rocky 9.8,  ssh 127.0.0.1:2222  root / ccure-test-only
docker start ccure-ubuntu-target   # Ubuntu 24.04, ssh 127.0.0.1:2223  root / ccure-test-only
docker start ccure-nuclei-target   # nginx on 127.0.0.1:8099 serving .env and .git/config
```

`ccure-nuclei-target` exists because neither real host triggers a Nuclei
template — 10.180.6.14 is a Windows workstation with no web server, and a
scanner that finds nothing there looks identical to one that is broken. It
serves a deliberately exposed `.env` and `.git/config`, which must produce
**4 findings, all Confirmed at QoD 99**. Zero from it is a regression.

Expected at the time of writing: Rocky 48 findings (4 Critical), Ubuntu 7 (all
with no fix published upstream). A run returning **zero** on either is a
regression, not a clean host.

### Coverage figures

`VulnMatcher.coverage()` reports two percentages and they answer different
questions. `coverage_pct` is over every collected package;
`coverage_pct_software` excludes toolchain components — SDK headers, `vs_*`
resource MSIs, IntelliSense metadata — which NVD publishes no CPE for because
none is independently vulnerable. On a real Windows host 98 of 191 packages
are such components, so the unfiltered figure understates coverage as badly as
counting them assessed would overstate it. Keep reporting both.

### Windows assessment

Windows is absent from the uninstall registry, so package matching never saw
the OS. `engines/credentialed/windows_patch.py` compares the host's build
against MSRC's published fixed builds instead.

- **Do not match on installed KBs.** `Get-HotFix` returned **4 entries** on a
  fully patched host — cumulative updates supersede one another, so the KB that
  first fixed a CVE is never present. Build comparison is the only reliable
  primitive.
- The collector must supply the **UBR**. `Win32_OperatingSystem.Version` stops
  at `10.0.26200` and omits the revision; without it every host looks like the
  day-zero release. `windows_collector` reads it from the registry and folds it
  into `os_version_id`.
- **Compare only within the host's own build line.** Microsoft lists one
  product against several lines — Windows 11 25H2 carries both `10.0.26100.x`
  and `10.0.26200.x` fixes. Taking the earliest fix across lines picks a
  `26100` build a `26200` host exceeds, silently dismissing real findings. This
  reported 19 missing patches where the truth was 736.
- A build line that maps to no product is reported as **not assessed**, never
  as "no missing patches".

## Policy Compliance Engine

The engine is an orchestration layer over the existing scan modules, not a
scanner: `core/compliance_evidence.py` adapts each module's output into a
normalised payload, `core/compliance_tasks.py` evaluates rules against it, and
both machine verdicts and human attestations land in one finding model.

Six things that were wrong for a long time and must not be reintroduced:

- **A rule resolves to a control *within the scan's framework*.** Rules are
  deliberately crosswalked across standards, so `.first()` on
  `compliance_rule_controls` has no defined answer — measured on the shipped
  catalogue, 57 of the 114 rules in the ISO default policy resolved to a
  control belonging to a *different* framework, so an ISO scan wrote half its
  findings onto DPDP, GDPR and IEC 62443 and ISO itself scored as unassessed.
  Use `resolve_controls_for_rule(db, rule_id, framework_id)`, which is ordered
  and returns *every* matching control. There is no fallback control; a rule
  that maps to nothing in this framework is skipped.

- **Every status rollup goes through `roll_up_statuses()`.** Four call sites
  each built `{f.control_id: f for f in findings}` — an unordered dict
  comprehension in which the last row won — so a control carrying twelve rules
  reported whichever verdict the database happened to return last. A host with
  SSH closed and SMB open could score `pass` on a control covering both.
  `RolledFinding` / `rolled_up_control_findings()` in the router exist so report
  generators get the rolled-up verdict without changing their `.status` access.

- **An attestation outranks the engine's own placeholder.** The scan writes one
  org-level `manual_review` finding per manual control, at
  `org_finding_id_for(org, control)`; the attestation endpoint writes to that
  same id. They used to be different ids *and* `manual_review` outranked `pass`
  in the rollup, so attesting a control never moved the score — which disabled
  63 of ISO 27001's 93 controls.

- **A rule's evidence key must be one the adapter actually emits.**
  `tests/compliance/test_compliance_rule_wiring.py` asserts this statically and would have
  caught the two defects it exists for: 35 rules named `auto_scan`, an evidence
  source with no adapter, and 14 more read `offline_configuration` keys that
  were computed and then left out of the return dict. Between them, 49 of 79
  rules could never produce a pass or a fail. When adding an adapter key, put it
  in the returned dict *literal* — the guard reads the key surface statically —
  and drop `None` values at the end so uncollected keys become `manual_review`.

- **Never synthesise evidence.** `attrs["password_policy"]` was a hard-coded
  `{complexity: True, history_length: 24, min_length: 14}` written for every
  host, so any rule reading it passed unconditionally everywhere. It is
  collected now (`net accounts` on Windows, login.defs + pwquality + the PAM
  stack on Linux) and keys that could not be read are omitted, which the engine
  renders as not assessed. The Windows parser matches on labels, not line
  position — an earlier positional version silently reported one setting's
  number as another's when a line was missing.

- **`credential_validation` is a credentialed source.** It belongs in
  `CREDENTIALED_EVIDENCE_SOURCES` with the other three. Without it, a host the
  scanner could not authenticate to reported ISO A.8.2 as *failed* rather than
  unassessed.

Scheduling: `compliance_scan_schedules` is driven by
`compliance.run_scheduled_scans` on beat every 60s. That task passed
`created_at=` to `ComplianceScanRun` before the column existed, so it raised
`TypeError` on every tick, was swallowed by a bare `except`, and reported
`success: False` — no scheduled scan had ever run. The CRUD endpoints under
`/compliance/schedules` did not exist either.

**The `compliance` queue needs a consumer.** The only container subscribed to
it sits behind the `container-scanner` profile and is not started here, so beat
was publishing 1,440 messages a day into a queue nothing read.
`start_host_scanner_worker.ps1` now subscribes to `scanner,default,compliance`.
If you see the queue growing, that worker is not running.

Seeding: `python -m scripts.seed_compliance` globs `*_controls_seed.json`
rather than naming files — two frameworks existed as seed files and were never
loaded. `scripts/enrich_iso27001_seed.py` owns the ISO Annex A descriptions,
evidence checklists and crosswalks; edit the enrichment table there, not the
generated JSON. `scripts/seed_real_rules.py` generates a manual attestation
placeholder for every control that has no explicit rule — the membership test
must normalise dotted vs underscored control ids, or every control gets a
placeholder including the ones that are fully automated.

### ISO/IEC 27001:2022

`scripts/enrich_iso27001_seed.py` owns the Annex A descriptions, evidence
checklists, crosswalks, scannability and module hints; edit the tables there,
never the generated JSON.

Four things that were wrong and are now guarded by
`tests/compliance/test_compliance_iso27001.py`:

- **An `archived` rule with no successor is a control switched off by
  accident.** `run_scan_task` evaluates `active` only, which is right — but 24
  of the 93 had a single rule and it was archived, so they produced no finding
  on any run, never reached the reviewer's findings queue, and the SoA printed
  them as "Not assessed": A.5.1, A.5.2, A.5.24, A.5.26, A.5.29, A.5.35, A.5.36
  among them. They stayed attestable the whole time, which is why it looked
  cosmetic. The seeder converges its own placeholders now;
  `scripts/cleanup_iso27001.py` reports and repairs anything it cannot reach.

- **`semi_auto` is a claim of automation.** Eighteen controls carried it with no
  automated rule at all. The register, the coverage figures and the SoA's
  scan-mode column all read it as partial automation.
  `test_scannability_only_claims_automation_that_exists` covers `semi_auto` as
  well as `auto`, and a `scan_module_hint` is set only where something runs.

- **Four controls could already be answered** and simply were not wired:
  A.5.18 ← `account_review_completed`, A.8.13 ← `backup_frequency_days`,
  A.8.18 ← `uac_enabled`, A.8.1 ← `session_timeout_minutes`. When a control
  gains a real check its old attestation placeholder must be *unlinked* —
  `manual_review` outranks `pass`, so leaving it suppresses the verdict the new
  check produces. A.8.13 and A.8.18 landed in that state immediately.

- **A crosswalk must name an id the target catalogue actually uses.** Thirteen
  did not: `GDPR:5-1` against an id of `GDPR_5_1`, `DPDP_2023:1-1` against
  `DPDP_1_1`, `CERT_IN_2022:IR-1` against `cert_in_ir_1`, `IEC_62443:SR 5.1`
  against `SR-5.1`. Each silently resolved to nothing in gap analysis and in
  cross-framework rule inheritance.

**ISO automation is NIST's automation.** `AUTOMATED_ISO_CONTROLS` in
`core/nist_csf_catalogue.py` is the list of Annex A controls carrying a real
check, and NIST CSF derives its own `scannability` from it. Wiring a new ISO
rule therefore means adding that control there and regenerating the CSF seed,
or NIST is left claiming `manual` for a Subcategory that now inherits an
automated rule. A.8.13 did exactly that to PR.DS-11 and RC.RP-03.

### Only two frameworks are switched on

Thirteen catalogues ship. Eleven are **parked** while ISO/IEC 27001:2022 and
NIST CSF 2.0 are finished: still seeded, still crosswalk-reachable, but not
offered, not scannable, not reportable and not installable.
`core/compliance_frameworks.py` is the list, overridable with
`COMPLIANCE_ACTIVE_FRAMEWORKS`. Turning one back on is one entry there plus
`python -m scripts.set_active_frameworks --apply`.

- **Parking is never a data decision.** Do not delete or un-seed a parked
  catalogue. `main.py`'s bootstrap condition names all thirteen, so a missing
  seed file makes it permanently true and the whole seeder runs on every
  container start without ever satisfying itself. The parked catalogues are
  also the *targets* of ISO's and NIST's crosswalks, which
  `/compliance/gap-analysis` and the rule mapper both read.

- **`ComplianceFramework.is_active` is a trap.** It is set at seed time and read
  by no query anywhere, so setting it looks like it worked and changes nothing.
  `tests/compliance/test_framework_activation.py` fails if anything starts reading it.

- **Two layers, both needed.** `ComplianceTenantFramework.is_enabled` already
  gated the register, policies, scans, findings, attestation, evidence,
  schedules and the dashboard. It did not gate **any** of the thirteen report
  endpoints — `/compliance/reports/nis2` rendered a full PDF for a framework no
  tenant had installed — and it could not stop a tenant admin re-installing
  from the marketplace. `require_active_framework()` covers both, answering 403
  for a parked catalogue and 404 only for one that does not exist.

- **The scheduler is the only path that starts a scan without a request**, and
  it checked neither the installation list nor the tenant flag.
  `POST /compliance/schedules` requires the framework to be enabled *at the
  moment the schedule is created*; nothing re-checked it afterwards, so a
  framework uninstalled or parked later kept being scanned every five minutes
  on beat. `run_scheduled_scans` now checks both.

- **`compliance.run_reverify` checks the framework itself**, though nothing can
  currently hand it a parked one — it is reachable only from
  `run_reremediation_task`, itself reachable only from the two remediation
  endpoints, and both refuse a framework the tenant has not enabled. That is a
  property of the call chain, not of the function: it takes a finding id and
  writes a verdict, so a caller added later would rewrite a parked framework's
  finding with no check anywhere in between. It refuses without touching the
  finding or writing a history row.

- **Listing endpoints outlive their framework.** `/compliance/scans`,
  `/compliance/scans/{id}` and `/compliance/schedules` were tenant-scoped only,
  so a run or schedule for a parked framework stayed visible with a score the
  workspace can no longer open. All three are scoped to the active list now.

- **A parked framework's tests still run.** They activate themselves with the
  `activate_frameworks` fixture rather than the session switching everything
  on, so the parked path stays exercised and the parked suites do not rot.

### NIST CSF 2.0

`core/nist_csf_catalogue.py` is the catalogue — six Functions, 22 Categories,
106 Subcategories — and `scripts/enrich_nist_csf_v2_seed.py` renders it into
`nist_csf_v2_controls_seed.json`. Edit the core module, never the JSON;
`tests/compliance/test_nist_csf_v2_framework_integration.py` fails if they diverge.

Six things that were wrong and must not come back:

- **Count the distribution, not the total.** The catalogue had exactly 106 rows
  and the wrong ones: `RS.AN-08` was missing and `RC.RP-07` was invented, so
  Respond carried 12 against the standard's 13 and Recover 9 against 8. The two
  errors cancelled and 106 looked correct. The real shape is
  GV 31 / ID 21 / PR 22 / DE 11 / RS 13 / RC 8, and the per-Category counts are
  asserted too.

- **`PR.AC-*`, `PR.PT-*`, `PR.IP-*`, `ID.SC-*`, `DE.CM-04`, `RS.RP-01` are CSF
  1.1.** CSF 2.0 renamed or re-homed all of them — identity moved to `PR.AA`,
  supply chain to the new `GV.SC`. 102 of the 693 references other frameworks make
  named 1.1 identifiers, which resolve to control ids that do not exist, so the
  NIS 2 rule mapper inherited nothing and `/compliance/gap-analysis` computed
  coverage over crosswalks that could never match — 40 of PCI-DSS's 62 CSF
  references were dangling. `scripts/fix_csf_11_crosswalks.py --check` is the
  guard; the mapping table lives in it.

- **`scannability` is derived, never asserted.** A Subcategory is `auto` exactly
  when its crosswalk reaches an ISO control carrying a rule wired to a real
  adapter key (`AUTOMATED_ISO_CONTROLS`). Twelve claimed `auto` against modules
  that do not exist — `sast_dast_scan`, `ha_failover_check`, `app_locker_scan`,
  `ir_triage_matrix` — and five claimed `manual` while inheriting automated
  rules through a crosswalk that had no business carrying them: `ID.AM-07`,
  "inventories of data are maintained", was answered by A.8.8's
  critical-vulnerability count.

- **"Already mapped" must be read from the links that exist, not the ones this
  run inserted.** The flag was set inside `if not n_link:`, so on any second run
  every link already existed, nothing set it, and all 106 Subcategories were
  handed an attestation placeholder — including the 27 with real automated
  checks, which `manual_review` then suppressed in the rollup. It was
  progressive rather than one-off because `main.py`'s bootstrap condition
  (`soc2_ctrl_count < 61` against a 55-control catalogue) was true on every
  container start, so the seeder ran on every restart.

- **Only rules that evaluate something cross a crosswalk.** Inheriting another
  framework's *manual* placeholders satisfied the mapped test with a rule that
  checks nothing, put ISO's control title into the remediation text a NIST
  reviewer reads, and leaked 20 NIST placeholders onto NIS 2 controls.

- **CSF order is not alphabetical.** `ORDER BY theme, control_number` opens the
  report on Detect and runs Govern as OC, OV, PO, RM, RR, SC; NIST publishes
  GV, ID, PR, DE, RS, RC and OC, RM, RR, PO, OV, SC. `core/nist_csf.py` holds
  the sequence and `control_sort_key` consults it first.

`run_scan_task` evaluates `active` rules only, which is right — but an
`archived` rule with a NULL `superseded_by_rule_id` is not a lifecycle state,
it is a control switched off by accident, and five Subcategories' *only* rule
was in it. The seeder now reactivates the placeholders it owns.
`scripts/cleanup_nist_csf_v2.py` reports the same condition for every other
framework, where roughly 700 such links remain and are **not** repaired.

`scripts/cleanup_nist_csf_v2.py` (dry run by default, `--apply` to write)
removes Subcategories the standard does not define, placeholders sharing a
Subcategory with an automated rule, and NIST placeholders linked outside NIST
CSF. `seed_compliance.py` only upserts, so a catalogue correction that *removes*
a control needs it.

**The Statement of Applicability is framework-scoped.** ISO/IEC 27001:2022
clause 6.1.3(d) requires applicability, justification for inclusion,
implementation status and justification for exclusion per control; the export
carried none of the four and emitted every installed framework's controls under
an ISO title. `/compliance/reports/soa` takes `framework_id`, sorts numerically
via `control_sort_key` (a string sort gives A.5.1, A.5.10, A.5.11 … A.5.2), and
renders an approval block.

`python-docx` is a real dependency. It was absent from `requirements.txt` while
every `_generate_*_docx` path guarded on the import, so a DOCX request either
returned a PDF or downloaded a 29-byte file reading "python-docx is not
installed."

## File uploads

Exactly **two** endpoints accept a file, and both go through
`core/upload_guard.py`: `POST /compliance/controls/{id}/evidence` and
`POST /assets/import-amt`. A third surface *looks* like an upload and is not —
the scan target list on `NewScan.jsx` is parsed by `FileReader` in the browser
and only the extracted target strings are POSTed, which
`validate_scan_targets()` re-validates from scratch. Guards there are UX, not a
boundary.

Keep the shared primitives shared. The two endpoints previously carried
different and differently incomplete versions of the same three checks, which
is the shape every finding in the August 2026 upload audit took.

- **The declared `Content-Type` is attacker-controlled.** `UploadFile.content_type`
  is the string from the multipart part header and nothing more. The evidence
  whitelist used to be satisfied by that string alone, so `malware.exe` renamed
  to `malware.pdf` was accepted as a PDF. `assert_content_matches()` checks the
  payload's own signature. There is deliberately **no `python-magic` or
  `filetype` dependency** — libmagic is not in the API image, and ten formats
  with stable signatures is a table a reviewer can read.

- **Text has no magic number**, so `text/plain` and `text/csv` are confirmed by
  *exclusion*: must decode as UTF-8, must carry no NUL or C0 control bytes. Get
  this backwards and declaring `text/plain` becomes an unconditional bypass of
  the whole whitelist — a PE fails on its first NUL.

- **OOXML is a ZIP, and archives are excluded from the whitelist on purpose.**
  A bare ZIP renamed `.docx` has exactly OOXML's magic bytes. `_looks_like_ooxml()`
  requires `[Content_Types].xml` in the central directory. Only the directory is
  read, so a zip bomb costs the directory parse and nothing more.

- **Never build `Content-Disposition` with an f-string.** The filename is
  user-supplied and reaches a response header. `os.path.basename()` is not
  sanitisation: the API runs on Linux, where `\` is not a separator, and it
  strips neither quotes nor control characters. Use `content_disposition()`,
  which emits RFC 6266 — an ASCII `filename=` plus an RFC 5987 `filename*=`.

- **Read with a cap, never `read()`.** `file.file.read()` on the AMT import was
  unbounded, so the endpoint's per-request memory budget was whatever host
  nginx allowed through — 50 MB, JSON-amplified, on a sync endpoint holding a
  threadpool worker. `read_capped()` / `read_capped_async()` read MAX + 1 and
  test for overflow, which never allocates past the limit and cannot be lied to
  by a declared `Content-Length`.

- **Validate before you destroy.** `import-amt` is an overwrite: it deleted the
  organisation's entire AMT inventory *before* discovering whether any record
  carried a usable MAC. A file that parsed as JSON but used the wrong field
  names — `macAddress1`, or an export from another tool — wiped the inventory
  and returned `{"success": true, "records_imported": 0}`. The unique-record set
  is now built first and an import that would leave nothing is refused. Do not
  reorder these.

- **`{"data": ...}` is not necessarily a list.** `{"data": {...}}` and
  `{"data": "text"}` both satisfied the structure check; iterating either
  yielded dict keys or single characters and `item.get()` raised
  `AttributeError` outside any handler — a 500 for the wrong file. The
  `isinstance(records, list)` check is load-bearing.

- **A per-file cap bounds one request, not a loop of them.** Evidence has a
  25 MB per-file limit *and* a per-tenant quota
  (`COMPLIANCE_EVIDENCE_TENANT_QUOTA_BYTES`, default 2 GiB), because
  `compliance:attest` was otherwise an unbounded write to the API host's disk.
  Both upload endpoints also carry `@limiter.limit`; `conftest` disables the
  limiter session-wide, so `tests/security/test_upload_validation.py` asserts
  registration in `Limiter._route_limits` rather than exercising a 429.

- **The quota check is a read-modify-write and must stay serialised.**
  SUM → compare → insert spans three statements; two concurrent uploads each
  read the same total, each conclude they fit, and the quota is exceeded.
  `_lock_tenant_evidence_quota()` takes `pg_advisory_xact_lock` keyed on the
  tenant, so the read and the write are one critical section and Postgres
  releases it at COMMIT or ROLLBACK. It is a deliberate no-op on SQLite, which
  serialises writers anyway.

- **Only an explicit `OK` from clamd is `clean`.** A timeout, a dropped
  connection, a reply with no NUL terminator, an `ERROR`, or anything the
  parser does not recognise is `scanner_unavailable`. This is the single most
  important property of `scan_for_malware()`: a scanner failure reported as
  clean is worse than having no scanner, because it launders an unscanned file
  into an audit trail that says it was checked. The NUL is checked *before* the
  content, because a truncated reply ending in "OK" is otherwise read as a
  verdict.

- **Deploying a scanner means requiring it.** `UPLOAD_AV_REQUIRED` defaults to
  on whenever `CLAMAV_HOST` is set. The email domain guard fails open for a
  blocklist that did not load and that is right there — refusing every signup
  is the worse outage. Malware inverts the trade: evidence upload is
  low-frequency, so refusing it while the scanner is down costs a retry,
  whereas storing an unscanned file costs the thing the scan exists for.
  A required scanner that cannot answer raises `MalwareScanUnavailable` → **503**,
  deliberately not the **400** a detection gets: the file is not accused of
  anything. With no `CLAMAV_HOST` there is no scan and no error, and the
  response says `malware_scan: not_configured` — never a silent clean verdict.
  `docker compose --profile av up -d clamav` starts one.

- **`COMPLIANCE_EVIDENCE_DIR` defaults to a development path.** `/app` is the
  API container's mount of `./Backend`, so the default writes real tenant
  evidence into the source tree. It is gitignored, but a production deployment
  should point it at a dedicated backed-up volume outside the repository. The
  test suite redirects it to `tmp_path` via an autouse fixture.

- **Scan then persist, never persist then scan.** Nothing in the evidence
  endpoint touches the disk until every check has passed: read → empty → magic
  bytes → AV scan → quota → *then* the first byte is written. Do not move the
  write earlier for convenience; a refused upload must never be briefly present
  in storage where a backup or an indexer can reach it.

- **Evidence filesystem writes and their database rows must behave as one
  logical unit; any failure after the filesystem write must remove the newly
  written file.** The bytes land before `db.commit()`, so a failure between them
  leaves a file nothing points at — unreachable through the API, and **invisible
  to the quota**, which enforces against `SUM(size_bytes)` over *rows*. Such an
  orphan consumes disk that nothing accounts for, nothing reclaims, and no
  figure in the system ever shows. Row construction, `db.add` and `db.commit`
  are therefore wrapped: the handler rolls back, unlinks, and re-raises, so the
  end state is always file-and-row or neither. If the unlink itself fails the
  path is logged and the original error still propagates — masking it to report
  a cleanup failure would be worse.

  `test_failed_commit_leaves_no_orphaned_file` covers it, and **its injection
  point is load-bearing**. Patching `ComplianceEvidenceFile` — the obvious lever
  — detonates in the quota query *above* the write, so the file is never created
  and the test passes having exercised nothing. It patches `sanitize_filename`,
  which has one call site, inside the row constructor. The test also captures
  the evidence directory's *contents* at the moment of failure to prove the
  write actually happened first: "no file at the end" is equally consistent with
  "never written". Capture the bytes, not the `Path` — by assertion time the
  cleanup has unlinked it.

Downloads stream with `FileResponse`. The evidence download used to `fh.read()`
the whole file into a `Response`.

The AMT replacement is **atomic**: the DELETE and the INSERTs share one
transaction with a single `db.commit()` at the end, so a failure partway
through leaves the old inventory intact. Validating before the delete (above)
is necessary but not sufficient on its own — both properties are needed, and
`test_amt_import_replacement_is_atomic` proves the second by detonating an
insert. Field values are also bounded by `_amt_text`/`_amt_int` before they
reach the columns: the byte and record caps bound the file, not a single
megabyte-long `asset_name`, which used to reach Postgres and return a
DataError as an unhandled 500.

## Audit-log retention (phase 6a)

**Retention is installed but disabled, and that is the shipped state.**
`AUDIT_LOG_RETENTION_DAYS` is `0`; nothing purges anything until a period is
agreed with the business or compliance owner. ISO 27001 A.5.33 and A.8.15
require a *defined* period and do not supply one, so choosing a number in code
would be inventing a compliance position. `AUDIT_RETENTION_MIN_DAYS` (90) is a
floor the same setting cannot lower — "9" for "90" is not a recoverable typo.

**Legacy rows only.** Phase 6a removes rows with `record_hash IS NULL`, written
before the tamper-evidence chain existed. Nothing can ever link to one:
`prev_hash` references a `record_hash` value and a legacy row has none, so
removing them cannot break a chain *for any dataset*, past or future. That is
structural, not a property of the current data. Chained-record deletion is
phase 6b and needs its own approval.

**`audit_logs` is HASH partitioned on `org_id`, so partition-drop retention is
impossible.** There is no time-based partition to detach; retention is
row-level `DELETE`, batched.

**The privileged half is a second DBA bootstrap**,
`scripts/audit/bootstrap_chain_retention.sql`, run as a superuser exactly like
`bootstrap_chain.sql`. It creates the `audit_maintenance` role (NOLOGIN,
deliberately **not** `audit_chain_writer` — separation of duties between the
role that computes hashes and the role that can delete rows), the
`audit_retention` schema owned by it, the anchor and hold tables, and
`audit_retention.purge_legacy_v1`. Verify with
`scripts/audit/verify_retention_bootstrap.py`. Without it every retention path
reports "not installed" and refuses, which is the safe direction.

**The function is the boundary; the trigger is defence in depth.** `ccure_user`
may EXECUTE `purge_legacy_v1` — the Celery task has to — but cannot alter it,
cannot drop it (it does not own the schema), and is not a member of
`audit_maintenance`. Every precondition lives inside the function where the
caller cannot reach it, and the Python checks in `core/audit_retention.py` are
duplicates for a better error message, never the control.

**The append-only trigger's DELETE escape has two conditions and both matter.**
`current_user = 'audit_maintenance'` is true only inside the SECURITY DEFINER
function. `OLD.record_hash IS NULL` is the phase boundary *as a database
constraint*: during 6a the maintenance role cannot delete a chained row even
through its own function, even if that function's predicate were wrong. Do not
relax either half without the phase-6b approval.

**An anchor is an accounting record, not preserved content.** For a legacy row
there was never any cryptographic continuity to preserve, and no copy of the
event exists anywhere afterwards. Never describe a legacy anchor as preserving
deleted audit contents. Phase 6b's chained anchors *do* carry continuity
evidence and will require an archive artefact.

**The anchor is written before the delete, in the same transaction.** So an
anchor without its deletion is impossible and a deletion without its anchor is
impossible. One transaction **per batch**, never per run: the purge holds the
organisation's chain-head `FOR UPDATE` lock for a batch, and for as long as it
does, no audit event can be written for that tenant.

**An unaccounted deletion is detectable, and that is what the accounting buys.**
`audit_chain_note_legacy_purge_v1` decrements `legacy_event_count` in the same
transaction as the deletion, and nothing else can reach the head. So a
privileged out-of-band removal leaves the head *ahead* of the surviving rows,
and `verify_chain.py` reports it as a break. The check is **directional**: a
head *behind* the row count means rows were inserted with the chain trigger
disabled — how real pre-chain history and every legacy test fixture come to
exist — and is a note, not a break.

**Retention defers to exports rather than racing them.** The export takes a
shared, **transaction-scoped** advisory lock; the purge takes an exclusive,
**non-blocking** one and skips that organisation until the next run. Never use
session-scoped advisory locks here: they release when the *connection* closes,
and SQLAlchemy pools connections, so one would leak onto the next unrelated
request that drew the same connection.

**No HTTP endpoint deletes an audit row.** `/admin/audit-logs/retention/preview`
is read-only and superadmin-only; execution is beat
(`ccure.tasks.purge_expired_audit_logs`) or
`scripts/audit/purge_audit_retention.py --apply`. Destroying audit history
therefore needs shell access to the host as well as the role.

**Dry run is the default everywhere** and writes nothing at all — no delete, no
anchor, no head update, no audit event. The backup precondition
(`AUDIT_RETENTION_REQUIRE_BACKUP_HOURS`) is deliberately checked only on the
mutating path: a dry run is exactly what an operator does *before* taking a
backup.

`archive_mode` is still `off`, so a purge is recoverable only back to the last
dump. That is why the backup check is a hard refusal rather than a warning.

## Reports

- `GET /reports/download/{scan_id}?fmt=…` — `JSON`/`executive` → executive PDF,
  `XML`/`technical` → technical PDF, `CSV` → host inventory. All PDF; the
  `JSON`/`XML` names are historical.
- Reports are generated at scan completion and stored on
  `scans.report_executive_path` / `report_technical_path`. The download endpoint
  serves the stored file and only regenerates when it is missing — do not make
  generation unconditional again (it orphaned a PDF pair per download and bumped
  `scans.updated_at`, which corrupted the Scan History date).
- No Excel/XLSX export exists in the scan modules. DOCX exists only in
  Compliance.
