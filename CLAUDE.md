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

## Data model notes

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

### Active template verification (Nuclei)

`engines/vulnerability/plugins/nuclei_probe.py` runs ProjectDiscovery's
templates and produces the only findings in this product that are *proven*
rather than inferred — a template matched a live response, so the
vulnerability is present and reachable now. They grade as `active_check` →
`CONFIG_CHECK`, QoD 99, Confirmed.

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
