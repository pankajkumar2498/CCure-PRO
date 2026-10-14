# Phase 10.5 — Production cut-over through the gateway

> **Superseded in part (6 Oct 2026, Phase 9.6c).** Where this document describes HS256 tokens, `JWT_SECRET_KEY`, `CCURE_TOKEN_SIGNING_ALG` or `CCURE_ACCEPT_LEGACY_HS256`, that is **history**: the platform signs and accepts ES256 only and holds no JWT secret. `MFA_ENCRYPTION_KEY` is required and has no fallback. Current state: `CLAUDE.md`, "Token signing keys" and "MFA key".

|                      |                                                                                                                                                                                                                                                                                                                                                                                                                    |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Status**           | **Superseded in part by [10.6](PHASE10_6_HARDENING.md)** (host nginx → gateway now over a unix socket; the bridge address `172.31.254.1` is no longer trusted — §§2, 10 below describe the 10.5 state). **Live since 30 Sep 2026, 11:26:44 IST.** `:443` → host nginx → `api-gateway` → `gateway-auth` → api. Rollback rehearsed live at 11:43:48–11:43:52 (both directions proven). Committed with this document. |
| **Baseline**         | `a4c29f5` (Phase 10.4). The 10.2 design, the 10.1 characterisation and the 10.3/10.4 records remain the source of truth for behaviour.                                                                                                                                                                                                                                                                             |
| **Frozen decisions** | X2-a, X6-a (`/api/ir/*` stays 404), route classes 17 / 251 / 3 / 2, `OPTIONS` unauthenticated, `DELETE /reports/{id}` ticket-or-bearer, no `X-Request-ID` on gateway refusals, identity headers stripped, token policy and signing keys. None changed.                                                                                                                                                             |
| **Not done here**    | 10.6/10.7: `127.0.0.1:8000` stays published and `172.18.0.1` stays trusted. F10-3 (uvicorn WebSocket ticket log line), the stale `Backend/openapi.json`, O14 (host nginx log format) and DNS are untouched.                                                                                                                                                                                                        |

## 1. What changed in production

| Item                              | Before                                                                      | After                                                                                                              |
| --------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `/etc/nginx/conf.d/ccure.conf`    | `638fd33f…` — `/api/` → `127.0.0.1:8000`                                    | `79d45132…` — `/api/auth/` and `/api/` → `172.31.254.10:8080` (the gateway); nothing else in the file differs      |
| `ccure-api`                       | started 29 Sep 12:18 UTC, uvicorn `--proxy-headers --forwarded-allow-ips=*` | recreated 30 Sep 05:34 UTC, uvicorn `--no-proxy-headers`, `TRUSTED_PROXIES=127.0.0.1,::1,172.18.0.1,172.31.254.10` |
| `ccure-gateway-auth` (new)        | —                                                                           | `ccure-gateway-auth:10.5` (`94cd55c4…`), `172.31.254.11`, no port, read-only, uid 10001                            |
| `ccure-api-gateway` (new)         | —                                                                           | `nginx@sha256:98522025…`, `172.31.254.10`, no port, read-only, uid 101                                             |
| Network `ccure-audit-pro_gateway` | —                                                                           | `internal`, `172.31.254.0/24`, bridge `.1`; api joins it at `.20`                                                  |

Files: `docker-compose.yml` (services `gateway-auth`, `api-gateway`, network `gateway`, the api's
`TRUSTED_PROXIES` and second network), `gateway/nginx/site/production.conf`,
`gateway/edge/host-nginx/ccure.{direct,gateway}.conf`, `scripts/linux/gateway_edge_switch.sh`.

## 2. The gateway's address — read from Docker, then pinned

- **Measured, not guessed.** Before the change the live default network was `172.18.0.0/16`
  (gateway `.1`, api `.7`). The host routes are `10.180.20.0/22`, `172.17.0.0/16` and `172.18.0.0/16`.
  `172.31.254.0/24` overlaps none of them, nor any Docker network.
- **After creation, `docker network inspect` shows:**
  - `ccure-audit-pro_gateway` is `internal=true`, `172.31.254.0/24`, with `gw=172.31.254.1`;
  - `ccure-api-gateway=172.31.254.10`, `ccure-gateway-auth=172.31.254.11`, `ccure-api=172.31.254.20`.
- **Host nginx arrives at the gateway as `172.31.254.1`.** That is the bridge. It dials the container
  directly, so there is no published port and no docker-proxy hop. The gateway's own access log records
  `peer=172.31.254.1` for every request since the switch.
- **The api sees the gateway as `172.31.254.10`.** That is the one address added to `TRUSTED_PROXIES`.

**Why a dedicated internal network, not a static address on the default one (O7) and not the old
`gateway` service on `127.0.0.1:8082` (O3).** Both were recommendations in the proposal, never
decisions (§15 of `PHASE10_API_GATEWAY.md` decided X2, X6, the `DELETE` route and M3). 10.3 left
the address question open for the cut-over. The choice made here, for the owner's review:

- **`internal: true`.** gateway-auth and the gateway have no route off the host and nothing
  published. gateway-auth is reachable from that bridge alone, which is "internal only" in the
  strongest form Docker offers.
- **No published port.** `8082` is where the 10.3/10.4 alongside stack publishes its own gateway,
  so the two would collide. And a loopback port is one more listener for other host processes.
- **Static IPAM on a user-defined network** keeps the addresses stable across container
  re-creation. That is what `set_real_ip_from`, the upstreams and `TRUSTED_PROXIES` need.
- **The published `:8000` keeps its old peer.** Measured on a throwaway pair of networks before
  the change: a container on two networks keeps the default network's route (`gw_priority: 1`).
  Its published port still arrives as that network's gateway. So `172.18.0.1` still means "host
  nginx on the direct path", and the rollback needs no api change.
- **The old `gateway` / `alt-gateway` service is untouched** and still parked behind its profile.
  Repurposing or retiring it is not needed for the cut-over.

## 3. Cut-over and rollback mechanism

`scripts/linux/gateway_edge_switch.sh {status|cutover|rollback|rehearse}`, run by the owner with sudo.

- **Mechanism: a whole-file swap between two pinned files.** It does not use the proposal's
  include + symlink.
  - Both files are committed and pinned by SHA-256 in the script.
  - The direct file is byte-identical to the pre-10.5 live file (`638fd33f…`, as fingerprinted in 10.4).
  - `gateway/production/tests` proves that the gateway file differs from it **only** in the two
    `proxy_pass` lines (and comments). So "change the two locations together" still holds.
  - A live file matching neither pin is never overwritten.
  - The pre-10.5 file is also kept once, as `/etc/nginx/ccure-rollback/ccure.conf.pre-10.5`. That
    is outside `conf.d`, so nginx never loads it.
- **`nginx -t` before every reload.** A failure restores the previous file without reloading.
- **Every switch is proven over `:443`, not assumed.**
  - `GET /api/scans` with no credential is refused 403 by both paths.
  - Only the application stamps `X-Request-ID` on that refusal (frozen fact). So the header's
    presence names the hop that answered (V19).
  - A cut-over whose proof fails rolls itself back to direct.
- **Tested before use.** Every branch was exercised against stubs: preflight refusal, `nginx -t`
  failure, a failed proof with automatic rollback, idempotence, `rehearse`, and a tampered file.

Live record (switch log `/etc/nginx/ccure-rollback/switch.log`):

    11:26:42 == cutover (live=direct)      11:26:44 OK: :443 → gateway (path=gateway, health=200)
    11:43:48 == rehearse (live=gateway)    11:43:50 OK: :443 → direct :8000 (path=direct, health=200)
                                           11:43:52 OK: :443 → gateway (path=gateway, health=200)

`systemctl reload` is graceful. A WebSocket or SSE stream open at the moment of a switch keeps its
old path until it closes.

## 4. F10-1 activation

The API was recreated at 11:03:55 and answered again at 11:04:17, so the window was **22 s**.
Before that, no scan was running or queued and no session had been issued in the previous hour. It
started with:

    Client IP resolution trusts 4 proxy range(s): 127.0.0.1/32, ::1/128, 172.18.0.1/32, 172.31.254.10/32
    uvicorn main:app --host 0.0.0.0 --port 8000 --no-proxy-headers

Measured afterwards: each caller sent eleven requests to `/auth/check-email` (limit 10/min), every one
with a different forged `X-Forwarded-For` / `X-Real-IP`.

| Caller                               | Rate-limit key logged           | Scheme with forged `X-Forwarded-Proto: https` |
| ------------------------------------ | ------------------------------- | --------------------------------------------- |
| frontend proxy `127.0.0.1:3200/api/` | `172.18.0.8` (its own address)  | `Location: http://…`                          |
| container `ccure-beat` → `api:8000`  | `172.18.0.5` (its own address)  | `Location: http://…`, no HSTS                 |
| host process → `127.0.0.1:8000`      | the forged value (no 429 fired) | —                                             |
| client → `:443` → gateway            | the real client (§6)            | `https` from the edge only                    |

The third row is the **documented residual**, unchanged by design: a host process reaches `:8000` as
`172.18.0.1`, which stays trusted so that the rollback works. 10.7 closes it.

The `:3200` response also carries the frontend container's own
`Strict-Transport-Security: max-age=31536000; includeSubDomains`. That is fact 8 of 10.1, pre-existing,
and not the application's header.

## 5. Request buffering at host nginx — decision: unchanged

10.4 found that host nginx keeps nginx's default `proxy_request_buffering on`. So a request body
larger than 16 KiB is spooled to its client-body temp directory before it is proxied. The gateway
behind it streams (`proxy_request_buffering off`, `proxy_max_temp_file_size 0`).

**Kept as it is for 10.5.** The reasons:

- **Changing it is a change in upload behaviour, not in routing.** Today the edge absorbs a slow
  uploader, so the gateway and the API see the body arrive at LAN speed. With buffering off, a slow
  client would hold an API worker for the whole upload — the evidence endpoint is `async`, but the
  AMT import is a sync endpoint on the threadpool. That is a new exposure the cut-over has no reason
  to take on.
- **The rollback depends on it.** The switch is valid only because the two host nginx files differ
  in nothing but `proxy_pass`, which the static test pins.

**What it still means:** an evidence upload is briefly on the host's disk under nginx's temp path
before the application's checks run. That is the pre-existing behaviour, now recorded. If it is to
change, the smaller change is to put `client_body_temp_path` on a tmpfs, which keeps the protection
and removes the disk write. That is a separate host-nginx change for the owner.

**Proven end to end:**

- a 20 MiB upload through `:443` reaches the application whole (§6);
- after it and the report downloads, the live gateway's `/var/cache/nginx` and `/tmp` held **0 files**
  (V10).

## 6. Validation after the cut-over

### 6.1 Credential-less matrix, `:443` before vs after (`scripts/gateway/cutover/live_checks.py`)

1,140 requests per run, all sent both to `:443` and to `:8000`:

- every bearer and ticket-or-bearer route (254), each with no credential and with a forged ES256;
- five bearer refusal variants on each zone;
- identity spoofing, CORS with an allowed and a disallowed origin, and a client `X-Request-ID`;
- tickets: invalid, empty, legacy, and combinations with a bad bearer;
- all six WebSocket refusals;
- the public routes;
- `OPTIONS` preflights;
- 404, 405 and 307, including a 307 with forged `X-Forwarded-Proto`/`X-Forwarded-For`;
- four `/api/ir/*` requests;
- the SPA, and the `:80` redirect.

Same responses before and after:

- **Two captures before any change:** 1,140 / 1,140 identical. The comparison is stable.
- **Before vs after the api restart:** 1,140 / 1,140 identical.
- **Before vs after the cut-over:** **0 unexpected differences.**
  - 603 identical. That is all 569 direct requests and 34 edge ones: public routes, `OPTIONS`,
    404/405/307, `/api/ir/*` (still 404), WebSocket refusals, the SPA and the redirect.
  - **537 edge refusals are now answered by the gateway.** Each is identical in status, body and
    every header value, with exactly one difference: no `X-Request-ID`, and `"request_id": null` in
    place of the application's id. That is the frozen decision.

This one comparison covers several of the required checks:

- the authentication/refusal matrix;
- `OPTIONS`/404/405/307 and `/api/ir/*`;
- CORS and the security headers — each header name occurs as many times as before;
- forged `X-Forwarded-Proto`: the 307 is still `https://`;
- identity-header spoofing.

### 6.2 With the owner's credential (`live_checks.py valid`, run by the owner)

All 21 checks **PASS** through the gateway, most comparing the edge with `:8000` directly:

- **Login and identity:**
  - login;
  - `/auth/me` edge = direct;
  - spoofed `X-Tenant-ID` / `X-User-ID` / `X-Ccure-Auth-Sub` / `X-Forwarded-User` / `X-Remote-User`
    / `X-Ccure-Policy` change nothing.
- **Headers:**
  - a client `X-Request-ID` is preserved, once;
  - CORS on an authenticated success;
  - HSTS exactly once.
- **Downloads:**
  - the report download by bearer is byte-identical edge vs direct;
  - the download by ticket is byte-identical to the bearer download;
  - a ticket is reusable within 60 s.
- **Ticket precedence:**
  - valid ticket + garbage bearer → 200, and garbage ticket + valid bearer → 401 (ticket first);
  - a ticket is refused as a bearer, and an access token is refused as a ticket, each the same as direct;
  - `DELETE /reports/{nonexistent}` is the same as direct.
- **Streaming:**
  - scan WebSocket 101 with the same first frame as direct, and the web-scan WebSocket 101;
  - SSE `connected` in under 2 s;
  - the SoA PDF streamed complete.
- **Uploads:** a **20 MiB upload** is refused by the application with the same 400 as direct. The
  refusal depends on its **last** byte (invalid UTF-8), so it proves the whole body arrived, and
  nothing is stored.
- **Session:**
  - refresh rotates the cookie;
  - logout revokes the session (refresh after logout = 401).

The output, `cutover_valid_probe.json` (archived in `docs/archive/architecture/phase10/`), was checked:

- 0 JWT-shaped strings, no cookie values and no credential;
- success bodies are kept as size + SHA-256 only.

### 6.3 Rate limiting and client identity

- **Test:** `GET /api/auth/check-email` (limit 10/min) through `:443` from `127.0.0.1`. Each request
  forged a fresh `X-Forwarded-For`/`X-Real-IP` and `X-Forwarded-Proto: http`.
- **The limit held.** Requests 1–10 → 200. The 11th → 429 `RATE_LIMIT_EXCEEDED` from the
  **application** (it carries `X-Request-ID`; host nginx's own 429 would not).
- **The log names the real client:** `RATE_LIMIT_REJECTED … ip=127.0.0.1`.
- **A second client was unaffected.** Its request, from `10.180.22.127`, got 200.
- **The gateway log agrees:** `peer=172.31.254.1` (host nginx) and `client=127.0.0.1` /
  `10.180.22.127`. No forged `203.0.113.*` address appears anywhere.
- **Same as before.** The same test before the change gave the same result.

### 6.4 Latency and errors

200 requests per series, a new connection each time, paced at about 10/s:

| Series (p50 / p95 ms)                     | Before, `:443` | Before, `:8000` | After, `:443` | After, `:8000` |
| ----------------------------------------- | -------------- | --------------- | ------------- | -------------- |
| public `GET /api/`                        | 7.25 / 9.39    | 2.98 / 3.96     | 5.36 / 7.09   | 2.03 / 2.85    |
| bearer refusal `GET /api/scans`           | 8.63 / 11.11   | 4.43 / 5.70     | 5.42 / 7.03   | 3.80 / 4.85    |
| valid bearer `/api/auth/me` (owner, n=20) | —              | —               | 53.26 / 79.46 | 46.19 / 49.00  |

**What the latency shows:**

- **The edge overhead on `:8000` fell.**
  - Public: +4.27 → +3.33 ms at p50, and +5.43 → +4.24 at p95.
  - Refusals: +4.20 → +1.62 at p50. The gateway answers a refusal without reaching the application.
- **The api process restarted between the two runs, so absolute numbers moved on both paths.**
  Read the overhead columns, not the raw times.
- **The authenticated series is paced at 2.2 s per request under host nginx's `/api/auth/` zone.**
  Its p95 over 20 samples is one outlier. The alongside suite's 250-request measurement is the
  reliable figure for `auth_request` overhead. Re-run in this phase (§7), it gave +0.56 / +0.52 ms
  (p50 / p95) public and +2.08 / +1.83 ms authenticated, within the +5 ms p95 budget (O12).

**Errors:**

- **Since 11:26:42, no 5xx on any hop.** The gateway logged 226 × 200, 2 × 307, 3 × 400, 274 × 401,
  471 × 403, 6 × 404, 1 × 405, 1 × 422 and 1 × 429. Every 401/403 was a deliberate test refusal.
- **No errors in the logs.** The api log has no traceback or ERROR, and gateway-auth logs nothing
  but refusal lines.
- **The 20-series latency run had 0 errors.**

### 6.5 Logs and leakage

- **The new containers' logs are clean.** `ccure-api-gateway` (1,060 lines) and `ccure-gateway-auth`
  (757) contain **0** JWT-shaped strings and **0** occurrences of `ticket=`, `token=`,
  `Authorization`, `Cookie` or the refresh cookie name. The gateway logs `$uri` (no query), the
  principal id and `jti`.
- **Two pre-existing leaks remain, deferred as instructed:**
  - The **application** log still records 7 uvicorn `WebSocket …?ticket=…` lines from the probe's
    sockets — **F10-3**.
  - Host nginx's own `access.log` still logs query strings — **O14, not approved, unchanged**. It
    is readable only by `adm`, so the owner can count it: `sudo grep -c 'ticket=' /var/log/nginx/access.log`.

### 6.6 Production fingerprint, before vs after (`scripts/gateway/cutover/fingerprint.sh`)

**Changed, and only these:**

- the host nginx file hash;
- `ccure-api`'s start time and compose hash (its `172.18.0.7` address is kept);
- the two new containers, which publish nothing;
- the new internal network;
- `TRUSTED_PROXIES` and the uvicorn command line.

**Unchanged:**

- `nginx.conf`;
- every host listener — no new port;
- every other container: db, redis, frontend, worker, web-worker, beat, portainer;
- the keyset (`keyset.json` `043bfca1…`, directory listing identical);
- the JWKS response (`56121c03…`);
- `CCURE_TOKEN_SIGNING_ALG=ES256` and `CCURE_ACCEPT_LEGACY_HS256=false`;
- alembic head `f3b5d7e9a1c4`, 68 tables, and the column and constraint digests.

The ad-hoc backup `ccure_db_20260930_104720_ops.dump` was taken before any change. The 02:30 full
dump is the self-contained restore point.

## 7. Tests

| Suite                                                      | Result                                                                                      |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `gateway/production/tests` (new, static)                   | 20 passed                                                                                   |
| gateway-auth unit tests (10.2b)                            | 133 passed                                                                                  |
| 10.2d harness                                              | 53 + 9 (checker stopped, fail closed) passed; 243 log lines, 0 token problems               |
| 10.3 alongside + 10.4 TLS                                  | 33 + 20 + 45 passed; 802 log lines, 0 token problems; its production-untouched check passed |
| full backend suite (live api container, `ccure_pytest_db`) | **6,300 passed, 211 skipped, 0 failed** (13 min 51 s) — identical totals to 10.3/10.4       |

Static tests run on a full checkout, since the api container mounts only `Backend/` and `docs/`:

    docker run --rm --network none -v "$PWD":/repo:ro -w /repo \
        ccure-audit-pro-backend:latest python -m pytest -q -p no:cacheprovider gateway/production/tests

## 8. M3

The read-only sampler has run from 29 Sep 18:51 IST (corrected in 10.6; this line first said 20:51), recording ESTABLISHED sockets every 10 s. At
the time of the cut-over it had 5,798 samples, about 16 h.

- **Host-side dialers of `127.0.0.1:8000`:** `www-data` (host nginx) 6 times and the operator
  account 4 times. No other process was seen.
- **API-side peers of `:8000`:** only `172.18.0.1` (docker-proxy). No container called `api:8000`
  at a sampled instant.

Long-lived connections were rare and low, so the gateway's default `worker_connections` (1024 per
worker, 8 workers) is ample against the edge's `limit_conn 40`. The sampler runs to 20:50 IST and,
now that host nginx no longer dials `:8000`, it measures exactly what 10.7 needs to know (M6):
whether anything still uses the direct port.

## 9. Rollback

    sudo scripts/linux/gateway_edge_switch.sh rollback

One nginx file, `nginx -t`, a graceful reload, and a proof over `:443` that the application answers
directly. Rehearsed live (§3). The gateway containers can keep running; nothing reaches them.

**To roll back F10-1 as well** (not expected): run `git revert` on the api's `TRUSTED_PROXIES` / network
lines and on 10.3's `start.sh`, then `docker compose up -d --no-deps api`.

**The HS256 rollback now also needs the routing rollback.** gateway-auth cannot verify HS256 (risk
recorded in the proposal §10). The Phase 9 §17 order becomes:

1. `gateway_edge_switch.sh rollback`;
2. then `CCURE_ACCEPT_LEGACY_HS256=true`;
3. then `docker compose up -d --no-deps api`.

## 10. Remaining risks and deferred items

- **The host-process residual on `:8000`** (§4). Any local process can still forge a client address.
  10.7 closes it by unpublishing `:8000` and dropping `172.18.0.1`, and that removes the rollback path.
- **Any host process can reach `172.31.254.10:8080`** and would be treated as the trusted edge. This
  is the same class of residual, in a new place. Closing it needs the gateway to trust host nginx by
  something other than the bridge address (a unix socket, or mTLS). It is not in 10.5's scope.
- **F10-3** (application WebSocket log line) and **O14** (host nginx query-string logging) remain,
  so tickets still reach two logs.
- **Pre-existing compose drift on `beat`, `worker`, `web-worker`.** Their running config differs
  from `docker-compose.yml`, and it did before this phase. Every compose command here used
  `--no-deps` and named only the services it touched. A plain `docker compose up -d` would recreate
  those three.
- **Not exercised live:**

  - V16 (fail closed) — stopping gateway-auth in production would refuse every authenticated user;
    the harness proves it in isolation;
  - V9's 10-minute heartbeat;
  - an interactive browser session.

  The owner is advised to use the application normally for one full 30-minute token lifetime, which
  exercises silent refresh in a real browser.

- **Stale `Backend/openapi.json`** is unchanged, and the CI contract gate still fails on it as before.
