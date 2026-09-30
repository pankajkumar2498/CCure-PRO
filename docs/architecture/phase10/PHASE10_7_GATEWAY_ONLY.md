# Phase 10.7 — Gateway-only production ingress

|                 |                                                                                                                                                                                                                                                                                      |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Status**      | **Live since 30 Sep 2026, 16:08:55 IST.** The published and direct ingress paths to the API are removed. `:443` → host nginx → api-gateway → gateway-auth → API is the only production ingress. **M3 and V-N1 were still running at commit time and are not claimed complete** (§8). |
| **Plan**        | [`PHASE10_7_PLAN.md`](PHASE10_7_PLAN.md), approved by the owner on 30 Sep 2026. It was followed step by step; the one change of order is recorded in §6.                                                                                                                             |
| **Not claimed** | This is **not** absolute gateway-only API reachability. A host process can still dial the API's internal address, `172.31.254.20:8000`, as an **untrusted** client (§2). That residual is deferred to optional **Phase 10.8** and is not implemented here.                           |
| **Unchanged**   | X2-a, X6-a (`/api/ir/*` 404), token policy and keys, certificates and CA, host nginx (both files, the socket edge, request buffering), the gateway and gateway-auth, the database, F10-3, O14, and the stale `Backend/openapi.json`.                                                 |

## 1. What changed

| #   | Change                                                                                                                                                                                                             | Live since |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| C1  | `docker-compose.yml` `api`: no published port; `TRUSTED_PROXIES=127.0.0.1,::1,172.31.254.10`; `API_BIND_HOST=172.31.254.20`                                                                                        | 16:08:55   |
| C2  | `Backend/start.sh`: `--host ${API_BIND_HOST:-0.0.0.0}`. The default keeps every other user of the script unchanged.                                                                                                | 16:08:55   |
| C3  | `docker-compose.yml` `frontend`: joins the `gateway` network at `172.31.254.30`                                                                                                                                    | 16:05:44   |
| C4  | `Frontend/nginx.conf`: `/api/` → `http://172.31.254.10:8080` (no URI; `/api` is kept, and the gateway strips it). It no longer sends forwarding headers the gateway ignores.                                       | 16:05:44   |
| C5  | frontend image rebuilt; the old one is kept as `ccure-audit-pro-frontend:pre-10.7` (`c75b8631…`), and the new one is `3cc1137e…`                                                                                   | 16:05:44   |
| C6  | `docker-compose.emergency-direct.yml` (new, emergency only, §7)                                                                                                                                                    | —          |
| C7  | `gateway_edge_switch.sh`: `rollback` refuses unless `127.0.0.1:8000` is listening, and prints the emergency command; a failed `cutover` never falls back to a direct file that cannot work; new `emergency-status` | —          |
| C8  | `live_checks.py` and `fingerprint.sh`: the "direct" reference is `172.31.254.20:8000`; the fingerprint records whether `:8000` is listening                                                                        | —          |
| C9  | tests (§9); `scripts/ci/smoke_frontend.sh` rewritten to the new `/api/` contract (§9)                                                                                                                              | —          |
| —   | `api_peer_sampler.sh` (new, read-only; V-N1)                                                                                                                                                                       | —          |
| —   | VS Code remote setting `remote.portsAttributes` `8000`/`3200`: `onAutoForward: ignore`, in `~/.vscode-server/data/Machine/settings.json` (outside the repository)                                                  | 15:25      |

## 2. Production topology after 10.7

    LAN client ──TLS──▶ 10.180.22.127:443  host nginx (unchanged; private-CA certificate)
        /api/ ──unix:/var/lib/ccure-edge/gateway.sock──▶ api-gateway 172.31.254.10
                                                           │ auth_request
                                                           ├─▶ gateway-auth 172.31.254.11
                                                           └─▶ api 172.31.254.20:8000 (listens here only)
        /     ──▶ 127.0.0.1:3200 frontend (static SPA)

    127.0.0.1:3200/api/ (local tools) ──▶ frontend 172.31.254.30 ──TCP──▶ api-gateway :8080
                                                                  (an untrusted client) ──▶ gateway-auth / api

| Property                               | After 10.7                                                                                 |
| -------------------------------------- | ------------------------------------------------------------------------------------------ |
| Host listeners                         | `0.0.0.0:80`, `0.0.0.0:443` (nginx); `127.0.0.1:{3200, 5432, 6379, 9443}`. **No `:8000`.** |
| API listens on                         | `172.31.254.20:8000` only                                                                  |
| API trusts (client address and scheme) | `127.0.0.1`, `::1`, `172.31.254.10` (the gateway)                                          |
| Gateway trusts                         | the unix socket (host nginx) only — unchanged from 10.6                                    |

**What remains reachable.** A host process can dial `172.31.254.20:8000`, because
the host sits on the bridge. It arrives as `172.31.254.1`, which is untrusted:

- it cannot choose its own client address or scheme (V-C4);
- the application still requires its own valid token;
- it bypasses gateway-auth and host nginx's `limit_req`, which are defence in depth.

This is the documented residual, deferred to optional 10.8.

## 3. Gate 0

| Gate                            | Result                                                                                                                                                                                                                                    |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| G0.1 M3                         | **Not complete at commit.** The owner's decision was to proceed without waiting; §8 holds the state at commit time.                                                                                                                       |
| G0.2 VS Code                    | **PASS.** The owner stopped the 8000/3200 forwards and reloaded the window. The workstation has no listener on 8000 or 3200. On the VM there is no connection to either port, from any process. The auto-forward ignore rule is in place. |
| G0.3 backup                     | **PASS.** `ccure_db_20260930_153229_ops.dump`, remote copy ok; the 02:30 full dump is the self-contained restore point.                                                                                                                   |
| G0.4 fingerprint and invariants | **PASS.** OpenAPI `2fc271bb…`, 273 routes, 93 rate-limited routes, 21 Celery tasks, 11 beat entries.                                                                                                                                      |

## 4. Frontend (Steps 2–3)

- **V-F1 — the rebuild changes only the nginx config.** All 13 files in the
  image were compared by SHA-256: the six served SPA files (`index.html`,
  `index-CkVhwOG4.js`, `index-Dw-V0jdT.css`, the font, the favicon,
  `50x.html`) and nginx's own. Only `/etc/nginx/conf.d/default.conf` differs.
  The candidate passes `nginx -t`.
- **UX4G harness: 253 / 253 states identical**, old image against candidate.
  The harness serves its own frontend container and mocks `/api` in the
  browser, so it never used the live `:3200`. The address literal also removes
  its need for an `api` host override.
- **V-F2 — `:3200/api/` goes through the gateway.**
  - `GET /api/` and `/api/api/pipeline-modes` → 200.
  - A bearer route with no credential → 403 **without `X-Request-ID`**, with
    an empty upstream: gateway-auth refused it.
  - The gateway log shows `peer=172.31.254.30 client=172.31.254.30`.
- **V-F3 — the path cannot forge identity or scheme.** Eleven requests forged
  `X-Forwarded-For`/`X-Real-IP` and `X-Forwarded-Proto: https`. The API's 429
  names **`ip=172.31.254.30`**, and the redirect is `http://`. That response
  also carries `Strict-Transport-Security: max-age=31536000; includeSubDomains`,
  which is the frontend container's own static header (10.1 fact 8, older than
  10.7), not the application's.
- **V-F4 — the logged-in flow over `:3200`** (owner's account):

  - login and `/auth/me`: 200;
  - downloads by bearer and by ticket: 200 each, byte-identical (46,191 B);
  - WebSocket: 101 and the first frame;
  - SSE: 200, `connected`;
  - 20 MiB upload: refused by content (400), so it arrived whole;
  - refresh rotates the cookie; logout, then refresh → 401.

  The first run of the probe crashed on its own SSE read. It did not catch the
  socket timeout while waiting for the 25 s heartbeat. The path itself was
  measured on all four hops — `:443`, gateway TCP, `:3200`, and the API
  directly — with the first byte in 0.01–0.02 s every time. The crash left
  one probe session open: its refresh cookie existed only in the dead process,
  so it is unusable. It expires within 7 days and shows in the owner's session
  list. It was not mass-revoked, because that would sign the owner out elsewhere.

## 5. Closing `:8000` (Step 4)

The API was recreated at 16:08:34 and answered through `:443` again at
16:08:55, so the interruption was **21 s**. It had been announced, and no scan
was running. Its start-up log reads:

    Client IP resolution trusts 3 proxy range(s): 127.0.0.1/32, ::1/128, 172.31.254.10/32
    Uvicorn running on http://172.31.254.20:8000

| Check | Result                                                                                                                                                                              |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| V-C1  | Nothing listens on `127.0.0.1:8000`, and `curl` is refused (exit 7). Docker shows no published port. From the LAN, `10.180.22.127:8000` is refused.                                 |
| V-C2  | Inside the container, only `172.31.254.20:8000` is open; `127.0.0.1` and `172.18.0.7` refuse. The host is refused at `172.18.0.7:8000`, and `ccure-beat` at `api:8000` (Errno 111). |
| V-C3  | The API trusts exactly three addresses, as above.                                                                                                                                   |
| V-C4  | **The residual:** a host process at `172.31.254.20:8000` with forged headers → 429 on **`ip=172.31.254.1`**; the redirect is `http://`, with no HSTS.                               |
| V-C5  | gateway-auth `/healthz` returns 200, and every credentialed request below verified through it.                                                                                      |

The 9 gateway 5xx responses since the change are all 502s between 16:08:46 and
16:08:54. Each is the operator's own health poll during the announced restart
(`GET /api/`). There were no others.

## 6. LAN, application and dependency verification (Steps 5–7)

- **V-L1 — through `https://10.180.22.127`** (the IP as `Host` and TLS name):
  - **21/21** credentialed checks from the VM, edge against direct;
  - **from the second machine** (`10.180.6.30`, which has no direct path at all):
    - login;
    - `X-Request-ID` echoed once; CORS `https://10.180.22.127`; HSTS `max-age=300`;
    - a gateway refusal without `X-Request-ID`;
    - a 20 MiB upload refused by content;
    - **a full scan**: start 200 `running`, WebSocket 101 with 5 progress
      frames, status `complete`, scan-events SSE 20 events, the report PDF by
      ticket;
    - refresh rotation, and logout then 401.
- **V-L2 — the 1,140-request capture over `:443`, compared with the last
  capture before 10.7:**
  - **the edge side is 571 / 571 identical**;
  - the direct side is 567 identical, with 2 differing only in the `Location`
    of the trailing-slash 307s, which now name the new reference address.
- **V-L3 — observation:** **27/27 PASS** (`observe_10_7*.json`, owner's account).

  - The 21-check battery, run again.
  - One session held past the real 30-minute expiry:
    - the access token, 20 s after `exp`, got **401 through the gateway and
      401 direct**;
    - refresh after expiry returned 200 with a new token, and that token was
      accepted through the gateway;
    - the notification SSE stream was held **1,850 s** with heartbeats never
      more than **25.0 s** apart;
    - the WebSocket answered 101 and delivered its frames;
    - logout, then refresh → 401.

- **V-L4 — trust:**
  - the gateway TCP caller is keyed on its own address and cannot forge `https`;
  - the socket refuses a non-`www-data` user;
  - through `:443`, the 11th request is the application's 429 keyed on the real
    client `127.0.0.1`, and a second client is unaffected.
- **V-L5 — logs:**
  - The gateway and gateway-auth logs contain 0 tokens and 0 `ticket=`.
  - **The frontend container's own access log now holds 4 ticket-bearing
    lines**, from V-F4's download and WebSocket requests. It logs full request
    lines with the query string, as it always has. The `:3200/api/` path is
    local tooling only, and the tickets had a 60-second life. It is the O14
    class, and recorded not changed.
  - The API log (F10-3) holds 12 WebSocket ticket lines since the restart, all
    from the probes.
- **V-L6 — latency** (200 requests each):
  - `:443` public: p50 / p95 4.94 / 6.66 ms;
  - `:443` refusal: 4.49 / 5.68 ms;
  - 0 errors, and no 5xx outside the restart window.
- **V-N1:** a 24-hour sampler of the API's `:8000` peers
  (`api_peer_sampler.sh`) started at 16:14 IST and was running at commit (§8).
- **V-N2 — nothing in production calls `:8000`.**
  - No crontab, `/etc/cron*` or systemd entry.
  - No service environment names an API URL except gateway-auth's JWKS URL,
    which uses `172.31.254.20`.
  - The only references left in the repository are:
    - comments;
    - the Windows deployment's host nginx configuration;
    - the Vite development proxy;
    - the parked `alt-gateway` configuration.

**Rehearsal (V-R):** **PASS, both directions, live, with the owner.** No scan was running.

| Step | Time (IST)          | Who      | Result                                                                                                                                                                                                                        |
| ---- | ------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R1   | 16:46:22 → 16:46:43 | operator | emergency override applied: the API restarted in 21 s; `127.0.0.1:8000` listening; uvicorn on `0.0.0.0:8000`; `trusts 4 proxy range(s)` including `172.18.0.1`; `:443` still through the gateway (200)                        |
| R2   | 16:49:22 → 16:49:24 | owner    | `gateway_edge_switch.sh rollback` → `OK: :443 → direct :8000 (path=direct, health=200)`                                                                                                                                       |
| R3   | 16:50               | operator | through `https://10.180.22.127`: login 200; `/auth/me` 200; a refusal **with** `X-Request-ID` (the API answered directly); **0** requests reached the gateway; logout 200; host nginx file `638fd33f…`                        |
| R4   | 16:51:24 → 16:51:26 | owner    | `gateway_edge_switch.sh cutover` → `OK: :443 → gateway over /var/lib/ccure-edge/gateway.sock (path=gateway, health=200)`                                                                                                      |
| R5   | 16:51:47 → 16:52:07 | operator | API back to normal: restarted in 20 s; `trusts 3 proxy range(s)`; `172.31.254.20:8000` only; no `:8000` listener; `:443` refusal without `X-Request-ID` (the gateway); compose hashes for `api` and `frontend` equal the file |

**One change of order from the plan.** The plan returned to normal as
"`docker compose up -d --no-deps api`, then `cutover`". In that order,
`:443` has no working API path between the two steps, because host nginx still
points at a direct port that has just closed. The rehearsal ran `cutover`
first, while `:8000` was still open, and then restored the API. The runbook in
§7 has that order.

## 7. Emergency procedure (restores `:8000` temporarily)

1.  **Bring the API back on `:8000`.** This takes about 22 s:

        docker compose -f docker-compose.yml -f docker-compose.emergency-direct.yml up -d --no-deps api

    Check that `127.0.0.1:8000` is listening and that the log reads
    `trusts 4 proxy range(s)`. The gateway path keeps working in this state,
    because the API is on `0.0.0.0` and includes `172.31.254.20`.

2.  **Point host nginx straight at it:**

        sudo scripts/linux/gateway_edge_switch.sh rollback

    This proves `path=direct`.

3.  **Return to normal.** Host nginx first, while `:8000` is still open:

    sudo scripts/linux/gateway_edge_switch.sh cutover
    docker compose up -d --no-deps api # closes :8000 again (~22 s)

**The emergency state is the post-10.3 direct configuration** that ran in
production until the 10.5 cut-over. `emergency-status` names the state of each
layer. While the override is applied, `fingerprint.sh` reports
`127.0.0.1:8000 listening: YES`.

## 8. M3 and V-N1 at commit time

**M3 was still running at commit. It is not claimed complete.** Its sampler
ends at about 20:51 IST on 30 Sep. The final `m3_summary.py` run on the finished
log, and any caller it finds, belong to a follow-up record.

State at 16:52:37 IST:

| Period (IST)                             | Hours | Host dialers of `127.0.0.1:8000` | API peers on `:8000`                                      |
| ---------------------------------------- | ----- | -------------------------------- | --------------------------------------------------------- |
| 29 Sep 18:51 – 30 Sep 11:26, direct      | 16.51 | `www-data` 6, `cdac` 4           | `172.18.0.1` 11                                           |
| 11:26 – 12:34, gateway over TCP          | 1.13  | none                             | `172.31.254.10` 2                                         |
| 12:34 – 16:52, socket gateway, then 10.7 | 4.28  | `cdac` 1,616, `www-data` 1       | `172.31.254.10` 586, `172.18.0.1` 1,617, `172.31.254.1` 3 |

**Every entry so far is accounted for:**

- `cdac` until 15:57 is the VS Code server's forwarded connection. It was gone
  after the G0.2 clean-up at about 15:59.
- `www-data` at 16:50 is host nginx during the rehearsal's direct window
  (16:49:24–16:51:26).
- `172.31.254.1` is the operator's own reference calls to `172.31.254.20:8000`.
- From 16:08:55 on, nothing listens on `127.0.0.1:8000`, apart from the
  rehearsal's emergency window (16:46–16:52).

**V-N1** (`api_peer_sampler.sh`, 24 h from 16:14 IST, output in
`~/ccure-samplers/vn1_api_peers.log`) was also still running at commit. At
16:52 it held 233 samples:

- API peers: the gateway `172.31.254.10` 189 times, and `172.31.254.1` once
  (16:15:11, the operator's observation battery calling the direct reference);
- one host socket, owned by root, at 16:22:23 to `10.254.20.20:8000`. That is
  the **alongside test stack's** API, dialled by its runner, which uses the
  host network, during this phase's regression run. It is not production.

No unexplained caller.

**Unrelated host listener.** The after-fingerprint shows `127.0.0.1:27188`,
held by the VS Code server (pid 1501209). It is VS Code's own loopback port,
restarted when the window was reloaded at G0.2, and has nothing to do with
CCure.

## 9. Tests

| Suite                                 | Result                                                                                                                                         |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `gateway/production/tests` (static)   | **29 passed** (5 new for 10.7)                                                                                                                 |
| trust harness                         | **23 passed** (5 new: the frontend's `/api/` path, from the committed `Frontend/nginx.conf`), plus the stale-socket restart and the log checks |
| gateway-auth unit tests               | 133 passed                                                                                                                                     |
| 10.2d harness                         | 53 + 9 passed; 245 log lines, 0 token problems                                                                                                 |
| 10.3 alongside + 10.4 TLS             | 33 + 20 + 45 passed; 802 log lines, 0 token problems; production untouched during the run                                                      |
| UX4G harness (old image vs candidate) | 253 / 253 states identical                                                                                                                     |
| `scripts/ci/smoke_frontend.sh`        | candidate PASS; `pre-10.7` FAIL (it cannot start without an `api` host), as intended                                                           |
| full backend suite                    | **6,300 passed, 211 skipped, 0 failed** (12 min 51 s), after the fixture below                                                                 |

**The first full run failed 16 tests, all of one kind.**

- **Which tests:** the trusted-proxy tests in `test_ip_resolver.py`,
  `test_rate_limiting.py` and `test_trusted_proxy_boundary.py`.
- **Why:** they assume `172.18.0.1` is trusted, which is `config.py`'s
  default. The suite runs inside the live API container, where 10.7 had just
  set `TRUSTED_PROXIES` to the gateway only. `core/ip_resolver.py` reads that
  setting once, at import, so the tests were testing the host's configuration,
  not the code.
- **The fix:** the session fixture `pin_trusted_proxies_to_the_code_default`
  (in `tests/conftest.py`) pins the resolver to `config.py`'s own default, which
  it reads from the source file, so there is still one list. No test was
  weakened, and no application code changed. It is the same lesson as the
  eager-mode test in CLAUDE.md: a test must not depend on how the machine it
  runs on is configured.

**Application invariants, before and after** (live API): **identical**. OpenAPI
`2fc271bb…`, 273 routes, 93 rate-limited routes, 21 Celery tasks, 11 beat
entries.

**Production fingerprint, before and after 10.7.** Only the intended
differences:

- **the API:** its start time and compose hash; no published port; the
  `172.31.254.20` bind; the 3-entry trust list;
- **the frontend:** its image (`3cc1137e…`), compose hash, and the `gateway`
  network at `.30`;
- **the host:** no `127.0.0.1:8000` listener. The one other listener change,
  `127.0.0.1:27188`, is VS Code's own (§8).

**Unchanged:**

- the host nginx file (`5682c968…`, the socket gateway) and `nginx.conf`;
- the gateway and gateway-auth;
- db, redis, worker, web-worker, beat and portainer;
- the keyset and the JWKS;
- `ES256`, and legacy `false`;
- the schema head, the tables, and the column and constraint digests.

**The CI smoke test was rewritten.** `scripts/ci/smoke_frontend.sh`, run by
`.github/workflows/images.yml`, asserted that the image proxies `/api/` to a
host called `api` on port 8000. That is the contract 10.7 deliberately changes,
and the plan's §8 had missed the test.

- **How it works now.** A stand-in upstream adds `172.31.254.10` to its own
  loopback (`NET_ADMIN`), and the frontend joins its network namespace. The test
  therefore needs no host network on the live subnet. The stand-in serves its
  marker only at `/api/`, so a proxy that stripped the prefix would fail.
- **Result:** the candidate **passes**. The `pre-10.7` image **fails**
  (it cannot start without an `api` host), which shows the test tells the two
  apart.

## 10. Remaining risks and follow-ups (not part of 10.7)

- **The host → `172.31.254.20:8000` residual** (§2). It is closed by the API
  listening on a unix socket shared with the gateway: optional **10.8**.
- **The browser certificate warning on LAN machines.** The certificate is valid
  for `10.180.22.127`, but its private issuer is not trusted by the
  organisation's machines. Separate follow-up; unchanged.
- **Tickets and reset tokens in logs:** the API (F10-3), host nginx (O14), and
  now also the frontend container's log, for requests to `:3200/api/` — the
  same class as O14.
- **One orphaned probe session** from V-F4's first run (§4). It is unusable,
  and it expires within 7 days.
- **The stale `Backend/openapi.json`.**
- **The password shared in chat**, which should be rotated.
