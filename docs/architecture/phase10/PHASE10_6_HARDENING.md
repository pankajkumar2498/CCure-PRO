# Phase 10.6 — Post-cut-over hardening and observation

|               |                                                                                                                                                                                                                                                            |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**    | **Live since 30 Sep 2026, 12:34:54 IST.** **M3 was still running at commit (it ends 20:51 IST) and is not claimed complete — §7.** host nginx → gateway over a unix socket; the gateway trusts that socket and nothing else. Committed with this document. |
| **Baseline**  | `234d25d` (Phase 10.5). [`PHASE10_5_CUTOVER.md`](PHASE10_5_CUTOVER.md) remains the record of the cut-over itself.                                                                                                                                          |
| **Unchanged** | X2-a, X6-a (`/api/ir/*` 404), route classes, token policy, signing keys, the application, the database, host nginx's request buffering, `:8000` (still published; 10.7 not started), the stale `Backend/openapi.json`, F10-3, O14.                         |

## 1. The trust gap (root cause)

In 10.5 the gateway accepted `X-Real-IP` and `X-Forwarded-Proto` from one peer
address: `172.31.254.1`. That is the address host nginx came from when it
connected to the gateway.

The problem is that `172.31.254.1` is not host nginx. It is the bridge address,
and **every** process on the host has it when it connects into that Docker
network.

**Reproduced live before the fix.** A host process — the operator's shell,
uid 1001 — sent eleven requests to `http://172.31.254.10:8080/api/auth/check-email`,
each carrying a forged `X-Real-IP: 203.0.113.77`:

- The gateway logged `peer=172.31.254.1` and `client=203.0.113.77`.
- The API rate-limited and audit-logged **`ip=203.0.113.77`**.
- With `X-Forwarded-Proto: https` forged as well, the API answered
  `Location: https://…` and added HSTS.

So any local process could pick its own rate-limit key, its own audit address
and its own scheme. This is the same class of hole as F10-1, one hop further
out.

## 2. The fix: a unix socket, authenticated by the filesystem

**Host nginx now connects to the gateway through a unix socket,
`/var/lib/ccure-edge/gateway.sock`.** The gateway treats a peer as the edge
only when it arrives on that socket. The rule is in
`gateway/nginx/trust/unix_edge.conf`:

    set_real_ip_from unix:;
    map $realip_remote_addr $ccure_from_edge { default 0; "unix:" 1; }

(A `geo` block cannot match the literal `unix:`, which is why it is a `map`.)

**Who can connect is decided by file permissions.**

- nginx always creates its socket with mode `0666`. We measured this, so the
  socket's own mode protects nothing.
- The directory holding it is `root:www-data 0770`, and that is what gates access.
- Host nginx's workers run as `www-data`, and no other account is a member of
  that group (`getent group www-data`).
- Measured with throwaway containers: uid 33 and root connect; uids 101, 1000,
  1001 and 65534 get `PermissionError`. On the live host, the operator account
  cannot even list the directory.

**Every TCP caller is now an ordinary client.** The gateway still listens on
`:8080`, but it trusts no IP address. A TCP caller's own address and `http` are
what reach the application; `proxy_api.conf` sets both headers and never appends.

**Why not mTLS.** mTLS would give the same assurance, but it needs a CA, a
client key for host nginx, rotation, and verification settings on both sides.
The socket needs no key material at all. It relies on an access-control system
the host already has, rather than adding a second authentication system.
Token policy is untouched.

**How it was wired in.**

| File                                                     | Change                                                                                                                                                   |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `gateway/nginx/gateway.conf`                             | `include /etc/nginx/ccure/listen.d/*.conf;` — a glob that matches nothing in the harness and alongside stacks, so they are unchanged                     |
| `gateway/nginx/listen/unix_edge.conf` (new)              | `listen unix:/run/ccure-edge/gateway.sock;`                                                                                                              |
| `gateway/nginx/trust/unix_edge.conf` (new)               | the rule above. The trust harness mounts this same file.                                                                                                 |
| `gateway/nginx/site/production.conf`                     | upstreams only; `include`s the trust file. The IP trust on `172.31.254.1` is removed.                                                                    |
| `gateway/nginx/entrypoint/30-ccure-edge-socket.sh` (new) | removes a stale socket before nginx starts (see below)                                                                                                   |
| `docker-compose.yml` (`api-gateway`)                     | `group_add: ["33"]`; bind `/var/lib/ccure-edge` → `/run/ccure-edge` with `create_host_path: false`; the three new files mounted read-only                |
| `gateway/edge/host-nginx/ccure.gateway.conf`             | `proxy_pass http://unix:/var/lib/ccure-edge/gateway.sock;` in both `/api/` locations. It still differs from `ccure.direct.conf` in those two lines only. |
| `scripts/linux/gateway_edge_switch.sh`                   | knows three states (direct, the 10.5 TCP gateway, the socket gateway); adds `harden` and `logcount`                                                      |

**Three details that looked unnecessary and are not:**

- **A stale socket stops nginx from starting.** nginx deletes its socket when
  it exits cleanly. After a `kill -9`, the file stays behind, and the next
  start fails with `bind() … (98: Address in use)`. We measured this. The
  entrypoint script removes the old socket first. Only one `api-gateway`
  container can exist, so a socket present at start is never a live one.
- **`create_host_path: false`.** If the directory did not exist, Docker would
  create it as `root:root 0755`. The gateway could then not create its socket,
  and host nginx would answer 502. Refusing to start makes the cause visible.
- **`group_add: ["33"]`** assumes the host's `www-data` group is gid 33.
  `harden` checks this before doing anything.

**`/var/lib/ccure-edge`, not `/run`.** A directory under `/var/lib` survives a
reboot without a tmpfiles.d entry, and the stale-socket cleanup covers the old
file. A directory under `/run` would need systemd to recreate it on every
boot, before Docker starts.

## 3. The production change

`sudo scripts/linux/gateway_edge_switch.sh harden` was run by the owner. It
refuses to start unless the live file is the 10.5 file, and it does five
things:

1. Creates `/var/lib/ccure-edge` as `root:www-data 0770`.
2. Recreates `api-gateway` alone (`docker compose up -d --no-deps`).
3. Checks the gateway **through the socket**: health returns 200, and a refusal
   carries no `X-Request-ID`, which shows gateway-auth answered.
4. Installs the pinned socket version of host nginx's file, runs `nginx -t` and
   a graceful reload.
5. Proves over `:443` that the gateway is answering.

If anything fails after step 2, the script switches host nginx to direct.
Direct does not depend on the gateway at all, so it is always safe to land on.

    12:34:50 == harden (live=gateway-tcp, sha=79d4513217a4fb42)
    12:34:50 created /var/lib/ccure-edge root:www-data 0770
    12:34:50 recreating api-gateway (compose project ccure-audit-pro) with the edge socket
    12:34:52 installing ccure.gateway.conf
    12:34:54 OK: :443 → gateway over /var/lib/ccure-edge/gateway.sock (path=gateway, health=200)

**Exposure during the change:**

- About 2 s while the gateway was recreated.
- Then about 2 s in which host nginx still used TCP. Those requests were
  treated as coming from `172.31.254.1`. That fails safe: the address was never
  a forged one.

**Rollback:** `sudo scripts/linux/gateway_edge_switch.sh rollback` puts host
nginx on direct `:8000`. That path was proven again in the sandbox and live in
10.5.

The 10.5 TCP file is recognised by its SHA but never installed. The gateway no
longer believes TCP, so that file would work but put every client into one
bucket. **Undoing 10.6 therefore means `rollback`, then `git revert` and
`docker compose up -d --no-deps api-gateway`, then `cutover`.**

**Script branches checked before use** (in a sandbox with stubbed commands):

- `recreate` fails → direct;
- no socket appears → direct;
- the gateway does not answer → direct;
- the directory has the wrong owner or mode → nothing changed;
- the happy path, idempotence, `rehearse`, `rollback`, and `cutover` from direct;
- `cutover` from the TCP state → refused, pointing to `harden`.

## 4. Tests of the boundary

### 4.1 Trust harness (`gateway/production/trust_harness/run.sh`), isolated

The harness runs the **production files**, not replicas of them:

- **The edge is host nginx's own file.** It runs the committed
  `ccure.gateway.conf` with four mechanical rewrites: ports 443→8443 and 80→8080,
  and the two IPv6 listeners dropped. `run.sh` asserts that nothing else
  differs.
- **It runs as uid 33**, as host nginx's workers do.
- **The gateway** runs `gateway.conf`, `proxy_api.conf`, the route map, the trust
  file, the listener file and both entrypoint scripts, all mounted unchanged.
- **The stub API** echoes back what it received.
- **The rate-limit key** is computed by the API's own `core/ip_resolver.py`,
  loaded unchanged with the production trust list.

**18 tests pass:**

- **The legitimate path** (TLS to the edge, then the socket):
  - the upstream sees the real client in `X-Real-IP` and `X-Forwarded-For`, and `https`;
  - this holds whatever the client forged in those three headers;
  - the rate-limit key is the client.
- **TCP to the gateway, standing in for a host process:**
  - the caller's own address and `http` reach the upstream;
  - no forged value reaches it at all;
  - the rate-limit key is the caller, across six forgery shapes, including
    `127.0.0.1`, `172.31.254.1` and the literal `unix:`;
  - identity headers are stripped.
- **The socket:**
  - uids 1001, 101, 1000 and 65534 are refused;
  - uid 33 is admitted, and what it asserts is believed. That is the boundary:
    host nginx always overwrites both headers;
  - the directory is `0:33 0770` and the socket is `0666`.

**Two more checks:**

- **A `kill -9` leaves a stale socket.** The cleanup script removes it, nginx
  starts, and the legitimate-path tests pass again.
- **The logs:** no forged address is logged as the client of an untrusted peer.
  The one forged client in the gateway log is the deliberate uid-33 test.

### 4.2 Live, after the change (`live_checks.py trust` and `ratelimit`)

- **TCP caller:** the host process sent the same forged request as in §1. The
  API's 429 names **`ip=172.31.254.1`**, its own address. The redirect is
  `http://…` and carries no HSTS.
- **The socket as the operator account:** `PermissionError`.
- **Through `:443`:** eleven requests to `/api/auth/check-email`, each forging a
  new address. The 11th got the application's 429 with `ip=127.0.0.1`, and a
  second client (`10.180.22.127`) was unaffected. The gateway log shows
  `peer=unix:`, with `client` = the real address.

### 4.3 Static (`gateway/production/tests`, 24 tests)

These pin that:

- the trust file names `unix:` and no IP anywhere, including `172.31.254.1`;
- the listener is added per deployment;
- the compose bind, the group and the mounts are as described;
- the stale-socket script runs before the CORS script;
- host nginx's gateway file differs from the direct file only in `proxy_pass`;
- the switch script's pins match the files, and it recognises the 10.5 SHA
  without installing it;
- the script's single docker action is recreating `api-gateway`;
- every failure in `harden` lands on direct.

## 5. Post-cut-over observation (live, owner's account)

The owner provided the credential for this run. It was passed through the
environment from a mode-0600 file, which was deleted as soon as the run started.
It was never on a command line and never printed or written.

**The one-minute battery through the socket gateway: 21/21 PASS.** It covers:

- login, `/auth/me` byte-identical to direct, and spoofed identity headers
  changing nothing;
- `X-Request-ID` preserved once, CORS on a success, and HSTS once;
- downloads by bearer and by ticket, byte-identical, and ticket reuse within 60 s;
- ticket precedence both ways, and a ticket refused as a bearer and vice versa;
- `DELETE /reports`;
- scan and web-scan WebSockets, SSE `connected` in under 2 s, and the streamed PDF;
- a 20 MiB upload reaching the application whole;
- refresh rotation and logout.

Authenticated `/auth/me` latency, gateway vs direct: p50 53.57 / 44.44 ms and
p95 58.79 / 49.26 ms. In 10.5 the gateway's p95 was 79.46.

**One session held past its access token's lifetime** (13:24–13:55 IST, `observe_10_6.json`):
**6/6 PASS.**

| Check                                                  | Result                                                                                                                                         |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Notification SSE open through the whole token lifetime | 200. Held **1,850 s (30.8 min)**, 76 events, `connected` first, heartbeats never more than **25.1 s** apart                                    |
| Scan WebSocket                                         | 101, 3 frames, then the server's own close frame at 40 s (the scan is complete)                                                                |
| The access token, 20 s after its `exp`                 | **401 through the gateway and 401 direct.** The gateway's refusal is the application's `Invalid or expired token` body with `request_id: null` |
| `/auth/refresh` after expiry                           | 200, with a new access token and a rotated cookie                                                                                              |
| The refreshed token                                    | accepted through the gateway                                                                                                                   |
| Logout, then refresh                                   | 200, then 401                                                                                                                                  |

**Streams outlive the token.** The SSE stream opened with the first token kept
flowing after that token expired. The application authenticates a stream when
it opens, and the gateway does the same, since `auth_request` runs once per
request. This is the application's existing behaviour, recorded here and not
changed. A revoked session's open stream stays open until it disconnects.

**The first attempt was a defect in the probe, not in the gateway.** The
probe's first run checked "expired" about 90 s before the token actually
expired. The wait was measured from the end of the WebSocket hold, and that
socket closed early. The probe now waits for an absolute deadline — the token's
`exp` plus 20 s — and records how long after expiry it checked (`20.0`).

**The browser.** The owner asked that everything be run from here with their
credential, so no interactive browser session was run. Silent refresh is
exercised above by the same `/api/auth/refresh` call the SPA makes, through the
same host nginx location. One difference remains: the cookie is sent by the
script, not by a browser's cookie jar.

**Unchanged by the migration (1,140-request capture, before vs after
`harden`):** 1,140 / 1,140 identical. The capture is the credential-less matrix
from 10.5 §6.1: every route's refusals, the public routes, OPTIONS, 404/405/307,
`/api/ir/*`, CORS, the security headers, WebSocket refusals, the SPA and the
`:80` redirect.

**Latency (200 requests each, new connection each time):**

| Series                              | p50 / p95 (ms) |
| ----------------------------------- | -------------- |
| `:443` public, 10.5 over TCP        | 5.36 / 7.09    |
| `:443` public, 10.6 over the socket | 4.96 / 6.61    |
| `:443` refusal, 10.5                | 5.42 / 7.03    |
| `:443` refusal, 10.6                | 4.66 / 5.93    |

There were no errors in any series.

**Logs:**

- The gateway and gateway-auth logs contain **0** JWT-shaped strings and **0**
  `ticket=` strings.
- The gateway logs `$uri` with no query string, the peer, the resolved client,
  the principal id and the `jti`.

## 6. F10-3 — WebSocket tickets in logs (measured, not changed)

A WebSocket ticket is a 60-second, reusable credential, and it travels in the
URL (`?ticket=`). Where it lands:

| Log                                                          | Count (30 Sep 2026)                                                                                                                                |
| ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| gateway, gateway-auth                                        | **0**                                                                                                                                              |
| API container (uvicorn `WebSocket …?ticket=…` line)          | **23** lines since the API restarted at 11:03 IST; every one is from this phase's own probes. The API logs no HTTP requests, only WebSocket lines. |
| host nginx `access.log` (current and 12 rotated, `logcount`) | **156** lines with `ticket=`, **91** of them WebSocket (`/progress?ticket=`); **63** with `token=` (the reset and verify links of 10.1 fact 9)     |

- **These are full ticket values, in two logs.** They can be used for 60 s
  after issue, which is well before any log is read. After that they are
  inert, but they remain a credential-shaped record in retained logs.
- **The fixes are the two recorded in the proposal**, both unchanged here as
  instructed:
  - F10-3: a filter on uvicorn's WebSocket access line, in the application;
  - O14: host nginx's log format.
- **A second observation on the same line.** The uvicorn line records the
  socket peer — the gateway, or `172.18.0.1` — not the resolved client. It
  cannot serve as an audit record of who opened a socket. The audit trail, not
  this line, is the record of that.

## 7. M3 — the final result

**M3 is STILL RUNNING and is not claimed complete.** The sampler runs until
30 Sep 20:51 IST. At the owner's instruction this phase was committed at
14:04 IST, before that. What follows is its state at 14:04:15 IST, summarised
by `scripts/gateway/cutover/m3_summary.py`. The final figures belong to 10.7,
which should re-run that script on the finished log.

The sampler is read-only and reads `/proc`. Every 10 s it records ESTABLISHED
sockets: host sockets dialling `127.0.0.1:8000`, with their uid, and sockets
on the API's `:8000`, with their peer.

| Period (IST)                                              | Samples (h)   | Host dialers of `127.0.0.1:8000` (samples) | API peers on `:8000` (samples)        |
| --------------------------------------------------------- | ------------- | ------------------------------------------ | ------------------------------------- |
| 29 Sep 18:51 – 30 Sep 11:26, before the cut-over          | 5,942 (16.51) | `www-data` 6, `cdac` 4                     | `172.18.0.1` 11                       |
| 11:26 – 12:34, gateway over TCP (10.5)                    | 408 (1.13)    | none                                       | `172.31.254.10` (gateway) 2           |
| 12:34 – 14:04, gateway over the socket (10.6), incomplete | 534 (1.48)    | **`cdac` 423**                             | `172.31.254.10` 376, `172.18.0.1` 423 |

**An unexpected caller was found.** From about 12:53 IST, one long-lived
connection to `127.0.0.1:8000` was held by **the VS Code Remote-SSH server
process** (`~/.vscode-server/…/node`, uid `cdac`, pid 1995515). It was open in
every sample since then, and it is still open at 14:04.

- **What it is consistent with:** a VS Code forwarded port, meaning someone on
  the workstation using `http://localhost:8000` through the SSH session.
- **What we don't know:** which tab or tool on the workstation opened it. The
  sampler cannot see that.
- **Why it matters:**
  - That traffic goes to the API **directly**. It bypasses host nginx, the
    gateway and gateway-auth.
  - It arrives as `172.18.0.1`, which is trusted, so what it asserts about
    itself is believed.
  - **Closing `:8000` in 10.7 would silently cut it off.**

**What the partial result supports:**

- Since the cut-over, host nginx has not dialled `:8000` at all.
- No container other than the gateway was seen calling the API.
- The one host caller found is the VS Code connection above. The owner must
  identify it, and move it or accept losing it, before 10.7.
- **What it does not show:** short-lived connections that fall between the
  10-second samples. The API logs HTTP requests without their peer, so the
  sampler is the only runtime evidence. A per-request log of `:8000` callers
  for a period would complete M6.

**Static cross-check.** Nothing in the crontab, `/etc/cron.d` or the systemd
units calls `:8000`. In the repository only three things reference it:

- the Vite dev-server proxy, used in development;
- `scripts/validate_release.ps1`, a Windows tool;
- the frontend container's `/api/` → `api:8000`. This goes container to
  container, so the sampler does not see it (fact 8, §9).

## 8. Regression

| Suite                                    | Result                                                                                    |
| ---------------------------------------- | ----------------------------------------------------------------------------------------- |
| trust harness (new)                      | 18 passed, plus the stale-socket restart (3) and the log checks                           |
| `gateway/production/tests` (10.5 + 10.6) | 24 passed                                                                                 |
| gateway-auth unit tests                  | 133 passed                                                                                |
| 10.2d harness                            | 53 + 9 passed; 243 log lines, 0 token problems                                            |
| 10.3 alongside + 10.4 TLS                | 33 + 20 + 45 passed; 802 log lines, 0 token problems; production untouched during the run |
| full backend suite                       | **6,300 passed, 211 skipped, 0 failed** (12 min 47 s)                                     |

**Application invariants, live API, before and after** (identical):

| Invariant           | Value       |
| ------------------- | ----------- |
| OpenAPI SHA-256     | `2fc271bb…` |
| routes              | 273         |
| rate-limited routes | 93          |
| Celery tasks        | 21          |
| beat entries        | 11          |

**Production fingerprint, before and after 10.6.** The only differences are:

- the host nginx file (`79d45132…` → `5682c968…`);
- `ccure-api-gateway`'s start time and compose hash.

Everything else is unchanged:

- `nginx.conf` and every host listener;
- every other container, including `ccure-api`, which was not restarted;
- the keyset and the JWKS;
- `ES256`, and legacy `false`;
- alembic head `f3b5d7e9a1c4`, 68 tables, and the column and constraint digests.

## 9. Remaining risks

- **`www-data` and root are trusted, by design.** They are host nginx and the
  host's administrator. **Membership of the `docker` group is root on this VM**
  and can do anything, including this. The operator account is in `docker`.
- **`:8000` is still published and `172.18.0.1` still trusted**, as instructed.
  Any host process can still forge a client address on the direct port. 10.7
  closes it, and the M3 result in §7 is its evidence.
- **The frontend container's `/api/` → `api:8000` proxy** (fact 8) is a second
  way to the API that skips the gateway. Since 10.3 it cannot forge an address,
  but it bypasses gateway-auth. 10.7 must remove it or send it through the gateway.
- **Tickets and reset tokens in logs** (§6): F10-3 and O14 are still open.
- **The gateway's TCP `:8080` still answers.** It is harmless now, since no
  caller is trusted, but it is a second way in for anything on the internal
  network. Removing it would change the shared `gateway.conf`; left for 10.7.
- **`beat`, `worker` and `web-worker` compose drift** is pre-existing, and
  every command used `--no-deps`.
