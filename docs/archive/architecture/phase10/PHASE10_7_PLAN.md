# Phase 10.7 — Gateway-only API access (implementation plan, for review)

|                                   |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**                        | **Approved by the owner and implemented on 30 Sep 2026** — outcome in [`PHASE10_7_GATEWAY_ONLY.md`](../../../architecture/phase10/PHASE10_7_GATEWAY_ONLY.md), which records the one change of order (§6 of the outcome: `cutover` before restoring the API). Original status: plan only. Written 30 Sep 2026 against HEAD `491e7fa` (10.6), after the verification-only readiness pass.                                                                                                                                                                                                  |
| **Owner decisions (30 Sep 2026)** | (1) M3 completes at 20:51 IST before it is claimed. (2) The VS Code forwards of 8000 and 3200 are not needed and are removed. (3) The frontend's `/api/` is routed **through the gateway**, not deleted, and the UX4G harness must keep working. (4) Rollback capability is kept as an explicit emergency procedure; `:8000` stays closed in normal operation. (5) The second-machine test (21/21 plus a full scan over `https://10.180.22.127/`) is the evidence that LAN users do not need `:8000`. (6) Certificate and CA are unchanged; the browser warning is a separate follow-up. |
| **Unchanged**                     | X2-a, X6-a (`/api/ir/*` 404), route classes, token policy, signing keys, the database, host nginx's request buffering and its TLS, the unix-socket edge (10.6), F10-3, O14, the stale `Backend/openapi.json`.                                                                                                                                                                                                                                                                                                                                                                            |

## 1. What the readiness pass established (evidence for this plan)

- **LAN users need `:443` only.** From `10.180.6.30` over `https://10.180.22.127/`
  (IP as `Host` and TLS name), 21/21 credentialed checks passed:

  - login, session, and refresh;
  - WebSocket and SSE;
  - a 20 MiB upload, and downloads by ticket and by bearer.

  A full basic scan also passed: start, WebSocket progress, status reaching
  `complete`, the scan-events SSE stream, and the report PDF.

- **The SPA does not use `:8000` or `:3200`.** It was built with
  `VITE_API_BASE_URL=/api`, a relative path, and the served bundle contains
  neither `:8000` nor `:3200`. The gateway log shows every request from that
  machine as `peer=unix:` with the correct `client`.
- **From the LAN, `:8000` and `:3200` are not reachable at all.** Both are bound
  to loopback.
- **The remaining users of `:8000`:**
  - the VS Code Remote-SSH forward. On the workstation, `Code.exe` listens on
    `127.0.0.1:8000` and `:3200`; on the VM, the VS Code server holds one
    keep-alive connection to `127.0.0.1:8000`, open since 12:53 IST;
  - this project's own probe tooling.
  - No cron job, systemd unit or backend component calls it.
- **The frontend `/api/` shortcut** (`127.0.0.1:3200/api/` → frontend nginx →
  `api:8000`):
  - Since 28 Sep it carried 38 requests: this project's `curl` probes, plus
    **one real browser session on 29 Sep at 23:02**. That session was Windows
    Chrome at `http://127.0.0.1:3200`, reached through the VS Code forward. Its
    `check-email?q=probe@example.com` is the SPA's own self-registration check
    on the login page.
  - **The UX4G harness does not use the live `:3200`.** It serves its own
    frontend container, and the browser answers every `/api` call itself
    (`Frontend/scripts/ux4g-harness/README.md`).
- **New finding: unpublishing `:8000` alone does not make the API gateway-only.**

  - A host process can reach the API at its container addresses: both
    `172.18.0.7:8000` (default network) and `172.31.254.20:8000` (gateway
    network) answered 200 from the host.
  - Every container on the default network can reach `api:8000`: worker, beat,
    web-worker, frontend, portainer, db and redis.

  §4 deals with this.

## 2. Target production topology after 10.7

    LAN client ──TLS──▶ 10.180.22.127:443  host nginx (unchanged; private-CA cert)
        /api/  ──unix:/var/lib/ccure-edge/gateway.sock──▶ api-gateway 172.31.254.10
                   (the ONLY trusted edge; root:www-data 0770)   │ auth_request
                                                                  ├─▶ gateway-auth 172.31.254.11
                                                                  └─▶ api 172.31.254.20:8000
        /      ──▶ 127.0.0.1:3200  frontend (static SPA)

    127.0.0.1:3200/api/ (local tools only) ──▶ frontend nginx 172.31.254.30
                   ──TCP──▶ api-gateway :8080 (untrusted TCP client) ──▶ gateway-auth / api

| Property                                   | Before 10.7                                                   | After 10.7                                                               |
| ------------------------------------------ | ------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Published `127.0.0.1:8000`                 | yes                                                           | **no**                                                                   |
| API listens on                             | `0.0.0.0:8000` in its container (both networks)               | **`172.31.254.20:8000` only** (the internal `gateway` network)           |
| API `TRUSTED_PROXIES`                      | `127.0.0.1, ::1, 172.18.0.1, 172.31.254.10`                   | **`127.0.0.1, ::1, 172.31.254.10`**                                      |
| Frontend `/api/`                           | → `api:8000` directly (bypasses gateway-auth)                 | → **`172.31.254.10:8080`** (through the gateway, as an untrusted client) |
| Frontend networks                          | default                                                       | default + `gateway` (`172.31.254.30`)                                    |
| Host published ports                       | 80, 443, 127.0.0.1:{3200, 5432, 6379, 8000, 9443}             | 80, 443, 127.0.0.1:{3200, 5432, 6379, 9443}                              |
| Who may assert a client address to the API | host nginx on `:8000`, the gateway, and in-container loopback | **the gateway**, and in-container loopback only                          |
| Who may assert it to the gateway           | the unix socket (host nginx)                                  | unchanged                                                                |

### What remains reachable, and why it is acceptable

- **Host processes can still dial `172.31.254.20:8000`.** The host is on every
  bridge network, and no Docker setting removes it from one. Such a caller
  arrives as `172.31.254.1`, which is **untrusted**, so it cannot forge a client
  address or scheme. The application still verifies its own tokens, so the
  caller needs a valid credential exactly as it would through the gateway. What
  it skips is gateway-auth and host nginx's `limit_req`, which are both
  defence in depth.
- **To remove even that**, the API would have to listen only on a unix socket
  shared with the gateway (the 10.6 pattern, one hop further in). That requires
  code changes in gateway-auth's JWKS fetch and in the gateway's upstream. It is
  recorded as a **follow-up (10.8, optional)**, not done here.
- **Anyone in the `docker` group** is root on this VM, and nothing here changes
  that.

## 3. Changes, file by file

| #   | File                                                                   | Change                                                                                                                                                                                                                                                                                                                                                                     |
| --- | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C1  | `docker-compose.yml` — `api`                                           | Remove `ports: 127.0.0.1:8000:8000`. Set `TRUSTED_PROXIES=127.0.0.1,::1,172.31.254.10`. Add `API_BIND_HOST=172.31.254.20` (C2). The comments name the emergency procedure (§6).                                                                                                                                                                                            |
| C2  | `Backend/start.sh`                                                     | `--host ${API_BIND_HOST:-0.0.0.0}` in both branches. The default keeps every other user of `start.sh` unchanged: the alongside stack, and any developer setup.                                                                                                                                                                                                             |
| C3  | `docker-compose.yml` — `frontend`                                      | Join the `gateway` network at `172.31.254.30`, keeping the default network as it is. Keep `127.0.0.1:3200:80`: host nginx serves the SPA from it.                                                                                                                                                                                                                          |
| C4  | `Frontend/nginx.conf` — `location /api/`                               | `proxy_pass http://172.31.254.10:8080;` (**no URI**, so `/api` is kept and the gateway strips it) in place of `http://api:8000/`. Stop sending `X-Real-IP`/`X-Forwarded-For`/`X-Forwarded-Proto`, which the gateway ignores from TCP anyway, so the file says what actually happens. Keep the Upgrade headers, the 50 MB body limit, buffering off and the 3600 s timeout. |
| C5  | frontend image                                                         | Rebuild, because the config is baked in (`COPY nginx.conf`). There have been **no frontend commits since the running image was built** (28 Sep), and `npm ci` is lock-pinned. The rebuilt bundle must have **identical asset file hashes** (§7 V-F1), which proves only `nginx.conf` changed. The current image is kept as `ccure-audit-pro-frontend:pre-10.7`.            |
| C6  | `docker-compose.emergency-direct.yml` (new)                            | An override used **only** in an emergency (§6): it re-publishes `127.0.0.1:8000:8000`, restores `TRUSTED_PROXIES=127.0.0.1,::1,172.18.0.1,172.31.254.10` and sets `API_BIND_HOST=0.0.0.0`. Nothing reads it in normal operation.                                                                                                                                           |
| C7  | `scripts/linux/gateway_edge_switch.sh`                                 | `rollback` refuses unless `127.0.0.1:8000` is actually listening, and prints the emergency procedure. Without that check, `rollback` would install a file that can only fail (its proof would catch it, but the operator deserves the reason first). A new `emergency-status` prints what state each layer is in. No other behaviour changes.                              |
| C8  | `scripts/gateway/cutover/live_checks.py`, `fingerprint.sh`             | Take the "direct" reference as `172.31.254.20:8000` (reachable from the host, untrusted) rather than `127.0.0.1:8000`. `fingerprint.sh` records the absence of the `:8000` listener, and the API's bind address.                                                                                                                                                           |
| C9  | tests (§8)                                                             | static production tests, trust harness extension, alongside unchanged                                                                                                                                                                                                                                                                                                      |
| C10 | `CLAUDE.md`, `PHASE10_API_GATEWAY.md`, new `PHASE10_7_GATEWAY_ONLY.md` | Record the change, the topology and the emergency procedure. Update CLAUDE.md where it says `:8000` is "published" or that the api is "`127.0.0.1:8000`".                                                                                                                                                                                                                  |

**Not changed:**

- host nginx files and the socket edge;
- gateway-auth, and the gateway's configuration — its TCP `:8080` stays, because
  C4 now uses it, and it trusts nobody;
- certificates;
- token policy.

## 4. Gateway-only API access — how each path is closed

| Path to the API today                          | After 10.7                                                                       | Mechanism       |
| ---------------------------------------------- | -------------------------------------------------------------------------------- | --------------- |
| LAN → `:443` → host nginx → gateway            | unchanged (the one production path)                                              | —               |
| host process → `127.0.0.1:8000` (docker-proxy) | **refused** (nothing listening)                                                  | C1              |
| host process → `172.18.0.7:8000`               | **refused** (the API does not listen on the default network)                     | C2              |
| container on default network → `api:8000`      | **refused**, same reason                                                         | C2              |
| frontend `:3200/api/` → `api:8000`             | → gateway → gateway-auth → API                                                   | C3, C4          |
| VS Code forward → `127.0.0.1:8000`             | removed (§5), and nothing is listening anyway                                    | C1, §5          |
| host process → `172.31.254.20:8000`            | **still reachable, untrusted** (§2): no forgery, application auth still required | residual (10.8) |
| gateway / gateway-auth → `172.31.254.20:8000`  | unchanged                                                                        | —               |

## 5. VS Code forwarding clean-up (owner, before the change)

1.  In VS Code, open the **Ports** panel of the Remote-SSH window and **Stop
    Forwarding** `8000` and `3200`.
2.  Stop VS Code forwarding them again automatically. Add this to the remote
    settings (`Remote [SSH: ccurepro]` → settings.json):

        "remote.portsAttributes": {
          "8000": { "onAutoForward": "ignore" },
          "3200": { "onAutoForward": "ignore" }
        }

    After 10.7, `:3200` is still published on the VM, so auto-forwarding would
    otherwise bring it back.

3.  **Verify:**

    - on the workstation, `Get-NetTCPConnection -State Listen` shows no `Code`
      listener on 8000 or 3200;
    - on the VM, `ss -tnp` shows no VS Code-server connection to `127.0.0.1:8000`.

    I can run both checks. The M3 sampler's `cdac` series stops at that moment.

This is done **before** C1, so the dangling VS Code connection closes cleanly and
is not cut mid-flight.

## 6. Emergency rollback procedure (restores `:8000` temporarily)

**When to use it:** the gateway path is broken and can't be fixed quickly —
for example, gateway-auth cannot fetch keys, or the gateway container won't start.

**Order:** always bring the API back first, then point host nginx at it.

1.  **Re-publish and re-trust the API.** This is about 22 s of API downtime:

        docker compose -f docker-compose.yml -f docker-compose.emergency-direct.yml up -d --no-deps api

    Check: `ss -ltn | grep 127.0.0.1:8000`, and that the start-up log reads
    `trusts 4 proxy range(s): …172.18.0.1…`.

2.  **Point host nginx straight at it** (the proven pre-10.5 file, `638fd33f…`):

        sudo scripts/linux/gateway_edge_switch.sh rollback

    The script checks `:8000` is listening first (C7), then runs `nginx -t`, a
    graceful reload, and the `:443` proof. `path=direct` is proven when the API's
    own refusal carries `X-Request-ID`.

3.  **The frontend `/api/` path** still points at the gateway. If the gateway is
    down, that path answers 502. The SPA itself is unaffected, because browsers
    use host nginx's `/api/`. It is restored with the gateway.
4.  **Returning to normal:**

        docker compose up -d --no-deps api          # no override: :8000 closed again (~22 s)
        sudo scripts/linux/gateway_edge_switch.sh cutover

    `cutover` preflights the gateway through the socket, and proves the path
    over `:443`.

**What the emergency state is.** It is exactly the post-10.3 direct
configuration, which ran in production from 29 Sep until the 10.5 cut-over and
was characterised then. Nothing untested is introduced.

**A faster but degraded alternative, not recommended and not built.** Host
nginx could proxy straight to `172.31.254.20:8000` with no container change.
But the API would see every user as `172.31.254.1`, so the whole organisation
would share one rate-limit bucket — 10 logins a minute between everyone — and
the audit trail would lose every client address. It is recorded here so nobody
reaches for it believing it is harmless.

**Rehearsal.** The procedure is rehearsed **once, live, with the owner
present**, as the last step of 10.7 (§7 V-R). That costs two API restarts of
about 22 s each, and two nginx reloads.

## 7. Implementation sequence and verification

**Gate 0: prerequisites.** No change until all four hold:

- **G0.1:** M3 is finished (after 20:51 IST). The final `m3_summary.py` has run
  on the complete log and is recorded. **Every `:8000` caller in the final data
  is accounted for.** The expected ones are host nginx before the cut-over, the
  operator's probes, and the VS Code server; anything else stops the plan.
- **G0.2:** the VS Code clean-up (§5) is done and verified.
- **G0.3:** a fresh ops dump has been taken and the remote copy confirmed.
- **G0.4:** a before-fingerprint has been taken, along with the invariants
  (OpenAPI hash, 273 routes, 93 limits, 21 tasks, 11 beat entries).

**Step 1: code and tests, offline.** C2, C4, C6, C7, C8 and C9. Run every static
test and harness in isolation (§8). Nothing live changes.

**Step 2: frontend image.**

- Keep the current image as `ccure-audit-pro-frontend:pre-10.7`, then rebuild.
- **V-F1:** the new image's `/usr/share/nginx/html/assets/*` file names **and
  SHA-256s** equal the old image's, and only `/etc/nginx/conf.d/default.conf`
  differs.
- `nginx -t` passes in the new image.
- The **UX4G harness** runs one pass against the new image (`serve.mjs up` →
  `run.mjs`). With an IP literal, nginx starts even without the harness's `api`
  host override. The harness's browser interception is untouched.

**Step 3: frontend live.** Apply C3 and C5:
`docker compose up -d --no-deps frontend`. This is a short SPA blip; the API
itself is unaffected. Then verify the path from `127.0.0.1:3200/api/`:

- **V-F2:**
  - `GET /api/` → 200;
  - `GET /api/api/pipeline-modes` → 200;
  - a bearer route with no credential → 403 **without** `X-Request-ID`, which
    proves the gateway answered;
  - the gateway log shows `peer=172.31.254.30 client=172.31.254.30`.
- **V-F3:** a forged `X-Forwarded-For`/`X-Real-IP`/`X-Forwarded-Proto` sent to
  `:3200` → the API's key is `172.31.254.30`, the scheme is `http`, and there is
  no HSTS (rate-limit test on `/auth/check-email`).
- **V-F4:** with the owner's credential over `:3200`:
  - login, `/auth/me`, a ticket download, WebSocket 101 plus the first frame,
    SSE `connected`, and a 20 MiB upload refused whole — the 50 MB frontend
    limit, then the gateway, then the API;
  - refresh, and logout.
- **V-F5:** SPA and assets over `:443` are byte-identical to before (the capture
  comparison, §V-L2).

**Step 4: close `:8000`.** Apply C1 and C2: `docker compose up -d --no-deps api`.
About 22 s of API downtime, announced to the owner beforehand. Then verify:

- **V-C1:** `ss -ltn` shows no `127.0.0.1:8000`, and `curl 127.0.0.1:8000` is
  refused. From the workstation, `10.180.22.127:8000` is refused, as before.
- **V-C2:** inside the API, uvicorn listens on `172.31.254.20:8000` only.
  `172.18.0.7:8000` is refused from the host, and `api:8000` is refused from
  `ccure-beat`.
- **V-C3:** the start-up log reads
  `Client IP resolution trusts 3 proxy range(s): 127.0.0.1/32, ::1/128, 172.31.254.10/32`.
- **V-C4:** a host process at `172.31.254.20:8000` with forged headers → key
  `172.31.254.1`, `http`, no HSTS. That is the residual: untrusted.
- **V-C5:** gateway-auth still fetches the JWKS: `/healthz` is 200, and a bearer
  success goes through the gateway.

**Step 5: LAN and application verification.**

- **V-L1:** from the second machine (`10.180.6.30`), over
  `https://10.180.22.127/`, re-run the readiness probes: the 21-check battery and
  the full basic scan (WebSocket, SSE, status, report). The result must equal the
  readiness pass. The "direct" reference is now C8's.
- **V-L2:** the 1,140-request capture over `:443`, before vs after → identical.
- **V-L3:** the credentialed observation (`observe`, about 32 min), repeated:
  real token expiry, refresh, and a 30-minute SSE stream through the gateway.
- **V-L4:** rate-limit identity through `:443`, per real client, with forged
  headers ignored; plus the `trust` checks from 10.6.
- **V-L5:** leakage. The gateway and gateway-auth logs contain 0 tokens and 0
  `ticket=`. F10-3 and O14 are recorded as before, not changed.
- **V-L6:** latency and errors. 200-request series over `:443`, with no 5xx on
  any hop since the change.

**Step 6: no production path depends on `:8000`.**

- **V-N1:** a 24-hour read-only sampler with the same shape as M3, now watching
  the API's `:8000` peers. Expected peers are the gateway (`172.31.254.10`) and
  the operator's reference calls (`172.31.254.1`). **Any other peer is a
  finding.**
- **V-N2:** static search again: cron, systemd, scripts and the environments of
  every service contain no `:8000` caller except the documented tooling.

**Step 7: rehearse the emergency rollback** (V-R, owner present). Run §6 in full,
proving each state:

- direct, then `path=direct`;
- a login through `:443` works;
- back to normal, then `path=gateway`, `:8000` closed again, and trust at 3 ranges.

**Step 8: regression, then commit.**

- The full suite and every Phase 10 suite (§8).
- The after-fingerprint: only the intended differences, listed in advance —
  - the API: its compose hash and start time, no published port, its trust and bind settings;
  - the frontend: its image, compose hash and networks;
  - no other container, key, schema or nginx file.
- Commit, and stop.

## 8. Tests

| Suite                                            | Change for 10.7                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `gateway/production/tests` (static)              | Add assertions that:<br>• the API publishes no port;<br>• `TRUSTED_PROXIES` is exactly `127.0.0.1,::1,172.31.254.10`, and names neither `172.18.0.1` nor any range;<br>• `API_BIND_HOST=172.31.254.20` equals its static address;<br>• the frontend is on `gateway` at `.30`, and `Frontend/nginx.conf` proxies `/api/` to `172.31.254.10:8080` with no URI;<br>• the emergency override contains exactly the three restorations;<br>• the switch script refuses `rollback` without `:8000`. |
| trust harness (10.6)                             | Add a `frontend` service built from the **committed `Frontend/nginx.conf`** on the harness network. Assert that `/api/` through it reaches the stub **via the gateway**, and that forged headers yield the frontend's own address and `http`, both in what the stub receives and in the API resolver's key.                                                                                                                                                                                  |
| `Backend/tests` (full suite)                     | Unchanged. `start.sh`'s default keeps `0.0.0.0`, and `TestClient` does not use the network.                                                                                                                                                                                                                                                                                                                                                                                                  |
| 10.2d harness, 10.3/10.4 alongside, gateway-auth | Unchanged. Re-run: the alongside `api` uses `start.sh` with no `API_BIND_HOST`, so it keeps `0.0.0.0`.                                                                                                                                                                                                                                                                                                                                                                                       |
| UX4G harness                                     | One pass against the rebuilt image (Step 2).                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Invariants                                       | OpenAPI hash, 273 routes, 93 limits, 21 Celery tasks, 11 beat entries: identical before and after.                                                                                                                                                                                                                                                                                                                                                                                           |

## 9. Risks and how each is handled

| Risk                                                                                | Handling                                                                                                                                      |
| ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| A caller of `:8000` M3 could not see (short-lived, between samples) breaks silently | G0.1 plus V-N2 static search; V-N1 samples the API's peers for 24 h after; the emergency procedure restores `:8000` in about 22 s.            |
| The frontend rebuild ships something other than the nginx change                    | V-F1: identical asset hashes, or stop. `pre-10.7` tag for instant rollback: `docker tag` then `up -d --no-deps frontend`.                     |
| Binding the API to `172.31.254.20` fails at start (the address is not yet up)       | compose attaches networks before start. Measured in Step 1 on a scratch stack. Rollback: the emergency override sets `API_BIND_HOST=0.0.0.0`. |
| gateway-auth or the gateway down → the `:3200` tools path answers 502               | Accepted: `:3200/api/` is not a production path (§1).                                                                                         |
| The emergency override is used and forgotten, leaving `:8000` open                  | `fingerprint.sh` and the switch script's `status` report `:8000` listening as a finding; the CLAUDE.md note.                                  |
| Two API restarts in one session                                                     | Announced beforehand; done at a quiet time; no scan running (checked, as in 10.5).                                                            |

## 10. Separate follow-ups (not part of 10.7)

- **Browser certificate warning on LAN machines.** The certificate is valid for
  `10.180.22.127`, but its issuer ("CCure Audit PRO Internal Root CA (Linux
  Dev)") is not trusted by the organisation's machines. Distribute that CA, or
  issue from a CA they already trust. Owner decision; no change in 10.7.
- **10.8 (optional):** make the API listen on a unix socket shared with the
  gateway only, which closes §2's residual (host processes →
  `172.31.254.20:8000`).
- **F10-3 and O14:** tickets and reset tokens still reach the API and host
  nginx logs.
- **The stale `Backend/openapi.json`.**
- **The password shared in chat**, which should be rotated.
