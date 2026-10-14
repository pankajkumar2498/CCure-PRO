# Phase 10.3 — Gateway alongside, and the proxy trust boundary (F10-1)

|                      |                                                                                                                                                                                                                                                                       |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**           | Committed with this document. **No production cut-over**: host nginx still sends `:443` straight to `:8000`, `:8000` stays published, and no live container, configuration, database, key or credential was touched.                                                  |
| **Baseline**         | `e85fa82` (Phase 10.2 complete). The 10.2 design and 10.1 characterisation remain the source of truth.                                                                                                                                                                |
| **Frozen decisions** | X2-a, X6-a (`/api/ir/*` 404), 17 / 251 / 3 / 2 route classes, `OPTIONS` unauthenticated, `DELETE /reports/{id}` ticket-or-bearer, no `X-Request-ID` on gateway refusals, identity headers stripped, gateway-auth public-key-only, legacy HS256 refused. None changed. |

## 1. F10-1: root cause

The API ran uvicorn with `--proxy-headers --forwarded-allow-ips='*'` (`Backend/start.sh`). In uvicorn 0.29, `'*'` makes **every** peer a trusted proxy. For every caller able to reach `:8000`:

- the scope's client address was replaced with the **leftmost** `X-Forwarded-For` entry, the one field a client controls;
- the scheme was replaced with the caller's `X-Forwarded-Proto`.

That happened before the application ran. `core.ip_resolver`'s own "is the peer a trusted proxy?" test therefore judged the _forged_ address, never the socket peer.

Two more things kept it open:

- **`_is_secure_request` read the raw `X-Forwarded-Proto` header**, so any caller could claim HTTPS (HSTS).
- **`TRUSTED_PROXIES` defaulted to the whole Docker pool** (`172.16.0.0/12`), so even without uvicorn every container on the compose network was a proxy. That includes the frontend's `/api/` proxy on `:3200`, which _appends_ `X-Forwarded-For`.

Phase 10.1 proved all of this live: a forged `X-Forwarded-For` became the rate-limit key directly on `:8000` and through `:3200/api/`, and only host nginx (which overwrites the header) produced the real client.

## 2. The fix

| File                                  | Change                                                                                                                                                                                                                                                                                                                                   |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Backend/start.sh`                    | `--no-proxy-headers` (both branches). uvicorn trusts no forwarding header.                                                                                                                                                                                                                                                               |
| `Backend/core/trusted_proxy.py` (new) | `TrustedProxyHeadersMiddleware`, registered **outermost** in `main.py`. For a peer in `TRUSTED_PROXIES`, and only then, it sets the scope's client from the forwarding headers and its scheme from `X-Forwarded-Proto` (exactly `http`/`https`; `ws`/`wss` on a WebSocket). An untrusted peer's scope is left as the socket reported it. |
| `Backend/core/ip_resolver.py`         | `resolve_client()`: the one resolution rule, now shared by `get_client_ip` (rate-limit key, audit address) and the middleware (`request.client`, `request.url`). `is_trusted_peer()`. Behaviour of `get_client_ip` unchanged.                                                                                                            |
| `Backend/main.py`                     | `_is_secure_request` reads `request.url.scheme`, the resolved scheme, never the raw header. The middleware is registered.                                                                                                                                                                                                                |
| `Backend/config.py`                   | `TRUSTED_PROXIES` default `127.0.0.1,::1,172.18.0.1`, previously `…,172.16.0.0/12`.                                                                                                                                                                                                                                                      |

Why the middleware replaces uvicorn's option rather than narrowing it:

- **uvicorn 0.29 takes exact addresses only**, so a range cannot be expressed.
- **It hands the application a `None` client when every hop is trusted.**
- **It would be a second, separately configured trust list** from the one `get_client_ip` reads.

### Trusted peers, and why

| Peer               | Where                                                                                        | Why                                                                                                                                                                   |
| ------------------ | -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `172.18.0.1`       | the live compose network `ccure-audit-pro_default` (`172.18.0.0/16`, gateway `.1`, measured) | Host nginx reaches the loopback-published `:8000` through docker-proxy, and the API sees that as the network gateway. It is the one proxy on today's production path. |
| `127.0.0.1`, `::1` | inside the API container                                                                     | In-container callers only. Nothing outside the container arrives from loopback, since `:8000` traffic arrives from docker-proxy.                                      |

**Nothing else.** Specifically _not_:

- the frontend container (`172.18.0.8`), whose `/api/` proxy appends `X-Forwarded-For`;
- workers, beat, portainer or any other container;
- the Docker pool;
- a LAN range.

The gateway container is added by its fixed address **when it fronts the API** (10.5). Until then nothing on the live network needs to trust it.

**Residual (unchanged by design, closed at cut-over):** every _host_ process connecting to `127.0.0.1:8000` also arrives as `172.18.0.1`, so it is treated as host nginx. Only unpublishing `:8000`, so that the API is reachable through the gateway alone and the gateway's address is the one trusted peer, closes that. This is the configuration the alongside `api` service runs (§3) and proves.

### Activation on the live API

The committed code is **not yet running live**: the API container was not restarted in this phase. `start.sh`, `main.py` and `config.py` are bind-mounted, so the fix takes effect at the API's **next restart**, with the values above, and needs no environment change. That restart is the owner's decision.

**Verification after that restart:**

- the start-up line `Client IP resolution trusts 3 proxy range(s): 127.0.0.1/32, ::1/128, 172.18.0.1/32`;
- a request through `https://ccurepro.cdac.in` logs the real client in any `RATE_LIMIT_REJECTED` line;
- a forged `X-Forwarded-For` sent to `127.0.0.1:3200/api/…` now keys on `172.18.0.8`.

**Rollback:** `git revert` of this commit and restart the API. Or, to restore only the old trust width, set `TRUSTED_PROXIES` on the API service.

## 3. Alongside validation against the real application

`gateway/alongside/` is its own compose project (`ccure-gw-alongside`, `10.254.20.0/24`), run by `gateway/alongside/run.sh`. It contains:

- **`api`:** the real backend image, running a scratch copy of the working tree's `Backend/`. Every `.env*` file is excluded and the run asserts none reached the copy. It uses the real start-up path: migrations on a fresh database, then seeding. It has its own Postgres and Redis and a throwaway token keyset. Its `TRUSTED_PROXIES` is **the gateway only** (`10.254.20.10`), the target state.
- **`api-edge`:** the same code with **production's committed trust**: the docker-proxy peer (`10.254.20.1`, host nginx's position; `172.18.0.1` live).
- **`gateway` and `gateway-auth`:** the committed 10.2 artefacts, unchanged. `route_policy.map` is mounted, never copied. Only the site file is new (`gateway/nginx/site/alongside.conf`, trusting the edge's docker-proxy address).
- **`insider`:** an untrusted container peer (`10.254.20.50`).
- **The runner:** it uses the **host network**, so it reaches the loopback-published ports exactly as host nginx does.
- **Credentials:** one throwaway superadmin, whose password is generated per run and never printed. All tokens are real, issued by that `api`. No live credential, key or database was used.

**Results: 33 passed.**

| Area             | Result (gateway compared with the same request to the application directly)                                                                                                                                                         |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Public routes    | All 17 reachable without credentials; 14 compared response for response, the 3 rate-limited ones (3/min) reached once                                                                                                               |
| Bearer           | Valid → forwarded, identical body. Missing, `Bearer `, `Basic`, garbage → identical status and body; the gateway sends no `X-Request-ID` and `request_id: null`                                                                     |
| Identity         | Spoofed `X-Tenant-ID`, `X-User-ID`, `X-Ccure-Auth-Sub` and `X-Forwarded-User` change nothing: `/auth/me` is the verified user                                                                                                       |
| Tickets          | Valid ticket, ticket-first (valid ticket + garbage bearer; garbage ticket + valid bearer → the application's 401), empty ticket, invalid, missing, reuse within 60 s: identical. `DELETE /reports/{id}` ticket-or-bearer: identical |
| WebSocket        | Valid ticket: same outcome as direct. Missing or invalid ticket: bare 403, empty body, both paths                                                                                                                                   |
| SSE              | `/notifications/stream`: 200 `text/event-stream`, first event `connected`, both paths                                                                                                                                               |
| Streaming        | ISO SoA PDF: same status and type, complete PDF                                                                                                                                                                                     |
| `OPTIONS`        | Preflight reaches the application: 200 with its CORS answer                                                                                                                                                                         |
| 404/405/307      | Unknown path, wrong method (with `Allow`), `/api/ir/*`: identical. The 307 is `https://` through the gateway and `http://` directly (§4)                                                                                            |
| `X-Request-ID`   | A client value is preserved, once                                                                                                                                                                                                   |
| CORS             | Allow-Origin, Allow-Credentials and Vary equal on responses and refusals                                                                                                                                                            |
| Security headers | Each exactly once and equal. HSTS through the gateway only (the edge's https)                                                                                                                                                       |
| Rate limits      | Through the gateway each edge-asserted client has its own bucket: 10 allowed, the 11th a real 429 `RATE_LIMIT_EXCEEDED` with `Retry-After`, and a second client unaffected                                                          |

**F10-1 regressions (real application):**

- **A direct caller** (`api`, untrusted docker-proxy peer) cannot forge a client address: twelve different forged addresses shared **one** bucket. It also cannot forge HTTPS: the redirect is `http://` and there is no HSTS.
- **A container caller** (`insider` → `api`, and `insider` → `api-edge`) cannot forge either.
- **The gateway** ignores an untrusted peer's `X-Real-IP` and `X-Forwarded-Proto` too.
- **Production's committed config** (`api-edge`) still honours host nginx's position: a per-client bucket, a second client unaffected, and an `https://` redirect.

**Latency** (250 requests per path, a new connection for each, as host nginx does):

| Path                       | Direct p50 / p95 | Gateway p50 / p95 | Overhead p50 / p95   |
| -------------------------- | ---------------- | ----------------- | -------------------- |
| Public (no `auth_request`) | 1.53 / 1.77 ms   | 1.88 / 2.16 ms    | **+0.35 / +0.39 ms** |
| Bearer (`auth_request`)    | 8.64 / 9.86 ms   | 10.46 / 11.55 ms  | **+1.82 / +1.69 ms** |

Both are within the design's +5 ms p95 budget.

**Exposure:**

- `127.0.0.1` only: `8082` (gateway), `18000`/`18001` (the two APIs, for comparison), `18050` (the relay).
- gateway-auth publishes nothing.
- gateway (uid 101) and gateway-auth (uid 10001) are read-only with all capabilities dropped, and hold no private key, keyset or `.env`.

**Logs:**

- **Gateway and gateway-auth:** 617 lines (573 access records), **0** of the run's 6 real tokens, and no query string, credential header, cookie or Referer.
- **The application's own log holds the WebSocket ticket** in 3 uvicorn `WebSocket …?ticket=…` access lines. That is the pre-existing F10-3, not the gateway, and it is deferred (§6).

## 4. Direct `:8000` — what it is and is not

| Caller                                              | Today (live, until the API restarts)                    | After this commit (on restart)                                          | After cut-over (10.5)    |
| --------------------------------------------------- | ------------------------------------------------------- | ----------------------------------------------------------------------- | ------------------------ |
| Host nginx (`:443` → `:8000`)                       | client and scheme from its headers (it overwrites them) | same: `172.18.0.1` is trusted                                           | through the gateway only |
| Another **host** process → `127.0.0.1:8000`         | can forge address and scheme                            | **can still forge**: it arrives as `172.18.0.1`, the same as host nginx | `:8000` unpublished      |
| A container → `api:8000` (worker, beat, portainer…) | can forge                                               | **cannot**: its own address, `http`                                     | cannot                   |
| `127.0.0.1:3200/api/` (frontend proxy)              | can forge (appended header)                             | **cannot**: keyed on `172.18.0.8`, `http`                               | to be removed (10.7)     |
| LAN                                                 | not reachable (`:8000` is loopback-bound)               | same                                                                    | same                     |

## 5. Tests

- Trust boundary: `tests/security/test_trusted_proxy_boundary.py`, **36 tests**.
- Existing fixtures updated: two in `test_ip_resolver.py` and `test_rate_limiting.py` named a container as "the proxy", which is exactly the assumption F10-1 removes.
- Alongside: 33 passed. The 10.2d harness: 62 passed. gateway-auth: 133. Static config: 13.
- Full backend suite: **6,300 passed, 211 skipped, 0 failed**.
- **OpenAPI, the 273-route table, limiter registrations (93), Celery tasks (21) and beat (11) are identical to the 10.2 baseline.**

## 6. Deferred, recorded

- **Activating the trust fix live** is an API restart (§2), for the owner.
- **F10-3:** uvicorn's WebSocket access line writes the ticket to the application log. Pre-existing; it needs a logging filter in the application. Not changed here.
- **The host-process residual** on `:8000` (§4) is closed by the cut-over.
- **The gateway's fixed address on the live network:** the live default network was created without a user-configured subnet. Whether Docker accepts a static `ipv4_address` there, or a dedicated gateway network is needed, is settled at the cut-over.
- **`Backend/openapi.json` is stale** (it lacks `/auth/jwks.json` and `/auth/service-token`; found in 10.2c). Not fixed, as instructed.
