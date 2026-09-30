# Phase 10 — The API Gateway (proposal)

|                    |                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**         | Approved in principle (29 Sep 2026). Decisions in §15. Implementation is staged: 10.1 characterisation done, 10.2a committed `42128b9`, 10.2b `f5d7da1`, 10.2c `5cd89c3`, 10.2d `e85fa82`; 10.3 (gateway alongside the real application, proxy trust boundary F10-1) committed with this revision — [`phase10/PHASE10_3_ALONGSIDE.md`](phase10/PHASE10_3_ALONGSIDE.md). No production cut-over; 10.4 not started. No live infrastructure has been changed. |
| **Baseline**       | HEAD `fc38b31`, measured live on `ccurepro` (10.180.22.127) on 29 Sep 2026                                                                                                                                                                                                                                                                                                                                                                                 |
| **Plan reference** | `CCURE_PLATFORM_MODULAR_ARCHITECTURE.md` rev 4: §3.2, rules 9 and 12, Phase 10 row, decisions D7 and D10                                                                                                                                                                                                                                                                                                                                                   |
| **Decides**        | D7 (gateway technology), D10 (TLS termination), the fate of `alt-gateway`, and `/api/ir/*` routing                                                                                                                                                                                                                                                                                                                                                         |

---

## 1. Summary

**Recommendation for D7:** an nginx gateway container that asks a separate **token-check container** about each request (`auth_request`). The token-check container:

- is stateless and holds no secrets;
- verifies tokens against the platform's **public** keys (JWKS);
- has no database, no Redis and no mount of `./Backend`.

**Recommendation for D10:** host nginx keeps TLS. The gateway sits behind it on loopback, and fronts `/api/` only.

**The existing `gateway` service is repurposed.** The name, container name and loopback port 8082 stay. `nginx/gateway.conf` and the plain-HTTP whole-stack mode are retired.

**`/api/ir/*` is authenticated at the gateway, then answered by the gateway itself** with an explicit `503 MODULE_NOT_DEPLOYED`. It is never proxied to the core, and never a 404.

**Cut-over in four stages:**

1. alongside;
2. validate;
3. host-nginx switch;
4. rollback switch.

The switch and the rollback are each one symlink in host nginx plus `nginx -t && systemctl reload nginx`. Port 8000 stays published on loopback until the rollback path is no longer wanted.

**Two pre-existing defects must be fixed inside Phase 10**, because the gateway makes them live (§3):

- **F10-1**: uvicorn trusts `X-Forwarded-For` from any peer, so `TRUSTED_PROXIES` is not the effective trust boundary.
- **F10-3**: download and WebSocket tickets, and emailed reset and verification tokens, are written to access logs.

---

## 2. Inventory (measured)

### 2.1 Live route table

This is the running app's `app.routes`, read inside `ccure-api`, classified by the auth dependencies each route resolves. `ENV=production`, so `/docs`, `/redoc` and `/openapi.json` are **off**.

| Class                                                                 | Count | Routes                                                                                                                                                                                                                                                                                                     |
| --------------------------------------------------------------------- | ----: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| HTTP operations                                                       |   271 | —                                                                                                                                                                                                                                                                                                          |
| · bearer (`get_current_user` / `require_permission` / `require_role`) |   251 | everything else                                                                                                                                                                                                                                                                                            |
| · ticket **or** bearer (`get_current_user_flexible`)                  |     3 | `GET /reports/download/{scan_id}`, `GET /reports/export/{scan_id}`, **`DELETE /reports/{scan_id}`**                                                                                                                                                                                                        |
| · no authentication                                                   |    17 | `/auth/`: `check-username`, `check-email`, `register`, `verify-email`, `resend-verification`, `login`, `logout`, `jwks.json`, `refresh`, `forgot-password`, `reset-password`, `login/send-email-otp`, `login/verify-mfa`, `service-token`; `GET /`; `GET /api/pipeline-modes`; `GET /api/workflow-example` |
| WebSocket                                                             |     2 | `/scans/{scan_id}/progress`, `/web-scans/{scan_id}/progress` — ticket in `?ticket=`                                                                                                                                                                                                                        |

Top-level prefixes, by route count:

- admin 63, compliance 47, auth 19;
- dashboard 17, assets 17;
- web-scans 13, remediation 12;
- scans 11, scan 11, scan-policies 11;
- scan-schedules 10, user 8;
- credentials 7, notifications 7;
- findings 6, api 4, config-audit 4;
- reports 3, topology 2, `/` 1.

No route lives under `/ir`. Public paths at the edge are `/api/` + the route path, so `/api/api/pipeline-modes` is the real public URL of the third public group. That is pre-existing and harmless.

### 2.2 Every token carrier

| #   | Carrier                              | Where it arrives                                                                                                                                                                                                                                                  | Kind (`type`)             | Verified today by                                                                                              | Notes                                                                                                                                                                                                                                                                                                                                       |
| --- | ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C1  | `Authorization: Bearer`              | 251 + 3 HTTP routes                                                                                                                                                                                                                                               | `access` (30 min)         | `tokens.verify(expected_kind=ACCESS)` + a DB load of the user, org-active check and role/org claim consistency | **Missing header → 403 `{"detail":"Not authenticated"}`** (HTTPBearer); invalid/expired → 401 + `WWW-Authenticate: Bearer`. The SPA refreshes **only on 401** (`axiosInstance.js`).                                                                                                                                                         |
| C2  | Refresh cookie `ccure_refresh_token` | `/auth/refresh`, `/auth/logout`                                                                                                                                                                                                                                   | `refresh` (7 d)           | `ccure_platform.identity.router`                                                                               | `HttpOnly`, **`Secure` static (`REFRESH_COOKIE_SECURE=True`)**, `SameSite=lax`, `Path=/`, no Domain. Also accepted **in the request body** (`RefreshRequest`).                                                                                                                                                                              |
| C3  | `?ticket=` on HTTP                   | the 3 flexible routes                                                                                                                                                                                                                                             | `ticket` (60 s)           | `tokens.verify(expected_kind=TICKET)`                                                                          | **Replayable for 60 s** (not single-use), and accepted on a destructive `DELETE`. The SPA does **not** use it — downloads are authenticated `fetch` (`utils/download.js`, `api/reports.js`).                                                                                                                                                |
| C4  | `?ticket=` on WebSocket              | both progress sockets                                                                                                                                                                                                                                             | `ticket`                  | `decode_token` (any kind) + a hand check of `type == "ticket"`                                                 | CLAUDE.md earmarks both logins for Phase 10. `scan_history` checks the `scans:read` permission; `web_scans` checks deleted/active. **Neither checks org deactivation**, which every HTTP route does. Issued by `POST /auth/ticket` (bearer). SPA sites: `NewScan.jsx`, `Phase3Results.jsx`, `CredentialedResults.jsx`, `useScanPolling.js`. |
| C5  | SSE over `fetch` + Bearer            | `GET /scans/events`, `GET /notifications/stream`                                                                                                                                                                                                                  | `access`                  | as C1                                                                                                          | Authenticated at connect only. The stream outlives the 30-minute token, unchanged behaviour. `X-Accel-Buffering: no` is set by the app.                                                                                                                                                                                                     |
| C6  | Streamed/file responses + Bearer     | 13 `/compliance/reports/*`, `/admin/audit-logs/export`, `/assets/reconciliation/drilldown` (StreamingResponse); `/web-scans/{id}/report`, `/web-scans/{id}/findings/{fid}/screenshot`, `/compliance/evidence/{id}/download`, the two report routes (FileResponse) | `access`                  | as C1                                                                                                          | Large bodies; must not be buffered to gateway disk.                                                                                                                                                                                                                                                                                         |
| C7  | Body tokens                          | `/auth/login/verify-mfa`, `send-email-otp` (`mfa_token`, 5 min); `/auth/verify-email`, `/auth/reset-password` (`token`); `/auth/refresh` (`refresh_token`)                                                                                                        | various                   | router                                                                                                         | Public routes. Not a gateway concern except that they stay **unauthenticated at the gateway**.                                                                                                                                                                                                                                              |
| C8  | **Emailed links**                    | `…/verify-email?token=` and `…/reset-password?token=` on `FRONTEND_URL`                                                                                                                                                                                           | —                         | SPA → C7                                                                                                       | They reach **host nginx's `location /`**, whose access log records the query string (F10-3).                                                                                                                                                                                                                                                |
| C9  | Service tokens                       | `POST /auth/service-token` (public), then `Bearer` with `aud` `urn:ccure:core` / `urn:ccure:ir`                                                                                                                                                                   | `service_access` (10 min) | `require_service_scope`                                                                                        | Registry empty; **no route consumes one yet** (Phase 14).                                                                                                                                                                                                                                                                                   |

### 2.3 The path today

```
client ─HTTPS→ host nginx 1.24 (0.0.0.0:443, h2, TLS, HSTS, edge zones)
                 ├─ /api/auth/ → 127.0.0.1:8000/auth/   (zone ccure_auth 30r/m b10, conn 40)
                 ├─ /api/      → 127.0.0.1:8000/        (zone ccure_api 20r/s b40, conn 40, WS upgrade, buffering off, 3600 s)
                 └─ /          → 127.0.0.1:3200         (frontend container)
       127.0.0.1:8000 ─docker-proxy→ ccure-api:8000 (uvicorn 0.29, --proxy-headers --forwarded-allow-ips='*')
```

- **Live config** is `/etc/nginx/conf.d/ccure.conf`; `sites-enabled/` is empty. `scripts/host-nginx/nginx-host.conf` in the repo is the **Windows** file, not this one.
- **Headers host nginx sets upstream:** `X-Real-IP $remote_addr`, `X-Forwarded-For $remote_addr` (**overwrite**, not append), `X-Forwarded-Proto $scheme`, `Host`.
- **Access log:** the Ubuntu default `combined` format at `/var/log/nginx/access.log`, which includes the full `$request`, **query string included**. It is readable by `adm` only, so this session could not count tickets in it (M1).
- **Docker** has no `daemon.json`, so the userland proxy is on (5 `docker-proxy` processes). A container sees loopback-published traffic as coming from **172.18.0.1**.
- **Listeners:** 0.0.0.0:80/443 (nginx), 0.0.0.0:22, **0.0.0.0:5901** (VNC; CLAUDE.md says the desktop was disabled — an incidental observation, outside Phase 10). Everything else is on 127.0.0.1: 3200, 5432, 6379, 8000, 9443. Port 8082 is free.

### 2.4 The existing `gateway` service (`alt-gateway` profile)

- **Service:** `nginx:stable-alpine`, which floats (1.30.5 today, with `auth_request`, `realip` and njs present); `127.0.0.1:${GATEWAY_PORT:-8082}:80`, where root `.env` sets `GATEWAY_PORT=8082`.
- **Config:** `nginx/gateway.conf`, which is **plain HTTP** and fronts the whole stack (`/api/` → api, `/` → frontend). It:
  - **appends** `X-Forwarded-For` (`$proxy_add_x_forwarded_for`);
  - sets `X-Forwarded-Proto $scheme` (i.e. `http`);
  - authenticates nothing;
  - adds server-level `add_header` security headers that would duplicate the API's.
- **Status:** not running and never used on the VM. The compose comment already explains why it must not be used as is (the refresh cookie is `Secure`).

### 2.5 Rate limiting and `TRUSTED_PROXIES`

- **Edge (host nginx):** the zones above, keyed on `$binary_remote_addr`. The peer is the real client there.
- **Application:**
  - `@limiter.limit` on 42 routes, plus `BaselineRateLimitMiddleware` at 600/min;
  - both keyed by `core.ip_resolver.get_client_ip`, with counters in Redis;
  - `RATE_LIMIT_MEMORY_FALLBACK=20/minute`;
  - exempt paths `/`, `/docs*`, `/redoc*`, `/openapi.json`.
- **`TRUSTED_PROXIES` live = `['127.0.0.1', '::1', '172.16.0.0/12']`.** That is the **code default**; neither `.env` sets it on the VM. CLAUDE.md says `Backend/.env` sets `127.0.0.1,::1,172.18.0.0/16` (true of the Windows deployment, not this one) — **F10-2**.
- **uvicorn runs `--proxy-headers --forwarded-allow-ips='*'`** (`Backend/start.sh`). In uvicorn 0.29, `'*'` means: for **every** peer, replace `scope["client"]` with the **leftmost** `X-Forwarded-For` entry, and replace `scope["scheme"]` from `X-Forwarded-Proto`. This happens before the app runs. `get_client_ip` therefore never sees the socket peer: its "is the peer a trusted proxy?" test is applied to whatever the leftmost XFF entry says — **F10-1**. It is safe today only because host nginx **overwrites** XFF and nothing else is supposed to reach :8000.

### 2.6 CORS, security headers, HSTS, cookie (measured through host nginx)

- **CORS:** `CORSMiddleware` with an explicit list:
  - `https://ccurepro.cdac.in`, `https://10.180.22.127`, `https://localhost`, and the localhost/127.0.0.1 dev ports;
  - `allow_credentials=True`, `allow_headers=*`.
  - An allowed-origin preflight answers 200 with ACAO echoed. A disallowed origin answers 400 without ACAO.
  - The request-ID middleware answers PNA preflights itself, against the same list.
  - Host nginx adds no CORS headers.
  - **The SPA is same-origin** (`VITE_API_BASE_URL=/api`), so its requests do not depend on CORS at all.
- **API security headers** (app): `nosniff`, `DENY`, `no-referrer`, `CSP default-src 'none'…`, `CORP same-site`, plus HSTS `max-age=300` only when `X-Forwarded-Proto: https`. Host nginx `/api/` hides and re-adds HSTS and `nosniff`. **Measured: exactly one of each on an API response.**
- **SPA (`/`):** host nginx's server-level `add_header` set **plus** the frontend container's own. Measured: **`X-Content-Type-Options`, `X-Frame-Options` and `Referrer-Policy` each appear twice** — the add_header-inheritance trap in another form. This is pre-existing and not on the gateway's path (F10-9).
- **Unauthenticated `GET /api/scans`:** measured `403`, **with** `X-Request-ID` and the full API header set.
- **Unauthenticated WebSocket upgrade:** measured `403`, **without** `X-Request-ID`. The app closes before accept, and uvicorn answers the refusal itself (F10-7).
- **`X-Request-ID` is taken from the client** if one is sent (`main.py` `_request_id_middleware`) — F10-8.

### 2.7 Identity headers and tenant

- **No production code reads `X-Tenant-ID`**, or any `X-User-*` / `X-Org-*` / `X-Auth-*` header. The only mention is the service-identity dependency's docstring, which refuses it, and `test_x_tenant_id_cannot_override_the_token` pins that.
- **The tenant comes from the verified token's `org_id` claim, re-checked against the DB user.** 107 route parameters take `?org_id=`, honoured **only for superadmin** by ten per-router `_resolve_org` helpers. That is an authorisation question for the service, not the gateway.

### 2.8 Streaming and downloads

- **Host nginx `/api/`:** `proxy_buffering off`, `proxy_cache off`, 3600 s read/send timeouts, `client_max_body_size 50m`, `Upgrade`/`Connection` mapped.
- **`/api/auth/` carries no Upgrade headers**, which is correct: there is no socket there.
- **The largest legitimate upload** is compliance evidence (25 MB cap in-app).

### 2.9 Ticket exposure in logs

| Log                                              | Records query string?                                                                                                                                                                                                                    | Measured                            |
| ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| host nginx `access.log` (`combined`)             | **yes**, for every location, including `/verify-email?token=` and `/reset-password?token=`                                                                                                                                               | not countable without `adm` (M1)    |
| `ccure-api` container log (json-file, 20 MB × 5) | **yes, for WebSockets**: uvicorn logs `'"WebSocket %s" …'` with `get_path_with_query_string` at INFO on `uvicorn.error`, which `ACCESS_LOG_LEVEL` does not govern. Measured line: `('127.0.0.1', 0) - "WebSocket /scans/x/progress" 403` | 0 tickets in the retained log today |
| uvicorn HTTP access log                          | would, but `uvicorn.access` is at WARNING                                                                                                                                                                                                | —                                   |
| `ccure.api` warning lines                        | path only, no query                                                                                                                                                                                                                      | —                                   |

---

## 3. Findings the gateway makes live

| ID        | Finding                                                                                                                                                                                                                                                                                           | Why Phase 10 must act                                                                                                                                                                                                                                                                  |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **F10-1** | `--forwarded-allow-ips='*'`: uvicorn rewrites the client address from the leftmost XFF entry **for any peer**, so `TRUSTED_PROXIES` is not the effective boundary. Any process that reaches `api:8000` (host loopback, any compose container) picks its own rate-limit bucket and audit-trail IP. | A gateway that appended XFF (as `nginx/gateway.conf` does) would hand that choice to every browser. **Fix in Phase 10:** set `--forwarded-allow-ips` to the gateway's fixed address and `172.18.0.1` (the rollback path). After that `get_client_ip`'s own walk is the boundary again. |
| **F10-2** | `TRUSTED_PROXIES` on the VM is the code default `172.16.0.0/12`, not the `/16` CLAUDE.md records.                                                                                                                                                                                                 | Set it explicitly to the gateway's address (plus loopback and `172.18.0.1` while rollback exists), and correct CLAUDE.md.                                                                                                                                                              |
| **F10-3** | Tickets and emailed reset/verification tokens are written to logs (§2.9).                                                                                                                                                                                                                         | The gateway adds a third log. Its `log_format` must log `$uri`, not `$request`/`$args`. Host nginx's format should get the same change, and the uvicorn WebSocket line needs a redacting filter. A reset token in a log is an account-takeover window.                                 |
| F10-4     | Tickets are replayable for 60 s and accepted on `DELETE /reports/{scan_id}`.                                                                                                                                                                                                                      | The gateway can restrict tickets to `GET` on the two download routes and to WebSocket upgrades. **Nothing in the SPA uses the others** (measured). Single-use tickets are a separate change (§8).                                                                                      |
| F10-5     | The WebSocket logins use `decode_any_kind` and skip the org-deactivation check.                                                                                                                                                                                                                   | CLAUDE.md earmarks them for Phase 10: move both to `tokens.verify(expected_kind=TICKET)` + `_load_auth_context_from_payload`.                                                                                                                                                          |
| F10-6     | A missing bearer answers **403**, an invalid one **401**, and the SPA refreshes only on 401.                                                                                                                                                                                                      | The gateway must **mirror both statuses and bodies exactly**, or the SPA's behaviour changes (§8, O5).                                                                                                                                                                                 |
| F10-7     | A refused WebSocket already carries no `X-Request-ID`.                                                                                                                                                                                                                                            | "No `X-Request-ID`" cannot tell gateway from app for sockets, so a different discriminator is needed (§7).                                                                                                                                                                             |
| F10-8     | The client's `X-Request-ID` is echoed verbatim.                                                                                                                                                                                                                                                   | Every "no `X-Request-ID`" test must send none. Whether the gateway strips it is O9.                                                                                                                                                                                                    |
| F10-9     | Duplicate security headers on the SPA (`/`).                                                                                                                                                                                                                                                      | Pre-existing; not on the gateway path. Recorded, not fixed here unless O11 says so.                                                                                                                                                                                                    |
| F10-10    | `127.0.0.1:8000` stays published: a host process can bypass the gateway (rule 12).                                                                                                                                                                                                                | It is also the rollback path. Remove it in a later, separate step (10.7).                                                                                                                                                                                                              |
| F10-11    | `nginx:stable-alpine` floats.                                                                                                                                                                                                                                                                     | Pin the gateway image (e.g. `nginx:1.30.5-alpine`).                                                                                                                                                                                                                                    |
| F10-12    | `nginx/gateway.conf` appends XFF, sends `X-Forwarded-Proto: http`, fronts the SPA over HTTP and authenticates nothing.                                                                                                                                                                            | Retire it (§5.3).                                                                                                                                                                                                                                                                      |
| F10-13    | The token-check component cannot reuse `tokens.py` as is. `_current_keyset()` loads a key **directory holding private keys**, and `config.py` loads `Backend/.env`, which holds `JWT_SECRET_KEY` and `MFA_ENCRYPTION_KEY`.                                                                        | The checker needs a public-only keyset source (JWKS). The verification rules must be factored into a pure module both share, so there is one verifier, not two (§5.1).                                                                                                                 |

Also observed, outside Phase 10:

- `ALLOW_SELF_REGISTRATION=True` live (CLAUDE.md says default off). The route stays public at the gateway either way.
- VNC is listening on `0.0.0.0:5901`.

---

## 4. D7 — options

### Option A (recommended): nginx gateway + `auth_request` to a token-check container

```
client ─HTTPS→ host nginx (TLS, HSTS, edge zones, XFF := $remote_addr)
                 ├─ /api/ → 127.0.0.1:8082 → ccure-gateway (nginx, compose network)
                 │             ├─ auth_request → gateway-auth:8080/check   (no published port)
                 │             ├─ /api/ir/ → 503 MODULE_NOT_DEPLOYED (after auth)   [Phase 13: ir-service]
                 │             └─ /api/    → api:8000/  (prefix stripped exactly as today)
                 └─ /     → 127.0.0.1:3200 (frontend, unchanged)
```

| Aspect                        | Design                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Trust boundary**            | Host nginx is the network edge: TLS and the true client address. The gateway is the **authentication** boundary: nothing past it is unauthenticated except the public allowlist. The api is the **authorisation** boundary, and re-verifies the token itself (rule 9). `gateway-auth` holds public keys only: it can verify and cannot mint.                                                                                                                                                                                                                                                                |
| **Where verification runs**   | `gateway-auth`, a separate container on the compose network with no published port. It is stateless and holds no DB, Redis or secrets, and does **not** mount `./Backend` or any `.env`. Keys come from `http://api:8000/auth/jwks.json`: fetched at start (not ready until fetched), cached, refetched on an unknown `kid` (at most once per 30 s), and last-good kept on fetch failure. Rules are identical to `tokens.verify`: ES256 pinned by `kid`, `iss`/`aud`/`sub`/`jti`/`iat`/`nbf`/`exp` required, leeway 0, `type` = expected kind, `ptype` checked, legacy HS256 refused (the cut-off is live). |
| **Authorization header**      | `auth_request /_auth` with `proxy_pass_request_body off`. The header is passed to the checker; `kind=access`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| **Cookies**                   | Not verified at the gateway. The refresh cookie only authenticates `/auth/refresh` and `/auth/logout`, which are public at the gateway and verified by the platform. `Set-Cookie` passes through untouched: no `proxy_cookie_path`, no `proxy_cookie_flags`.                                                                                                                                                                                                                                                                                                                                                |
| **Tickets**                   | Per-location policy. `ticket` is accepted only on `GET /api/reports/download/*`, `GET /api/reports/export/*` and the two WebSocket upgrades (O4). The checker gets the ticket from `$arg_ticket` via a request header on the subrequest, never logged.                                                                                                                                                                                                                                                                                                                                                      |
| **WebSockets**                | `auth_request` runs on the upgrade `GET` before the proxy. The upgrade then proceeds with `Upgrade`/`Connection` mapped, HTTP/1.1, 3600 s timeouts. A refusal is an HTTP 401/403 on the upgrade, and the browser's `onerror` fires as it does today.                                                                                                                                                                                                                                                                                                                                                        |
| **SSE, streaming, downloads** | Authenticated at connect, as today. `proxy_buffering off`, `proxy_request_buffering off` (evidence bodies do not land in the gateway's temp dir), `proxy_max_temp_file_size 0`, 3600 s timeouts, `client_max_body_size 50m` (same as the edge). `X-Accel-Buffering: no` from the app is honoured.                                                                                                                                                                                                                                                                                                           |
| **Identity propagation**      | The gateway **clears** `X-Tenant-ID`, `X-CCure-*` and `X-Forwarded-User` on every request (`proxy_set_header … ""`). Phase 10 sets `X-CCure-Principal` / `X-CCure-Token-Jti` from the checker (`auth_request_set`) for log correlation only. **No code reads them**, and a guardrail test keeps it that way until a consumer is approved (O8).                                                                                                                                                                                                                                                              |
| **Tenant**                    | From the token's `org_id`, and only inside the api (DB-rechecked). The gateway neither reads nor sets a tenant. `?org_id=` stays an app-level superadmin rule.                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| **Rate limiting**             | Edge zones stay in host nginx, unchanged and keyed on the real peer. **The gateway has no `limit_req` or `limit_conn` in Phase 10**: its peer is always 172.18.0.1, so any zone there would be one bucket for every user. App limits are unchanged. The gateway uses the `realip` module (`set_real_ip_from 172.18.0.1; real_ip_header X-Real-IP;`) and **sets** `X-Real-IP` and `X-Forwarded-For` to that value (overwrite, never append), with `X-Forwarded-Proto $http_x_forwarded_proto`. The auth subrequest never reaches the api, so it consumes no baseline budget.                                 |
| **Failure behaviour**         | Fail closed. Checker unreachable, timeout or 5xx → `503 {"success":false,"error_code":"AUTH_UNAVAILABLE"}` + `Retry-After: 5` (explicit; never a pass-through). Public routes do not call the checker, so sign-in keeps working. JWKS unavailable at start → checker not ready → the compose healthcheck holds it. api down → 502, as today.                                                                                                                                                                                                                                                                |
| **Operational complexity**    | Two small containers. nginx config is already the team's idiom. The checker is ~150 lines over a shared verification module. New ops surface: two healthchecks, two logs, one pinned image.                                                                                                                                                                                                                                                                                                                                                                                                                 |
| **Rollback**                  | Host nginx include swap (§6). The gateway can stay running while unused. The token cut-off rollback (HS256) additionally requires the **routing** rollback, because the checker cannot verify HS256 (no secret, deliberately).                                                                                                                                                                                                                                                                                                                                                                              |

**Variant A2, rejected:** the checker as a route inside the core api (`auth_request` → `api:8000/internal/auth/check`). It reuses the code with no packaging work, but:

- every request would hit the api twice, halving the 600/min baseline;
- IR's authentication would depend on the core being up, which the plan forbids ("IR's own work never depends on the core");
- the api container holds the JWT secret and MFA key, which the checker needs neither of.

### Option C (viable alternative): nginx + njs, verification inside the gateway

The official image ships `ngx_http_js_module`, and njs WebCrypto can verify ECDSA P-256. JWKS would be fetched with `ngx.fetch` into a `js_shared_dict_zone`.

| Aspect                                                       | Difference from A                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Trust boundary / verification                                | Inside the nginx process. One container instead of two.                                                                                                                                                                                                                                                                                                       |
| Carriers, streaming, identity, tenant, rate limits, rollback | Same as A.                                                                                                                                                                                                                                                                                                                                                    |
| Failure                                                      | JWKS fetch failure handled in njs; no separate readiness.                                                                                                                                                                                                                                                                                                     |
| Complexity                                                   | **A second, hand-written JWT verifier in JavaScript** that must match `tokens.verify` rule for rule: alg pinning, `kid`, required claims, leeway 0, kind/ptype, the legacy refusal. Every future change to Phase 9's rules has to be made twice, in two languages, and a divergence is silent. That is the risk the platform has been removing since Phase 8. |

**Not recommended.** It is kept as the fallback if the extra container proves operationally unwelcome.

### Rejected as not meeting the plan

- **Routing-only gateway** (nginx without verification; the api keeps verifying). It fails rule 9 and the Phase 10 exit criterion ("refused at the gateway").
- **Envoy `jwt_authn`, Traefik `forwardAuth`, Kong.** Each is a new technology with no footing in the current architecture. Traefik `forwardAuth` is option A in another product.

---

## 5. Settled / proposed

### 5.1 Where the token-check component runs

In its own container `gateway-auth`:

- on the compose network; not published; `logging: *default-logging`; `restart: unless-stopped`;
- read-only root filesystem, non-root user, no volume mounts at all;
- env: `CCURE_TOKEN_ISSUER`, `CCURE_TOKEN_USER_AUDIENCE`, `CCURE_JWKS_URL`.

Its source lives under `gateway/token_check/`. The verification rules move into a pure module (proposed: `ccure_platform/identity/verification.py`: no `config`, no key directory, keys injected). `tokens.py` and the checker both use it, so the rules exist once. The checker image copies only that module plus `python-jose` and `cryptography`, pinned to the backend's versions (3.3.0 / 46.0.7).

### 5.2 TLS (D10)

**TLS stays at host nginx.**

- It holds the PKI, the 80→443 redirect, HSTS and the edge zones.
- It is the only routable listener, and a Docker-published `0.0.0.0:443` would bypass the host firewall.
- The loopback hop to 8082 does not leave the host, the same reasoning recorded for PostgreSQL TLS on the VM.

Revisit only if the gateway ever needs to be the network edge.

### 5.3 The existing `alt-gateway` service

- **Repurpose, don't add.** Service `gateway` and container `ccure-gateway` keep their names, and the port stays `127.0.0.1:${GATEWAY_PORT:-8082}`.
- **Config** comes from `gateway/nginx/` (the plan's folder). The image is pinned.
- **Profile:**
  - Stages 1–2: under a new opt-in profile `gateway` (replacing `alt-gateway`), so `docker compose up -d` does not start it before validation.
  - Stage 3: the profile is removed, so it is part of the whole stack like `beat`.
- **Retired:** `nginx/gateway.conf` and the "deployments that terminate TLS elsewhere" plain-HTTP whole-stack mode. It has no user, and it is the configuration F10-1/F10-12 would turn into a spoofing path.

### 5.4 `/api/ir/*`

`location /api/ir/` in the gateway:

1. `auth_request` (user `access`; service tokens with `aud=urn:ccure:ir` from Phase 14);
2. then `return 503` with body `{"success":false,"error_code":"MODULE_NOT_DEPLOYED","module":"ir","message":"CCure IR is not deployed yet."}`, `Content-Type: application/json`, `Cache-Control: no-store`.

- **Not 404:** "not deployed" and "no such route" are different facts (the UI-integrity rule).
- **Not proxied to the core:** the core must not own IR's namespace.
- **Unauthenticated:** 401/403 as elsewhere, so the stub leaks nothing to anonymous callers.
- **Phase 13** swaps the `return` for `proxy_pass http://ir-service:8000/;` (prefix `/api/ir/` stripped). Whether `/api/ir/health` is public is decided there.

### 5.5 Route policy at the gateway

One `map` on `$request_method:$uri` → carrier policy: `none`, `bearer`, `ticket_or_bearer` or `ticket`. **The default is `bearer`** (fail closed).

- `none`: the 17 public routes, **plus every `OPTIONS`** (preflights carry no credentials; CORS stays the app's).
- `ticket_or_bearer`: the two download `GET`s.
- `ticket`: the two sockets.
- The flexible `DELETE /reports/{id}` becomes `bearer` at the gateway (O4).

A new test, in the style of `test_endpoint_limit_inventory`, compares the map with the live route table. A route added as public in the app but not in the map fails the build, not production.

The gateway reproduces the app's refusals **exactly** (O5):

- missing credential → `403 {"detail":"Not authenticated"}`;
- invalid or expired → `401 {"detail":"Invalid or expired token"}` + `WWW-Authenticate: Bearer`.

Gateway-generated responses carry `Content-Type: application/json`, `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`, set **only in the named error locations**. Proxied responses get no `add_header` at the gateway, so no header is ever emitted twice. The HSTS header on the way out is host nginx's `always`.

Log format: `$remote_addr [$time_local] "$request_method $uri $server_protocol" $status $body_bytes_sent $request_time $upstream_response_time "$http_user_agent" auth=$ccure_auth_result`. **No `$request`, `$args`, `$request_uri` or `Authorization`.**

---

## 6. Staged cut-over

**10.1 — Characterisation, no behaviour change.**

- Capture a baseline through the current path into a fixture: status, header **names and counts**, `Set-Cookie` attributes (values masked), CORS answers for an allowed and a disallowed origin, and the WebSocket refusal. Sample set: a public route, a bearer route, a flexible route, both sockets, both SSE streams, a FileResponse and a StreamingResponse.
- Measure latency (M2).
- Move the WebSocket logins to `tokens.verify(TICKET)` (F10-5).
- Add the log redaction for the uvicorn WebSocket line (F10-3).

**10.2 — Checker + shared verification module**, tests only. Characterisation: the checker and `tokens.verify` agree on a corpus covering every kind, expiry, `nbf`, a wrong `aud`/`iss`/`kid`/`alg`, legacy HS256, a service token and malformed input.

**10.3 — Stage 1: alongside.**

- `docker compose --profile gateway up -d gateway gateway-auth`. Host nginx is untouched and live traffic still goes direct.
- Set the api's `--forwarded-allow-ips` and `TRUSTED_PROXIES` to the gateway's fixed IP, `172.18.0.1` and loopback. The gateway gets a fixed address via an `ipv4_address` on the default network, or its own network (O7).
- The gateway is reachable only at `http://127.0.0.1:8082` from the VM.

**10.4 — Stage 2: validation.**

- A second **test-only** host-nginx server block on `127.0.0.1:8443` (TLS, same certificate, not routable) proxies `/api/` to 8082. That lets every criterion in §7 be run with TLS, HSTS, the edge zones and real `X-Forwarded-Proto`, without touching the live server block.
- Then the owner does a browser session against it via an SSH tunnel.

**10.5 — Stage 3: switch.**

- Take a backup first (`scripts/backup_db.sh --skip-reference-data`; no schema change, but CLAUDE.md's rule for risky work).
- `/etc/nginx/conf.d/ccure.conf` includes `/etc/nginx/ccure/api-upstream.conf`, a symlink to either `api-via-gateway.conf` or `api-direct.conf`. Both define the `/api/auth/` and `/api/` locations, and they are **identical except for `proxy_pass`**, so the "change the two together" rule survives:
  - `api-via-gateway.conf` uses `proxy_pass http://127.0.0.1:8082;` with the `/api/` prefix preserved; the gateway strips it.
  - `api-direct.conf` is today's `http://127.0.0.1:8000/` and `/auth/`.
- `ln -sfn … && nginx -t && systemctl reload nginx`. `reload` works on Linux; the Windows `OpenEvent` caveat does not apply.
- Remove the `gateway` profile. Re-run §7 on the live hostname.

**10.6 — Stage 4: rollback switch, rehearsed.**

- Point the symlink back at `api-direct.conf`, then `nginx -t && systemctl reload nginx`. That is one command and changes nothing else; the gateway keeps running unused.
- The rollback keeps working because `127.0.0.1:8000` stays published, and `172.18.0.1` stays in `--forwarded-allow-ips` and `TRUSTED_PROXIES`.
- Rehearse live once (flip, verify, flip back), as 9.6b did.

**10.7 — Later and separate:** close the `127.0.0.1:8000` publish and drop `172.18.0.1` from the trust lists. This removes the rollback path, so it waits for the owner (O10) and for M6.

---

## 7. Verification criteria (all must hold after 10.4, and again after 10.5)

| #   | Criterion                                                                                                                                                                                                                                                                                                                                                                | How it is measured                                                                                 |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| V1  | **An unauthenticated request is refused by the gateway, never reaching the app.** `GET /api/scans` with no `Authorization` and **no client `X-Request-ID`** → `403 {"detail":"Not authenticated"}` with **no `X-Request-ID`**. An expired or garbage bearer → `401` + `WWW-Authenticate: Bearer`, no `X-Request-ID`.                                                     | curl, and the **api log shows no line** for that request (count before/after).                     |
| V2  | **WebSockets:** no ticket, a bad ticket, an access token as a ticket, and a ticket for another kind are all refused **at the gateway** — **401**, where the app says 403 (F10-7) — and the gateway log shows `auth=denied`, with no uvicorn `WebSocket …` line. A valid ticket upgrades (101) and receives the initial status frame for a real scan.                     | a websocat/Python client; api log                                                                  |
| V3  | **Per-client rate-limit buckets.** Two different client addresses (the workstation and the VM itself) each get their own count: drive one to a `@limiter.limit` 429 and the other is unaffected. The 429's audit record names the **real** client IP, not 172.18.x. A request carrying a forged `X-Forwarded-For: 1.2.3.4` through the edge resolves to the true client. | `/scan/…` 5/min route or `/auth/check-email`; `core.rate_limit_audit` log; `audit_logs.ip_address` |
| V4  | **`TRUSTED_PROXIES` / `--forwarded-allow-ips`:** the start-up `log_trust_boundary()` line names exactly the gateway IP, `172.18.0.1` and loopback. A request from **inside another container** straight to `api:8000` with a forged XFF resolves to that container's own address.                                                                                        | api start-up log; `docker exec ccure-beat curl …`                                                  |
| V5  | **Refresh cookie:** `Set-Cookie` on login and refresh has the same attributes as the 10.1 baseline: `HttpOnly; Secure; SameSite=lax; Path=/`, no Domain. Silent refresh works in the browser past a 30-minute access-token expiry (or with a shortened token in the rehearsal environment). Logout clears it.                                                            | header diff; owner's browser session                                                               |
| V6  | **CORS:** an allowed-origin preflight gives 200 + ACAO echo + `Allow-Credentials: true`. A disallowed origin gives 400 and no ACAO. A PNA preflight from a disallowed origin gives 403. All three are byte-for-byte the baseline, and all reach the app (preflights are `none` at the gateway). The gateway adds **no** CORS header of its own.                          | curl diff against 10.1                                                                             |
| V7  | **`add_header` inheritance:** for each sampled response, every header name occurs the **same number of times** as in the baseline, and **exactly once** for `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and `Content-Security-Policy` on `/api/` responses — including the gateway's own 401/403/503.                    | header-count diff script                                                                           |
| V8  | **HSTS:** one `Strict-Transport-Security: max-age=300` on `/api/` responses, on gateway refusals, and on `/`. The app still sees `X-Forwarded-Proto: https` (its own HSTS logic fires; host nginx hides it).                                                                                                                                                             | curl; a debug log of `request.url.scheme` for one request                                          |
| V9  | **SSE:** `/api/notifications/stream` and `/api/scans/events` deliver the first event within 2 s, heartbeat for 10 minutes, and are not buffered: events arrive one at a time, not in bursts. `limit_conn` is still 40 per client at the edge.                                                                                                                            | a `curl -N` timestamped reader                                                                     |
| V10 | **Downloads:** a 20 MB+ PDF/XLSX download and an evidence upload near 25 MB succeed. **No file is written under the gateway's `/var/cache/nginx`** during either. The response is byte-identical (sha256) to the direct path.                                                                                                                                            | `docker exec ccure-gateway find /var/cache/nginx -type f` during the transfer                      |
| V11 | **Ticket exposure:** after exercising WebSockets and a ticket download, `grep -c 'ticket=' ` is **0** in the gateway log, 0 in the api container log since the change, and 0 in host nginx `access.log` since the format change (sudo). A reset-link visit logs `/reset-password` without the token.                                                                     | grep, redacted counts only                                                                         |
| V12 | **Ticket scope:** a valid ticket is refused on `DELETE /api/reports/{id}` and on an ordinary bearer route. It is accepted on the two download `GET`s.                                                                                                                                                                                                                    | curl                                                                                               |
| V13 | **Identity headers:** a request carrying `X-Tenant-ID`, `X-CCure-Principal` and `X-Forwarded-User` arrives at the api without the client's values (captured with a temporary echo route in the **test** environment only, or by tcpdump on the bridge in stage 2).                                                                                                       | test harness                                                                                       |
| V14 | **`/api/ir/*`:** with no token → 403/401 from the gateway; with a valid token → `503 MODULE_NOT_DEPLOYED`. The api logs nothing.                                                                                                                                                                                                                                         | curl                                                                                               |
| V15 | **Public allowlist:** each of the 17 public routes answers exactly as the baseline without a token. The route-map inventory test passes.                                                                                                                                                                                                                                 | curl loop; pytest                                                                                  |
| V16 | **Fail closed:** `docker stop gateway-auth` → bearer routes answer `503 AUTH_UNAVAILABLE`, public routes still work, nothing reaches the api unauthenticated. Start it again → recovery within one request.                                                                                                                                                              | curl                                                                                               |
| V17 | **Overhead:** gateway p95 added latency ≤ 5 ms on three sampled routes versus M2 (O12).                                                                                                                                                                                                                                                                                  | a loop of 500 requests                                                                             |
| V18 | **Suites:** the security suites, `tests/auth`, and the full suite pass (against `ccure_pytest_db`, never while another run is going).                                                                                                                                                                                                                                    | pytest                                                                                             |
| V19 | **Rollback:** flip to `api-direct.conf` → V1 now shows the **app's** 403 **with** `X-Request-ID` (proving traffic bypasses the gateway), login, refresh, sockets and downloads work. Flip back → V1 as specified.                                                                                                                                                        | rehearsal record                                                                                   |

---

## 8. Open decisions for the owner

| #            | Decision                                                                          | Recommendation                                                                                                                                                                                            |
| ------------ | --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **O1 = D7**  | Gateway technology                                                                | **Option A**: nginx + `auth_request` + a separate `gateway-auth` container                                                                                                                                |
| **O2 = D10** | TLS termination                                                                   | **Host nginx keeps TLS**; the gateway is behind it on loopback                                                                                                                                            |
| O3           | The existing `gateway` / `alt-gateway` service                                    | Repurpose it (same name/port, new config, pinned image); retire `nginx/gateway.conf` and the plain-HTTP mode                                                                                              |
| O4           | Ticket scope at the gateway                                                       | Tickets only on the two download `GET`s and the two sockets; `DELETE /reports/{id}` bearer only. Single-use tickets: **defer** to its own change (it needs a Redis `jti` store, like service assertions). |
| O5           | Refusal status for a missing credential                                           | **Mirror today exactly**: 403 missing, 401 invalid. Changing it to 401 would make the SPA refresh on every anonymous call — a behaviour change, not Phase 10's.                                           |
| O6           | Fix F10-1 (`--forwarded-allow-ips`) and F10-2 (`TRUSTED_PROXIES`) inside Phase 10 | **Yes.** The gateway is what turns them from latent into live.                                                                                                                                            |
| O7           | How the gateway gets a fixed address                                              | A static `ipv4_address` on the existing default network (no new network; the other containers are unaffected)                                                                                             |
| O8           | Forwarded identity headers                                                        | Strip always. Set `X-CCure-Principal` / `X-CCure-Token-Jti` for logs only; **no consumer until approved** (a guardrail test).                                                                             |
| O9           | Client-supplied `X-Request-ID`                                                    | Leave it as is in Phase 10 (the gateway passes it through); record F10-8 for a later decision                                                                                                             |
| O10          | When to close `127.0.0.1:8000`                                                    | Separate step 10.7, after M6 and a period on the gateway; it removes the rollback path                                                                                                                    |
| O11          | SPA (`/`) via the gateway, and the F10-9 duplicate headers                        | Not in Phase 10 (the gateway fronts `/api/` only; the SPA is static). Revisit in Phase 12 with the homepage shell.                                                                                        |
| O12          | Latency budget                                                                    | p95 +5 ms                                                                                                                                                                                                 |
| O13          | Service tokens at the gateway                                                     | Checker supports `service_access`; **disabled** in the gateway map until Phase 14 has a consumer                                                                                                          |
| O14          | Host nginx log format change (redact query strings everywhere, including `/`)     | Yes, in 10.5, since that file is edited anyway. It is live infrastructure, so it is listed separately for approval.                                                                                       |

## 9. Measurements still to take before implementation

| #   | Measurement                                                                         | Why                                                                                                            | How                                                                                                                  |
| --- | ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| M1  | Count of `ticket=` and `token=` lines in host nginx access logs (current + rotated) | Sizes F10-3; decides whether existing logs need purging                                                        | `sudo zgrep -c 'ticket=\|token=' /var/log/nginx/access.log*` — counts only. The session could not read them (`adm`). |
| M2  | Latency baseline p50/p95 on three routes via the current path                       | The V17 gate                                                                                                   | 10.1                                                                                                                 |
| M3  | Peak concurrent long-lived connections (SSE + WS) per client and in total           | Sizing the gateway's `worker_connections` (each proxied connection costs two) against the edge `limit_conn 40` | `ss -tn state established '( dport = :8000 )'` sampled over a working day                                            |
| M4  | The source address the gateway container sees from host nginx                       | Must be `172.18.0.1` (userland proxy) for `set_real_ip_from`                                                   | stage 1                                                                                                              |
| M5  | Whether anything outside the SPA uses `?ticket=` on the three flexible routes       | O4 would break it                                                                                              | Host nginx logs (with M1, sudo): method and path only                                                                |
| M6  | Every client that calls `127.0.0.1:8000` directly (scripts, tooling, the workers?)  | Before 10.7 closes it                                                                                          | `ss`/api logs over a day; grep scripts for `:8000`                                                                   |

## 10. Risks

- **Every request passes through two more hops** (gateway + checker). Mitigations: the fail-closed 503, V16, V17, and a one-command rollback.
- **Silent loss of per-client limits** if `realip`, `--forwarded-allow-ips` or `TRUSTED_PROXIES` disagree. That has failed silently before; V3/V4 are mandatory, not sampling.
- **The WebSocket path through two nginx hops** (h2 at the edge, h1.1 upgrade behind it). V2 is run from a real browser, not only curl.
- **Rule drift between the checker and the api.** One shared verification module, plus the 10.2 agreement corpus.
- **HS256 rollback now also needs the routing rollback** (the checker cannot verify HS256). Record it in the Phase 9 runbook §17.
- **Live changes** in 10.5 and 10.6: a backup first, the 8443 test block, the owner present for the flip, and the same stop-and-report pattern as 9.6b.

---

## 11. Proposed Phase 10 decision

> **D7:** nginx gateway container (`ccure-gateway`, pinned image, `127.0.0.1:8082`) using `auth_request` to a separate, stateless `gateway-auth` container that verifies ES256 tokens against the platform JWKS with the same rules as `tokens.verify` (one shared verification module), holding no secrets, no database and no mount of `./Backend`.
> **D10:** TLS stays at host nginx; the gateway fronts `/api/` only.
> **alt-gateway:** repurposed as the Phase 10 gateway; `nginx/gateway.conf` and the plain-HTTP mode retired.
> **`/api/ir/*`:** authenticated at the gateway, answered `503 MODULE_NOT_DEPLOYED` until Phase 13 points it at `ir-service`.
> **Also in Phase 10:** F10-1/F10-2 trust-boundary fixes, the WebSocket logins onto `tokens.verify(TICKET)`, ticket and token redaction in every log, and tickets restricted to downloads and sockets.
> **Cut-over:** 10.1 characterise → 10.2 checker → 10.3 alongside → 10.4 validate (TLS test block on 127.0.0.1:8443) → 10.5 symlink switch → 10.6 rehearsed rollback; closing `:8000` is a separate, later 10.7.

---

## 12. Phase 10.1 outcome — facts frozen from live characterisation

Source: [`phase10/PHASE10_1_CHARACTERISATION.md`](phase10/PHASE10_1_CHARACTERISATION.md) and `phase10/route_auth_matrix.json`, measured at HEAD `fc38b31` on 29 Sep 2026. Where these differ from §§4–7 above, **these win**, and 10.2 is designed against them.

1. **Refusal envelope:** `{success, error_code, message, detail, request_id}`. Unmatched routes are the exception and return `{"detail":"Not Found"}`.
2. **No 401 currently sends `WWW-Authenticate`.**
3. **A missing credential is answered per route class:**
   - bearer routes: **403** "Not authenticated";
   - a non-Bearer scheme: **403** "Invalid authentication credentials";
   - ticket-or-bearer routes: **401** "Authentication token is missing.";
   - WebSockets: **403**, empty body, no `X-Request-ID`.
4. **The ticket is evaluated before `Authorization` when both are present.** Confirmed with valid credentials: a valid bearer plus a garbage ticket → 401 "Invalid or expired download ticket."
5. **Unknown routes return 404 before authentication**, and that includes `/api/ir/*`.
6. **`GET /api/reports/download/<scan_id>` genuinely uses ticket authentication** (M5: a real HTTP 200 on 29 Sep; probe: 200 with bytes identical to the bearer download).
7. **F10-1 is experimentally confirmed.** Direct `:8000` and `:3200/api/` both key the rate limit on a forged `X-Forwarded-For`; host nginx keys on the real client address.
8. **`:3200/api/` is a bypass path.** It also merges frontend-injected headers into API responses (`HSTS max-age=31536000; includeSubDomains`, a second CSP). It must be dealt with in 10.7.
9. **Reset/verify URLs keep `?token=`**, which caused 49 `token=` Referer exposures in retained host-nginx logs.
10. **A failed refresh or logout can leave a dead cookie:** the clearing `Set-Cookie` is written and then discarded by the raised exception.
11. **WebSocket refusal is 403, not 401.**
12. **`OPTIONS` must pass without credentials.** A preflight on a protected route answers 200 today.

Added by the valid-credential run (§3.5 of the characterisation):

13. **Tickets are reusable within their 60 s lifetime**, across routes and across edge/direct. One ticket served three downloads and four WebSocket upgrades.
14. **Access tokens remain valid after logout** until they expire (≤ 30 min).
15. **Refresh rotates on every use.** Reusing the pre-rotation cookie fails for that session only. Logout clears the cookie at `Path=/` **and** `Path=/auth`.
16. **Notification SSE heartbeats every 25 s; scan-events SSE every ~2 s.**
17. **One file, one hash:** the valid download is byte-identical (SHA-256 `71fd2cbc…`) over edge bearer, edge ticket, direct bearer and direct ticket. That is the reference for V10.

O5 (§8) is superseded by fact 3: fidelity is per class, not one rule.

## 13. Unresolved decisions — owner to decide; not chosen here

**X2 — `WWW-Authenticate` on 401**

- **X2-a** Preserve the current behaviour: no 401 sends `WWW-Authenticate`. The gateway's 401s omit it too.
- **X2-b** Deliberately introduce `WWW-Authenticate: Bearer` on 401. This is a documented behaviour change (RFC 6750 §3), and it would be made in the app and the gateway together, so the two layers never disagree.

**X6 — unknown routes**

- **X6-a** Preserve 404-before-auth. The gateway knows the route table (from the matrix) and answers an unmatched path with the bare `{"detail":"Not Found"}` 404 without authenticating. Equivalently, it passes the path to the app unauthenticated. That includes `/api/ir/*` until Phase 13.
- **X6-b** The gateway authenticates unknown routes and returns its configured auth refusal (403/401 per fact 3), so an anonymous caller can no longer tell a real route from a missing one. An authenticated caller still receives the app's 404.

Until the owner chooses, 10.2 builds both variants behind a single configuration switch in the gateway map, and **neither ships**. Where each decision touches the implementation is listed in [`phase10/PHASE10_2_DESIGN.md`](phase10/PHASE10_2_DESIGN.md) §10.

## 14. Status of valid-credential characterisation

It was executed on 29 Sep 2026 at 20:35 IST with the **owner's own credential**, supplied by the owner in the session with the instruction to verify it. It was not minted or fabricated. The owner's written brief for this step had said to leave it pending, so this run is **recorded as provisional** until the owner confirms it as the baseline. If it is not confirmed, facts 13–17 and §3.5 of the characterisation revert to **pending, not verified**. Because the password was shared in chat, the owner is advised to rotate it.

## 15. Decisions taken (owner, 29 Sep 2026) — supersedes §13 and §14

- **X2 = X2-a.** Preserve the current 401 behaviour; no `WWW-Authenticate` is added, in the gateway or the app.
- **X6 = X6-a.** Preserve 404/405/307-before-auth for unrouted requests. **`/api/ir/*` stays the current 404 throughout Phase 10**; the `MODULE_NOT_DEPLOYED` 503 stub (§5.4) is not introduced.
- **`DELETE /reports/{id}`** stays ticket-or-bearer in 10.2. Ticket narrowing is a separate decision (O4).
- **Valid-credential characterisation is confirmed** as the baseline. §14's "provisional" no longer applies.
- **M3** is still sampling; it sizes nginx connections later and blocks nothing before 10.2d.
- **10.2a** (shared verification module) is committed as `42128b9`, and **10.2b** (the `gateway-auth` checker) with this record: [`phase10/PHASE10_2_DESIGN.md`](phase10/PHASE10_2_DESIGN.md) §§15–16.
