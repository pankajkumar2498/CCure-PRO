# Phase 10.2 — Gateway authentication: design (not implemented)

|                                   |                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**                        | **10.2a committed** (`42128b9`, §15). **10.2b committed** (`f5d7da1`, §16): the `gateway-auth` checker. **10.2c committed** (`5cd89c3`, §17): the route-policy generator. **10.2d committed** with this revision: the nginx `auth_request` configuration and its local harness, see §18. Phase 10.2 is complete; nothing is deployed. No nginx, Compose, routing, port, trust boundary or token policy was changed, and nothing was deployed. |
| **Owner decisions (29 Sep 2026)** | **X2 = X2-a**: preserve the current 401 behaviour; no `WWW-Authenticate` is added. **X6 = X6-a**: preserve 404/405/307-before-auth for unrouted requests. So **`/api/ir/*` stays the current 404 throughout Phase 10**; the `MODULE_NOT_DEPLOYED` 503 stub is not introduced. **`DELETE /reports/{id}` stays ticket-or-bearer** in 10.2, since preserving behaviour is the scope; any ticket narrowing is a separate decision (O4).           |
| **Baseline**                      | Phase 10.1 is complete and is the golden baseline. The valid-credential characterisation is **confirmed** by the owner. M3 is still sampling; it is needed only later, to size nginx connections.                                                                                                                                                                                                                                             |
| **Inputs**                        | [`PHASE10_1_CHARACTERISATION.md`](PHASE10_1_CHARACTERISATION.md), `route_auth_matrix.json`, decision record [`../PHASE10_API_GATEWAY.md`](../PHASE10_API_GATEWAY.md) §§12–14                                                                                                                                                                                                                                                                  |
| **Governing rule**                | **Preserve observed behaviour.** Every response the gateway generates must be the response the application gives today for the same request, apart from `X-Request-ID` being absent. The only exceptions are the two open decisions X2 and X6, and the gateway must not pick either one silently.                                                                                                                                             |
| **Scope of 10.2**                 | Build and test the shared verification module, the `gateway-auth` checker, the generated nginx configuration and the test harness. All of it runs **only** in unit tests and in a disposable, isolated compose project (`ccure-gw-test`) with a stub upstream. Nothing is attached to the live network; that is 10.3.                                                                                                                         |

---

## 1. Components

```
gateway/
  nginx/
    gateway.conf                 hand-written: server, auth locations, error mapping, logging
    generated/route_policy.map   GENERATED from the live route table (§4)
    generated/public_routes.conf GENERATED exact-match locations for the 17 public routes
    generated/cors_origins.map   GENERATED at container start from CORS_ALLOW_ORIGINS (§9)
  token_check/
    app.py                       the gateway-auth service (~150 lines)
    Dockerfile                   python:3.11-slim + pinned python-jose 3.3.0, cryptography 46.0.7
Backend/ccure_platform/identity/verification.py   pure verification rules (moved out of tokens.py)
scripts/gateway/generate_route_policy.py          writes gateway/nginx/generated/*
tests/gateway/…                                   see §13 (new group dir, no __init__.py)
```

## 2. The verification boundary

### 2.1 One verifier

`ccure_platform/identity/verification.py` holds `_decode` and `verify` from `tokens.py`, **unchanged in behaviour**, with every input injected:

```python
def verify(token, *, expected_kind, issuer, audience, keys: Mapping[str, PublicKey],
           legacy: LegacyPolicy | None) -> Verified | Refused
```

- **`keys`** comes from the api's keyset or, in the checker, from JWKS.
- **`legacy`** is `None` in the checker. The checker holds no HS256 secret, so a legacy token is always refused there. That is correct, because `CCURE_ACCEPT_LEGACY_HS256=false` is live.
- **`Refused` carries a reason code** (the same vocabulary as `tokens._refuse`), so the gateway can choose the right refusal (§8).
- **`tokens.py` becomes a caller.** Its public surface (`sign`, `verify`, `decode_any_kind`, `keyset_status`, …) is unchanged, and the Phase 9 characterisation tests must pass untouched.

### 2.2 `gateway-auth` (the checker)

- **Stateless.** No database, no Redis, no mount of `./Backend`, no `.env`, and none of `JWT_SECRET_KEY`, `MFA_ENCRYPTION_KEY` or any private key.
- **Container hardening:** read-only root filesystem, non-root, no published port. `logging: *default-logging`.
- **Configuration (environment):**
  - `CCURE_TOKEN_ISSUER`, `CCURE_TOKEN_USER_AUDIENCE` — must equal `tokens.ISSUER` and `USER_AUDIENCE`, and a test pins that;
  - `CCURE_JWKS_URL=http://api:8000/auth/jwks.json`.
- **Endpoints:**
  - `GET /check` — internal, reached only from nginx `auth_request`;
  - `GET /healthz` — 200 only once a JWKS has been loaded.
- **Inputs, all as request headers from nginx:** `Authorization` (passed through), `X-Ccure-Policy`, `X-Ccure-Args` (= `$args`, see §5), `X-Ccure-Method`.
- **Output:**
  - `204` + `X-Ccure-Auth-Sub`, `-Jti`, `-Ptype`, `-Kind` on success;
  - `401` or `403` + `X-Ccure-Refusal: <code>` on refusal, where `<code>` is one of the §8 codes.
- **It logs only:** the reason code, the policy, the **unverified** `kid` and `jti` (as `tokens._refuse` already does), and the latency. **Never** a header value, query, token or cookie.

### 2.3 Keys and JWKS

- **Load:** fetched at start; the checker is not healthy until it has a JWKS.
- **Refetch:** on an unknown `kid`, at most once per 30 s; the last good JWKS is kept if a fetch fails.
- **Rate limit:** the app limits `/auth/jwks.json` to 60/min per peer. The checker's own address is its bucket, and at most 2/min of refetches cannot trip it.
- **Algorithm:** only `ES256`, pinned per `kid`; `alg:none` and HS256 are refused (observed today as 401 "Invalid or expired token").
- **Rollback coupling:** rolling tokens back to HS256 (`CCURE_ACCEPT_LEGACY_HS256=true`) **also requires** the routing rollback (the host-nginx symlink back to direct), because the checker cannot verify HS256. That goes in the Phase 9 runbook §17.

## 3. The nginx `auth_request` flow

```nginx
# every protected request:
location /api/ {                       # prefix stripped exactly as host nginx does today
    auth_request      /_auth;
    auth_request_set  $ccure_refusal  $upstream_http_x_ccure_refusal;
    auth_request_set  $ccure_sub      $upstream_http_x_ccure_auth_sub;
    auth_request_set  $ccure_jti      $upstream_http_x_ccure_auth_jti;
    error_page 401 = @refuse_401;
    error_page 403 = @refuse_403;
    error_page 500 502 503 504 = @auth_unavailable;   # checker down (auth subrequest failed)
    proxy_intercept_errors off;                        # the app's own 4xx/5xx pass through untouched
    proxy_pass http://api:8000/;
    …identity strip, forwarding headers, streaming settings (§§10–11)…
}

location = /_auth {
    internal;
    proxy_pass              http://gateway-auth:8080/check;   # no URI or query passed on
    proxy_pass_request_body off;
    proxy_set_header        Content-Length "";
    proxy_set_header        X-Ccure-Policy $ccure_policy;       # from the generated map (§4)
    proxy_set_header        X-Ccure-Args   $args;               # parsed by the checker, never logged
    proxy_set_header        X-Ccure-Method $request_method;
    proxy_connect_timeout 1s;  proxy_read_timeout 2s;
}
```

- **An `error_page` inside `/api/` catches only nginx-generated statuses.** With `proxy_intercept_errors off`, the application's 401/403/500 reach the client exactly as today. Only a refusal from the auth subrequest, or its failure, is rewritten.
- **The 500 from a failed auth subrequest is distinguished by `$ccure_refusal` being empty.** An internal assertion test covers that.

## 4. Route policy, generated from the characterisation

`scripts/gateway/generate_route_policy.py` reads the **live route table** (`route_table.py` output, the same shape as `route_auth_matrix.json`'s `routes`) and writes:

1. **`route_policy.map`**
   - `map "$request_method:$ccure_app_path" $ccure_policy { … }`, where `$ccure_app_path` is the URI with `/api` removed.
   - Entries are written **in the application's route order**: exact paths first, then each `{param}` template as `~^METHOD:/prefix/[^/]+/…$`. nginx picks the first matching regex in order of appearance, which is the same rule Starlette uses.
   - Values: `bearer | ticket_or_bearer | ticket | none`, plus the X6 class `unrouted` (§7).
   - The generator **refuses** to emit if two templates overlap with different policies and cannot be ordered safely.
2. **`public_routes.conf`**
   - One `location = /api/<path>` per public route, with **no** `auth_request`, so sign-in, refresh, logout, JWKS and the reset/verify endpoints keep working when the checker is down.
   - The same proxy and streaming settings as `/api/`.
3. **Drift gate**
   - A test regenerates from the running app's routes and compares the result with the committed files, exactly as `scripts.contracts.generate_schemas` is guarded.
   - A route added to the app without regenerating fails CI.

Policy per class:

- 17 × `none`;
- 251 × `bearer`;
- `GET /reports/download/{id}` and `GET /reports/export/{id}` × `ticket_or_bearer`;
- 2 WebSocket × `ticket`;
- `DELETE /reports/{id}`: **ticket_or_bearer, preserving today's behaviour**. Narrowing it to bearer is O4 and is not done in 10.2.

## 5. Ticket-first handling (fact 4)

The checker implements `get_current_user_flexible`'s order exactly:

1. **Read the query the way Starlette does.** `X-Ccure-Args` is parsed with `urllib.parse.parse_qsl(keep_blank_values=True)`, percent-decoded, and **the last `ticket` value wins**. nginx's `$arg_ticket` returns the _first_ value and does not decode, so it is deliberately not used. With `?ticket=good&ticket=bad`, `$arg_ticket` would pass what the app refuses.
2. **If `ticket` is non-empty,** verify it as kind `ticket`. On failure refuse `invalid_ticket`, and **do not look at `Authorization`**. This is observed: a valid bearer plus a garbage ticket gives 401.
3. **An empty `?ticket=`** is falsy in the app, so the checker falls through to the bearer path. Tested.
4. **Otherwise use the bearer path with the flexible parser** (§6, `auto_error=False` semantics): a missing or non-Bearer header → `missing_flexible` (401 "Authentication token is missing.").
5. **Tickets stay reusable within 60 s** (fact 13). The checker keeps no `jti` store, and single-use tickets remain O4.

## 6. Bearer handling

The checker reproduces FastAPI's `HTTPBearer` parsing (`get_authorization_scheme_param`):

| Header                                                                               | Strict bearer route                                          | Flexible route (no ticket) |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------- |
| absent                                                                               | 403 `missing_bearer` "Not authenticated"                     | 401 `missing_flexible`     |
| `Bearer` with empty credentials                                                      | 403 `missing_bearer`                                         | 401 `missing_flexible`     |
| another scheme (`Basic …`)                                                           | 403 `non_bearer_scheme` "Invalid authentication credentials" | 401 `missing_flexible`     |
| `Bearer <bad>`, including `alg:none`, legacy HS256, unknown `kid`, expired, a ticket | 401 `invalid_bearer` "Invalid or expired token"              | 401 `invalid_bearer`       |
| `Bearer <valid access>`                                                              | 204 → forwarded                                              | 204 → forwarded            |

- **Scheme matching is case-insensitive,** as in FastAPI.
- **The gateway checks cryptography and kind only.** Deleted or inactive users, deactivated organisations and role/org claim drift are still refused by the app, which re-verifies (rule 9). Those responses carry `X-Request-ID`, because the app produced them.
- **Access tokens survive logout for ≤ 30 min at both layers** (fact 14). The gateway is not a revocation point, and nothing may describe it as one.

## 7. WebSockets, `OPTIONS`, public routes, `/api/ir/*` and unrouted requests

- **WebSockets** (`ticket` policy, the two progress routes):
  - the ticket is taken from the query (§5), and any `Authorization` header is ignored, as observed;
  - a refusal is **403 with an empty body**, no `X-Request-ID` and no API security headers (facts 3 and 11). Host nginx adds HSTS and `nosniff` as it does today;
  - an access token used as a ticket → 403;
  - on success the upgrade proceeds (`Upgrade`/`Connection` mapped, HTTP/1.1, 3600 s timeouts);
  - the auth subrequest never carries the `Upgrade` headers.
- **`OPTIONS`** (fact 12): `map $request_method` forces `$ccure_policy = none`, and the checker answers `none` with 204 without reading any credential. That includes PNA preflights, which the app answers in its request-ID middleware (no `X-Request-ID`). Trade-off: while the checker is down, preflights get 503. The SPA is same-origin and sends no preflights, so only cross-origin clients are affected, and they are refused closed.
- **Public routes:** the generated exact locations (§4), with no auth subrequest. Cookies, bodies and `Set-Cookie` pass through untouched, with **no** `proxy_cookie_path`, since the app clears both `Path=/` and `Path=/auth` (fact 15).
- **`/api/ir/*`:** an unknown route today (fact 5). Under X6-a it stays the app's 404 throughout Phase 10.
- **Unrouted requests.** The characterisation found three kinds of answer the app gives _before_ authentication, all in the route table's blind spot:

  - **404** `{"detail":"Not Found"}`: unknown path;
  - **405** `{"detail":"Method Not Allowed"}` plus `Allow: …`: known path, wrong method (HEAD on a GET route included);
  - **307** trailing-slash redirect. _Pre-existing bug:_ its `Location` drops `/api`, so `/api/scans/` redirects to `https://ccurepro.cdac.in/scans`, which is the SPA.

  The map marks any request matching no `(method, template)` pair as `unrouted`. What happens to `unrouted` is X6.

## 8. Refusal preservation

The checker returns a reason code, and nginx renders the matching body from `map $ccure_refusal $ccure_refusal_body`:

| Code                  | Status | Body (`request_id` is `null`; the gateway invents no id)                                                                                                     |
| --------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `missing_bearer`      | 403    | `{"success":false,"error_code":"HTTP_403","message":"Not authenticated","detail":"Not authenticated","request_id":null}`                                     |
| `non_bearer_scheme`   | 403    | … `"Invalid authentication credentials"` …                                                                                                                   |
| `invalid_bearer`      | 401    | … `"Invalid or expired token"` …                                                                                                                             |
| `missing_flexible`    | 401    | … `"Authentication token is missing."` …                                                                                                                     |
| `invalid_ticket`      | 401    | … `"Invalid or expired download ticket."` …                                                                                                                  |
| `ws_refused`          | 403    | empty body, `Content-Type: text/plain`, no other headers                                                                                                     |
| (checker unavailable) | 503    | `{"success":false,"error_code":"AUTH_UNAVAILABLE","message":"Authentication is temporarily unavailable.","detail":"…","request_id":null}` + `Retry-After: 5` |

**Headers on a gateway refusal** equal the app's refusal headers minus `X-Request-ID`:

- `Content-Type: application/json`;
- `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'`, `Cross-Origin-Resource-Policy: same-site`;
- **not** `nosniff` or HSTS: host nginx adds those with `always` and hides upstream copies, so emitting them would produce duplicates;
- **CORS, preserved:** for an allowed `Origin`, `Access-Control-Allow-Origin: <origin>`, `Access-Control-Allow-Credentials: true` and `Vary: Origin`, exactly as the app sends on its 403 today (observed). The allow-list is `cors_origins.map`, generated at gateway start from the **same `CORS_ALLOW_ORIGINS` value** the api reads, so there is one source.
- **`WWW-Authenticate` is decided by X2** (§10).

The gateway adds no `add_header` at server level. These headers are set only inside the named refusal locations, so proxied responses are never touched and no header appears twice.

## 9. `X-Request-ID`, identity headers, forwarding

- **`X-Request-ID`:** passed through unchanged, echo included (fact and F10-8 preserved). Gateway refusals carry none, in the header or the body (`request_id: null`). O9 remains open.
- **Identity headers:** on every proxied request, `proxy_set_header` clears `X-Tenant-ID`, `X-Ccure-Auth-Sub`, `X-Ccure-Auth-Jti`, `X-Ccure-Auth-Ptype`, `X-Ccure-Auth-Kind` and `X-Forwarded-User`. The auth values are then set from `auth_request_set` for logs only. A guardrail test asserts that no production code reads any of these headers.
- **Forwarding:**
  - `realip` trusts `172.18.0.1` only (M4) and reads `X-Real-IP`;
  - `X-Real-IP` and `X-Forwarded-For` are **set** to the resolved client, never appended;
  - `X-Forwarded-Proto` is taken from host nginx (`$http_x_forwarded_proto`), so the app's HSTS and scheme logic sees `https`;
  - `Host` is passed through.
- **F10-1 fix** (`--forwarded-allow-ips`, `TRUSTED_PROXIES`) is **10.3**, together with the gateway's fixed address. 10.2 only tests the header handling against the stub.

## 10. Where X2 and X6 change the implementation

**X2 (`WWW-Authenticate`):**

| #   | Place                           | X2-a (preserve: none)        | X2-b (introduce)                                                                                                                      |
| --- | ------------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `@refuse_401` in `gateway.conf` | no header                    | `add_header WWW-Authenticate 'Bearer' always;` (and `error="invalid_token"` for `invalid_bearer` / `invalid_ticket`, if chosen)       |
| 2   | The app                         | unchanged                    | `main.py`'s exception handler must stop dropping `HTTPException.headers` (F9-11), or the app and gateway disagree on the same request |
| 3   | Refusal fixtures and tests      | expect absence on every 401  | expect presence; the characterisation's "no `WWW-Authenticate`" assertion becomes a recorded behaviour change                         |
| 4   | SPA                             | nothing                      | nothing reads it (checked: no `www-authenticate` in `Frontend/src`); browsers do not prompt for `Bearer`                              |
| 5   | Checker                         | none (the header is nginx's) | none                                                                                                                                  |

**X6 (answers before authentication):**

| #   | Place                                          | X6-a (preserve 404/405/307 before auth)                                                                                                                                 | X6-b (authenticate unrouted)                                                                                                            |
| --- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `route_policy.map`, `unrouted` value           | → `none`: forwarded to the app **unauthenticated**, so the app's own 404/405/307 is reproduced exactly (including the broken 307 `Location` and the 405 `Allow` header) | → `bearer` (strict): an anonymous caller gets 403 "Not authenticated"; an authenticated caller gets the app's 404/405/307               |
| 2   | "Nothing unauthenticated reaches the app" (V1) | **does not hold** for unrouted requests; V1 is restated as "for every _routed_ protected path"                                                                          | holds for every path                                                                                                                    |
| 3   | Map-drift failure mode                         | a route missing from the map is forwarded unauthenticated, and **the app's own auth still refuses it**; the drift gate (§4) must fail CI first                          | a route missing from the map is authenticated as strict bearer; a public route missing from the map breaks loudly (403), never silently |
| 4   | `/api/ir/*`                                    | anonymous and authenticated both get today's 404 until Phase 13; the §5.4 stub (401/403 → 503) is **not** introduced in 10.2                                            | anonymous → 403; authenticated → the stub's `503 MODULE_NOT_DEPLOYED` (a change from 404, and itself part of accepting X6-b)            |
| 5   | Checker                                        | `unrouted` never reaches it                                                                                                                                             | `unrouted` is handled as `bearer`                                                                                                       |
| 6   | Tests                                          | 404/405/307 fixtures replayed byte-for-byte through the gateway                                                                                                         | fixtures expect the auth refusal for anonymous callers and the app's answer for authenticated ones                                      |
| 7   | Route enumeration                              | unchanged: an anonymous caller can distinguish routes (404 versus 403)                                                                                                  | removed for anonymous callers                                                                                                           |

**Decided 29 Sep 2026: X2-a and X6-a.** So:

- `@refuse_401` carries no `WWW-Authenticate`, and the app is unchanged (X2 rows 1–3, column a).
- `unrouted` → `none`, forwarded to the app unauthenticated so its own 404/405/307 is reproduced (X6 rows 1–3 and 5–6, column a). V1 is restated as "for every routed protected path".
- `/api/ir/*` keeps today's 404; no stub in Phase 10 (X6 row 4, column a).

The `CCURE_GATEWAY_UNROUTED` switch and the X2-b/X6-b variants are **dropped** from the 10.2 build. T16 and T17 test only the chosen variants.

## 11. Fail-closed, streaming and logging

- **Fail closed:**
  - checker unreachable, timed out or 5xx → 503 `AUTH_UNAVAILABLE` (§8) on every protected route and on `OPTIONS`;
  - public routes are unaffected;
  - the api down → 502, as today;
  - the gateway starts only after `gateway-auth` is healthy (`depends_on: condition: service_healthy`).
- **Streaming:**
  - `proxy_buffering off`, `proxy_request_buffering off` (evidence uploads do not land in the gateway's temp dir), `proxy_max_temp_file_size 0`;
  - 3600 s read/send timeouts. That exceeds the 25 s notification heartbeat by a wide margin; any timeout below 30 s breaks it (fact 16);
  - `client_max_body_size 50m`;
  - `X-Accel-Buffering: no` from the app is honoured, and nginx strips it.
- **Logging:**
  - `log_format ccure_gw '$remote_addr [$time_iso8601] "$request_method $uri" $status $body_bytes_sent rt=$request_time ut=$upstream_response_time policy=$ccure_policy refusal=$ccure_refusal sub=$ccure_sub jti=$ccure_jti';`
  - **no `$request`, `$args`, `$request_uri`, `$http_referer`, `$http_authorization` or `$http_cookie`**. `$uri` is the decoded path without its query.
  - **The nginx _error_ log is the leak nobody configures:** on an upstream error it writes `request: "GET /…?ticket=… HTTP/1.1"`. The gateway sets `error_log stderr crit;`. The operational signal comes from the access log's `$status`, `$upstream_status` and `refusal=`. Host nginx has the same exposure today (risk R2).

## 12. Implementation order for 10.2 (review stop after each)

1. **10.2a — verification module.** Move the rules into `verification.py`; `tokens.py` delegates. Gate: the Phase 9 suites, the token characterisation and the full suite pass unchanged, and an agreement corpus (§13 T1) passes.
2. **10.2b — checker.** `gateway/token_check/` with JWKS loading and the reason codes; unit-tested against the corpus and the §6/§8 tables.
3. **10.2c — generator.** `generate_route_policy.py`, the generated files and the drift gate. Both X6 variants are generated and tested; neither is selected.
4. **10.2d — nginx config and the isolated harness.** `gateway.conf`, and a disposable compose project `ccure-gw-test` containing:

   - the gateway;
   - the checker;
   - a **golden-replay stub upstream** that answers each `(method, path)` with the recorded application response from `edge_probe_results.json` and `valid_probe_results.json`, and echoes the request headers it received;
   - a stub JWKS signed by a throwaway key.

   No live network, no live keys. The whole §13 suite runs against it.

## 13. Tests that prove behaviour preservation

All of them are generated from, or checked against, `route_auth_matrix.json`. None needs the live system.

| #   | Test                                                                                                                                                                                                                                                                                    | What it proves                                                   |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | --- | ------------------------------------------------------------------------------- | --------- |
| T1  | **Verifier agreement corpus**: every kind × {valid, expired, `nbf` in the future, wrong `aud`/`iss`/`kid`/`alg`, `alg:none`, legacy HS256, a service token, garbage, truncated}, through `tokens.verify` (before 10.2a) and `verification.verify`                                       | one verifier, byte-identical decisions                           |
| T2  | **Checker decision table**, one row per matrix sub-case: policy × {header absent, empty Bearer, Basic, garbage, valid, ticket-as-bearer} × {no ticket, empty ticket, garbage ticket, valid ticket, access-as-ticket, expired ticket, duplicate `ticket` params, percent-encoded ticket} | §5 and §6 are exactly `HTTPBearer` + `get_current_user_flexible` |
| T3  | **Refusal fidelity**: for every `(class, sub-case)` the matrix records, the gateway's response equals the recorded app response in status, body (`request_id` excepted), header **names and counts** (`X-Request-ID` excepted) and CORS headers for an allowed and a disallowed origin  | fact 1–3, 11; §8                                                 |
| T4  | **No `X-Request-ID`** on any gateway-generated response, and `request_id: null` in its body; a client `X-Request-ID` is echoed unchanged on proxied responses                                                                                                                           | V1, fact 7, O9 preserved                                         |
| T5  | **Ticket-first**: valid bearer + garbage ticket → 401 ticket message; valid ticket + garbage bearer → forwarded; `?ticket=good&ticket=bad` → refused (last wins, as Starlette)                                                                                                          | fact 4, risk R1                                                  |
| T6  | **Ticket reuse** within 60 s is **accepted** (not narrowed) on the downloads and WebSockets                                                                                                                                                                                             | fact 13, O4 untouched                                            |
| T7  | **WebSocket**: missing, garbage, HS256, unknown kid, access-as-ticket → 403, empty body, no `X-Request-ID`; valid → 101 and frames relayed                                                                                                                                              | facts 3, 11                                                      |
| T8  | **`OPTIONS`**: an allowed-origin preflight on a protected route → forwarded, 200 with ACAO; disallowed → the app's 400; PNA allowed/disallowed → the app's 200/403                                                                                                                      | fact 12                                                          |
| T9  | **Public routes**: each of the 17 reaches the upstream with **the checker stopped**                                                                                                                                                                                                     | §7, fail-closed scope                                            |
| T10 | **Fail closed**: checker stopped → every protected route 503 `AUTH_UNAVAILABLE` with `Retry-After: 5`; nothing forwarded (the stub records zero hits)                                                                                                                                   | §11                                                              |
| T11 | **Identity stripping**: client-sent `X-Tenant-ID`, `X-Ccure-Auth-*` and `X-Forwarded-User` never reach the stub with the client's values                                                                                                                                                | §9                                                               |
| T12 | **Forwarding**: a forged `X-Forwarded-For` from the client never reaches the stub; the stub sees `X-Forwarded-For` = the `X-Real-IP` host nginx set; `X-Forwarded-Proto` = `https`                                                                                                      | F10-1 on the gateway hop                                         |
| T13 | **Logs**: after the whole suite, `grep -E 'ticket=                                                                                                                                                                                                                                      | token=                                                           | eyJ | Bearer'` over the gateway's access **and** error logs and the checker's log = 0 | F10-3, R2 |
| T14 | **Streaming**: an SSE stub emitting 25 s heartbeats stays open for 120 s, with events delivered as they are sent (timestamps, no batching); a 30 MB file and a 25 MB upload leave nothing under `/var/cache/nginx` and match by SHA-256                                                 | fact 16, V9, V10                                                 |
| T15 | **Cookies**: the `Set-Cookie` headers from the recorded login, refresh and logout (two paths) reach the client byte-identical                                                                                                                                                           | fact 15                                                          |
| T16 | **Unrouted**, run once per X6 variant: 404, 405 (+`Allow`) and 307 (+`Location`) per §10                                                                                                                                                                                                | X6, both variants                                                |
| T17 | **`WWW-Authenticate`**, run once per X2 variant                                                                                                                                                                                                                                         | X2, both variants                                                |
| T18 | **Drift gate**: the generated map equals regeneration from the live route table; every route in the table has exactly one policy; the 17 public routes are exact locations; the matrix route count equals the app's                                                                     | §4                                                               |
| T19 | **Guardrails**: `verification.py` imports only the stdlib, `jose` and `cryptography`; only `tokens.py` and the checker import it; no production code reads `X-Tenant-ID` / `X-Ccure-*`; the checker image contains no `.env` and no private key                                         | §2                                                               |
| T20 | **Existing suites**: Phase 9 token tests, security suites (169 today) and the full suite unchanged                                                                                                                                                                                      | no regression                                                    |

## 14. Additional risks found while designing

- **R1 — query parsing differs between nginx and Starlette.** `$arg_ticket` is the _first_ occurrence and is not percent-decoded; Starlette takes the _last_ and decodes. The checker therefore parses `$args` itself (§5), and T5 pins it.
- **R2 — the nginx error log writes the full request line, query included**, on upstream errors. The gateway uses `crit`; host nginx has the same exposure today and needs the same treatment in the O14 change.
- **R3 — 405 and 307 are also answered before authentication, and the app's 307 `Location` drops `/api`** (a pre-existing bug: a slash-redirect lands on the SPA). Both widen X6 beyond "unknown routes".
- **R4 — the app's refusals include `Access-Control-Allow-Origin` for allowed origins.** A gateway refusal without it would look like a network error to a cross-origin client. §8 preserves it from the same `CORS_ALLOW_ORIGINS` value, which puts an origin list into nginx; the alternative is a documented fidelity gap. Covered by T3.
- **R5 — an empty-body 403 through `return 403 ""`** in a named location: nginx may substitute its own HTML error page for an empty `return` text. T7 must prove the body is empty. If it is not, the refusal is rendered by a tiny static empty file instead.
- **R6 — `X-Request-ID` is echoed at any length** (a 300-character value was observed). The gateway preserves it (O9), but its access log should not print it unbounded, so it is left out of the log format above.
- **R7 — `Retry-After: 60` and `X-RateLimit-*` on successful responses** (slowapi, observed on 200 downloads and on JWKS). The gateway passes them through untouched. It is recorded as a pre-existing oddity, not a gateway concern.
- **R8 — the valid-credential baseline is provisional.** It was run with the owner's credential at the owner's in-session instruction (decision record §14). T3/T5/T6/T7/T15 depend on it.
- **R9 — M3 is not yet complete.** The working-day peak arrives at about 20:50 IST on 30 Sep; `worker_connections` is sized after it.

## 15. 10.2a — the shared verification module (committed `42128b9`)

**What moved.** Every verification rule `tokens.py` held moved to `ccure_platform/identity/verification.py`:

- header checks (refused `jku`/`x5u`/`jwk`/`x5c`/`crit`; a missing or non-string `kid`);
- the fenced legacy HS256 path;
- key choice by `kid` only, and `alg` pinned to the key;
- the python-jose options (`iss`, `aud`, `sub`, `jti`, `iat`, `nbf`, `exp` required; leeway 0);
- the required-claims check, token kind, principal type, and `legacy_service`;
- the any-kind decode, and the service-assertion rules;
- the reason codes.

The kind, ptype, claim and header vocabularies are defined there, and `tokens` re-exports the **same objects**.

**What is injected.**

- `keyset`: a zero-argument provider, called at the same point as before;
- `legacy`: `LegacyHS256(secret)` or `None`;
- `issuer` and `audience`;
- for assertions, `key_for`, `audience` and `now`.

The module reads no configuration, environment, key directory, file, database or Redis, and logs nothing. Importing it loads no application module.

**What `tokens.py` still does.**

- Signing is unchanged.
- It reads `JWTConfig.ACCEPT_LEGACY_HS256`, `SECRET_KEY` and the keyset **at call time**, as before.
- It turns a `Refusal` into the same `ccure.tokens` log line and `None`.
- Public names, signatures and return values are unchanged.

**Evidence.**

- **T1 before/after:** 156 tokens × 5 kinds × 3 audiences (+ a wrong-issuer pass, the any-kind decode, 21 service assertions, the no-keyset path and the unverified readers), with legacy off and on — **5,362 evaluations, 0 differences** in payload, raised exception and log record (level, reason, legacy flag, kid, jti, ptype). Run in a disposable, network-less container with throwaway keys.
- **Permanent test:** `tests/auth/test_verification_agreement.py`, which pins:
  - the recorded table;
  - agreement between `tokens.verify` and a **JWKS-only** verifier (public keys rebuilt from `KeySet.jwks()`, no private key, no secret) over every token × kind × audience;
  - that the JWKS-only verifier refuses every legacy HS256 shape;
  - the import boundary;
  - that `jwt.decode` is called nowhere but `verification`.
- **`tests/repo/test_token_guardrails.py`:** the one existing test changed. Its closed set of JWT-importing modules is now `{tokens, verification}`, which the move requires.
- **Inventory:** OpenAPI (sha256), the route table (273), limiter registrations (93), Celery tasks (21) and beat (11) are identical between HEAD and the working tree.

**Pre-existing behaviour now pinned, not changed:**

- a token whose `iat` is in the future is accepted, because python-jose does not check `iat` and the rules require only `nbf`;
- `alg: none` carrying a known `kid` is refused as `alg_mismatch`;
- an any-kind decode of a service token fails on the user audience.

## 16. 10.2b — the `gateway-auth` checker (committed `f5d7da1`)

**Files** (`gateway/token_check/`):

| File                                     | What it holds                                                                                                                  |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `config.py`                              | The settings: issuer, user audience and JWKS URL (all required), plus JWKS max age (300 s) and minimum refetch interval (30 s) |
| `jwks.py`                                | `JwksKeySource`, the key source `verification` asks for, built from public members only                                        |
| `checker.py`                             | `decide()` and `REFUSALS`, the code → (status, message) table nginx will render in 10.2d                                       |
| `app.py`                                 | The ASGI service: `/check`, `/healthz`, and a lifespan loader that retries until a key set is loaded                           |
| `Dockerfile` + `Dockerfile.dockerignore` | The image and its **allow-list** build context                                                                                 |
| `tests/`                                 | 131 tests                                                                                                                      |

**JWKS source rules:**

- only EC P-256 / ES256 signing keys are taken;
- a set carrying any private member is refused whole;
- a failed fetch keeps the last good set;
- an unknown `kid` refetches at most once per 30 s;
- the whole set is refetched after 300 s, so a removed key stops verifying;
- no redirects are followed, and the body is capped at 64 KiB.

**`app.py` responses:**

- `204` with `X-Ccure-Auth-{Sub,Jti,Ptype,Kind}` on success; no principal headers on no-credential routes;
- `401`/`403` with `X-Ccure-Refusal` on refusal;
- `503` while no key set is loaded;
- `500` for an unknown policy or an internal error — never a pass.

**Behaviour, as reproduced.**

- **Policies:** `none` and every `OPTIONS` pass without reading a credential.
- **`bearer`** is FastAPI's `HTTPBearer()`.
- **`ticket_or_bearer`** is `get_current_user_flexible`: ticket first, and on a ticket failure the `Authorization` header is never consulted.
- **`ticket`** is the WebSocket login: `decode_any_kind` + `type == "ticket"` + `sub`, so every refusal is the same bare 403.
- **Query:** parsed as Starlette parses it (latin-1, `parse_qsl(keep_blank_values=True)`, last `ticket` wins). The first `Authorization` header wins, as in Starlette.
- **No legacy HS256 secret is ever passed** (`legacy=None`).

**Tests (131, run in a disposable, network-less container from the core image):**

- **T2 decision table:** `test_checker.py`, every policy × credential shape.
- **Parity with the real application:** `test_fastapi_parity.py`. The core's own `get_current_auth_context` and `get_current_user_flexible` run with only the DB load stubbed, over 17 `Authorization` shapes × 12 query shapes × 2 routes = **408 combinations, 0 mismatches**. Also Starlette's `QueryParams` on 12 raw queries, and the WebSocket acceptance rule over 11 token shapes.
- **Golden baseline:** `test_matrix_parity.py`, every recorded outcome in `route_auth_matrix.json` (35 cases, bearer / ticket-or-bearer / WebSocket / SSE) reproduced with the recorded status and message. It also asserts that no recorded 401 carried `WWW-Authenticate` (X2-a).
- **Key source:** `test_jwks.py`, covering parsing, private-member refusal, skipped key types, off-curve points, duplicates, readiness, last-good retention, the refetch floor under a forged-kid burst, removal after max age, and HTTP redirect/size/JSON refusal.
- **Service:** `test_app.py`, covering the responses and headers, fail-closed states, 404 for everything else, lifespan loading, and **logs holding no token, query or `Bearer`**.
- **Boundary:** `test_boundary.py`, which checks that imports are confined to stdlib + `cryptography` + `verification` (no JWT library directly, no core config, keys, tokens, DB or Redis), that the build context is an allow-list, that the image is unprivileged with no access log, and that the base image is pinned by digest.

**The image:** `ccure-gateway-auth:10.2b-dev`, built locally, not deployed, not in Compose.

- **Build:** context 40.9 kB (the repository is 3.2 GB); base image the core's `python:3.11-slim` digest; 210 MB; uid 10001.
- **Contents:** `/srv` holds the five checker modules and the three `ccure_platform` files. There is no `.env`, keyset or private key.
- **Unconfigured:** it refuses to start (`ConfigError: CCURE_JWKS_URL is required`).
- **Smoke test** (no network, read-only root, `--cap-drop ALL`, `no-new-privileges`, JWKS from a stub on the container's loopback):
  - before keys: `/healthz` 503, bearer 503, `OPTIONS` 204;
  - after keys: `/healthz` 200 and all 13 cases as characterised;
  - 0.2–0.7 ms per check;
  - 0 tokens in the container log.

**Changed alongside:** `build_matrix.py` now carries the recorded _message_ of valid-credential refusals into the matrix. Regenerating from the same inputs **only added** six messages (four for the checker's cases, two refresh-cookie ones); no existing value changed.

**Deliberately not in 10.2b:**

- no nginx configuration, route-policy generator or compose harness (10.2c/d);
- no compose service or live network;
- the image is not deployed;
- M3 still pending, for connection sizing in 10.2d/10.3.

## 17. 10.2c — the route-policy generator (committed `5cd89c3`)

**Files**

| File                                                      | What it is                                                                                                                                                                                                                           |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Backend/scripts/gateway/route_policy.py`                 | The generator: `live_inventory(app)` → `compile_policy()` → `render_json()` / `render_map()`, plus `evaluate()` (nginx map semantics). CLI: `python -m scripts.gateway.route_policy` with `--check`, `--write` or `--emit json\|map` |
| `gateway/policy/route_policy.json`                        | The machine-readable policy (schema `ccure.gateway.route_policy/1`), generated                                                                                                                                                       |
| `gateway/policy/route_policy.map`                         | The nginx fragment for 10.2d, generated. Two maps: `$ccure_route_class` keyed on `$ccure_scope:$request_method:$ccure_app_path`, and `$ccure_policy`, the checker policy per class                                                   |
| `Backend/tests/repo/test_gateway_route_policy.py`         | 50 tests                                                                                                                                                                                                                             |
| `gateway/token_check/tests/test_route_policy_contract.py` | Every policy the generator can emit is one `gateway-auth` knows                                                                                                                                                                      |

**Source.** The live application's route table (`main.app.routes`), in route order: one entry per (route, method), with WebSocket routes as scope `websocket`. Each route is classified by the dependencies it resolves:

- `get_current_user_flexible` → ticket_or_bearer;
- `get_current_user` / `get_current_auth_context` → bearer;
- neither → public;
- a service-token dependency → **refused** (no gateway policy until Phase 14).

The inventory must also equal the Phase 10.1 characterisation (`route_table.json`) row for row.

**Classes and counts**

| Class            | Checker policy     |                                    Count |
| ---------------- | ------------------ | ---------------------------------------: |
| public           | `none`             |                                       17 |
| bearer           | `bearer`           |                                      251 |
| ticket_or_bearer | `ticket_or_bearer` |    3 (incl. `DELETE /reports/{scan_id}`) |
| websocket        | `ticket`           |                                        2 |
| options          | `none`             | every `OPTIONS`; a rule before any route |
| unrouted         | `none`             |                        the map's default |
| **total routes** |                    |                                  **273** |

**Order.**

- **The Starlette rule:** Starlette dispatches to the first route whose path and method match.
- **The nginx rule:** an nginx `map` checks exact keys first, then regexes in order.
- **How the generator reconciles them:** a literal path becomes an exact key only when no earlier route of the same scope and method matches it; otherwise it becomes a regex in its place, and every templated route is a regex in its place. For the current table that gives 151 exact keys, 122 regexes and 0 shadowed routes.
- **Refusals:** a duplicate with a different class, or a literal shadowed by an earlier template of a different class, is refused, as is any path converter, any `OPTIONS` route, and any key unsafe in nginx.

**X6-a and `/api/ir/*`.** An unrouted request (unknown path, wrong method, trailing-slash redirect, `HEAD` on a `GET` route, a plain `GET` to a WebSocket path, all of `/api/ir/*`) resolves to `unrouted` → checker policy `none`. It reaches the application unauthenticated, and the application answers 404/405/307 as today. X2-a: the map carries no `WWW-Authenticate`.

**Proof of equivalence.**

- `evaluate()` (nginx semantics) equals **Starlette's own router** (`route.matches()`, first FULL match) for every route and for over 1,500 matched and unmatched samples.
- **Real nginx** (`nginx:stable-alpine`, scratch config, no network) evaluated the generated map on 1,868 requests and agreed with `evaluate()` on all of them.

**Determinism and drift.**

- **Determinism:** the output depends only on the route table: no timestamps, a fixed key order, and a trailing newline. Two independent generations, in separate containers and separate processes, were byte-identical.
- **Drift:** `test_committed_policy_matches_the_live_application` regenerates from the live app and compares bytes with `gateway/policy/*`. `test_inventory_matches_the_phase_10_1_characterisation` compares the inventory with the characterisation. `--check` exits 1 naming the stale file.
- **Where the byte comparison runs:** in the api container `gateway/` is not mounted, so the test skips with that reason (the compose-file precedent). CI runs on a full checkout.
- **Proven on a full read-only checkout:**
  - the clean tree passes;
  - a tampered map (DELETE flipped to bearer) fails;
  - a missing JSON fails;
  - **an added application route fails**: it would have been classified public, making 274 routes and 18 public.

**Not in 10.2c:** no nginx configuration beyond the generated fragment, no public-route `location` blocks (design §4 item 2 moves to 10.2d, since they need the proxy settings 10.2d writes), no compose wiring, no deployment.

**Found, not fixed (pre-existing, unrelated):** the tracked `Backend/openapi.json` lacks `/auth/jwks.json` and `/auth/service-token` (Phase 9.3/9.5) and was last regenerated on 25 Sep (`f9fbee1`), so CI's OpenAPI contract gate would already fail at `f5d7da1`. 10.2c leaves the schema byte-identical to HEAD.

## 18. 10.2d — nginx `auth_request` configuration and local harness (committed with this revision)

**Files**

| File                                                | What it is                                                                                                                              |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `gateway/nginx/gateway.conf`                        | The gateway: request classification, `auth_request`, refusal rendering, fail-closed handling, redacted logging                          |
| `gateway/nginx/proxy_api.conf`                      | The proxy settings every forwarding location shares: prefix strip, identity stripping, forwarding headers, WebSocket upgrade, streaming |
| `gateway/nginx/site/harness.conf`                   | Per-environment settings **for the harness only**: upstreams and the one trusted edge address. Production gets its own file in 10.3     |
| `gateway/nginx/entrypoint/40-ccure-cors-origins.sh` | Renders the CORS allow-list map from `CCURE_CORS_ALLOW_ORIGINS` at start; refuses a malformed origin                                    |
| `gateway/harness/docker-compose.yml`                | The isolated harness (project `ccure-gw-harness`, internal network `10.254.10.0/24`, no published port)                                 |
| `gateway/harness/stub_api.py`                       | The API stand-in, built from `gateway/policy/route_policy.json`                                                                         |
| `gateway/harness/outsider.py`                       | An untrusted client, for the trust-boundary tests                                                                                       |
| `gateway/harness/run.sh`                            | The end-to-end driver                                                                                                                   |
| `gateway/harness/scan_logs.py`                      | The log-redaction scan                                                                                                                  |
| `gateway/harness/tests/`                            | 62 harness tests (53 with gateway-auth up, 9 with it stopped), 13 of them static configuration checks                                   |

**Flow.**

1. **Classification.** The **generated** `route_policy.map` classifies every `/api/` request (`$ccure_scope:$request_method:$ccure_app_path`, with the application path being the URI minus `/api`).
2. **Unauthenticated classes.** Policy `none` (public, `OPTIONS`, unrouted) is sent with `return 418` → `@ccure_noauth` in the rewrite phase, before the access phase in which `auth_request` runs. These requests never touch gateway-auth. That is how X6-a is preserved, and why public routes, preflights and unrouted requests keep working while gateway-auth is down.
3. **Protected classes.** Everything else goes through `auth_request /_ccure_auth`:
   - 204 → forwarded with `X-Ccure-Auth-{Sub,Jti,Ptype,Kind}` from gateway-auth;
   - 401/403 + `X-Ccure-Refusal` → `@ccure_refuse`, which renders the application's own status and body for that code;
   - any other outcome → `@ccure_auth_unavailable` → `503 AUTH_UNAVAILABLE` + `Retry-After: 5`, and nothing is forwarded.
4. **The subrequest** carries the client's `Authorization` and the gateway-set `X-Ccure-Policy/Method/Args`; `Cookie`, `Upgrade` and the body are removed. The client cannot supply its own policy, method or query.

**Refusals.**

- **Codes:** the five JSON codes return the characterised body with `request_id: null`.
- **Headers:** the application's security headers (`nosniff`, `DENY`, `no-referrer`, the API CSP, `CORP same-site`), and the CORS headers the application's CORSMiddleware would send: `Access-Control-Allow-Credentials` whenever an `Origin` is present, and `Access-Control-Allow-Origin` + `Vary: Origin` for an allowed one. There is **no `X-Request-ID`** and **no `WWW-Authenticate`** (X2-a).
- **WebSockets:** `ws_refused` is a bare `403`, `text/plain`, zero length.
- **Unknown codes:** a code nginx does not know fails closed as 503.

**Headers.** `add_header` appears only in the two locations that generate responses. Proxied responses are untouched, so every application header arrives exactly once. Measured: header counts via the gateway equal those direct from the stub.

**Identity.** On every forwarded request the gateway clears `X-Tenant-ID`, `X-Tenant`, `X-Org(-ID)`, `X-Organization-ID`, `X-User(-ID/-Email/-Role)`, `X-Auth-User`, `X-Auth-Request-User/-Email`, `X-Forwarded-User/-Email`, `X-Remote-User`, `Remote-User` and every `X-Ccure-*`, then sets `X-Ccure-Auth-*` from gateway-auth only. On the unauthenticated path those are absent.

**Trust boundary.**

- `realip` trusts **one** edge address (`set_real_ip_from`, harness: 10.254.10.10). `X-Real-IP` and `X-Forwarded-For` are **set** to the resolved client, never appended.
- `X-Forwarded-Proto` is believed only from that edge (`geo` on `$realip_remote_addr`).
- An untrusted peer's claims are ignored. This is proven with a second client, at 10.254.10.20.
- The core's own `--forwarded-allow-ips` remains the 10.3 change (F10-1).

**Streaming.**

- `proxy_buffering` and `proxy_request_buffering` are off, with `proxy_max_temp_file_size 0` and 3600 s timeouts.
- **Proof that nothing touches disk:** the harness mounts both nginx temp directories **read-only and empty**, so any attempt to buffer to disk would fail the request. A 30 MiB download and a 25 MiB upload passed byte-identical (SHA-256).
- **SSE:** events arrive one second apart as produced; the first arrives in < 0.5 s.
- **WebSockets:** upgrade to 101 with the frame relayed.

**Logging.**

- The access log is JSON (`escape=json`): peer, resolved client, method, `$uri` captured before the rewrite, status, bytes, times, upstream status, class, policy, refusal code, `sub` and `jti`.
- **Never** `$request`, `$request_uri`, `$args`, a cookie, `Authorization` or the Referer; a static test pins it.
- The error log is `crit` only (design R2).
- `scan_logs.py` found **0** of the 24 tokens minted during a run, no `ticket=`/`token=`, no JWT-shaped string, no `Bearer <value>`, `Authorization`, `Cookie` or `Referer`, in 245 gateway and gateway-auth log lines. It fails on a planted leak (negative control).

**Proof against the Phase 10.1 baseline.**

- **Refusals:** every authentication-layer refusal the characterisation recorded from the **real application** (the edge probe's direct target) — 25 HTTP cases and 10 WebSocket cases — was replayed through the gateway. Status, body (apart from `request_id`), header names and the security, content-type and CORS values are equal.
- **Valid-credential cases** (9 HTTP, 4 WebSocket) match the recorded status and message.
- **Unrouted requests** (404, 405 + `Allow`, 307 + `Location`, `HEAD`, `/api/ir/*`, `%2F`) get the same answer through the gateway as from the stub directly.

**Security posture.**

- nginx (digest-pinned `nginx:stable-alpine` 1.30.5) runs as uid 101 and gateway-auth as uid 10001. Both have a read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, and no published port.
- The harness network is `internal` (no route out).
- The gateway-auth image holds no `.env`, keyset or private key; neither container gets a database, Redis, JWT secret or MFA key.

**Where the implementation refined this design** (each found or settled by the harness):

- **Public routes** are not generated `location` blocks (§4 item 2). The map's `none` policy routes them, together with `OPTIONS` and unrouted requests, to `@ccure_noauth` before authentication. There is one source (the generated map), no second list, and `OPTIONS` no longer depends on gateway-auth (§7's accepted trade-off is gone).
- **Refusals carry `X-Content-Type-Options`**, as the application's own do (§8 had left it to host nginx). Host nginx hides the upstream copy and adds its own, so the client still sees exactly one.
- **Server-level `set` runs again inside the auth subrequest** (with the subrequest's empty `$args` and its own `$uri`). Request facts are therefore captured inside `location /api/`. The first harness run caught this as tickets never reaching gateway-auth; map caching had hidden it for the policy.
- **nginx runs `auth_request_set` on every outcome**, not only on 2xx/401/403. So "authentication had already succeeded" is `$ccure_auth_status ~ ^2`.
- **`return 403 ""` makes nginx serve its HTML error page.** The empty WebSocket body is an empty _variable_.
- **`add_header` applies to a whole location**, so `Retry-After` comes from a map on `$status` (503 only).

**Not in 10.2d:** host-nginx cutover, the core's `--forwarded-allow-ips` / `TRUSTED_PROXIES`, the production site file, `127.0.0.1:8082`, closing `:8000`, the root `docker-compose.yml`, and any deployment. Those are 10.3 onwards. The stale `Backend/openapi.json` (§17) is still not fixed.
