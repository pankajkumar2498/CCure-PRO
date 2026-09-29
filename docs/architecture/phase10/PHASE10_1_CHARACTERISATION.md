# Phase 10.1 — Gateway characterisation (golden baseline)

|                           |                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**                | Characterisation only. No application code, nginx, Docker/Compose, routing, log format, token policy or live behaviour was changed. Committed with 10.2b.                                                                                                                                                                                                                                                 |
| **Baseline**              | Live application + host nginx at HEAD `fc38b31`, 29 Sep 2026, 19:40–20:20 IST                                                                                                                                                                                                                                                                                                                             |
| **Proposal**              | [`../PHASE10_API_GATEWAY.md`](../PHASE10_API_GATEWAY.md)                                                                                                                                                                                                                                                                                                                                                  |
| **Valid-credential half** | **Observed 29 Sep 2026, 20:35 IST**. The owner supplied their own sign-in in the session and instructed that it be used. It is an org_admin in `org_default`; MFA is not enabled on it. No credential was minted or fabricated. The probe signed in once and signed out at the end; the output holds no token or cookie value. Results are in §3.5, and the matrix now contains **no** `pending` entries. |

## 1. Artefacts

| File                                                   | What it is                                                                                                                                                                                                                                                                                                      |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `route_auth_matrix.json`                               | **The matrix** (schema `ccure.phase10.route_auth_matrix/1`): every one of the 273 live routes with its auth class, response kind, guards, registered limits and proposed gateway policy, plus per-class refusal behaviour and per-surface observations. Each observation cites the probe case it was read from. |
| `route_table.json`                                     | The live route table, dumped from `app.routes` inside `ccure-api`                                                                                                                                                                                                                                               |
| `edge_probe_results.json`                              | 155 observed anonymous/invalid-credential responses (edge and direct `:8000`, plus the SPA and `:3200`): status, every header with its count, redacted body sample                                                                                                                                              |
| `valid_probe_results.json`                             | _(created when the owner runs the valid probe)_                                                                                                                                                                                                                                                                 |
| `scripts/gateway/characterization/route_table.py`      | Route dump, run inside the api container                                                                                                                                                                                                                                                                        |
| `scripts/gateway/characterization/edge_probe.py`       | Anonymous/invalid probe (stdlib only, read-only by construction)                                                                                                                                                                                                                                                |
| `scripts/gateway/characterization/live_valid_probe.py` | Valid-credential probe, interactive, for the owner                                                                                                                                                                                                                                                              |
| `scripts/gateway/characterization/build_matrix.py`     | Assembles the matrix from the three inputs                                                                                                                                                                                                                                                                      |

No output file contains a token: `grep -c eyJ` = 0 on all three JSON files. Ticket and token query values are written as `<X>`.

## 2. Commands

```bash
# route table (read-only import of the app)
docker exec -i -w /app ccure-api python - < scripts/gateway/characterization/route_table.py \
  | tail -1 > docs/architecture/phase10/route_table.json

# anonymous / invalid-credential probe (47 s; paced under host nginx's ccure_auth zone)
python3 scripts/gateway/characterization/edge_probe.py > docs/architecture/phase10/edge_probe_results.json

# F10-1 live proof: 11 × GET /auth/check-username?q=… (10/min) with a forged X-Forwarded-For,
# once per path, then the RATE_LIMIT_REJECTED line in `docker logs ccure-api`
curl -H 'X-Forwarded-For: 203.0.113.77' http://127.0.0.1:8000/auth/check-username?q=…
curl -k -H 'X-Forwarded-For: 203.0.113.78' https://127.0.0.1/api/auth/check-username?q=…
curl -H 'X-Forwarded-For: 203.0.113.79' http://127.0.0.1:3200/api/auth/check-username?q=…

# focused suites (disposable ccure_pytest_db; nothing else running)
docker exec -w /app ccure-api sh -c 'DATABASE_URL="$TEST_DATABASE_URL" python -m pytest -q \
  tests/auth/test_token_characterisation.py tests/auth/test_legacy_cutoff.py tests/auth/test_service_identity.py \
  tests/security/test_cors_and_headers.py tests/security/test_rbac_routes.py tests/security/test_rate_limit_headers.py \
  tests/security/test_rate_limiting.py tests/security/test_endpoint_limit_inventory.py'
#   → 169 passed

# OWNER, in their own terminal (prompts for credentials with getpass; signs out at the end):
python3 scripts/gateway/characterization/live_valid_probe.py
python3 scripts/gateway/characterization/build_matrix.py docs/architecture/phase10/route_table.json \
  docs/architecture/phase10/edge_probe_results.json docs/architecture/phase10/valid_probe_results.json \
  > docs/architecture/phase10/route_auth_matrix.json
```

The valid probe's SSE and WebSocket parsers were self-tested against a throwaway local server (scratchpad `probe_selftest.py`), because they cannot be exercised live without a credential.

## 3. Observed results

Every result below was identical on the edge and on direct `:8000`, apart from the headers host nginx adds (HSTS and `nosniff`).

### 3.1 The error envelope (every API refusal except an unmatched route)

```json
{
  "success": false,
  "error_code": "HTTP_403",
  "message": "Not authenticated",
  "detail": "Not authenticated",
  "request_id": "<same as X-Request-ID>"
}
```

- **No 401 anywhere carries `WWW-Authenticate`.** F9-11 is confirmed live.
- An unmatched route answers Starlette's bare `{"detail":"Not Found"}`, not the envelope.

### 3.2 Refusals by class

| Class (count)        | Missing credential                         | Other scheme (`Basic`)                       | Invalid credential                                                                                                  | Notes                                                                                                                         |
| -------------------- | ------------------------------------------ | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| bearer (251)         | **403** `Not authenticated`                | **403** `Invalid authentication credentials` | **401** `Invalid or expired token` (garbage, `alg:none`, legacy HS256, unknown ES256 kid all alike)                 | An empty `Bearer ` is 403 "Not authenticated"                                                                                 |
| ticket_or_bearer (3) | **401** `Authentication token is missing.` | —                                            | invalid ticket → **401** `Invalid or expired download ticket.`; invalid bearer → **401** `Invalid or expired token` | **A ticket is evaluated first.** Garbage ticket + garbage bearer gives the _ticket_ message. Includes `DELETE /reports/{id}`. |
| ws_ticket (2)        | **403**, empty `text/plain`                | bearer header ignored → 403                  | **403** (garbage, HS256, unknown kid)                                                                               | No `X-Request-ID` and no API headers; `connection: close` direct                                                              |
| SSE (2, bearer)      | 403 as bearer                              | —                                            | 401 as bearer                                                                                                       | JSON envelope, not an event stream                                                                                            |
| public (17)          | reachable                                  | —                                            | —                                                                                                                   | empty bodies → 422 `VALIDATION_ERROR`; refresh/logout without a cookie → 401                                                  |

### 3.3 The 11 items requested

1. **`GET /api/reports/download/<scan_id>`**
   - missing credential → 401 "Authentication token is missing.";
   - invalid ticket → 401 "Invalid or expired download ticket.";
   - invalid bearer → 401 "Invalid or expired token".
   - Valid bearer and valid ticket → 200 with identical bytes. A replayed ticket within 60 s → 200. Expired → 401. A valid bearer with a garbage ticket → 401 (the ticket wins). See §3.5 rows 3–10.
   - M5 shows a real ticket download (HTTP 200) on 29 Sep. Ticket support on downloads is **in use**, not WebSocket-only.
2. **WebSocket ticket routes.** Missing and invalid tickets both give 403 on the upgrade, byte-identical to each other. A valid ticket → 101. The same ticket reused on the same route, the other route and direct → 101. An access token as the ticket → 403. See §3.5 rows 11–13.
3. **`/reset-password` and `/verify-email`.**
   - Served by the SPA with 200 and the index document, whatever the token.
   - `Referrer-Policy: strict-origin-when-cross-origin` is sent **twice**.
   - Neither page removes `?token=` from the address bar. `ResetPassword.jsx` reads it at line 49 and `VerifyEmail.jsx` at line 40; neither calls `history.replaceState`. Every same-origin request the page then makes carries the full URL as its Referer, which is where the 49 Referer exposures in M1 come from.
4. **Public allowlist.** 17 routes, matching the proposal. 14 carry a registered limit; `/`, `/api/pipeline-modes` and `/api/workflow-example` do not.
5. **`/api/ir/*`.** Today it reaches the core and answers **404 `{"detail":"Not Found"}`, with or without a credential**. More generally, **an unmatched route answers 404 before authentication.**
6. **Direct `:8000`.**
   - Same statuses, bodies and API headers as the edge, minus HSTS.
   - **It believes a forged `X-Forwarded-For`**: the rate limiter keyed on `203.0.113.77`. The edge keyed on the real client (`127.0.0.1`), and `:3200/api/` keyed on the forged `203.0.113.79`. F10-1 is proven live on two paths.
7. **`X-Request-ID`.**
   - Generated as a UUID when absent.
   - **A client value is echoed verbatim**, a 300-character one included, in the header and in the body's `request_id`.
   - Absent on WebSocket refusals, PNA preflight answers, SPA responses and nginx-generated responses.
8. **Security headers.**
   - API responses, via the edge: exactly one each of `nosniff`, `DENY`, `no-referrer`, the CSP (`default-src 'none'`), `CORP same-site` and HSTS `max-age=300`.
   - API responses, direct: no HSTS, because there is no `X-Forwarded-Proto`.
   - SPA: `X-Content-Type-Options`, `X-Frame-Options` and `Referrer-Policy` are **duplicated**. `/assets/*` also carries **two `Cache-Control`** values.
   - WebSocket refusals: HSTS and `nosniff` only (added by the edge).
9. **CORS.**
   - Allowed-origin preflight → 200 with the origin echoed and `Allow-Credentials: true`. **The same holds on a protected route with no credential.**
   - Disallowed origin → 400 "Disallowed CORS origin", no ACAO.
   - PNA preflight: allowed → 200, disallowed → 403. Both are answered by the request-ID middleware: no `X-Request-ID`, no API headers.
   - A simple GET from a disallowed origin → 200 with `Access-Control-Allow-Credentials: true` and no ACAO (harmless).
   - Host nginx adds no CORS headers.
10. **Refresh cookie.**
    - Every failure path (no cookie, garbage, legacy HS256; logout without a cookie) → 401 "Invalid or expired refresh token", and **no `Set-Cookie` at all**. `_clear_refresh_cookie()` writes to a `response` that the raised `HTTPException` then discards, so a dead cookie is never cleared in the browser.
    - Login attributes, rotation, pre-rotation reuse, logout (two clearing cookies, `Path=/` and `Path=/auth`) and refresh-after-logout: §3.5 rows 1 and 17–20.
    - From the code: a reused, rotated refresh token fails for that session only. There is no family revocation.
11. **SSE and streaming.** Without a valid credential, refused before streaming begins (403/401 JSON). With a valid credential, `/scans/events` heartbeats every ~2 s and `/notifications/stream` every 25 s. See §3.5 rows 14–16.

### 3.5 Valid-credential results (`valid_probe_results.json`)

| #   | Case                                                  | Observed                                                                                                                                                                                                                                                                                                          |
| --- | ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Login                                                 | 200. `Set-Cookie: ccure_refresh_token=…; HttpOnly; Max-Age=604800; Path=/; SameSite=lax; Secure` (no Domain)                                                                                                                                                                                                      |
| 2   | Bearer `GET /scans`                                   | 200; `X-Request-ID` present; client `X-Request-ID` echoed; allowed `Origin` → ACAO echoed + `Allow-Credentials: true`                                                                                                                                                                                             |
| 3   | Download, bearer, edge / direct                       | 200 `application/pdf`, 46,191 bytes, `Content-Length`, `ETag`, `Last-Modified`, `Content-Disposition: attachment`. **Identical SHA-256** (`71fd2cbc…`) on every valid path below. `X-RateLimit-*` **and `Retry-After: 60` on a 200**.                                                                             |
| 4   | Download, ticket                                      | 200, same bytes                                                                                                                                                                                                                                                                                                   |
| 5   | **The same ticket again, within 60 s**                | **200.** A ticket is **reusable** while it is unexpired: three downloads (edge ×2, direct ×1) and four WebSocket upgrades from **one** ticket.                                                                                                                                                                    |
| 6   | Ticket + valid bearer                                 | 200                                                                                                                                                                                                                                                                                                               |
| 7   | **Valid bearer + garbage ticket**                     | **401 "Invalid or expired download ticket."** Ticket-first is confirmed with valid credentials: a present ticket overrides a valid bearer.                                                                                                                                                                        |
| 8   | Access token as `?ticket=`                            | 401 "Invalid or expired download ticket."                                                                                                                                                                                                                                                                         |
| 9   | Ticket as bearer on `/scans`                          | 401 "Invalid or expired token"                                                                                                                                                                                                                                                                                    |
| 10  | Ticket after 61 s                                     | 401 "Invalid or expired download ticket."                                                                                                                                                                                                                                                                         |
| 11  | WebSocket, valid ticket, both routes, edge and direct | **101**; first frame is JSON with keys `phase, progress, scan_id`, 561 bytes. No `X-Request-ID` on the 101; the edge adds HSTS + `nosniff`. _(Two cases asked for two frames and the finished scan sent one, so the probe's timeout discarded the frame; the 101 stands. The probe now keeps frames on timeout.)_ |
| 12  | WebSocket, the same ticket on the other route         | **101.** Reuse works across routes and across edge/direct.                                                                                                                                                                                                                                                        |
| 13  | WebSocket, access token as ticket                     | 403                                                                                                                                                                                                                                                                                                               |
| 14  | SSE `/scans/events`                                   | 200 `text/event-stream`, chunked, `Cache-Control: no-cache`; `connected` at 20 ms, `scans` at 42 ms, heartbeat every ~2.0 s                                                                                                                                                                                       |
| 15  | SSE `/notifications/stream`                           | 200; `connected` and a heartbeat at once, then **25 s heartbeats** (code: `routers/notifications.py:158`). The 8 s window saw no second heartbeat, so the probe stopped on its 11 s idle timeout.                                                                                                                 |
| 16  | StreamingResponse (ISO SoA PDF)                       | 200 chunked, 21,477 bytes, `Content-Disposition`, `X-RateLimit-*` + `Retry-After`                                                                                                                                                                                                                                 |
| 17  | Refresh with a valid cookie                           | 200; **rotated** (new cookie value); same attributes as login                                                                                                                                                                                                                                                     |
| 18  | Refresh with the pre-rotation cookie                  | 401 "Invalid or expired refresh token"; no family revocation                                                                                                                                                                                                                                                      |
| 19  | Logout                                                | 200; **two** clearing cookies, `Path=/` **and `Path=/auth`**, both `Max-Age=0; SameSite=lax; Secure`, without `HttpOnly`                                                                                                                                                                                          |
| 20  | Refresh after logout                                  | 401                                                                                                                                                                                                                                                                                                               |
| 21  | **Access token after logout**                         | **200.** Access tokens are stateless and remain valid until expiry (≤ 30 min). Neither the app nor a gateway can revoke them on logout.                                                                                                                                                                           |

### 3.4 M3 sampler (still running; ends about 20:50 IST on 30 Sep)

- **Samples:** 520, from 18:51 to 20:18 IST on 29 Sep.
- **Long-lived connections:** one, my own 20 s validation connection.
- **Dialers seen:** host nginx (uid 33) and me (uid 1001). The API-side peer was only ever `172.18.0.1`.
- **Nothing from `:3200` was long-lived.** The probes there were sub-second.
- **No user activity this evening**, so the working-day peak is still to come.

## 4. Discrepancies between the proposal and live behaviour

| #   | Proposal assumed                                          | Live behaviour                                                                                                                                                                       | Consequence                                                                                                                                              |
| --- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| X1  | Gateway refusal body `{"detail": …}`                      | The envelope in §3.1, including `request_id`                                                                                                                                         | The gateway must emit the envelope. `request_id` must be absent or null, never invented.                                                                 |
| X2  | Invalid → 401 **with** `WWW-Authenticate: Bearer`         | No 401 carries `WWW-Authenticate`                                                                                                                                                    | Mirroring today means omitting it. Adding it is a (correct) behaviour change, and a decision.                                                            |
| X3  | Missing → 403 uniformly                                   | 403 on bearer routes; **401** "Authentication token is missing." on the ticket-or-bearer routes; 403 "Invalid authentication credentials" for a non-Bearer scheme; 403 on WebSockets | The refusal is **per route class and per sub-case**, not one rule                                                                                        |
| X4  | One "invalid" message                                     | Invalid ticket → "Invalid or expired download ticket."; invalid bearer → "Invalid or expired token"                                                                                  | The checker must say which credential failed                                                                                                             |
| X5  | Ticket or bearer, unordered                               | **The ticket wins when present**; the bearer header is then not consulted                                                                                                            | The gateway must evaluate in the same order, or a request the app would refuse passes (or the reverse)                                                   |
| X6  | Default-bearer gateway, no stated effect on unknown paths | Unknown paths answer 404 **before** authentication, and `/api/ir/*` is 404 whether or not a credential is sent                                                                       | A default-bearer gateway turns anonymous 404s into 403s. That is a visible change (and arguably better against route enumeration), and needs a decision. |
| X7  | V2: gateway WebSocket refusal = 401                       | The app refuses the upgrade with **403**                                                                                                                                             | Mirror 403. The gateway-vs-app discriminator must then be the gateway's log line (or an agreed marker header), not the status.                           |
| X8  | `X-Request-ID` behaviour as a side note (F10-8)           | Echoed verbatim at any length, in the header **and** the body                                                                                                                        | V1 must send none. O9 now covers length and charset too.                                                                                                 |
| X9  | OPTIONS passes through                                    | Confirmed necessary: a preflight on a protected route must get 200 with no credential                                                                                                | Every `OPTIONS` = policy `none` at the gateway, as proposed                                                                                              |
| X10 | Tickets possibly restricted to sockets and downloads      | M5: **real** ticket use on `GET /api/reports/download/{id}`                                                                                                                          | Ticket-or-bearer on the two download GETs is **mandatory**. The `DELETE` stays open (O4).                                                                |
| X11 | `:3200` a bypass by code reading                          | Live: `:3200/api/` reaches the API, believes a forged XFF, and merges SPA headers into API responses, including **`HSTS max-age=31536000; includeSubDomains`** and a second CSP      | Stronger than recorded; 10.7 must remove or neutralise that location                                                                                     |
| X12 | Refresh failures clear the cookie                         | They never send `Set-Cookie`                                                                                                                                                         | Pre-existing defect, recorded; the gateway must not "fix" it silently                                                                                    |

## 5. Findings that must be carried into Phase 10.2

1. **Refusal fidelity table.** `gateway-auth` returns a _reason_, and the gateway maps (route class × reason) to the exact status, message and envelope in §3.2. Its tests are generated from `route_auth_matrix.json`, so they cannot drift from the baseline.
2. **Ticket precedence.** On ticket-or-bearer routes: if `ticket` is present, verify it as kind `ticket` and ignore `Authorization`; otherwise require `Bearer`. Same order as `get_current_user_flexible`.
3. **Ticket support on the download GETs is mandatory** (M5, X10). The ticket on `DELETE /reports/{id}` remains decision O4.
4. **WebSocket refusals mirror the app:** 403, empty body, no `X-Request-ID`. The gateway's own log line is the "refused at the gateway" evidence (X7).
5. **The shared verification module must reproduce the 401 cases observed:** `alg:none`, legacy HS256 while the cut-off is live, unknown `kid`, garbage. It also needs the valid-probe cases once recorded: expired ticket, access token as ticket, ticket as bearer.
6. **`WWW-Authenticate`** (X2) and **unknown-path 404 before auth** (X6) need an owner decision before the fidelity table is frozen.
7. **Envelope `request_id`** on gateway refusals is null or absent, and the gateway emits **no `X-Request-ID`** header (X1, V1).
8. **`OPTIONS` = `none`** for every path, including PNA preflights, which the app answers without `X-Request-ID` (X9).
9. **F10-1 is proven live** on `:8000` and `:3200`. The `--forwarded-allow-ips` and `TRUSTED_PROXIES` change belongs in 10.3, together with the gateway's fixed address.
10. **`:3200/api/`** (X11): the gateway design must include removing or re-pointing the frontend container's `/api/` location (10.7), and V4/V13 must test it.
11. **Referer leak of reset and verify tokens** comes from the SPA, not nginx. Log redaction (O14) must cover `$http_referer`. Removing it at the source (`history.replaceState`, or `Referrer-Policy: no-referrer` on those two routes) is a frontend change for the owner to schedule. It is not part of 10.2.
12. **Pre-existing defects recorded, not fixed:** refresh failures never clear the cookie (X12); duplicate SPA headers and a double `Cache-Control` on assets; `Retry-After: 60` and `X-RateLimit-*` on a **200** from `/auth/jwks.json` (slowapi); `/index.html` answers 404 with the HTML body.
13. **Valid-credential characterisation is complete** (§3.5). Still pending: the working-day M3 figure (sampler ends about 20:50 IST on 30 Sep).
14. **Tickets are reusable within their 60 s lifetime**, across routes and across edge/direct (§3.5 rows 5 and 12). The gateway must not add single-use semantics silently; single-use tickets are a separate decision (O4).
15. **Access tokens survive logout for up to 30 min** (§3.5 row 21). This is a property of stateless tokens; the gateway must not be described as enforcing logout.
16. **Cookie paths must pass through untouched.** The app clears both `Path=/` and `Path=/auth`, so no `proxy_cookie_path` may be added.
17. **The notifications heartbeat is 25 s**, so every read timeout on the SSE path must exceed it (the current 3600 s does).
