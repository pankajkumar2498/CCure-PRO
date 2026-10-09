# Phase 10.4 — Isolated TLS test listener (127.0.0.1:8443)

|                      |                                                                                                                                                                                                                                              |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**           | Committed with this document. **No production cut-over**: host nginx still sends `:443` straight to `:8000`, `:8000` stays published, and no live container, configuration, database, key, certificate, DNS entry or credential was touched. |
| **Baseline**         | `ecc7ac7` (Phase 10.3). The 10.2 design, the 10.1 characterisation and the 10.3 trust boundary remain the source of truth.                                                                                                                   |
| **Frozen decisions** | X2-a, X6-a (`/api/ir/*` 404), route classes, `OPTIONS` unauthenticated, `DELETE /reports/{id}` ticket-or-bearer, no `X-Request-ID` on gateway refusals, token policy. None changed.                                                          |

## 1. What was built

The full HTTPS path, end to end, against the real application — with nothing
live in it:

    client ──TLS──▶ edge-tls ──▶ gateway ──auth_request──▶ gateway-auth
             127.0.0.1:8443       (10.2d)  └──────────────▶ api (real application, 10.3 stack)

- **`edge-tls` is a replica of host nginx's `/api/` behaviour**
  (`gateway/edge/edge-tls.conf`), not a second gateway. Host nginx cannot be
  touched in this phase, and it is the hop that terminates TLS in production,
  so the replica copies what it does to a request: `X-Real-IP` and
  `X-Forwarded-For` set to `$remote_addr` (never appended), `X-Forwarded-Proto
$scheme`, `Host $host`, the WebSocket upgrade, `proxy_buffering off`, 3600 s
  read/send timeouts, `client_max_body_size 50m`, and the same header handling
  (server-level `nosniff`/`DENY`/`Referrer-Policy`/HSTS, with HSTS and
  `nosniff` hidden from upstream and re-added in the `/api/` blocks). It
  forwards to the **committed** gateway (`gateway/nginx/gateway.conf`,
  `proxy_api.conf`, the generated route map and gateway-auth) unchanged.
- **Deliberately omitted:** host nginx's `limit_req` zones. They are an
  edge-of-host control keyed on the socket peer and would make the per-client
  tests measure nginx rather than the application.
- **The gateway trusts the edge by address.** `alongside.conf`'s
  `set_real_ip_from` and trust `geo` name `10.254.20.5` (edge-tls) beside
  `10.254.20.1`, exactly as the production gateway will name host nginx's
  arrival address.
- **`runner-tls`** runs the HTTPS suite from inside the network
  (`10.254.20.60`). Through the published port every host client arrives as
  the docker-proxy address, so distinct client identities are only observable
  in-network. The listener checks also run from the host through
  `127.0.0.1:8443`.

## 2. Certificate strategy

- **Throwaway, generated per run**, by `gateway/alongside/make_test_tls.py`
  inside the backend image, into the run's scratch directory
  (`$ALONGSIDE_WORK/tls`), and deleted with the stack.
- A one-day CA ("CCure Phase 10.4 THROWAWAY test CA") signs one leaf. **The CA
  private key is never written** — it exists only in the generating process —
  so the CA can never sign anything else. The leaf key is mode 0600, owned by
  the nginx uid, and mounted read-only into edge-tls alone.
- SANs: `ccurepro.cdac.in`, `localhost`, `edge-tls`, `127.0.0.1`; EKU
  serverAuth only.
- **No production certificate, key, CA or keyset is referenced** — asserted
  statically over the edge config, the compose file and `run.sh` (§6). No key
  or certificate file is committed; the gateway-auth image's `.dockerignore` is
  an allow-list, so the scratch material cannot enter any image.

## 3. Results

**Listener** (from the host via `127.0.0.1:8443`, and in-network):

- Handshake verifies against the throwaway CA; the certificate's SANs are
  exactly the four above; a name outside them and the system trust store both
  fail verification.
- TLS 1.3 negotiated by default; TLS 1.2 offered with ECDHE suites only; TLS
  1.0 and 1.1 refused; session tickets off.
- Plain HTTP on the TLS port: nginx's `400 plain HTTP request was sent to HTTPS
port`, nothing from the application. There is no HTTP→HTTPS redirect on this
  listener by design — it has no plaintext port.
- `ss`: `127.0.0.1:8443` only.

**HTTPS path vs the application directly** (25 tests): same status, header set
and body as the direct request for the 13 public routes, bearer, the four
bearer refusals, all six ticket/bearer precedence combinations on
`GET /reports/download/{id}` and `DELETE /reports/{id}`, `OPTIONS`, 404/405/307
and `/api/ir/*` (404). Identity headers (`X-Tenant-ID`, `X-User-ID`,
`X-Ccure-Auth-Sub`, `X-Forwarded-User`, `X-Real-IP`) change nothing. A client's
`X-Request-ID` is preserved once; gateway refusals carry none (frozen). CORS
headers equal the direct response's. Every security header appears exactly
once.

**Scheme, HSTS, trust:**

- `GET /api/scans/` answers `307 Location: https://ccurepro.cdac.in/scans` —
  the application resolves **https** from the edge's `X-Forwarded-Proto`,
  believed because edge → gateway → api is trusted hop by hop (10.3).
- It does so with **no header**, with a spoofed `X-Forwarded-Proto: http`, and
  with that plus a forged `X-Forwarded-For`: the client cannot move the scheme.
- HSTS appears **exactly once**, `max-age=300`, on every response including
  gateway refusals and 404s.
- Rate-limit identity: the runner forged a fresh `X-Forwarded-For` and
  `X-Real-IP` on every request and was limited within 10 requests all the same;
  the insider (`10.254.20.50`) then made a request over TLS and got 200 — its
  own bucket. The API's `RATE_LIMIT_REJECTED` log records only
  `10.254.20.60` for the runner and never a forged `203.0.113.*` address, so
  `request.client`, the audit address and the limiter key agree.

**Streaming over HTTPS:**

- **WebSocket** upgrade over `wss` with a valid ticket: 101 and the same first
  frame as direct; without a ticket or with a bad one: a bare 403, no body, no
  `X-Request-ID`.
- **SSE** `/api/notifications/stream`: `event: connected` arrives in under 1 s.
- **20 MiB evidence upload** (`POST /compliance/controls/{id}/evidence`) through
  TLS: 201, and the application's own SHA-256 of what it stored equals the
  sent content's; the **download** through TLS is byte-identical, and equal to
  the same download taken directly.
- **Nothing buffered to disk by the gateway:** its proxy and body temp paths
  are mounted from an empty read-only directory, so any spill would fail the
  request; the 20 MiB upload and download succeeded.
- Timeouts: 3600 s read/send on the edge and in `proxy_api.conf`, 2 s on the
  auth subrequest (static test).

**Logging:** 802 gateway, gateway-auth and edge log lines scanned for the 12
tokens minted in the run (access, refresh cookie, tickets): **0 problems**.
The edge logs `$uri` (no query), method, status, bytes, time and the TLS
version — never `Authorization`, cookies, `Referer` or a ticket.

## 4. Finding: host nginx buffers request bodies to disk

Live host nginx has `proxy_buffering off` but **not**
`proxy_request_buffering off`, so a request body larger than
`client_body_buffer_size` (16 KiB by default) is written to nginx's
client-body temporary directory before it is proxied — every evidence upload
passes through the host's disk. The replica mirrors this faithfully (on a
tmpfs). The gateway itself does not buffer. Whether host nginx should gain
`proxy_request_buffering off` is a cut-over decision (10.5); it is not
changed here.

## 5. Production safety

`run.sh` fingerprints production before starting and again at the end and
fails on any difference — **read-only** (`sha256sum`, `docker inspect`,
`printenv`, one `SELECT`), and a static test pins that nothing else in the
script may name a production path:

| Check                               | Before = after                                        |
| ----------------------------------- | ----------------------------------------------------- |
| `/etc/nginx/conf.d/ccure.conf`      | sha256 `638fd33f797229b6…`                            |
| `ccure-api` started                 | `2026-09-29T12:18:09Z` (not restarted)                |
| `ccure-db` started                  | `2026-09-25T06:28:57Z`                                |
| live keyset                         | sha256 `043bfca1f8ddf429…`                            |
| token config                        | `CCURE_TOKEN_SIGNING_ALG=ES256`, legacy HS256 `false` |
| live schema head                    | `f3b5d7e9a1c4`                                        |
| `:8000`, `:443`                     | unchanged; not touched                                |
| `8443`, `8082`, `18000/18001/18050` | `127.0.0.1` only, removed with the stack              |

No live credential was used and no token was printed.

## 6. Tests

- `gateway/alongside/tls_tests/test_tls_listener.py` — 10: handshake, SANs,
  versions, plaintext.
- `gateway/alongside/tls_tests/test_https_app.py` — 25, in-network only.
- `gateway/alongside/tls_tests/test_tls_static.py` — 10: binding
  `127.0.0.1:8443` only, nothing published beyond loopback, TLS policy, no
  production cert/key/config referenced, host nginx never mounted or written,
  the live-state fingerprint read-only, no key can enter an image or be
  committed, edge header semantics, redacted log format, timeouts.
- `gateway/alongside/run.sh` runs 10.3 (33) + 10.4 (20 from the host; all 45
  in-network) and the exposure, secret, log, rate-limit-identity and
  production checks.

## 7. Deferred, recorded

- **10.5 cut-over** — not started. The TLS edge here is a replica; production
  TLS stays with host nginx.
- **`proxy_request_buffering`** on host nginx (§4).
- **F10-3**, the host-process residual on `:8000`, the gateway's address on
  the live network, and the stale `Backend/openapi.json` — unchanged from 10.3.
