---
paths:
  - "gateway/**"
  - "scripts/host-nginx/**"
  - "scripts/linux/**"
  - "scripts/tls/**"
  - "scripts/gateway/**"
  - "Frontend/nginx.conf"
  - "docker-compose*.yml"
  - "Backend/start.sh"
  - "Backend/core/trusted_proxy.py"
  - "Backend/core/ip_resolver.py"
  - "docs/TLS_SETUP.md"
---

# Host nginx, the gateway, TLS and response headers

> Scoped instructions. Claude Code loads this file when it reads or edits a file matching the `paths` above; every other agent is routed here by `AGENTS.md`. The text was moved verbatim from `CLAUDE.md` at `9bb84d9` (lines 1586–1612, 1644–1693, 1917–1973) and is maintained here. Frozen original: `docs/archive/engineering-record/runtime-architecture-and-edge-security.md`. The repository-wide rules in `CLAUDE.md` still apply.

  **Nginx carries a second layer** (`scripts/host-nginx/nginx-host.conf`:
  `ccure_auth` 30r/m on `/api/auth/`, `ccure_api` 20r/s on `/api/`). Not
  redundant with the application: Argon2 is deliberately expensive, so a login
  flood is CPU exhaustion on the API host whether or not any credential is
  guessed, and the process doing the hashing cannot defend against that. Keyed
  on `$binary_remote_addr` — at that hop the socket peer _is_ the client.
  `limit_req_status 429`, because nginx's default 503 reads as "this server is
  broken". **The `/api/auth/` block duplicates `/api/` in every other respect;
  change the two together.**

  Deploying it _(Windows deployment, history; on the VM host nginx's
  configuration is switched only with `scripts/linux/gateway_edge_switch.sh`,
  see "Since Phase 10.5" below)_: copy to `C:\nginx\conf\nginx.conf`, `nginx -t`, then
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


  **Since Phase 10.5 (live 30 Sep 2026) `:443` goes through the gateway:**
  host nginx → `ccure-api-gateway` (`172.31.254.10`) → `ccure-gateway-auth`
  (`.11`) → api (`.20`), on the `internal` compose network `gateway`, with no
  published port. The compose file sets `TRUSTED_PROXIES` on the api to the
  default above **plus `172.31.254.10`**.
  - **Since 10.6, host nginx reaches the gateway over a unix socket**,
    `/var/lib/ccure-edge/gateway.sock`, and the gateway believes
    `X-Real-IP`/`X-Forwarded-Proto` **only from that socket**.
    - **The directory is the authenticator.** It is `root:www-data 0770`
      (nginx makes the socket 0666), so only host nginx and root can connect.
    - **TCP callers are ordinary clients.** Over TCP every host process shares
      the bridge address `172.31.254.1`, which is how any local process could
      forge a client address in 10.5. The gateway's `:8080` still listens, and
      treats every TCP caller as the client.
    - **Do not add an IP to `gateway/nginx/trust/unix_edge.conf`.**
    - **Do not `mkdir` the directory by hand.** The bind is
      `create_host_path: false`, so a missing directory stops the gateway
      rather than letting Docker create it `root:root 0755`. `harden` creates it.
  - **Since 10.7 the gateway is the only production ingress.**
    - **The api publishes no port.** There is no `127.0.0.1:8000`.
    - **It listens only on `172.31.254.20:8000`** (`API_BIND_HOST`, read by
      `start.sh`; unset means `0.0.0.0`).
    - **It trusts `127.0.0.1, ::1, 172.31.254.10` only.**
    - **The frontend's own `/api/` goes through the gateway** at
      `172.31.254.10:8080` (`Frontend/nginx.conf`), as an untrusted client.
    - **Residual (optional 10.8):** a host process can still dial
      `172.31.254.20:8000`. It arrives untrusted, so it cannot forge an
      address, and it still needs a valid token.
    - **Do not describe this as absolute gateway-only reachability.**
  - **Emergency direct path (10.7).**
    - First: `docker compose -f docker-compose.yml -f
docker-compose.emergency-direct.yml up -d --no-deps api` (`:8000` back,
      `172.18.0.1` trusted).
    - Then: `sudo … rollback`.
    - Return **in this order**: `sudo … cutover` first, then
      `docker compose up -d --no-deps api`. The other order leaves `:443` with
      no working path.
    - Rehearsed live 30 Sep 2026.
    - A plain `docker compose up -d` never applies the override.
  - **Switch with** `sudo scripts/linux/gateway_edge_switch.sh
{status|harden|cutover|rollback|rehearse|logcount|emergency-status}`.
    `rollback` refuses while `:8000` is closed. It swaps between two SHA-pinned
    files in `gateway/edge/host-nginx/` and proves the path over `:443`. Never
    edit `/etc/nginx/conf.d/ccure.conf` by hand: the script refuses a file
    matching neither pin.
  - **`beat`, `worker` and `web-worker` already drift from the compose file**,
    so recreate services with `--no-deps` and name them.
  - **Record:** `docs/architecture/phase10/PHASE10_5_CUTOVER.md`,
    `PHASE10_6_HARDENING.md` and `PHASE10_7_GATEWAY_ONLY.md`.


- **TLS** — host Nginx terminates TLS on **443** and 301-redirects 80. Reached
  at **`https://ccurepro.cdac.in`** and `https://10.180.22.127` _(the Windows
  deployment's `ccurepro.cdacb.in` is not on the VM's certificate and does not
  resolve)_; the Docker published ports are bound to
  127.0.0.1 only, so this is the sole listener on a routable interface and the
  only hop that needs a certificate.

  Certificates come from a **private CA** — `scripts/tls/new_internal_ca.ps1`
  _(written for the Windows deployment, when the app was reached at
  10.180.6.14; the VM serves `https://ccurepro.cdac.in` and 10.180.22.127, see
  "Deployment: Linux VM")_.
  A public CA is impossible here, not merely inconvenient: the app is reached at
  a private address (10.180.22.127 on the VM, 10.180.6.14 on the Windows host)
  and CA/Browser Forum rules forbid certificates for reserved IP
  ranges. Clients run `scripts/tls/install_client_trust.ps1` once. See
  [docs/TLS_SETUP.md](docs/TLS_SETUP.md).

  Two things that look like faults and are not:

  - **`curl` on Windows fails with `CRYPT_E_NO_REVOCATION_CHECK`.** Schannel
    hard-fails when it cannot check revocation, and a private CA publishes no
    CRL. Browsers soft-fail this. Use `curl --ssl-no-revoke`, or verify with
    OpenSSL, which validates the chain properly.
  - **HSTS is ignored on an IP literal** (`https://10.180.22.127` on the VM,
    `https://10.180.6.14` on the Windows host). RFC 6797 §8.1.1 requires
    browsers to discard the header when the host is an IP literal. The IP form
    still gets encryption; only the hostname can be pinned. That is why
    `FRONTEND_URL` was the hostname on the Windows deployment. On the VM it is
    `https://10.180.22.127` (root `.env` and `Backend/.env`, 31 Oct 2026), so a
    link built from it cannot be pinned; whether to change it is an owner
    decision, recorded in the engineering record's open verification register.

  `max-age` is **300** in both Nginx and `main.py`. Raise them **together** and
  only after every client is confirmed working — HSTS is a one-way door, and a
  client that cached HTTPS-only for a year cannot reach a broken deployment to
  be told why. `tests/security/test_cors_and_headers.py` asserts the low value.

- **There is no plain-HTTP gateway any more.** The old `gateway` service
  (`alt-gateway` profile, `nginx/gateway.conf`) duplicated host Nginx's routing
  over plain HTTP. Phase 10 decision D7 retired it and it was removed on 9 Oct
  2026; ingress is host Nginx → `api-gateway` → `gateway-auth` / api. What it
  taught still holds for any proxy added later: over plain HTTP the browser
  refuses to store the refresh cookie (`REFRESH_COOKIE_SECURE` is set
  statically in `.env`, not derived from `X-Forwarded-Proto`), so every session
  dies at the 30-minute access-token expiry. Nothing may publish on `80` (host
  Nginx's redirect listener) or `8080` (the Oracle XE TNS listener on the
  Windows host).

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
  _first_ `Strict-Transport-Security`, so duplicates make ordering decide.
