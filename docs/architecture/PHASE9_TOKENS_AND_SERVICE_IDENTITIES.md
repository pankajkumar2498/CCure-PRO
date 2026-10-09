# Phase 9 — Verifiable tokens and service identities (design proposal)

> **Superseded in part (6 Oct 2026, Phase 9.6c).** Where this document describes HS256 tokens, `JWT_SECRET_KEY`, `CCURE_TOKEN_SIGNING_ALG` or `CCURE_ACCEPT_LEGACY_HS256`, that is **history**: the platform signs and accepts ES256 only and holds no JWT secret. `MFA_ENCRYPTION_KEY` is required and has no fallback. Current state: `CLAUDE.md`, "Token signing keys" and "MFA key".

|               |                                                                                                                                                                                                                                                                                                                               |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**    | **Design approved 29 Sep 2026** (`9e296b3`), with the owner's amendments in §11. **Steps 9.1–9.5 done**; ES256 issuance live since 29 Sep 2026 (§15.3); service identities built, none registered (§16); 9.6a done; 9.6b done as a **forced** cut-off on 29 Sep 2026 — legacy HS256 verification off since 17:40 IST (§17.5). |
| **Date**      | 29 Sep 2026                                                                                                                                                                                                                                                                                                                   |
| **Plan**      | [`CCURE_PLATFORM_MODULAR_ARCHITECTURE.md`](CCURE_PLATFORM_MODULAR_ARCHITECTURE.md) rev 4: Phase 9, §3.2 (gateway), §3.5 (IR), §3.9 (future auth service), §8.1–8.2, rules 9, 12, 13; decisions D4, D9                                                                                                                         |
| **Contracts** | [`contracts/PHASE4_INTEGRATION_CONTRACTS.md`](contracts/PHASE4_INTEGRATION_CONTRACTS.md) §4.1–4.3 (integration endpoints, service identity, tenant)                                                                                                                                                                           |
| **Builds on** | Phase 8 complete at `ef668dc`                                                                                                                                                                                                                                                                                                 |

## 0. What the plan already says, and what it leaves open

**Phase 9 in the plan:**

> Access and refresh tokens move from HS256 to RS256/ES256, with the public key
> at a JWKS endpoint. **During the switch both signatures are accepted** —
> refresh tokens are JWTs that live 7 days — so nobody is signed out. The
> platform issues service identities, and the core and IR each get one. D4 and
> D9 are settled here.
>
> _Done when:_ a token verifies with the public key alone; a service obtains
> its own token; an old HS256 token still refreshes until it expires.

**Already fixed elsewhere in the plan and contracts** (and followed here):

- **Asymmetric signing.** The gateway and every service can verify a token and
  none can mint one (§8.1).
- **Tokens are verified twice.** The gateway verifies first, then the service
  that handles the request (§3.2, rule 9).
- **Identity comes only from a verified credential.** The tenant comes from
  the token's claims. A caller-set `X-Tenant-ID` is never accepted (§8.2).
- **Integration calls come from services, never users.** Every call is made by
  a service identity. Scopes are module-prefixed atoms such as
  `audit:incident_evidence:write`. Every call is written to the audit log and
  carries its own rate limits (contracts §4.2).
- **Internal processes are not clients.** The Celery workers and beat talk to
  their own service's database and queues and never call another service
  (rule 12).
- **The issuer must be movable** to a separate authentication service later
  without touching modules (§3.9).

**Left open, and not silently chosen here (§H):**

- RS256 or ES256.
- D4: client credentials or platform-issued keys.
- D9: IR's permissions in the token, or looked up.
- The issuer and audience values.
- Key storage.
- The JWKS path.
- The transition window.
- Service-identity storage.
- The JWT library.

Each has a recommendation and needs the owner's answer.

---

## 1. Current token architecture — measured baseline (29 Sep 2026)

Measured from source at `ef668dc`, and from the running deployment with
read-only checks. No secret value was read or printed.

### 1.1 Token types

All are JWTs signed by one function, `jwt_handler._create_token`.

| `type` claim    | Created by                                                | Lifetime                                | Claims                                                    | Carried as                                                                               | Verified by                                                                                                                                                         |
| --------------- | --------------------------------------------------------- | --------------------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `access`        | `create_access_token` (login, MFA verify, refresh)        | 30 min (`ACCESS_TOKEN_EXPIRES_MINUTES`) | `sub`, `username`, `type`, `role`, `org_id`, `iat`, `exp` | `Authorization: Bearer`                                                                  | `identity.dependencies._decode_access_payload` → every protected route                                                                                              |
| `refresh`       | `create_refresh_token`, `refresh_access_token` (rotation) | 7 days (`REFRESH_TOKEN_EXPIRES_DAYS`)   | `sub`, `type`, `jti`, `iat`, `exp`                        | HttpOnly cookie `ccure_refresh_token` **or the request body** (`_resolve_refresh_token`) | `_get_refresh_session`: signature **plus** a `refresh_token_sessions` row matched on `jti` and a SHA-256 hash of the token, not revoked, not expired, `sub` matches |
| `ticket`        | `create_download_ticket` (`POST /auth/ticket`)            | 60 s                                    | `sub`, `username`, `type`, `iat`, `exp`                   | `?ticket=` query parameter                                                               | `get_current_user_flexible` (report and evidence downloads); **the two WebSocket logins** (`routers.scan_history`, `routers.web_scans`)                             |
| `mfa_challenge` | `create_mfa_challenge_token` (login step 1)               | 5 min                                   | `sub`, `username`, `type`, `role`, `org_id`, `iat`, `exp` | request body `mfa_token`                                                                 | `/auth/mfa/*` verify handlers                                                                                                                                       |

**None of them carries `iss`, `aud`, `nbf`, `kid` or a `jti`** — except the
refresh token, whose `jti` is its session key.

### 1.2 Algorithm, keys and library

- **HS256**, one symmetric secret (`JWT_SECRET_KEY`) for every token type.
  `ALGORITHM = "HS256"` is a module constant.
- **Library:** `python-jose[cryptography]==3.3.0`. PyJWT is not installed.
  `cryptography` 46.0.7 is present.
  - Version 3.3.0 has published 2024 advisories (algorithm confusion with
    certain key types; unbounded JWE decompression). Re-verify them against
    the advisory databases before implementation.
  - The current code pins `algorithms=["HS256"]` on decode, which is the usual
    mitigation for the first.
- **Configuration:** `config.JWTConfig.SECRET_KEY`, from the environment.
  - Compose **requires** `JWT_SECRET_KEY` from the root `.env` and injects it
    into **api, worker, web-worker and beat**. `Backend/.env` holds the same
    value.
  - A development default exists, and a known-weak-key list refuses it when
    `APP_ENV=production`.
- **Key reuse — the most important constraint (finding F9-1).**
  `MFA_ENCRYPTION_KEY` defaults to `JWT_SECRET_KEY`, and it is **unset** in
  both env files and all four containers. `AppConfig.MFA_KEY` is a Fernet key
  derived as `sha256(MFA_ENCRYPTION_KEY)`, and it encrypts `users.totp_secret`.
  **Three accounts hold an encrypted TOTP secret.** Rotating, replacing or
  unsetting `JWT_SECRET_KEY` before this is decoupled makes their MFA secrets
  undecryptable, which locks them out.

### 1.3 Verification behaviour

- **`decode_token(token)`** pins the algorithm, checks the signature and
  `exp`, and returns the payload or `None`.
  - It **does not check `type`**. Every caller checks it separately — ten
    call sites, each written by hand: seven in platform code, plus the
    rate-limit audit and the two WebSocket logins (F9-3).
- **Access tokens:**
  - The `type` must be `access`.
  - The user is loaded **on every request**. The request is refused if the
    account is deleted or inactive, or its organisation is deactivated.
  - The `role` and `org_id` claims must match the database when present. This
    is a compatibility rule for tokens issued before those claims existed.
  - So an access token has **no token-level revocation**, but deactivating an
    account or organisation takes effect on the next request.
- **Refresh tokens:**
  - They are stateful: rotation on every use, and the old row is marked
    `revoked_at` / `replaced_by`.
  - Logout revokes the presented token. Password reset, admin reset and any
    MFA change revoke all of the user's sessions.
  - **There is no reuse detection**: a replayed, already-rotated refresh token
    is refused but does not revoke its family.
  - Rows are purged daily (`purge_expired_refresh_sessions`).
- **Tickets are reusable for their 60 seconds** (no single-use `jti`), and
  travel in URLs, so they can appear in access logs (F9-4).
- **Rate-limit audit** (`core.rate_limit_audit`, wired in `main.py`) decodes
  any non-refresh token to name the caller in a 429 record.

### 1.4 Where tokens are made and read

| Where                                           | What                                                                   | Kind                                   |
| ----------------------------------------------- | ---------------------------------------------------------------------- | -------------------------------------- |
| `ccure_platform.identity.jwt_handler`           | all creation; `decode_token`; refresh rotation and revocation          | platform                               |
| `ccure_platform.identity.dependencies`          | access and ticket verification for routes                              | platform                               |
| `ccure_platform.identity.router`                | login, MFA challenge and verify, refresh, logout, ticket issue         | platform                               |
| `routers.user_profile`                          | reads the refresh cookie's `jti` to mark the current session           | platform-side router                   |
| `main.py`                                       | hands `decode_token` to `core.rate_limit_audit`                        | composition root                       |
| `core.rate_limit_audit`                         | decodes via the injected decoder                                       | infrastructure                         |
| **`routers.scan_history`, `routers.web_scans`** | **their own WebSocket ticket login** (`decode_token` + a `User` query) | module code, **reserved for Phase 10** |
| `scripts/admin/create_admin.py`                 | `hash_password` only                                                   | tooling                                |

**No other module touches token internals.** The Phase 8 identity ratchet
holds that: only the two WebSocket files and `core.tasks`'s mail re-export
still import identity internals.

### 1.5 Tests that pin token behaviour today

| Area                                 | Tests                                                                                                                               |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| Sessions, refresh, revocation, purge | `tests/auth/test_session_management.py` (10+)                                                                                       |
| MFA                                  | `tests/auth/test_mfa.py`                                                                                                            |
| Org deactivation vs tokens           | `tests/security/test_org_deactivation.py` (4)                                                                                       |
| Claims                               | `tests/security/test_tenant_isolation_admin.py::test_access_token_contains_org_and_role_claims`                                     |
| Ticket boundary                      | `tests/security/test_nvd_admin_authorization.py::test_a_download_ticket_cannot_reach_these_routes`; report and audit download tests |
| Uniform bad-token answer             | `tests/security/test_rate_limiting.py::test_bad_token_answers_uniformly_whatever_is_wrong_with_it`                                  |
| Password reset retires sessions      | `tests/auth/test_auth_self_reset.py`, `test_admin_reset_password.py`                                                                |

**Gap:** nothing tests the JWT layer itself — `alg: none`, a signature from a
different key, a refresh token presented as an access token, an expired access
token, or a missing `type`. Phase 9 writes these as characterisation tests
_before_ changing anything (step 9.1).

### 1.6 Compatibility constraints

- **The SPA** holds the access token **in memory** (`api/tokenStorage.js`) and
  refreshes via the cookie (`axiosInstance` → `POST /auth/refresh` with an
  empty body). It asks `POST /auth/ticket` for WebSocket and download tickets.
- **API clients** may hold refresh tokens: login and refresh return
  `refresh_token` in the body (`TokenResponse.refresh_token`), and refresh
  accepts one in the body.
- **Live refresh sessions last up to 7 days.** Signing out everyone is not
  acceptable (plan).
- **The two WebSocket paths call `decode_token` directly** and must not be
  modified in Phase 9.
- **Tickets have a 60-second life**, and downloads use them via
  `current_user_flexible`.
- **The endpoint inventory test** requires every unauthenticated route to have
  a rate limit or an allowlist entry, so a JWKS endpoint needs one.
- **The OpenAPI document** has been byte-identical since Phase 8.1. A new
  endpoint changes it, and needs an explicit decision (§H, O7).

---

## 2. Current service-identity baseline — measured

| Asked about                                      | What exists                                                                                                                                                                                                                                                        |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Service-to-service authentication                | **None.** No service calls another over HTTP. No production code in `Backend/` makes an HTTP request to the API.                                                                                                                                                   |
| Worker / service identities                      | **None.** The workers and beat are Celery processes. They connect to Redis (`redis://…:6379/0`, **no password**, bound to loopback and the Compose bridge) and to PostgreSQL as `ccure_user`. Celery messages carry no sender identity (F9-6).                     |
| API-to-API authentication                        | **None.** There is only one API.                                                                                                                                                                                                                                   |
| Scheduled / background tasks                     | Beat publishes by task name. Tasks act with the database's authority, and audit events from them name a `system_actor` string (`"system:retention"`, `core.audit_retention`) instead of a user.                                                                    |
| Gateway-to-core                                  | **None in use.** The `gateway` compose service is nginx, behind the `alt-gateway` profile, not started, doing no authentication. Host nginx does TLS and rate limits only.                                                                                         |
| Core-to-IR                                       | **Does not exist** (IR is Phase 13).                                                                                                                                                                                                                               |
| Anything service-like                            | The **`scanner` role** is a _human_ login role (`scans:create/execute/read`, `credentials:read`, `scan_policies:read`), held by one account that signs in interactively and has no MFA. **It is not a service identity and must not be repurposed as one** (F9-7). |
| Secrets held by processes that never mint tokens | The HMAC signing secret is injected into worker, web-worker and beat, which never issue a token (F9-8).                                                                                                                                                            |

The plan's statement "service identities do not exist (only the `scanner`
role)" is confirmed.

---

## 3. Phase 9 target architecture

### 3.1 One issuer, many verifiers

```
   ccure_platform.identity (in the core)                 verifiers
   ┌───────────────────────────────────────┐    ┌──────────────────────────────┐
   │ TokenIssuer  — private signing key(s) │    │ core routes (today)          │
   │   user tokens: access/refresh/ticket/ │    │ gateway token-check (Ph 10)  │
   │                mfa_challenge          │    │ IR service (Ph 13)           │
   │   service tokens (client credentials) │    │                              │
   │ TokenVerifier — keyset by kid         │◄───┤ JWKS (public keys only)      │
   │ JWKS endpoint — public keys only      │    │ TokenVerifier (same code)    │
   └───────────────────────────────────────┘    └──────────────────────────────┘
```

- **Issuance stays where it is**, in `ccure_platform.identity`, on the core.
  Only the core holds a private key. **Worker, web-worker and beat get no key
  at all.** They mint nothing, which fixes F9-8.
- **Verification is one implementation** (`TokenVerifier`). It takes the
  expected token kind, issuer and audience as **required** arguments; there is
  no parameterless decode. Every verifier uses it: the core's dependencies
  now, the gateway's token-check component in Phase 10, and IR in Phase 13.
  Whether it ships as a small leaf package the gateway and IR can install is
  O12.
- **Public keys are published** as a JWK Set at a public, rate-limited
  endpoint (path: O7). Verifiers cache it and refetch on an unknown `kid`,
  rate-limited so a stream of bogus `kid`s cannot hammer the issuer.
- **Moving the issuer later is a key-address change.** A separate
  authentication service (§3.9) takes over the private key and the JWKS URL,
  and verifiers do not change.

### 3.2 Signing

- **Algorithm** — RS256 or ES256 (O3). Recommendation: **ES256**. Tokens are
  smaller (they travel in URLs as tickets and in cookies), signing is faster,
  and it is supported by every mainstream library and by nginx-adjacent
  token-check tooling.
- **`kid`** — the RFC 7638 JWK thumbprint of the public key, set in every
  token header. A verifier selects the key **only** by `kid`, and each key
  carries its own algorithm, so the token's `alg` header can never choose the
  key type.
- **Keyset states:**
  - `active`: signs, and is published;
  - `next`: published, not yet signing — pre-distribution for a rotation;
  - `retired`: published, verify only, until every token it signed has
    expired;
  - `removed`: gone.

### 3.3 Claims

User tokens keep every claim they carry today; clients and the claim-consistency
check read them.

| Claim                        | User tokens                                                   | Service tokens                                                                           | Why                                                                                |
| ---------------------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `iss`                        | platform issuer (O5)                                          | same                                                                                     | issuer validation                                                                  |
| `aud`                        | the user-API audience (O5)                                    | the target service (`ccure:core` / `ccure:ir`, O5)                                       | audience validation; a token for IR is refused by the core and vice versa          |
| `sub`                        | user id (unchanged)                                           | `svc:<service_id>` — a namespace no user id can take                                     | separates humans from services structurally                                        |
| `ptype`                      | `"user"`                                                      | `"service"`                                                                              | required; the dependencies refuse the wrong kind                                   |
| `type`                       | `access` / `refresh` / `ticket` / `mfa_challenge` (unchanged) | `service_access`                                                                         | token kind, checked by the verifier, not by the caller                             |
| `jti`                        | all kinds (new for access, ticket, MFA)                       | yes                                                                                      | audit correlation; enables single-use tickets if chosen (O10)                      |
| `iat`, `exp`                 | unchanged                                                     | ≤ 15 min (O11)                                                                           |                                                                                    |
| `nbf`                        | = `iat`                                                       | = `iat`                                                                                  | no leeway (O15: 0 s, decided)                                                      |
| `role`, `org_id`, `username` | unchanged                                                     | —                                                                                        | compatibility; `org_id` stays validated against the database on every core request |
| `tenant`                     | —                                                             | the one organisation the token is bound to, or absent for a platform-wide service (§3.5) | tenant context from the credential, never from a header                            |
| `scope`                      | — (D9 may add module permissions, §H)                         | space-separated atoms (`audit:incident_evidence:write`)                                  | least privilege                                                                    |

### 3.4 Service identities

- **What a service identity is:** a platform-owned record with a stable id, a
  display name, the owning module (`core`, `ir`, later others), allowed scopes,
  a tenant binding (one organisation, or platform-wide with explicit tenant
  grants), a status (active or disabled), and credentials. It has **no
  password, no role and no row in `users`**, so it can never sign in to the SPA
  or pass `current_user`.
- **How a service authenticates** — D4, still open. The three candidates:

  | Option                                                                        | How                                                                                                                                                                                             | For                                                                                                                                                                  | Against                                                                                                                                                                      |
  | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | **A. Client credentials with `private_key_jwt`** (RFC 7523) — **recommended** | The service holds its own private key and registers its public key. It proves identity to the platform's token endpoint with a short signed assertion and receives a short-lived service token. | **No shared secret anywhere.** A leaked database row or log reveals nothing usable. Rotation is adding a key. It matches the plan's "verifiable, cannot mint" model. | A key pair per service to manage.                                                                                                                                            |
  | B. Client credentials with a client secret                                    | The service holds a random secret; the platform stores its hash.                                                                                                                                | Simplest; standard.                                                                                                                                                  | A shared secret between the service and the platform, leakable in transit or configuration.                                                                                  |
  | C. Platform-issued long-lived API key (opaque)                                | A bearer key checked by lookup.                                                                                                                                                                 | Simplest client.                                                                                                                                                     | **Cannot be verified with the public key alone.** The gateway and IR would have to call the platform on every request, which contradicts §8.1 and §3.9. **Not recommended.** |

- **Issuance:** a platform token endpoint (path: O7), public and
  rate-limited. It verifies the credential, then the identity's status, then
  that the requested scopes are a subset of those allowed, then the tenant
  grant. It issues a short-lived `service_access` token and writes an audit
  event.
  - **The core's own identity** (used to call IR in Phase 14) is issued the
    same way, in-process, through the same code path and the same audit event.
    It is not a shortcut.
- **Storage** — O9: two new platform-owned tables (`service_identities`,
  `service_credentials`: public keys, or hashed secrets under option B), or a
  static configuration registry. Recommendation: **tables**, one additive
  migration, because two services today will be four modules tomorrow and
  revocation needs a writable status. **This is a schema change and needs
  explicit approval** — the owner excluded "database restructuring" from this
  phase, and additive tables are listed here rather than assumed to be
  allowed.
- **Who gets one in Phase 9:** the core (for IR, used from Phase 14) and IR
  (registered now, used from Phase 13). **The Celery workers and beat do not
  get one** (rule 12). Confirm (O14).

### 3.5 Tenant context and the authorisation boundary

- **User tokens:** unchanged. `org_id` in the token is checked against the
  database on every core request, and the module decides permissions (RBAC).
- **Service tokens:**
  - **Bound to one tenant:** the `tenant` claim is the tenant. The token cannot
    name another.
  - **Platform-wide** (a future national Rank, §8.2): no `tenant` claim. The
    payload must name the tenant, and the platform checks it against the
    identity's grants.
  - **In every case:** a caller-supplied `X-Tenant-ID` is ignored and stripped
    at the gateway. Message bodies carry `tenant_id` for self-description, and
    it is **checked against the token, never trusted** (contracts §4.3).
- **Authorisation boundary:**
  - The platform authenticates and states scopes. **Each module decides**
    whether a scope permits an action (§3.2: the gateway answers _who_, the
    module answers _whether_).
  - A new dependency, `require_service_scope("audit:…")`, arrives with its
    **first consumer** (Phase 14's integration endpoints). Adding it to
    `ccure_platform.api` in Phase 9 with no caller would widen the API for
    nothing. It is exercised in Phase 9 by a test-only route.
- **Humans and services never cross:**
  - `current_user` / `require_permission` refuse a `ptype=service` token;
  - `require_service_scope` refuses a `ptype=user` token;
  - `sub` namespaces cannot collide.

### 3.6 Revocation and rotation

| What               | Mechanism                                                                                                                                                                                                                                                                                                                             |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| User access tokens | Unchanged: 30 minutes, with account and organisation status checked on every core request. (The gateway in Phase 10 checks the signature only; the core still checks status.)                                                                                                                                                         |
| Refresh tokens     | Unchanged: stateful sessions, rotation, revocation. Reuse detection (revoke the family on replay) is O13, not assumed.                                                                                                                                                                                                                |
| Service tokens     | Short-lived (≤ 15 minutes, O11). Disabling an identity or a credential stops new tokens at once. Outstanding tokens: the core re-checks the identity's status on every request (it has the database); IR and the gateway accept until `exp`, unless a denylist is chosen (O11).                                                       |
| Signing keys       | Rotation by `next` → `active` → `retired`, retiring only after `retired + max token lifetime (7 days) + margin`. Cadence and escrow: O6. Emergency revocation of a key means removing it from the keyset, so every token it signed fails, including live refresh sessions. That is a documented trade-off: those users sign in again. |
| The HS256 secret   | Accepted for verification only during the transition, then disabled by configuration, then removed from code. Its MFA use is decoupled first (F9-1).                                                                                                                                                                                  |

### 3.7 Failure behaviour

- **Every verification failure answers exactly as today.** A route answers
  401 `"Invalid or expired token"` with `WWW-Authenticate: Bearer`, uniform
  whatever is wrong (`test_bad_token_answers_uniformly_…` stays green). A
  ticket answers `"Invalid or expired download ticket."`. The response body
  never says _why_ a token failed.
- **The reason is logged server-side** (`bad_signature`, `unknown_kid`,
  `wrong_audience`, `wrong_type`, `expired`, `legacy_disabled`) with the
  `kid`, `jti` and `ptype` — **never the token**.
- **An unreachable or failing key store at start-up refuses to start.** A
  core that cannot sign must not come up half-working. A verifier with a
  cached keyset keeps verifying while the JWKS endpoint is briefly
  unreachable, and refuses unknown `kid`s.

---

## 4. Security model

| Requirement                           | How it is met                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **No shared secret between services** | The platform signs with a private key that only the core holds. Verifiers hold public keys only. Services authenticate to the platform with their own key pairs (D4 option A). The HS256 secret exists only for the transition, and only verifies.                                                                                                                                                                                                                                           |
| **Algorithm confusion**               | The key is chosen by `kid` only. Each key is pinned to its algorithm, and the verifier passes `algorithms=[key.alg]`. `none` is refused. `jku`, `x5u`, `jwk` and `x5c` headers are ignored, so no key is ever fetched from a token. The legacy HS256 path is taken only when `alg == "HS256"` **and** there is no `kid` **and** legacy acceptance is on. It uses the HMAC secret, never a public key, so a token forged by signing HS256 with the public key fails. A test proves each case. |
| **Issuer validation**                 | `iss` is required and must match the configured issuer. Tokens without it are accepted only as legacy HS256 during the transition.                                                                                                                                                                                                                                                                                                                                                           |
| **Audience validation**               | `aud` is required and must contain the verifier's audience. The core refuses a token minted for IR, and IR one minted for the core.                                                                                                                                                                                                                                                                                                                                                          |
| **Expiry**                            | `exp` is required. `nbf` and `iat` are checked, with no leeway (O15: 0 s).                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **Key IDs**                           | `kid` is required on every asymmetric token, and an unknown `kid` is refused after one rate-limited keyset refresh.                                                                                                                                                                                                                                                                                                                                                                          |
| **Key rotation**                      | The `next`/`active`/`retired` states (§3.6), with a runbook and a test that a retired key still verifies and a removed key does not.                                                                                                                                                                                                                                                                                                                                                         |
| **Replay**                            | Access tokens are bearer tokens, bounded by 30 minutes and TLS. Refresh rotation limits replay to one use, with optional family revocation (O13). Tickets are replayable for 60 seconds today (optional single-use `jti`, O10). Service tokens are short, `jti` goes to the audit log, and integration writes are idempotent on `message_id` (contracts §4.1).                                                                                                                               |
| **Services separate from humans**     | `ptype` is required, the `sub` namespace is `svc:`, and there is no `users` row, password, role or SPA path. The dependencies refuse the other kind, and the `scanner` human role is untouched.                                                                                                                                                                                                                                                                                              |
| **Tenant isolation**                  | The tenant comes from the verified token only. Single-tenant service tokens cannot name another tenant, and platform-wide ones need explicit grants. `X-Tenant-ID` is ignored.                                                                                                                                                                                                                                                                                                               |
| **Least privilege**                   | Service scopes are a subset of the identity's allowed scopes, requested per token. Worker, web-worker and beat hold no signing key. IR holds no key that can mint.                                                                                                                                                                                                                                                                                                                           |
| **Logging and audit**                 | Service-token issuance and every refused issuance go to the tamper-evident audit log (identity, scopes, tenant, `jti`, `kid`, outcome). Verification failures are logged with a reason code. Tokens, assertions, secrets and private keys are never logged, and tickets-in-URLs are flagged for Phase 10's access-log configuration.                                                                                                                                                         |
| **Secret and key protection**         | Private keys live in files outside the repository, readable only by the API process user, and mounted read-only into the API container alone. Their paths are in configuration; key material never goes in `.env`, images or git. A CI guard rejects committed private keys. Backup and escrow: O6. MFA gets its own key (F9-1) before the HS256 secret can be retired.                                                                                                                      |

---

## 5. Migration plan — small commits, each with a review stop

**One property holds throughout: verifiers learn a new key before any
issuer uses it.** Every step is reversible by `git revert` or by a
configuration flag. Nothing signs anyone out until the owner chooses the
legacy cut-off.

### 9.1 — Characterise and consolidate (no behaviour change) ← **first step**

- **Files:**
  - `ccure_platform/identity/tokens.py` (new): `TokenVerifier` and
    `TokenIssuer` wrappers around today's HS256. The token kind is a required
    argument, so `decode` without an expected kind does not exist;
  - `ccure_platform/identity/jwt_handler.py`: its functions delegate, with
    identical signatures and results;
  - `tests/auth/test_token_characterisation.py` (new);
  - `tests/repo/test_token_guardrails.py` (new).
- **Behaviour:** identical. Same HS256 tokens, same claims, same error
  bodies. `decode_token` keeps its signature and returns the same payload or
  `None`, so the two WebSocket paths and the rate-limit audit are untouched.
- **Tests:**
  - **Characterisation** (they pass before _and_ after the change): `alg:
none` refused; wrong-key signature refused; each kind refused where another
    is expected (refresh as access, ticket as access, access as ticket,
    `mfa_challenge` as access); expired refused; missing `type` refused; the
    exact claim sets of each kind; the uniform 401 body.
  - **Guardrails:** only `ccure_platform.identity.tokens` imports `jose` / JWT
    libraries (AST allowlist); no committed PEM private keys.
- **Rollback:** `git revert`.
- **Verify:**
  - the full suite;
  - OpenAPI byte-identical to `ef668dc`;
  - the 91 limiter keys and 45 Celery task names unchanged;
  - the live probe;
  - a token issued before the deploy still works after it.
- **Stop for review.**

### 9.2 — Decouple MFA encryption from the JWT secret (prerequisite)

- **Files:** `config.py` (a start-up warning when `MFA_ENCRYPTION_KEY` is
  unset and would derive from `JWT_SECRET_KEY`); a runbook; a test.
- **Operator action:** set `MFA_ENCRYPTION_KEY` to the **current**
  `JWT_SECRET_KEY` value in both env files and the compose environment. The
  derived Fernet key is then byte-identical, so no data changes.
- **Behaviour:** identical. The three MFA users keep working.
- **Tests:** the derived key is the same before and after for the same input;
  the MFA suite passes.
- **Verify:** an MFA user's secret decrypts in the running API (read-only
  check); a login with MFA on a test account.
- **Rollback:** unset the variable, and the default derivation returns.
- **Stop.**

### 9.3 — Keys, keyset and JWKS; verification accepts both (signing still HS256)

- **Files:**
  - `ccure_platform/identity/keys.py` (new): load from file paths; `kid`
    thumbprint; `active`/`next`/`retired`;
  - `tokens.py`: dual verification, per §4's algorithm-confusion rules;
  - `ccure_platform/identity/router.py`: the JWKS route — public, a rate
    limit, and a placement in the endpoint-limit inventory;
  - `config.py` (key paths, issuer, audiences);
  - `scripts/security/generate_signing_key.py` (new);
  - compose: a read-only key mount on **api only**;
  - tests.
- **Behaviour:** tokens are still issued with HS256. The core now also
  _accepts_ asymmetric tokens signed by its keyset, which nothing issues yet.
  JWKS is published.
- **OpenAPI:** changes by one route, unless O7 chooses `include_in_schema=False`.
- **Tests:**
  - an asymmetric token verifies with the public key alone (a test holding
    only the JWKS JSON);
  - wrong `kid`, wrong `aud`, wrong `iss`, HS256 signed with the public key,
    `jku`/`jwk` headers — all refused;
  - rotation: a retired key verifies, a removed one does not;
  - no private key is reachable from worker, web-worker or beat;
  - JWKS contains no private parameters.
- **Rollback:** revert. HS256 issuance was never changed.
- **Stop.**

### 9.4 — Issue asymmetric user tokens; accept legacy HS256 until the cut-off

- **Files:** `tokens.py` (the issuer switches on a flag, default on after
  review); `jwt_handler.py` (adds the `iss`, `aud`, `jti`, `nbf`, `ptype`
  claims); tests.
- **Behaviour:**
  - New access, refresh, ticket and MFA-challenge tokens are ES256/RS256 with
    the full claim set.
  - A legacy HS256 refresh token still refreshes, and its replacement is
    asymmetric. A legacy access token works until its 30 minutes run out.
  - The SPA, API clients, tickets, the WebSockets (through the unchanged
    `decode_token`), downloads and the rate-limit audit all keep working.
- **Tests:**
  - a legacy refresh token issues asymmetric tokens;
  - a mixed-age session;
  - logout of a legacy session;
  - claim consistency for new tokens;
  - the whole security suite.
- **Verify, live:**
  - log in and see the new header;
  - an old session refreshes;
  - WebSocket progress and a report download work;
  - the rate-limit audit names the caller.
- **Rollback:** flip the issuer flag back to HS256. Tokens issued
  asymmetrically in the meantime stay valid, because verification still
  accepts them.
- **Stop.**

### 9.5 — Service identities and service tokens

- **Files:**
  - the storage per O9 (a migration if tables are chosen: backup, rehearse on
    a restored copy, `table_ownership.yaml` entries);
  - `ccure_platform/service_identity/` (new, as the plan names it): the model,
    registration and issuance;
  - the token endpoint;
  - `require_service_scope` (in `ccure_platform.api` only if the owner accepts
    a test-only consumer until Phase 14; otherwise internal until then);
  - audit events;
  - `scripts/security/register_service_identity.py` (new);
  - tests.
- **Behaviour:** no existing route changes. A service can obtain a token.
  Human routes refuse it.
- **Tests:**
  - a service obtains a token with its credential (`private_key_jwt`
    assertion replay refused, wrong key refused, disabled identity refused);
  - scopes limited to those allowed;
  - tenant binding and cross-tenant refusal;
  - `current_user` refuses a service token, and a service-scope dependency
    refuses a user token;
  - issuance audited;
  - the endpoint rate-limited.
- **Rollback:** revert. With tables, the migration's downgrade drops two new,
  unused tables.
- **Stop.**

### 9.6 — Legacy cut-off (a separate, dated decision)

- **When:** ≥ 7 days + margin after 9.4, **measured**. No
  `refresh_token_sessions` row issued before the 9.4 deploy remains unexpired
  and unrevoked (a read-only query).
- **Change:** set legacy HS256 acceptance to off (configuration). A later
  commit removes the HS256 code and `JWT_SECRET_KEY`, once F9-1 is decoupled
  (9.2).
- **Rollback:** turn the flag back on.
- **Stop.** Phase 9 is done:
  - a token verifies with the public key alone;
  - a service obtains its own token;
  - an old HS256 token refreshed until it expired.

---

## 6. CI and test guardrails

| Prevents                                             | Guard                                                                                                                                                                                                                                                                                                                                  |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Modules implementing their own token verification    | An AST allowlist: only `ccure_platform.identity.tokens` (and O12's leaf package, if chosen) may import `jose`, `jwt` or `joserfc`, or call `.decode(` on them. The identity ratchet already refuses new module imports of `auth.jwt_handler` or platform internals. The two WebSocket files are the recorded exception until Phase 10. |
| Hardcoded signing keys                               | A repo scan fails on any tracked file containing `BEGIN … PRIVATE KEY`, a JWK with a `d` member, or a literal assigned to a key setting. `.gitignore` covers the key directory. The known-weak-key list refuses defaults in production.                                                                                                |
| Tokens accepted without issuer or audience           | `TokenVerifier.verify` has no default for `audience`, `issuer` or `expected_type`, so a call without them is a `TypeError`. A test calls it every wrong way. A static check ensures no route dependency uses a verification helper other than the platform's.                                                                          |
| Human tokens treated as services, and the reverse    | Tests: a service token against `current_user` / `require_permission` gives 401, and a user token against `require_service_scope` is refused. `ptype` and the `svc:` namespace are required by the verifier.                                                                                                                            |
| Direct access to another module's identity internals | Phase 8's identity ratchet, plan-feature containment and layer rules, extended so the new `service_identity` package is platform-internal, like `identity`.                                                                                                                                                                            |
| Tenant-context bypass                                | Tests: a single-tenant service token naming another tenant is refused, and an `X-Tenant-ID` header changes nothing. A static check: no module reads an `X-Tenant-ID` header.                                                                                                                                                           |
| Algorithm confusion                                  | The §4 tests: `none`; HS256 signed with the public key; a `jwk`/`jku` header; an unknown `kid`; a `kid` naming a key of another algorithm.                                                                                                                                                                                             |
| An unnoticed behaviour change                        | Per-step OpenAPI byte comparison (or an approved diff), limiter keys, Celery task names, the live probe — as in Phase 8.                                                                                                                                                                                                               |

---

## 7. Decisions needed before implementation (§H)

| #           | Decision                                                                   | Options                                                                                             | Recommendation                                                                                                                                                                              |
| ----------- | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **O1 = D4** | Service credential mechanism                                               | A `private_key_jwt` client credentials · B client secret · C opaque API key                         | **A** — no shared secret, verifiable with public keys                                                                                                                                       |
| **O2 = D9** | How IR learns a caller's `ir:` permissions                                 | carried in the user token · looked up through the gateway                                           | **Carried in the token**, as module-prefixed atoms for the target audience. Rule 5 says IR's work must not depend on the core being reachable. Staleness is bounded by the 30-minute token. |
| **O3**      | Signing algorithm                                                          | RS256 · ES256                                                                                       | **ES256**                                                                                                                                                                                   |
| **O4**      | JWT library                                                                | upgrade python-jose · PyJWT · joserfc                                                               | **PyJWT** (maintained; ES256/RS256 via `cryptography`), added to both runtimes. Re-verify python-jose advisories either way.                                                                |
| **O5**      | `iss` and `aud` values                                                     | a URL-form or name-form issuer; one user-API audience or per service                                | Issuer: the public base URL of the platform. User audience: one platform-wide API audience, with the module deciding permissions. Service audience: per target service.                     |
| **O6**      | Key storage, rotation cadence, escrow                                      | a file mount · Docker secret · KMS/HSM; 90/180 days; who holds the backup                           | A read-only file mount on api only, rotated every 180 days, with an offline escrow copy held by the project owner. A KMS/HSM is out of scope for this VM.                                   |
| **O7**      | Paths for the JWKS and token endpoints, and whether they appear in OpenAPI | `/.well-known/jwks.json` and `/api/auth/service-token`, or under `/auth/…`; in or out of the schema | JWKS under the auth prefix, so the gateway's public-route list stays one prefix (§3.2). **In** the schema — they are real API surface — with the OpenAPI diff approved at that step.        |
| **O8**      | Transition cut-off                                                         | a fixed date · measured "no live legacy sessions" · force re-login                                  | **Measured**, ≥ 7 days + 1 day after 9.4                                                                                                                                                    |
| **O9**      | Service-identity storage                                                   | new platform tables (a migration) · a static configuration registry                                 | **Tables** (additive). Needs explicit approval, since Phase 9 excludes database restructuring.                                                                                              |
| **O10**     | Ticket replay                                                              | keep reusable for 60 s · single-use via `jti` in Redis                                              | Keep as today in Phase 9 (behaviour change otherwise); revisit in Phase 10 with the WebSocket move                                                                                          |
| **O11**     | Service-token lifetime and revocation                                      | 5–15 min; a denylist or short `exp` only                                                            | 10 min, with no denylist; the core re-checks identity status                                                                                                                                |
| **O12**     | One verification library for the gateway and IR                            | a leaf package in this repo · each uses a standard library against JWKS                             | A small leaf package (stdlib + library only, like `ccure_contracts`), so there is exactly one verification implementation                                                                   |
| **O13**     | Refresh-token reuse detection                                              | add family revocation · leave as is                                                                 | Leave for Phase 9 (behaviour change); record as a follow-up                                                                                                                                 |
| **O14**     | Service identities for the Celery workers and beat                         | none (rule 12) · yes                                                                                | **None**                                                                                                                                                                                    |
| **O15**     | Clock-skew leeway                                                          | 0 · 30 s · 60 s                                                                                     | 30 s. **Decided 29 Sep 2026 by the project owner: 0 s** (see §11)                                                                                                                           |

---

## 8. The exact first implementation step

**9.1 — characterise and consolidate the token code, HS256 unchanged.**

1. Write `tests/auth/test_token_characterisation.py` against the current
   code, and see it pass. It pins:
   - the refusals: `alg: none`, a wrong-key signature, each token kind
     presented where another is expected, expiry, a missing `type`;
   - the claims of each kind;
   - the uniform 401 response.
2. Add `ccure_platform/identity/tokens.py`, holding HS256 issuing and
   verifying with a **required** expected kind. The `jwt_handler` functions
   delegate to it, keeping their public names, signatures and return values:
   `create_*`, `decode_token`, `refresh_access_token`, `revoke_refresh_token`.
3. Add `tests/repo/test_token_guardrails.py`. It checks two things: only
   `ccure_platform.identity.tokens` imports a JWT library, and no tracked file
   holds a private key.
4. Run the characterisation tests again (unchanged, green), the full suite,
   the OpenAPI comparison, the limiter and Celery comparisons, and the live
   probe. Show that a token minted before the deploy still verifies after it.

**Expected files:**

- **New:**
  - `Backend/ccure_platform/identity/tokens.py`
  - `Backend/tests/auth/test_token_characterisation.py`
  - `Backend/tests/repo/test_token_guardrails.py`
- **Changed:**
  - `Backend/ccure_platform/identity/jwt_handler.py`
  - possibly `Backend/scripts/architecture/identity_boundary.py`, if a new
    platform-internal module needs listing
  - `docs/architecture/PHASE9_TOKENS_AND_SERVICE_IDENTITIES.md`, with an "as
    built" section
- **Not touched:**
  - the WebSocket routers
  - `main.py`
  - `core.rate_limit_audit`
  - `config.py`
  - compose, the frontend and the database

---

## 9. Risks and rollback

| Risk                                                | Where      | Containment                                                                                                                    | Rollback                                                   |
| --------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------- |
| MFA users locked out by a secret change (F9-1)      | 9.2 onward | 9.2 decouples before anything touches the secret, with an identical derived key                                                | Unset `MFA_ENCRYPTION_KEY`                                 |
| Everyone signed out at the switch                   | 9.4        | Dual verification from 9.3; legacy refresh still works; the cut-off is measured (O8)                                           | The issuer flag back to HS256                              |
| Algorithm confusion or key-selection bug            | 9.3        | Key chosen by `kid` only, pinned algorithms, the §4 test set, and the legacy path fenced to HS256 without `kid`                | Revert 9.3; issuance was still HS256                       |
| A WebSocket or download broken by the new tokens    | 9.4        | Those paths call the unchanged `decode_token`, which gains dual verification; a live WebSocket and download are checked at 9.4 | The issuer flag                                            |
| Private key exposed                                 | 9.3 onward | Mounted into api only, read-only, never in `.env`, images or git; CI scan; worker, web-worker and beat hold nothing            | Emergency rotation: remove the `kid` (users sign in again) |
| Token endpoint abused (service-credential stuffing) | 9.5        | Rate limits, audit of refusals, and no shared secret under option A                                                            | Disable the identity or credential                         |
| Silent API change                                   | every step | OpenAPI, limiter-key and Celery-name comparisons each time; any intended OpenAPI change is listed and approved                 | Revert                                                     |
| Migration on a live database (if O9 = tables)       | 9.5        | Additive only: full dump, rehearsal on a restored copy, a downgrade that drops only the new tables                             | Alembic downgrade                                          |
| Scope creep into Phase 10                           | all        | The WebSocket paths, gateway, ticket model and `X-Request-ID` behaviour are explicitly out of scope                            | —                                                          |

---

## 10. Findings recorded by this investigation (not fixed by Phase 9 unless listed)

| #     | Finding                                                                                                                                      | Phase 9 handling                                                                                                                                                           |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F9-1  | The MFA encryption key derived from `JWT_SECRET_KEY` (unset separately; 3 users with TOTP secrets)                                           | **Resolved in 9.2**: `MFA_ENCRYPTION_KEY` set to the same value; derived key identical; all 3 proven                                                                       |
| F9-2  | python-jose 3.3.0 has published advisories                                                                                                   | Library decision O4                                                                                                                                                        |
| F9-3  | `decode_token` does not bind the token kind; 10 call sites check `type` by hand (7 platform, the rate-limit audit, 2 WebSocket)              | Structural fix in 9.1: the kind is a required argument                                                                                                                     |
| F9-4  | Tickets are reusable for 60 s and travel in URLs, which reach access logs                                                                    | Recorded; O10; Phase 10's access-log configuration                                                                                                                         |
| F9-5  | Refresh tokens are also accepted from the request body and returned in it                                                                    | Preserved for API-client compatibility; recorded                                                                                                                           |
| F9-6  | The Celery broker (Redis) has no authentication, and task messages carry no sender identity; anything that can reach Redis can enqueue tasks | Out of Phase 9 scope (rule 12); recorded for a separate decision                                                                                                           |
| F9-7  | The `scanner` role is a human login role with `scans:execute`; its one account has no MFA                                                    | Untouched; not a service identity; MFA for it is the owner's call                                                                                                          |
| F9-8  | The HMAC signing secret is injected into worker, web-worker and beat, which never mint tokens                                                | Fixed by design: the private key is mounted on api only (9.3), and the HMAC secret retires at 9.6                                                                          |
| F9-9  | No refresh-token reuse detection (family revocation)                                                                                         | O13, follow-up                                                                                                                                                             |
| F9-10 | No test exercises the JWT layer directly                                                                                                     | Fixed in 9.1 (25 characterisation tests)                                                                                                                                   |
| F9-11 | 401s lose the `WWW-Authenticate: Bearer` header the dependency sets (the error handler does not forward exception headers)                   | Found by 9.1's characterisation; pinned as observed, not fixed                                                                                                             |
| F9-12 | Host uid 1000, which owns the private key files so the api container can read them, is a real login account on the VM (`monitor`)            | Contained by location: the keyset sits under `/home/cdac` (mode 750), which `monitor` cannot enter. Recorded in §14; do not move the directory somewhere world-traversable |

## 11. Owner's review of this proposal (29 Sep 2026)

**Approved:**

- the scope: verifiable tokens and service identities only;
- 9.1 and 9.2 (9.2 is **mandatory** before any rotation or retirement of the
  JWT secret, and its proof is that existing MFA secrets decrypt before and
  after);
- **ES256** as the signing algorithm;
- service identities kept distinct from human users (the `scanner` account
  and role are not repurposed);
- **D4 direction**: each service owns a key pair, signs a short-lived
  assertion, the core verifies it and issues a short-lived service token, and
  there is no shared service secret;
- worker, web-worker and beat receive no private key;
- the verifier requires expected kind, issuer and audience, with no call path
  that omits them;
- principal type is an explicit claim, not inferred from the `svc:` namespace.

**Not approved, or changed:**

- **HS256 retirement (9.6) is not approved in advance.** It needs evidence at
  the time: no legacy sessions or tokens, MFA separated, rollback verified,
  runtime checks complete — and its own review.
- **A:** no python-jose → PyJWT migration in 9.1. A library change, if still
  wanted, is a separate reviewed change.
- **B: D9 is not decided.** First document IR's authorisation requirements,
  whether IR must authorise user actions while the core is unavailable, and
  the permission-staleness trade-off.
- **C: the service-identity tables are not approved.** 9.5 first needs the
  exact schema, ownership, constraints, tenant binding, key rotation and
  revocation, indexes, audit requirements and migration/rollback plan,
  reviewed.
- **D: JWKS is an intentional API addition.** After it, prove the OpenAPI
  delta is exactly the approved endpoint and nothing else, rather than
  byte-identity.
- **E:** replace manual token-type checks with a verifier that requires the
  expected kind.
- **F:** the two WebSocket authentication paths stay untouched in Phase 9.

**For 9.5, decided 29 Sep 2026:** O9 → a static registry, no migration (tables
only after a reviewed schema); O11 and the service half of O5 → 10-minute
service tokens, `aud` = the target service (`urn:ccure:core`, `urn:ccure:ir`),
no denylist; assertions ≤ 60 s, single use, replay store Redis fail-closed; the
live registry starts empty. Recorded in §16.

**O15, decided 29 Sep 2026 (after 9.3):** the JWT clock-skew leeway is **0
seconds**, for every token kind and on both verification paths. This is the
value 9.3 already implements and the HS256 path always used, so the decision
changed no code. The recommendation of 30 s is not adopted.

## 12. Step 9.1 — as built

**New: `ccure_platform/identity/tokens.py`**

- It is the only module that imports a JWT library (still python-jose, per A).
- `sign(claims, lifetime)` is exactly the old `_create_token`: the same
  `iat`/`exp`, HS256, and `JWT_SECRET_KEY` from `config.JWTConfig`.
- `verify(token, *, expected_kind)` is keyword-only with no default. An unknown
  kind raises. It returns the payload only for a correctly signed, unexpired
  token **of that kind**.
- `decode_any_kind(token)` is the legacy behaviour, kept separate. Issuer and
  audience become required keyword-only arguments of `verify` when the claims
  exist (9.3/9.4), so adding them fails every caller at once.

**Routed through it:**

- **`jwt_handler`:**
  - `_create_token` calls `tokens.sign`;
  - `decode_token` calls `tokens.decode_any_kind`;
  - `_get_refresh_session` calls `verify(…, REFRESH)`;
  - `SECRET_KEY` and `ALGORITHM` stay importable with the same values;
  - every public name, signature and return is unchanged.
- **Manual `payload.get("type")` checks replaced by `verify(…, expected_kind=…)`
  (E):**

  - `dependencies._decode_access_payload` (ACCESS);
  - `get_current_user_flexible`'s ticket branch (TICKET);
  - logout (REFRESH);
  - both MFA challenge endpoints (MFA_CHALLENGE);
  - `routers.user_profile._current_session_jti` (REFRESH).

  The error bodies and status codes are unchanged.

- **Untouched (F and the scope):**
  - the two WebSocket logins, which still call `decode_token`;
  - `main.py` and `core.rate_limit_audit`;
  - configuration, the database, compose and the frontend.

**Characterisation** (`tests/auth/test_token_characterisation.py`, 25 tests):
written first, passing against the code **before** the change, and unchanged
since. For all four kinds it covers:

- the header (`{"alg":"HS256","typ":"JWT"}`), the exact claim set and the
  lifetime (access 30 min, refresh 7 days, ticket 60 s, challenge 5 min);
- acceptance by the consuming path;
- refusal, with that path's own uniform error, of 13 invalid variants:
  tampered signature, tampered payload, wrong key, `alg: none` (with and
  without the trailing dot), HS512 with the right key, expired, no `type`,
  empty, garbage, two segments, three junk segments, and a non-JSON payload;
- refusal of each of the three other kinds;
- the legacy `decode_token` accepting every valid kind and refusing every
  invalid variant;
- refresh rotating once, a correctly signed refresh token with no session
  refused, and logout revoking.

**The characterisation found F9-11.** A protected route raises its 401 with
`WWW-Authenticate: Bearer`, but the application's error handler does not
forward exception headers, so clients receive none. It is pinned as observed,
not fixed.

**Guardrails** (`tests/repo/test_token_guardrails.py`, 7 tests):

- only the token module imports a JWT library;
- `verify` requires the kind;
- the any-kind decode has exactly the recorded callers (the two WebSocket
  routers and `main.py`), a set that can only shrink;
- no platform code checks `payload.get("type")` by hand;
- no private key material in the repository (a PEM block with a body, or a
  JWK `d`; a form placeholder showing only the header is not a match).

A mutation run with a planted module (a `jose` import, a hand type check, a
`decode_token` import) fails three of them.

**Continuity:**

- With the clock frozen, all four token kinds minted by the old code (HEAD)
  and by the new code are **byte-identical**.
- Each version decodes the other's tokens identically.
- A token issued before the deploy is therefore valid after it, and the
  reverse.

## 13. Step 9.2 — as built

**The derivation.** The formula is unchanged, now named
`config.derive_mfa_fernet_key`: the Fernet key is the urlsafe base64 of
SHA-256 of the MFA secret.

|                                     | Before 9.2                                                                                                  | After 9.2                                                                                                                                                                         |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Source of the MFA secret            | `MFA_ENCRYPTION_KEY` if set, else `JWT_SECRET_KEY`. It was set nowhere, so it was **always the JWT secret** | `MFA_ENCRYPTION_KEY`, now set in `Backend/.env` to the JWT secret's value at the time. The fallback still exists for an install that has not set it, and is announced at start-up |
| Empty value                         | derived a key from `""`                                                                                     | treated as unset, so it falls back                                                                                                                                                |
| Effect of changing `JWT_SECRET_KEY` | every stored MFA secret undecryptable                                                                       | none                                                                                                                                                                              |

**Code:**

- `config.py`: `JWTConfig.MFA_ENCRYPTION_KEY`, `JWTConfig.MFA_KEY_SOURCE`,
  `derive_mfa_fernet_key()`; `AppConfig.MFA_KEY` uses it.
- `main.py`: a `ccure.security` warning in the lifespan while the key still
  falls back.
- `tests/conftest.py`: pins the test process's `MFA_ENCRYPTION_KEY` to the test
  JWT secret, which is the key it always derived, so a developer's real
  `Backend/.env` never reaches tests.
- `Backend/.env.example`: documents the variable.
- **Unchanged:** the MFA endpoints, the stored records, the JWT secret, compose.

**The operator step.** `MFA_ENCRYPTION_KEY` was appended to `Backend/.env`.
The value was copied from `JWT_SECRET_KEY`, after checking that the root
`.env` (the copy compose injects) and `Backend/.env` hold the same value. The
file was backed up first to `Backend/.env.bak-pre-9.2` (mode 600,
git-ignored), and both files are git-ignored. No value was printed.

**Proof on the live database** (read-only, hashes only):

| Account                            | Before: decrypts | After: decrypts | Same plaintext | Ciphertext untouched |
| ---------------------------------- | ---------------- | --------------- | -------------- | -------------------- |
| `usr_self_a2cbaf04_chandan_6sis`   | yes              | yes             | yes            | yes                  |
| `usr_self_a2cbaf04_dhananjay_2i04` | yes              | yes             | yes            | yes                  |
| `usr_self_a2cbaf04_pankaj_r4v5`    | yes              | yes             | yes            | yes                  |

- The key source changed from `fallback:JWT_SECRET_KEY` to
  `MFA_ENCRYPTION_KEY`, and the derived Fernet key is **identical** (compared
  by SHA-256 of the key, never the key).
- **Separation shown live.** A throwaway process given a **random**
  `JWT_SECRET_KEY` still decrypts all 3 to the same plaintext. The same
  process with the old coupling (`MFA_ENCRYPTION_KEY` empty) decrypts **0 of
  3** — the lockout 9.2 removes. The real JWT secret was not touched.

**Tests:** `tests/auth/test_mfa_key_separation.py` (10). Fresh interpreters
with `SKIP_DOTENV_LOAD=1` cover:

- the formula;
- the fallback when unset or empty;
- the key when set;
- **changing the JWT secret alone leaves the MFA key unchanged**;
- the coupling it replaces;
- that initialising at the current JWT value is byte-identical;
- a secret encrypted before the separation decrypting after a JWT rotation
  (and not without the separation);
- the endpoints using the configured key.

**Rollback.** Remove the `MFA_ENCRYPTION_KEY` line, or restore
`Backend/.env.bak-pre-9.2`, then restart. The fallback derives the identical
key, so nothing breaks — as long as the JWT secret has not been rotated in the
meantime. **After any JWT rotation, `MFA_ENCRYPTION_KEY` must stay.**

**Not done, as instructed:** the JWT secret is not rotated; nothing from 9.3
(keys, JWKS, ES256), no service identities, no MFA record modified.

## 14. Step 9.3 — as built

**What 9.3 adds, and what it does not.** The platform can now _verify_ ES256
tokens signed by its own keyset, and publishes that keyset's public keys at
`GET /auth/jwks.json`. **Nothing issues an ES256 token yet** (that is 9.4):
`sign()` is unchanged and every token the platform hands out is still HS256.
Legacy HS256 tokens and live sessions are unaffected. No service identity, no
database change, no change to the two WebSocket paths, and the JWT secret is
neither rotated nor retired.

**The owner's values (29 Sep 2026):**

| Decision (§7)               | Value                                                                                                                                                  |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| O5 issuer                   | `https://ccurepro.cdac.in` (`JWTConfig.TOKEN_ISSUER`; must never change)                                                                               |
| O5 user audience            | `urn:ccure:api`, one platform-wide value (`JWTConfig.TOKEN_USER_AUDIENCE`, not configurable)                                                           |
| O6 storage, cadence, escrow | a host directory outside the repository, mounted read-only into **api only**; rotated every 180 days; an offline escrow copy held by the project owner |
| O7 JWKS                     | `/auth/jwks.json`, in the OpenAPI schema                                                                                                               |

### 14.1 Code

- **`ccure_platform/identity/keys.py`** (new) — the keyset. A directory
  holding `keyset.json` (version, and per key: `kid`, `alg`, `state`, `file`)
  and one unencrypted PKCS#8 PEM per private key. States: `next`, `active`,
  `retired`; _removed_ means absent from the manifest. `load_keyset()`
  **refuses the whole keyset** for any of:

  - a `kid` that is not the RFC 7638 thumbprint of its file's key;
  - a duplicate `kid`;
  - an unknown state, or an algorithm other than ES256;
  - a key that is not P-256;
  - a file name that is not a plain basename (no traversal, no hidden file);
  - a missing file;
  - more than one `active` key, or more than one `next`;
  - no keys at all — an empty JWKS would tell verifiers to trust nothing, and
    they cache it.

  A refused keyset is never partially used. `SigningKey` keeps the private key
  out of its `repr`.

- **`tokens.py`** — dual verification, in `_decode`:

  1. Any `jku`, `x5u`, `jwk`, `x5c` or `crit` header is refused. No key is ever
     taken from, or fetched because of, a token.
  2. `alg: HS256` with **no** `kid` is the legacy path. It verifies with the HMAC
     secret, only while `CCURE_ACCEPT_LEGACY_HS256` is on (the default until
     9.6), and exactly as before — no issuer or audience is checked, because
     legacy tokens carry neither.
  3. Anything else must carry a `kid` naming a key in the keyset. It is verified
     with that key's own algorithm (`alg` must equal it) and its public key, with
     `iss`, `aud`, `sub`, `jti`, `iat`, `nbf` and `exp` all required and leeway 0.
     `type` and `ptype` must be present too.
  4. `verify()` then checks the kind, as since 9.1, and for a `kid` token that
     `ptype` is the principal type the kind is issued to (`user` for all four
     kinds today).

  `verify(token, *, expected_kind, issuer, audience)` has **no defaults**. All
  seven call sites pass the platform issuer and user audience.
  `decode_any_kind` (the legacy any-kind decode, for its three fixed callers)
  applies the same rules with the platform issuer and user audience, so the
  unchanged WebSocket callers will accept an ES256 ticket once 9.4 issues one.

- **`config.py`** — `TOKEN_ISSUER`, `TOKEN_USER_AUDIENCE`, `TOKEN_KEYS_DIR`
  (`CCURE_TOKEN_KEYS_DIR`), `ACCEPT_LEGACY_HS256`.
- **`ccure_platform/identity/router.py`** — `GET /auth/jwks.json`:
  - public, 60/minute;
  - `Cache-Control: public, max-age=300`;
  - **503** "Token signing keys are not configured." when there is no usable
    keyset — never an empty set, which a verifier would read as "trust
    nothing" and cache;
  - it publishes every key in `next`, `active` or `retired`, with `kty`, `crv`,
    `x`, `y`, `kid`, `alg` and `use` only.
- **`main.py`** — the lifespan logs `Token keyset: <kid> (<state>), …`, or a
  warning naming why there is none.
- **`scripts/security/manage_token_keys.py`** (new; the plan called it
  `generate_signing_key.py` — it also rotates, so it was renamed). Commands are
  `list`, `generate --state next`, `set-state KID STATE` and `remove KID`.
  - Every change is validated by loading the whole resulting keyset, and rolled
    back if it would not load.
  - Key files are created `O_EXCL`, mode 600, and optionally chowned.
  - `remove` refuses the active key, and leaves the file on disk for escrow and
    forensics — it is untrusted because the manifest no longer names it.
  - The tool never prints key material.
- **`docker-compose.yml`** — `api` only gains `CCURE_TOKEN_KEYS_DIR=/run/ccure/keys`
  and `${CCURE_TOKEN_KEYS_HOST_DIR:?…}:/run/ccure/keys:ro`. The variable is
  **required**: were it defaulted, a missing directory would be created empty by
  Docker and read as "no keyset". Worker, web-worker and beat get neither.
- **Docs** — `BACKEND_API_REFERENCE.md` (the route), `.env.example` and
  `Backend/.env.example` (the variables).

### 14.2 Where §3 and §5 were not followed, and why

- **§3.7 "a failing key store at start-up refuses to start"** applies from 9.4,
  when signing depends on the keyset. In 9.3 nothing signs, so refusing to
  start would take authentication down for a keyset nothing yet uses. Instead
  the API starts, logs the reason, answers 503 on the JWKS, and refuses every
  `kid` token, while HS256 carries on.
- **§3.7 "the reason is logged server-side"** (`unknown_kid`, `wrong_audience`,
  …) is **not** implemented in 9.3. It is worth most once tokens are issued,
  and belongs with 9.4. Responses are uniform, as required.
- **O15 (clock-skew leeway)** was undecided when 9.3 was built, and 9.3 used
  **0**, which is what the HS256 path has always used. The project owner has
  since decided on 0 s (§11), so the implementation already matches and no
  change was needed.

### 14.3 The live keyset

- Directory `/home/cdac/ccure-keys` (mode 711), inside `/home/cdac` (mode 750).
- `keyset.json` is 644 (kids and states only).
- The private key is owned by 1000:1000 (the container user `ccure`) with mode 600. The host account `cdac` cannot read it.
- **F9-12:** host uid 1000 is the `monitor` login account. It is kept out only
  because it cannot traverse `/home/cdac`. **Do not move the keyset anywhere
  another account can traverse.**
- One key, generated 29 Sep 2026: `7jKpUJt99bl-LKmPjhDmFCtzSHQ80eW3W-vOTtdJJAs`,
  state **`next`**. It is published and verifies, and nothing signs with it; 9.4
  promotes it to `active`.
- `CCURE_TOKEN_KEYS_HOST_DIR=/home/cdac/ccure-keys` is in the root `.env`
  (git-ignored).
- **Escrow is pending:** the project owner takes the offline copy of
  `es256-20260929T054911Z-7jKpUJt9.pem`. It is readable only as root or uid
  1000, for example
  `sudo cp /home/cdac/ccure-keys/es256-*.pem <escrow medium>`.

### 14.4 Runbook

Every command runs the tool in the backend image as root, so files can be
owned by uid 1000:

    docker run --rm -u 0 -v /home/cdac/ccure-keys:/keys -v "$PWD/Backend":/app -w /app \
        ccure-audit-pro-backend:latest \
        python -m scripts.security.manage_token_keys --keys-dir /keys <command>

- **Inspect:** `list` prints kid, state, algorithm and file, then validates.
- **Apply a change:** `docker compose restart api`. The keyset is read once per
  process, and the start-up log names what was loaded.
- **Rotate** (every 180 days, from 9.4 onwards):
  1. `generate --state next --owner 1000:1000`, restart, and escrow the new file.
  2. Wait at least the JWKS cache time (5 minutes).
  3. `set-state <old> retired`, `set-state <new> active`, restart. The tool
     refuses two active keys, so retire first.
  4. After the longest token lifetime (7 days, the refresh token) plus a margin,
     `remove <old>` and restart.
- **Emergency revocation of a key:** `set-state` another key `active` if needed,
  `remove` the compromised one, restart. Every token it signed stops verifying,
  refresh sessions included, and those users sign in again (§3.6).
- **Roll back 9.3:** revert the commit and remove the compose lines. Nothing
  was ever issued with the new keys, so no token or session is affected. The
  key directory can stay.

### 14.5 Verification

- **Tests:**
  - `tests/auth/test_token_keys.py` is new, with 39 tests:
    - all four legacy HS256 kinds still verify with a keyset loaded, and
      nothing issues ES256;
    - legacy off refuses HS256;
    - `next`, `active` and `retired` keys verify, and a full rotation removes a
      key's tokens;
    - an ES256 access token reaches `/auth/me`;
    - a verifier holding **only the JWKS** checks a token;
    - 25 forged or malformed tokens are refused by `verify`, by the legacy
      decode and uniformly by a protected route: unknown or missing `kid`; a known `kid` over another key; HS256 with a `kid`; HS256 keyed
      with the public key, with and without its `kid`; an `ES384`/`RS256`
      header; `alg: none`; `jwk`, `jku`, `x5u` and `crit` headers; wrong or
      missing `iss`/`aud`; a service or missing `ptype`; missing `jti`, `nbf`
      or `iat`; not yet valid; expired; the wrong kind;
    - ten invalid keysets (including an empty one) and two non-P-256 keys
      are refused whole;
    - a refused keyset leaves ES256 off;
    - the JWKS has exactly the public members, 503 without a keyset,
      `Cache-Control`, and a registered limit;
    - no key reaches a `repr`.
  - Mutation-checked: removing the `kid` fence on the legacy path, the
    audience, the header refusal, the `ptype` check, the legacy flag or the
    thumbprint check each fails the suite.
  - `test_token_guardrails.py` changes: `verify` requires `issuer` and
    `audience` too; and **only `api` carries the keyset mount, read-only**
    (reads `docker-compose.yml`, skipped inside the container, which mounts
    `Backend/` only; mutation-checked by giving `worker` the mount, and by
    making it writable).
  - The 9.1 characterisation suite passes unchanged.
  - `tests/security/test_rbac_routes.py`: `/auth/jwks.json` added to the
    public-route allowlist, with its reason. The first full run failed there,
    which is that test doing its job: a new unauthenticated route needs a
    recorded decision.
- **OpenAPI** against `cf394ff`: 232 → 233 paths. The one added is
  `GET /auth/jwks.json`; no existing path, component or top-level member
  changed. Limiter keys 91 → 92 (`auth.router.jwks` only). Celery tasks: 45,
  identical.
- **Architecture:** 0 violations, 0 module cycles, component cycle 24, and
  identity imports/queries/joins 3/2/2 — all unchanged.
- **Live:**
  - The start-up log names the key.
  - `/auth/jwks.json` returns one key with no private member, directly and
    through host nginx.
  - `docker inspect`: the mount is `rw=false` on api, and worker, web-worker and
    beat have neither the mount nor the variable.
  - An ES256 token minted in the api container for a non-existent user answers
    "User not found" — verification passed. The same token with a wrong
    audience, or over a foreign key under the live `kid`, answers "Invalid or
    expired token".
  - `sign()` still produces HS256.
  - The Phase 8 live probe is identical.

## 15. Step 9.4 — as built

**What 9.4 does.** New tokens of all four kinds (`access`, `refresh`, `ticket`,
`mfa_challenge`) are signed **ES256** with the keyset's `active` key, and carry
the full claim set of §3.3. Legacy HS256 tokens still verify, and a legacy
session moves onto ES256 at its next refresh. Nothing else changed: no API,
route, rate limit, Celery task, WebSocket path, MFA key, service identity or
key-rotation behaviour.

**The owner's decisions for this step (29 Sep 2026):**

- **Code and tests only.** The live API keeps issuing HS256 until the owner
  reviews 9.4 and approves promoting the key. The escrow copy of `7jKp…` has
  been taken.
- **No active key means no start.** With ES256 selected and no usable active
  key, the API refuses to start (§3.7). It does not fall back to HS256.
- **Refusal logging is part of 9.4** (deferred from 9.3, §14.2).

### 15.1 Code

- **`tokens.py`** — the only place tokens are signed:
  - `sign()` under ES256 signs with `signing_key()` (the one `active` key),
    puts its `kid` in the header, and sets `iss`, `aud`, `ptype` (from the kind),
    `iat`, `nbf` (= `iat`) and `exp` itself. It adds a `jti` unless the caller
    chose one — the refresh token does, because its session row is keyed on it.
  - A caller supplying `iss`, `aud`, `ptype`, `iat`, `nbf` or `exp`, or a kind
    this module does not issue, is refused with `ValueError`, not overwritten.
  - `sign()` under HS256 is the 9.3 function unchanged: the rollback issues
    byte-for-byte the pre-9.4 token.
  - `signing_algorithm()`, `signing_key()` and `assert_signing_ready()` raise
    `SigningUnavailable` for an unknown setting, no keyset, or no active key.
  - Every refusal is logged with a reason code (§15.2). Accept and refuse
    decisions are unchanged from 9.3.
- **`config.py`** — `JWTConfig.TOKEN_SIGNING_ALG` (`CCURE_TOKEN_SIGNING_ALG`,
  default `ES256`, case-insensitive; `HS256` is the rollback).
- **`main.py`** — the lifespan calls `assert_signing_ready()` straight after
  the keyset log and before any database work. It logs
  `Token issuance: <how>`, or logs CRITICAL naming the fix and re-raises, which
  stops the API starting.
- **`docker-compose.yml`** — the api only gains
  `CCURE_TOKEN_SIGNING_ALG=${CCURE_TOKEN_SIGNING_ALG:-ES256}`. The workers and
  beat never sign, and a worker that tried would raise, since it has no keyset.
- **`tests/conftest.py`** — the suite runs the target state: ES256 from a
  throwaway keyset generated per session under `/tmp`, never the deployment's
  keys and whatever the container's own `CCURE_TOKEN_*` settings say.
- **Unchanged:** `jwt_handler.py` (the plan named it as where the claims would
  be added; they are added in `sign()` instead, so no caller can mint a token
  without them), every router, the WebSocket paths, the MFA key.

### 15.2 Refusal logging

Logger `ccure.tokens`, one line per refusal:
`token refused: reason=<code> legacy=<bool> kid=… jti=… ptype=…`. The kid, jti
and ptype are the token's own **unverified** values, each cut to 64 characters.
**The token is never logged.** Responses are unchanged and uniform.

| Reason                                    | Level   | Meaning                                                    |
| ----------------------------------------- | ------- | ---------------------------------------------------------- |
| `expired`                                 | INFO    | past `exp` — routine for a 30-minute access token          |
| `wrong_kind`                              | INFO    | a valid token of another kind (e.g. a refresh as a Bearer) |
| `malformed`                               | WARNING | not a JWT, or an unreadable header                         |
| `refused_header`                          | WARNING | `jku`, `x5u`, `jwk`, `x5c` or `crit` present               |
| `legacy_disabled`                         | WARNING | HS256 with legacy acceptance off (after 9.6)               |
| `missing_kid`, `unknown_kid`, `no_keyset` | WARNING | no key to verify with                                      |
| `alg_mismatch`                            | WARNING | the header's `alg` is not the key's algorithm              |
| `bad_signature`                           | WARNING | signature does not verify                                  |
| `wrong_issuer`, `wrong_audience`          | WARNING | a token for another issuer or service                      |
| `not_yet_valid`, `missing_claim`          | WARNING | `nbf` in the future; a required claim absent               |
| `wrong_ptype`                             | WARNING | a principal type this kind is not issued to                |

### 15.3 The live state after 9.4

**New tokens are issued ES256 in production since 29 Sep 2026, 14:44 IST**,
signed by the promoted `active` key. The code is the committed 9.4 (`71ec3df`).
Promotion followed the owner's review of 9.4 and the owner's escrow copy of the
key. **Legacy HS256 verification stays enabled**
(`CCURE_ACCEPT_LEGACY_HS256`, default on): HS256 tokens issued before the
switch keep working until they expire. Turning it off is the 9.6 cut-off,
which needs its own evidence and review.

|                                      | Before (14:43:40)                                                        | After (from 14:44:43)                                             |
| ------------------------------------ | ------------------------------------------------------------------------ | ----------------------------------------------------------------- |
| Key `7jKpUJt99bl-…` in `keyset.json` | `next`                                                                   | `active` — the manifest's `state` only; the key file is untouched |
| Root `.env`                          | `CCURE_TOKEN_SIGNING_ALG=HS256`                                          | `CCURE_TOKEN_SIGNING_ALG=ES256`                                   |
| api start-up log                     | `Token issuance: HS256 (legacy issuance, CCURE_TOKEN_SIGNING_ALG=HS256)` | `Token issuance: ES256 with key 7jKpUJt99bl-…`                    |

- **The keyset holds one key, and it is `active`.** The JWKS publishes that
  key only.
- **Worker, web-worker and beat have no key and no signing setting.**
- **Never leave ES256 selected without an active key.** ES256 is also the code
  default, so the API would refuse to start. That was proven against this
  keyset before promotion: "the token keyset has no active key". Set HS256
  first (the rollback below) before demoting or removing the active key.

**The promotion, as run:**

1. A database backup: `ccure_db_20260929_144352_ops.dump`.
2. Promote the key:
   `docker run --rm -u 0 -v /home/cdac/ccure-keys:/keys -v "$PWD/Backend":/app -w /app ccure-audit-pro-backend:latest python -m scripts.security.manage_token_keys --keys-dir /keys set-state 7jKpUJt99bl-LKmPjhDmFCtzSHQ80eW3W-vOTtdJJAs active`.
3. In the root `.env`, change `CCURE_TOKEN_SIGNING_ALG=HS256` to `ES256`.
   Nothing else in the file changed.
4. Run `docker compose up -d --no-deps api`.

**Live checks, all passed (29 Sep 2026):**

- **Start-up.** The API was healthy with
  `Token issuance: ES256 with key 7jKpUJt99bl-…` and 0 restarts.
- **Fresh tokens.** Access, refresh, ticket and MFA-challenge tokens minted in
  the api container are ES256, with the active `kid` and the full claim set.
  - The live API accepted an ES256 access token and an ES256 download ticket.
    Each reached the user lookup, for a user id that does not exist.
  - Both controls were refused: a garbage ticket, and a refresh token
    presented as a Bearer.
- **Existing HS256.** A token the API issued before the switch still verified
  after it.
- **Login → refresh → logout**, by the owner in a browser:
  - a fresh login rotated its session and was revoked at logout;
  - the browser's own **3-day-old HS256 session** (issued 26 Sep) refreshed
    into an ES256-era session, which the next logout revoked — a live legacy
    session crossing onto ES256;
  - no token was refused, and no 401 or error was logged during the test.
- **JWKS.** Only the active key, public members only, both directly and
  through host nginx.
- **Phase 8 live probe.** Identical.
- **Worker, web-worker and beat.** Not restarted. No key mount, no setting,
  and no key file anywhere on their filesystems.
- **Repository.** HEAD `71ec3df`, the working tree unchanged, and no
  application code touched.

**Not exercised live:** WebSocket progress, and the rate-limit audit naming a
caller. Both read tokens through the unchanged legacy decode, which accepts
every ES256 kind (`test_token_issuance.py`).

The SPA rotated the refresh token four times in three seconds after the login.
The same burst appears on 26 Sep, before ES256, so it is the SPA's behaviour on
page load, not an effect of 9.4. It is relevant to refresh-token reuse
detection (O13).

**Rollback to HS256 issuance:**

1. In the root `.env`, set `CCURE_TOKEN_SIGNING_ALG=HS256`.
2. Run `docker compose up -d --no-deps api`.
3. The start-up log must read
   `Token issuance: HS256 (legacy issuance, CCURE_TOKEN_SIGNING_ALG=HS256)`.

Tokens already issued ES256 stay valid, because verification accepts both and
the key stays published. Leave the key `active`; demoting it is not a
rollback step.

### 15.4 Findings

- **Tokens roughly double in size.** For realistic claims, access 289 → 560
  characters, refresh 271 → 500, ticket 233 → 504. That is well within
  cookie (4 KB) and URL limits. The ticket travels in a URL (F9-4), so it
  now fills a little more of an access-log line.
- **`refresh_access_token` commits the rotation before it signs the new
  access token.** A signing failure at that moment would leave the old
  session revoked and no token issued. This predates 9.4. It is unreachable
  now, because the key is loaded once and checked at start-up, so it is
  recorded, not changed.
- **The characterisation suite (9.1) now runs in HS256 mode.** That makes it
  the proof that the rollback issues byte-for-byte the pre-9.4 token. The
  ES256 tokens are characterised by `test_token_issuance.py`.

### 15.5 Verification

- **Tests:** `tests/auth/test_token_issuance.py` is new, with 54 tests:
  - the ES256 header with the active `kid`, per kind;
  - the claim set (legacy claims plus `iss`, `aud`, `ptype`, `jti`, `nbf`) with
    their values and lifetimes;
  - a unique `jti` per token, and the refresh `jti` matching its session row;
  - verification from the published JWKS alone;
  - acceptance by each consuming path (Bearer route, download ticket, legacy
    decode for the WebSockets and the rate-limit audit, MFA challenge,
    refresh rotation);
  - claim consistency still enforced;
  - a legacy refresh token replaced by ES256 tokens, a mixed-age session, and
    logout of either era;
  - ES256 tokens surviving a rollback to HS256;
  - every `sign()` refusal, and an unknown algorithm setting;
  - the API refusing to start without an active key;
  - refusal reasons and levels, the token and its signature never in the
    log, and oversized values truncated.
- **Updated:**
  - `test_token_keys.py` mints its legacy tokens through the HS256 mode, and
    its "nothing issues ES256 yet" test became "only the active key signs".
  - `test_token_characterisation.py` runs in HS256 mode, with no assertion
    weakened.
- **Mutation-checked** on a copy (8 of 8 caught): no `aud`, the wrong key
  signing, no start-up refusal, the token in the log, the caller's `jti`
  overwritten, the HS256 rollback gaining a claim, a non-active key signing,
  and reserved claims silently overwritten.
- **Suites:**
  - `tests/auth`, `tests/security` and `tests/repo`: 820 passed, 2 skipped.
  - The full suite: **6105 passed, 209 skipped, 0 failed** — 6051 at 9.3 plus
    the 54 new tests.
- **OpenAPI, rate-limit keys (92) and Celery tasks (45)** against `950e599`:
  byte-identical.
- **Architecture:** 0 violations, 0 cycles, component cycle 24, identity
  3/2/2.
- **Live:**
  - The API starts in HS256 mode with the new log line.
  - The Phase 8 probe is identical.
  - A token issued in the API container is HS256 and verifies.
  - ES256 selected against the live keyset refuses.

## 16. Step 9.5 — as built

**What 9.5 adds.** Platform-owned service identities, and service-to-service
authentication, by D4 option A (`private_key_jwt`, RFC 7523). A service proves
who it is with a short assertion signed by **its own** private key. The core
verifies it against the public key registered to that service and issues a
10-minute ES256 `service_access` token, signed by the platform key.

- **Nothing is shared.** No secret passes between the platform and any
  service.
- **Nothing changed for people.** Human authentication is unchanged, and so is
  every existing route.
- **Out of scope:** IR, and the 9.6 cut-off. Legacy HS256 verification is
  still on.

**The owner's decisions for this step (29 Sep 2026):**

| Decision                                            | Chosen                                                                                                                                                                                                             |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| O9 storage                                          | **Static registry, no migration**: `services.json` plus public keys, in a host directory outside the repository, read-only into the api only. Tables later, only with a reviewed schema                            |
| O11 lifetime and revocation; the service half of O5 | **10-minute** service tokens, no denylist; the identity re-checked on every request. `aud` = the target service, `urn:ccure:core` or `urn:ccure:ir`. Assertions **≤ 60 s**, single use, `aud` = the token endpoint |
| Replay store                                        | **Redis, fail closed**: an assertion `jti` is `SET NX` with a TTL, and an unreachable store refuses (503)                                                                                                          |
| Live registration                                   | **Empty registry**, nothing live: no credential exists until a service does (IR, Phase 13). `require_service_scope` stays out of `ccure_platform.api` until its first consumer (§3.5)                              |

### 16.1 Code

- **`ccure_platform/service_identity/`** (new):

  - **`registry.py`** — the format and a whole-registry validation that
    refuses rather than repairs. It checks:

    - the id pattern;
    - status `active` or `disabled`;
    - an audience from the service set;
    - scopes of the form `module:resource:action`;
    - at least one tenant;
    - safe file names;
    - each `kid` equals its key's RFC 7638 thumbprint;
    - keys are P-256.

    It also **refuses any file holding a private key**, a `kid` registered to
    two services, and a `kid` that is a platform signing key. The registry is
    loaded once per process, and unset means an empty registry.

  - **`replay.py`** — single use of an assertion `jti`, in Redis, failing
    closed.
  - **`router.py`** — `POST /auth/service-token`, form-encoded per RFC 6749
    §4.4 and RFC 7523, rate limit 30/minute. The checks, in order:

    1. the grant and assertion types;
    2. the assertion against the key registered to **that** service;
    3. the identity's status;
    4. single use of the assertion — after authentication, so an
       unauthenticated caller cannot fill the store;
    5. the requested scopes are a non-empty subset of those allowed;
    6. the tenant is one of those granted, and the organisation exists and is
       active.

    Then it signs the token and writes a `service.token_issued` audit event,
    actor `svc:<id>`, under the tenant, in one transaction. Every
    authentication failure answers the same 401 `invalid_client`; the reason
    goes to the log only.

  - **`dependencies.py`** — `service_principal_for(audience)` and
    `require_service_scope(scope)`, for the first consumer (Phase 14). Tenant
    context comes from the token's `tenant` claim only; `X-Tenant-ID` is never
    read. The identity's status and tenant grant are re-checked on every
    request.

- **`ccure_platform/identity/tokens.py`**:
  - The new kind `service_access`, with `ptype` `service`.
  - `sign_service_token()`: always ES256 with the active key, never HS256,
    even in the HS256 rollback mode.
  - `verify_service_assertion()`: the assertion check, living here because
    only this module may touch a JWT library.
  - `sign()` refuses the service kind, and `verify()` refuses it on the legacy
    HS256 path.
  - `unverified_header()` and `unverified_claims()`, for audit fields.
- **`config.py`** — `JWTConfig.SERVICE_REGISTRY_DIR`
  (`CCURE_SERVICE_REGISTRY_DIR`).
- **`main.py`** — the router is included, and the start-up log reads
  `Service identities: …`. A refused registry is a warning, not a stop:
  human sign-in must not depend on it.
- **`scripts/security/register_service_identity.py`** (new) — `register`,
  `add-key` (import the public key a service generated), `generate-key`
  (private key to a separate directory, never the registry or the platform
  keyset), `remove-key`, `set-status`, `set-scopes`, `set-tenants`, `list`.
  Each change is validated before it is kept, and no key material is printed.
- **Tests and guardrails:**
  - `tests/auth/test_service_identity.py` is new (65 tests).
  - `tests/security/test_rbac_routes.py` lists the endpoint as public, with
    its reason.
  - `tests/repo/test_platform_identity_move.py`'s limiter-key check now names
    the modules moved in 8.2, rather than every `ccure_platform.` key. A
    module created in the platform has no legacy name to keep.
    Mutation-checked: removing the identity router's legacy name still fails
    it.
- **Docs** — `BACKEND_API_REFERENCE.md` (the route), `Backend/.env.example`,
  this section, CLAUDE.md.
- **No schema change.** No migration, no table, and no `table_ownership.yaml`
  entry. `users`, `roles` and passwords are not touched: a service identity
  is not a user.

### 16.2 The service-token flow

```
service (e.g. IR, Phase 13)                        core (platform)
───────────────────────────                        ────────────────
signs an assertion with ITS OWN private key:
  header {alg: ES256, kid: <its key thumbprint>}
  {iss = sub = "ir",
   aud = https://ccurepro.cdac.in/api/auth/service-token,
   jti = <unique>, iat, exp ≤ iat + 60 s}
POST /auth/service-token  (form)          ──►  key_for("ir", kid): the key registered
  grant_type=client_credentials                 to ir, or refuse (401 invalid_client)
  client_assertion_type=…:jwt-bearer            verify ES256, aud, iss = sub, lifetime
  client_assertion=<JWT>                        identity active? jti unused? (Redis, fail closed)
  scope=audit:findings:read                     scopes ⊆ allowed?  tenant granted and active?
                                          ◄──   200 {access_token, Bearer, 600, scope, tenant}
                                                audit: service.token_issued (actor svc:ir)
Authorization: Bearer <service token>     ──►  require_service_scope("audit:findings:read"):
  token: ES256, platform kid,                   verify(kind service_access, aud urn:ccure:core),
  aud urn:ccure:core, sub svc:ir,               identity still active, tenant still granted,
  ptype service, tenant, scope                  scope present; tenant = the token's, never
                                                X-Tenant-ID
```

Verifiers other than the core (IR, the gateway) check the token against the
public JWKS alone.

### 16.3 Operating the registry (when the first service exists)

The live registry is empty, and `CCURE_SERVICE_REGISTRY_DIR` is not set on the
api, so every assertion answers 401. To register the first service:

1. Create the host directory (for example `/home/cdac/ccure-services`,
   inside `/home/cdac`, as for the keyset).
2. Register the service, and add the public key it generated:
   `register ir --name "Incident Response" --module ir --audience urn:ccure:core --scope … --tenant …`,
   then `add-key ir --public-key ir.pub.pem`. Run the tool with
   `--platform-keys-dir` so a platform `kid` is refused.
3. Mount the directory read-only on the api, at `/run/ccure/services`, with
   `CCURE_SERVICE_REGISTRY_DIR` set. That is a compose change made with the
   first registration.
4. Recreate the api. The log must read `Service identities: ir (active, 1 key(s))`.

To revoke, `set-status ir disabled` or `remove-key`, then restart the api.
Tokens already issued stop working at once, because every request re-checks
the identity.

### 16.4 Findings

- **The audit log redacts any field whose name contains "token".** The
  issued token's `jti` is therefore recorded as `issued_jti`. A first draft
  used `token_jti`, and the log stored `[REDACTED]`.
- **Platform-wide service identities (§3.5) are not implemented.** Every
  service token is bound to exactly one tenant: the identity's own, or one of
  its grants named in the request. A token with no tenant needs a consumer and
  a design; the national Rank of §8.2 is the first candidate.
- **Revocation latency is an api restart.** That is the static-registry
  trade-off the owner chose. Every request re-checks the in-memory registry,
  so a restart takes effect for live tokens too.
- **Two pre-existing inaccuracies in `BACKEND_API_REFERENCE.md`, not
  corrected** (outside this step):
  - its totals table says 155 HTTP operations against 271 registered;
  - its JWKS section still says tokens are HS256 until 9.4.

## 17. Step 9.6 — the legacy HS256 cut-off

**What 9.6 is (the owner's decisions, 29 Sep 2026):**

| Decision                                  | Chosen                                                                                                                                                                                                    |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Scope                                     | **Verification cut-off only.** `CCURE_ACCEPT_LEGACY_HS256=false` for the api. The HS256 code, HS256 issuance and `JWT_SECRET_KEY` stay as the rollback; removing them is a later step with its own review |
| When (O8)                                 | **Measured**: when no HS256 refresh session remains live. Nobody is signed out                                                                                                                            |
| Evidence ("runtime checks complete", §11) | **The session query returns 0, plus a live rehearsal** of the flip and its rollback. No new observation code                                                                                              |
| F9-8                                      | **Recorded, fixed later**, separately                                                                                                                                                                     |

9.6 is two steps. **9.6a** prepares the switch and changes nothing live.
**9.6b** flips it, when the measurement allows.

### 17.1 Step 9.6a — as built

- **`tokens.py`**:
  - `signing_algorithm()` refuses HS256 issuance while
    `CCURE_ACCEPT_LEGACY_HS256=false`. The API would otherwise issue tokens that
    it then refuses, which signs every user out at their next request.
  - Start-up and `sign()` both go through it, so the refusal cannot be
    bypassed at run time.
  - `legacy_verification_status()` gives the start-up line.
- **`main.py`**: the lifespan logs
  `Legacy HS256 verification: enabled (CCURE_ACCEPT_LEGACY_HS256=true)`
  **before** the issuance check, so a refusal is always preceded by the state
  that caused it. It sits next to `Token issuance: …`.
- **`docker-compose.yml`**: the api only gains
  `CCURE_ACCEPT_LEGACY_HS256=${CCURE_ACCEPT_LEGACY_HS256:-true}`. The root
  `.env` (git-ignored) carries `CCURE_ACCEPT_LEGACY_HS256=true`, and
  `.env.example` documents it. The switch is unchanged from its 9.3 meaning:
  any value except `false` keeps HS256 verifying.
- **Tests:**

  - `tests/auth/test_legacy_cutoff.py` is new (30 tests). With the switch
    **off**, HS256 is refused on:

    - a protected route;
    - a download ticket, over HTTP and through the dependency;
    - both WebSocket ticket logins (`routers.scan_history`, `routers.web_scans`);
    - the rate-limit audit's caller identification;
    - refresh, over HTTP and in-process;
    - logout, which can no longer name the session, while the token stays
      unusable;
    - every kind through `verify` and the legacy decode.

    Each refusal is logged `reason=legacy_disabled`.

  - **ES256 is unaffected** on every one of those paths, and so are service
    tokens.
  - With the switch **on again**, the same HS256 tokens verify, and HS256
    issuance — the 9.4 rollback — works.
  - The API refuses to start with HS256 issuance and the switch off.
  - Default parsing is checked in fresh processes.
  - `test_token_guardrails.py` gains a check that only the api carries
    `CCURE_TOKEN_SIGNING_ALG` and `CCURE_ACCEPT_LEGACY_HS256`.
  - Mutation-checked, 4 of 4 caught: no guard, the switch ignored when
    verifying, the status line not logged, the status line inverted.
  - The compose guardrail is also mutation-checked, by giving the worker the
    switch.

### 17.2 The measurement (29 Sep 2026, 16:40 IST)

The query that decides the cut-off (read-only). `09:14:35 UTC` is when the api
started issuing ES256 (§15.3), so anything issued before it is HS256:

```sql
SELECT count(*), count(DISTINCT user_id), max(expires_at)
FROM refresh_token_sessions
WHERE issued_at < '2026-09-29 09:14:35+00'
  AND revoked_at IS NULL
  AND expires_at > now();
```

- **Result:** 14 live HS256 refresh sessions across 5 accounts — superadmin,
  chandan_scanner, admin_chandan, dhananjay and pankaj. The last expires
  naturally at **3 Oct 2026, 22:12 IST**.
- **The figure can only fall.** Using one of those sessions rotates it to
  ES256, and nothing issues HS256.
- **Nothing else HS256 can still be valid.** Access tokens (30 minutes),
  tickets (60 seconds) and MFA challenges (5 minutes) from before 14:44:35 IST
  on 29 Sep have all expired.

### 17.3 Step 9.6b — the runbook for a measured cut-off

**Condition:** the query above returns **0**, at the earliest 3 Oct 22:12 IST,
with a margin (planned: 4 Oct). On this installation the owner instead chose
a forced cut-off on 29 Sep; §17.5 records it.

1. **Evidence.**
   - Re-run the query: it must return 0.
   - The api's start-up log shows no MFA-fallback warning, so the MFA key is
     read from `MFA_ENCRYPTION_KEY` (9.2).
   - The log reads `Token issuance: ES256 with key …`.
2. **Back up.** Run `scripts/backup_db.sh --skip-reference-data`.
3. **Flip.** In the root `.env`, set `CCURE_ACCEPT_LEGACY_HS256=false`, then
   run `docker compose up -d --no-deps api`. The log must read
   `Legacy HS256 verification: disabled (CCURE_ACCEPT_LEGACY_HS256=false)`.
4. **Rehearse, live.** Every check below must hold:
   - an HS256 access token, minted in the api container for a user that does
     not exist, is refused, and logged `reason=legacy_disabled`;
   - an ES256 one reaches the user lookup;
   - the owner's browser login, refresh and logout work;
   - a download ticket works;
   - then flip back to `true` and recreate: the same HS256 token reaches the
     user lookup — the rollback is proven;
   - then flip to `false` again and recreate.
5. **Confirm.** The Phase 8 live probe is identical. Worker, web-worker and
   beat are not restarted and have no signing key.
6. **Close.** Record it here, update CLAUDE.md, and commit the docs.

**Rollback at any time:** set `CCURE_ACCEPT_LEGACY_HS256=true` in the root
`.env`, then `docker compose up -d --no-deps api`. HS256 tokens still inside
their lifetime verify again.

### 17.4 Not in 9.6, and why

- **Removing the HS256 code, HS256 issuance and `JWT_SECRET_KEY`.** A later
  step, after a quiet period with the switch off, with its own review.
  Removing them also removes both rollbacks.
- **F9-8 is a separate follow-up**, and its shape changed with a finding on
  29 Sep:
  - **Compose is not the only route.** All four containers mount `./Backend`,
    so worker, web-worker and beat can read `Backend/.env`. That file holds
    `JWT_SECRET_KEY` **and** `MFA_ENCRYPTION_KEY`. Removing the secret from
    their compose environment alone changes nothing.
  - **Removing it outright breaks start-up.** An unset `JWT_SECRET_KEY` falls
    back to the development default, which `jwt_handler` refuses in
    production.
  - **The fix is a secrets-layout change**: move both secrets to api-only
    configuration. It moves the MFA key, whose value must never change, so it
    is reviewed on its own.
  - **The exposure shrinks after 9.6b:** with HS256 verification off, the JWT
    secret verifies nothing, and 9.5 already refuses HS256 service tokens.

### 17.5 Step 9.6b — as run: a FORCED cut-off (29 Sep 2026)

**The measured condition of §17.3 was not waited for.** At 17:32 IST the
query still returned 14. The project owner then decided on a **forced**
cut-off: the application has no active users, so there was nothing to gain
from waiting until 3 Oct 22:12 IST. The 14 remaining HS256 sessions were
**intentionally invalidated**, and the switch was flipped the same day. This
replaces the "measured" choice of O8 for this installation only; the runbook
in §17.3 remains the procedure where live users exist.

**Before anything changed (17:39 IST):**

- The §17.2 query returned **14 live HS256 refresh sessions across 5
  accounts**: superadmin ×6, dhananjay ×3, admin_chandan ×2, pankaj ×2,
  chandan_scanner ×1. The last would have expired on 3 Oct at 22:12 IST.
- The session ids were 7316, 7319, 7337, 7360, 7399, 7414, 7417, 7418, 7419,
  7424, 7425, 7429, 7430 and 7439. No token material was read or recorded.
- **Backup:** `ccure_db_20260929_173912_ops.dump`, which contains the
  `refresh_token_sessions` data (checked with `pg_restore -l`).

**The cut-off:**

| Step                  | When (IST) | What                                                                                                                                                                                                                               |
| --------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Revoke the 14         | 17:39:27   | One statement: `revoked_at = now()` for exactly those ids, still unrevoked and unexpired, which rolls itself back unless exactly 14 rows change. It changed 14. The rows are kept: a revoked row is the audit record of a sign-out |
| Count                 | 17:39:27   | The query returns **0**                                                                                                                                                                                                            |
| Flip                  | 17:40:04   | Root `.env`: `CCURE_ACCEPT_LEGACY_HS256=false`, the only line changed. Then `docker compose up -d --no-deps api`                                                                                                                   |
| Rollback rehearsal on | 17:47:23   | Switch `true`, api recreated                                                                                                                                                                                                       |
| Final state           | 17:48:19   | Switch `false` again, api recreated. It has been in this state since                                                                                                                                                               |

The key is untouched: the `7jKp…` file has been unchanged since 11:19, and
`keyset.json` since the 14:44 promotion.

**Live verification, all passed:**

- **Start-up.** The log reads
  `Legacy HS256 verification: disabled (CCURE_ACCEPT_LEGACY_HS256=false)` and
  `Token issuance: ES256 with key 7jKpUJt99bl-…`, with 0 restarts.
- **HS256 refused.** HS256 tokens were minted in a separate process, for a
  user id that does not exist:

  - the access token answers `401 Invalid or expired token`;
  - the ticket answers `401 Invalid or expired download ticket.`;
  - both refusals are logged by `ccure.tokens` with the reason code
    `legacy_disabled`.

  ES256 tokens of both kinds reach the user lookup (`User not found`).

- **A real login flow, over HTTPS through host nginx**, with the same calls
  the SPA makes, on the owner's account (no MFA) at 17:55:

  - **Login:** 200, an ES256 access token, the refresh cookie set, and
    `/auth/me` 200.
  - **Refresh:** a page reload refreshes, because the SPA holds the access
    token in memory only. `/auth/refresh` returned 200 with a new ES256
    token. Session 7484 was revoked with `replaced_by` pointing at session
    7485, and `/auth/me` returned 200.
  - **Download ticket:** `/auth/ticket` returned 200, an ES256 ticket.
    `/reports/download/scn_defa_c522b539_29sep26_fh9j?fmt=JSON` returned 200,
    a 46,191-byte PDF served from the stored file, and wrote the audit event
    `report.downloaded`.
  - **Logout:** 200. Session 7485 was revoked (audit event `user.logout`),
    and a refresh afterwards was refused with 401.

  The audit sequence is `user.login` → `report.downloaded` → `user.logout`,
  all `success`, with no refusal and no error logged. (Two earlier manual
  browser attempts logged in and out within 3–5 seconds and did not exercise
  refresh or a download, so they are not counted.)

- **JWKS.** One key, `7jKp…`, public members only.
- **The Phase 8 live probe is identical.**
- **Worker, web-worker and beat** were not restarted (started 05:49 UTC).
  They have no `CCURE_ACCEPT_LEGACY_HS256`, `CCURE_TOKEN_SIGNING_ALG` or
  `CCURE_TOKEN_KEYS_DIR`, no keys mount, and no key file anywhere in their
  filesystems.
- **Rollback rehearsal.** With the switch on, the same kinds of HS256 access
  token and ticket verified again (they reached the user lookup, with 0
  refusals), and HS256 issuance passed its start-up check
  (`HS256 (legacy issuance, …)`) in a separate process. Switched off again,
  HS256 was refused (`legacy_disabled`) and ES256 accepted.

**Final live state (from 29 Sep 2026, 17:48 IST):**

- **Issuance:** ES256, with the active key `7jKpUJt99bl-…`, unchanged.
- **Legacy HS256 verification:** disabled. `CCURE_ACCEPT_LEGACY_HS256=false`
  in the root `.env` and on the api only.
- **Live HS256 refresh sessions:** 0. Nothing issues HS256.
- **Still present, by decision (§17.4):** the HS256 code, the HS256 issuance
  mode and `JWT_SECRET_KEY`. They are the rollback.

**Rollback.** In the root `.env`, set `CCURE_ACCEPT_LEGACY_HS256=true`, then
`docker compose up -d --no-deps api`. The log must read
`Legacy HS256 verification: enabled`.

- **What it restores:** acceptance of HS256 tokens. None legitimately exists
  any more — the 14 sessions are revoked, and nothing issues HS256.
- **Rolling issuance back to HS256 too** (the 9.4 rollback) needs this step
  first, then `CCURE_TOKEN_SIGNING_ALG=HS256`. With the switch off, the API
  refuses to start in HS256 mode by design (§17.1).
- **The 14 revoked sessions are not restored by any rollback.** Restoring them
  would mean restoring the revoked rows from
  `ccure_db_20260929_173912_ops.dump` into a scratch database and copying
  them back — not advised, since their users are simply asked to sign in
  again.

**Findings:**

- **`certs/ccure-internal-ca.crt` in the repository is not the root that signs
  host nginx's certificate on this VM.** The live chain is signed by "CCure
  Audit PRO Internal Root CA (Linux Dev)", which is in the VM's system trust
  store. Recorded, not changed.
- **Phase 9 is complete for its approved scope.**
  - A token verifies with the public key alone (§14–15).
  - A service can obtain its own token (§16).
  - HS256 tokens were retired by a controlled cut-off (this section).
  - What remains is the removal step and F9-8 (§17.4), each needing its own
    decision.
