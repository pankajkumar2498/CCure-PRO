"""
Service identities: how one CCure service proves who it is to the platform
(Phase 9.5, docs/architecture/PHASE9_TOKENS_AND_SERVICE_IDENTITIES.md §3.4–3.5).

A service identity is platform-owned and is **not a user**: no row in
``users``, no role, no password, so it can never sign in to the SPA or pass
``current_user``. It has an id, the module that owns it, a status, the one
service it may obtain tokens for, the scopes it may be granted, the tenants it
may act for, and its public keys.

    registry.py      the registry: services.json + public keys, read-only
    replay.py        single use of an assertion jti (Redis, fail closed)
    router.py        POST /auth/service-token — assertion in, token out
    dependencies.py  service_principal / require_service_scope, for the first
                     consumer (Phase 14); deliberately not in ccure_platform.api

The flow (RFC 7523 ``private_key_jwt``, D4 option A): the service signs a
short assertion with **its own** private key; the platform verifies it against
the public key registered to that service, checks status, scopes and tenant,
and issues a 10-minute ES256 ``service_access`` token signed by the platform
key. No secret is shared between the platform and any service.
"""
