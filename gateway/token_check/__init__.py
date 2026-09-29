"""
gateway-auth — the gateway's token check (Phase 10.2b).

nginx asks this service, through ``auth_request``, whether a request carries an
acceptable credential for its route. It answers from the platform's
**public** keys only: it holds no JWT secret, no MFA key, no private key, no
``Backend/.env``, and reaches no database or Redis. The rules it applies are
``ccure_platform.identity.verification`` — the same module the core service
verifies with — so the gateway and the service cannot disagree about a token.

Modules:

* ``config``  — the three settings, all required, read once at start.
* ``jwks``    — the key source: the published JWK Set, fetched and cached.
* ``checker`` — the decision: route policy × credential → allow or a refusal
  code, reproducing ``HTTPBearer`` and ``get_current_user_flexible`` exactly.
* ``app``     — the ASGI service nginx calls (``/check``, ``/healthz``).

Design: ``docs/architecture/phase10/PHASE10_2_DESIGN.md`` §§2, 5–8.
"""
