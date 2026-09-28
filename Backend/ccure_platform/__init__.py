"""
The CCure platform: what every CCure module shares.

Sign-in, users, sessions, organisations, roles and permissions belong here —
not to Audit, Policy Pro, Rank or IR. Phase 8 of the modular-platform programme
moves them in (``docs/architecture/PHASE8_PLATFORM_IDENTITY.md``):

    identity/   sign-in, sessions, password reset, email verification, JWT
    tenancy/    organisations
    rbac/       roles, permissions, the require_permission / require_role checks
    api.py      the one way in for every module

Step 8.1 creates the package and the guardrails only; nothing lives here yet
and nothing imports it. Identity's code is still in ``auth/`` and
``db/models/``.

What does **not** belong here, and is refused by the guardrails:

* any module's business logic — Audit's scans, findings, compliance, reports;
* Audit's settings that sit on ``organizations`` today (asset and scan quotas,
  scan scope). They are Audit's, and step 8.4 moves them to the Audit-owned
  ``audit_organisation_settings``;
* any import of a module's code (``layer_rules``:
  ``platform-is-shared-foundation``).

Owner (decision D6, 28 Sep 2026): the Project Owner, until Phase 11 adds
``CODEOWNERS``. Audit maintains it in the meantime; the owner can change later.
"""
