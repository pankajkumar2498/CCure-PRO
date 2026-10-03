"""
RBAC: who may do what — the platform's authorization capability.

Two things live here, and only one is live.

**Live (legacy), until RBAC-8:** ``dependencies`` — the ``require_permission`` /
``require_role`` / ``user_has_permission`` checks that answer from ``users.role_id``,
``roles``, ``permissions`` and ``role_permissions``. It moved from ``auth/rbac.py``
in Phase 8.2; ``auth.rbac`` is an alias of the same module. **It is still the only
authorization authority.**

**Dark (RBAC-1), independent of every product module:**

    contract     stdlib-only dataclasses, vocabularies and grammars
    engine       the decision as a pure function over grants — never a role
    catalogue    permission declarations (data), validation, and the sync
    model        the rbac_* tables' seat, row → view converters, revisions
    resolver     rows → grants; the one place a role's rows are walked
    governance   escalation ceiling, assignment/role checks, lifecycle, continuity
    audit        RBAC's audit events, written through the platform audit log
    shadow       compare the new decision with the legacy one; wired to nothing

Nothing in the dark half is consulted by a route. A module reaches it through
``ccure_platform.api`` and nothing else; RBAC imports no module and does not know
which exist (``layer_rules``: ``rbac-is-module-agnostic``). Record:
``docs/architecture/RBAC_FOUNDATION.md``. The tables are defined in
``ccure_platform/models/rbac_tables.py``.

A role is ``id`` + ``key`` + ``display_name`` and **none of them is an authorization
input**.
"""
