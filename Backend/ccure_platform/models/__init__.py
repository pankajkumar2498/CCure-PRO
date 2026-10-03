"""
The platform's models — moved from ``db/models/`` in Phase 8.2, as they were.

* ``users``: ``User``, ``RefreshTokenSession``, ``PasswordResetToken``,
  ``EmailVerificationToken`` (identity) and ``AuditLog`` (the platform's audit
  trail — not the CCure Audit module).
* ``rbac``: ``Organization`` (tenancy), ``Role``, ``Permission``,
  ``RolePermission`` (RBAC).

* ``rbac_tables``: the new RBAC capability's seven ``rbac_*`` tables (RBAC-1).
  New, not moved: legacy ``roles`` / ``permissions`` / ``role_permissions`` stay
  in ``rbac`` until RBAC-8. Dark — no request path reads them yet.

The files moved whole rather than split by capability: ``db.models.users`` and
``db.models.rbac`` must stay aliases of *one* module each, and a class may not be
defined twice. ``db.models`` remains the registry every model is imported
through, so mapper configuration and table order are what they were.

Nothing here imports anything but ``db.base`` and SQLAlchemy (layer rule
``models-are-leaves``). The relationship strings ``Organization.assets`` /
``.scans`` and ``User.scans`` / ``asset_notes`` / ``asset_tags`` still name
Audit's models; they are removed in step 8.4, after checking that the
database's own foreign keys cascade as the ORM did.
"""
