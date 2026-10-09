"""
Identity: sign-in, sessions, password reset, email verification, MFA,
email-domain screening, JWT handling and account mail.

Moved from ``auth/`` in Phase 8.2. The old ``auth.*`` paths are aliases of these
same modules (``ccure_platform/_legacy.py``), and each module keeps its old
``__name__`` so logger names and limiter keys are unchanged.

Module code does not import from here: it reaches identity through
``ccure_platform.api`` (step 8.5; the ratchet in
``scripts/architecture/identity_boundary.py`` counts what is left).
"""
