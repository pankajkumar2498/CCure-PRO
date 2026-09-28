"""
The one way a CCure module reaches identity, organisations and roles.

Empty in step 8.1. Step 8.3 adds the functions, and step 8.5 switches the
modules to them. The functions this module may ever export are listed in
``scripts/architecture/identity_boundary.PLATFORM_API_SURFACE``; a test fails
on anything else.

Modules receive ids, names and frozen views from here — never an ORM ``User``
or ``Organization``. A later authentication service (plan §3.9) replaces what
is behind these functions, not their callers.
"""

__all__: tuple[str, ...] = ()
