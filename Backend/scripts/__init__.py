"""
Backend.scripts — application tooling: seeders, catalogue generators, feed syncs
and verification probes.

This marker is deliberate. The package is imported as `scripts.*` at runtime —
`core/email_security_tasks.py` calls `scripts.security.sync_disposable_domains`
and `main.py` bootstraps compliance through `scripts.seed_compliance` — and CI
runs `python -m scripts.seed_compliance`. Without a marker it resolved as a PEP
420 namespace package, which worked but left `scripts/security/__init__.py` as
the only marker in the tree and made the packaging look accidental.

Note that the imports above mean this is not purely developer tooling: the
running application still depends on two modules in here. Keep that in mind
before moving anything out.

The NIST CSF catalogue used to be a third. It lived here as
`nist_csf_v2_core.py` and `core/nist_csf.py` imported it, so the running
application depended on the tooling package to answer a compliance request. It
is `core/nist_csf_catalogue.py` now, and the two generators in here import *up*
into core, which is the direction that should hold.
"""
