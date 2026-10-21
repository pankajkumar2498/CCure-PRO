"""
engines/tls — the TLS engine: the sslyze wrapper both scan paths use.

The network checks' TLS plugin and the web scanner's audit phase assess TLS
through the one wrapper here, so the two paths cannot drift apart on what
"weak cipher" means (CLAUDE.md: there is one TLS engine; do not add a second).
It imports no application code, only sslyze and cryptography.

It lived in ``core/web/sslyze/`` until B9 of the module-independence plan, so
the network scan could not run without the web module; the old path is an alias
of the same module (``core/web/sslyze/wrapper.py``).
"""
