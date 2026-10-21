"""
Moved to ``engines/tls/wrapper.py`` (B9 of the module-independence plan).

It is the TLS engine both the network checks and the web scanner use, and under
``core.web`` the network scan could not run without the web module.

This path is an alias of the **same module object**, not a copy and not a star
re-export: every existing import, private name, ``isinstance`` check and
``patch.object`` target behaves exactly as before. New code imports from
``engines.tls.wrapper``.
"""

import sys

from engines.tls import wrapper as _module

sys.modules[__name__] = _module
