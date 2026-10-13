"""
A forked process never talks to PostgreSQL over its parent's connection.

The scanner worker and the web worker run Celery's prefork pool. Whatever the
parent connected before it forked sits in an engine's pool, and every child
inherits the same socket. ``core/utils.py`` probes the vulnerability-intel
database at import, so the parent always has one. Two children using it at once
interleave two protocol streams on one connection: psycopg2 reports "error with
status PGRES_TUPLES_OK and no message from the libpq" or "insufficient data in
"D" message", the package matcher logs a warning, and the host is reported with
no package findings.

Measured on 13 Oct 2026: a credentialed audit of an Ubuntu 24.04 host returned
0 CVEs from 2,699 packages while a Windows audit ran beside it, and a single
``vuln_intel`` connection was open in all 19 scanner-worker processes and all 5
web-worker processes. The Windows deployment never saw this because its worker
ran ``--pool=threads`` and did not fork.

``Engine.dispose(close=False)`` is SQLAlchemy's documented answer for a child
process: it gives the child an empty pool and drops the inherited connections
without closing them, since closing would send a Terminate down the socket the
parent and the other children still hold. A checkout-time PID check is not
enough here: ``pool_pre_ping`` pings the inherited connection before any
checkout listener runs, and that ping is itself the concurrent use.
"""

from __future__ import annotations

import os

from sqlalchemy.engine import Engine


def release_pool_after_fork(engine: Engine) -> Engine:
    """Give every process forked after this call a fresh pool for ``engine``."""
    os.register_at_fork(after_in_child=lambda: engine.dispose(close=False))
    return engine
