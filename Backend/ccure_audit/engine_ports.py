"""
What the scan engines are handed, registered (G3,
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

* The Nmap wrapper's shared state: the global process limiter's Redis lease and
  the result cache's Redis client (``core.redis_client``). Without them the
  wrapper falls back to its local semaphore and no cache, as it always did when
  Redis could not be reached.
* The credentialed version matcher's CVE repository: the vulnerability-
  intelligence database (``core/vuln_intel_repository.py``).

Registered here, not by the engines or by the infrastructure they use, so that
what Audit plugs into what is said in its composition root, as the host
directory and the evidence providers are. Loaded by name in every process that
scans: ``core/celery_app.py`` names it in Celery's ``imports``, which the worker
loads at start-up, and ``main.py`` loads through the same call.
"""

from __future__ import annotations

from core import redis_client
from core.nmap import wrapper as nmap_wrapper
from core.vuln_intel_repository import REPOSITORY
from engines.credentialed.vuln_matcher import register_cve_repository


def _lease_client():
    return redis_client.connect_nmap_lease_client()


def _cache_client():
    # Looked up at each call, so a test that replaces get_redis_client is
    # honoured as it was when the wrapper imported it.
    return redis_client.get_redis_client()


nmap_wrapper.register_shared_state(
    lease_client=_lease_client, cache_client=_cache_client
)
register_cve_repository(REPOSITORY)
