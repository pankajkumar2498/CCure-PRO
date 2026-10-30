"""
core/web/oast/client.py
────────────────────────────────────────────────────────────────────────────
OAST poll clients (Phase 9).

The collaborator records interactions; the client retrieves them so the session
can correlate. Two implementations behind one shape (``poll(since) -> list``):

  • ``HttpOastClient`` — polls a self-hosted collaborator's reserved
    ``/_ccure_oast/interactions`` endpoint over HTTP, with an optional bearer.
    This is the production path and the one the end-to-end test exercises.

  • ``LocalOastClient`` — reads straight from an in-process ``OastReceiver``'s
    inbox, for a receiver CCure runs itself (no network hop) and for unit
    tests of correlation.

``build_oast`` assembles a session + client from configuration. It never
selects the public interact.sh: CCure's own active OOB probes run only against
a collaborator the operator controls, so a scan with no self-hosted server
simply does not run them (and says so) rather than shipping target callbacks to
a third party.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Tuple
from urllib.parse import urlparse

log = logging.getLogger("ccure.web.oast.client")


class HttpOastClient:
    def __init__(
        self,
        control_url: str,
        *,
        auth_token: str = "",
        verify_tls: bool = False,
        timeout: float = 10.0,
    ) -> None:
        self.control_url = control_url.rstrip("/") + "/"
        self.auth_token = auth_token or ""
        self.verify_tls = verify_tls
        self.timeout = timeout

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}

    def is_available(self) -> bool:
        try:
            import httpx  # noqa: F401
        except Exception:
            return False
        try:
            import httpx

            with httpx.Client(verify=self.verify_tls, timeout=self.timeout) as c:
                r = c.get(self.control_url + "health", headers=self._headers())
                return r.status_code == 200
        except Exception as exc:
            log.debug("OAST collaborator health check failed: %s", exc)
            return False

    def poll(self, since: float = 0.0) -> List[dict]:
        try:
            import httpx

            with httpx.Client(verify=self.verify_tls, timeout=self.timeout) as c:
                r = c.get(
                    self.control_url + "interactions",
                    params={"since": since},
                    headers=self._headers(),
                )
                if r.status_code != 200:
                    return []
                return list(r.json().get("interactions", []))
        except Exception as exc:
            log.debug("OAST poll failed: %s", exc)
            return []


class LocalOastClient:
    """Reads interactions straight from an in-process receiver's inbox."""

    def __init__(self, receiver) -> None:
        self._receiver = receiver

    def is_available(self) -> bool:
        return self._receiver is not None

    def poll(self, since: float = 0.0) -> List[dict]:
        return self._receiver.inbox.since(since)


def build_oast(scan_id: Optional[str] = None) -> Optional[Tuple["object", "object"]]:
    """
    Build (OastSession, client) from the web settings, or None when active OOB
    probing is not configured.

    Returns None — meaning "the scan will not actively probe blind classes" —
    unless a self-hosted collaborator is configured. Never falls back to the
    public interact.sh for CCure's own probes.
    """
    from core.web import settings as web_settings
    from core.web.oast.session import OastSession

    if not getattr(web_settings.current(), "OAST_ENABLED", False):
        return None
    if not getattr(web_settings.current(), "OAST_ACTIVE_PROBES", True):
        return None

    server = (getattr(web_settings.current(), "OAST_SERVER", "") or "").strip()
    domain = (getattr(web_settings.current(), "OAST_DOMAIN", "") or "").strip()
    http_url = (getattr(web_settings.current(), "OAST_HTTP_URL", "") or "").strip()
    token = (getattr(web_settings.current(), "OAST_TOKEN", "") or "").strip()

    # A self-hosted collaborator must be identifiable. Prefer an explicit
    # control URL / domain; otherwise derive from OAST_SERVER.
    if not (server or domain or http_url):
        return None

    if not domain and server:
        domain = urlparse(server if "://" in server else f"//{server}").netloc or server
        domain = domain.split(":")[0]

    # Control URL for polling: explicit http_url base, else the server URL.
    control_base = http_url or (server if "://" in server else f"http://{server}")
    if not control_base:
        return None
    control_url = control_base.rstrip("/") + "/_ccure_oast/"

    session = OastSession(base_domain=domain, http_base_url=http_url, scan_id=scan_id)
    client = HttpOastClient(control_url, auth_token=token)
    return session, client
