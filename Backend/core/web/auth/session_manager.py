"""
core/web/auth/session_manager.py
────────────────────────────────────────────────────────────────────────────
Authentication & session management for authenticated web scanning.

Handles:
  - Form-based login (username/password submit)
  - Cookie-based session management
  - Bearer token / API key header injection
  - Session health monitoring (detect logout / session expiry)
  - Redis-backed session state caching for multi-phase scans
"""

import json
import logging
import time
from typing import Dict, List, Optional

log = logging.getLogger("ccure.web.auth")


class WebSessionManager:
    """
    Manages authentication state for web scans across all pipeline phases.

    Sessions are stored in Redis so they survive Celery worker restarts
    and can be shared between different scan phases (crawl → detect → audit).

    Usage:
        mgr = WebSessionManager(redis_client)
        session = await mgr.authenticate(
            auth_config={"type": "form_login", "login_url": "...", ...},
            scan_id="wsc_...",
        )
        # Use session in subsequent tool calls
        headers = session.get_auth_headers()
        cookies = session.get_cookies()
    """

    # Redis key TTL for session data (4 hours — matches max scan duration)
    SESSION_TTL = 14400

    def __init__(self, redis_client=None):
        self._redis = redis_client

    async def authenticate(
        self,
        auth_config: dict,
        scan_id: str,
    ) -> "WebSession":
        """
        Authenticate to the target application.

        Supported auth types:
          - form_login: Submit credentials to a login form
          - bearer_token: Static bearer token (API key)
          - cookie: Static cookie values
          - custom_header: Custom HTTP header

        Args:
            auth_config: Authentication configuration
            scan_id: Web scan ID for session key

        Returns:
            WebSession with auth state
        """
        auth_type = auth_config.get("type", "none")

        if auth_type == "none":
            log.info("No authentication configured for scan %s", scan_id)
            return WebSession(scan_id=scan_id)

        if auth_type == "bearer_token":
            return self._create_bearer_session(auth_config, scan_id)

        if auth_type == "cookie":
            return self._create_cookie_session(auth_config, scan_id)

        if auth_type == "custom_header":
            return self._create_header_session(auth_config, scan_id)

        if auth_type == "form_login":
            return await self._form_login(auth_config, scan_id)

        log.warning("Unknown auth type '%s' for scan %s", auth_type, scan_id)
        return WebSession(scan_id=scan_id)

    def _create_bearer_session(self, config: dict, scan_id: str) -> "WebSession":
        """Create session with static bearer token."""
        token = config.get("token", "")
        session = WebSession(
            scan_id=scan_id,
            headers={"Authorization": f"Bearer {token}"},
            auth_type="bearer_token",
        )
        self._save_session(session)
        return session

    def _create_cookie_session(self, config: dict, scan_id: str) -> "WebSession":
        """Create session with static cookies."""
        cookies = config.get("cookies", {})
        session = WebSession(
            scan_id=scan_id,
            cookies=cookies,
            auth_type="cookie",
        )
        self._save_session(session)
        return session

    def _create_header_session(self, config: dict, scan_id: str) -> "WebSession":
        """Create session with custom headers."""
        headers = config.get("headers", {})
        session = WebSession(
            scan_id=scan_id,
            headers=headers,
            auth_type="custom_header",
        )
        self._save_session(session)
        return session

    async def _form_login(self, config: dict, scan_id: str) -> "WebSession":
        """
        Perform form-based login using httpx.

        Config expected:
          {
            "type": "form_login",
            "login_url": "https://example.com/login",
            "username_field": "email",
            "password_field": "password",
            "username": "testuser",
            "password": "testpass",
            "success_indicator": "Dashboard",
            "method": "POST"
          }
        """
        login_url = config.get("login_url", "")
        username = config.get("username", "")
        password = config.get("password", "")
        username_field = config.get("username_field", "username")
        password_field = config.get("password_field", "password")
        success_indicator = config.get("success_indicator", "")
        method = config.get("method", "POST").upper()

        if not login_url or not username:
            log.warning("Incomplete form_login config for scan %s", scan_id)
            return WebSession(
                scan_id=scan_id, auth_error="Incomplete login configuration"
            )

        try:
            import httpx

            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=30.0,
            ) as client:
                form_data = {
                    username_field: username,
                    password_field: password,
                }

                if method == "POST":
                    resp = await client.post(login_url, data=form_data)
                else:
                    resp = await client.get(login_url, params=form_data)

                # Check for success
                is_success = resp.status_code in (200, 302, 303)
                if success_indicator:
                    is_success = (
                        is_success and success_indicator.lower() in resp.text.lower()
                    )

                if not is_success:
                    log.warning(
                        "Form login failed for scan %s (status=%d)",
                        scan_id,
                        resp.status_code,
                    )
                    return WebSession(
                        scan_id=scan_id,
                        auth_error=f"Login failed with status {resp.status_code}",
                    )

                # Extract cookies from response
                cookies = dict(resp.cookies)

                # Check for Set-Cookie headers
                session_cookies = {}
                for cookie_header in resp.headers.get_list("set-cookie"):
                    parts = cookie_header.split(";")[0]
                    if "=" in parts:
                        name, value = parts.split("=", 1)
                        session_cookies[name.strip()] = value.strip()

                all_cookies = {**cookies, **session_cookies}

                session = WebSession(
                    scan_id=scan_id,
                    cookies=all_cookies,
                    auth_type="form_login",
                    login_url=login_url,
                )

                self._save_session(session)
                log.info(
                    "Form login successful for scan %s (%d cookies)",
                    scan_id,
                    len(all_cookies),
                )
                return session

        except ImportError:
            log.error("httpx not installed — form login unavailable")
            return WebSession(scan_id=scan_id, auth_error="httpx not installed")
        except Exception as exc:
            log.warning("Form login error for scan %s: %s", scan_id, exc)
            return WebSession(scan_id=scan_id, auth_error=str(exc))

    def _save_session(self, session: "WebSession") -> None:
        """Persist session state to Redis."""
        if not self._redis:
            return
        try:
            key = f"webscan:session:{session.scan_id}"
            self._redis.setex(key, self.SESSION_TTL, json.dumps(session.to_dict()))
        except Exception as exc:
            log.debug("Failed to save session to Redis: %s", exc)

    def load_session(self, scan_id: str) -> Optional["WebSession"]:
        """Load session state from Redis."""
        if not self._redis:
            return None
        try:
            key = f"webscan:session:{scan_id}"
            data = self._redis.get(key)
            if data:
                return WebSession.from_dict(json.loads(data), scan_id)
        except Exception as exc:
            log.debug("Failed to load session from Redis: %s", exc)
        return None


class WebSession:
    """
    Represents an authenticated web scan session.

    Provides auth headers and cookies for use by detection tools.
    """

    def __init__(
        self,
        scan_id: str,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        auth_type: str = "none",
        login_url: str = "",
        auth_error: str = "",
    ):
        self.scan_id = scan_id
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.auth_type = auth_type
        self.login_url = login_url
        self.auth_error = auth_error
        self.created_at = time.time()

    @property
    def is_authenticated(self) -> bool:
        return bool(self.headers or self.cookies) and not self.auth_error

    def get_auth_headers(self) -> dict[str, str]:
        """Get all auth headers including cookie header."""
        result = dict(self.headers)
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            result["Cookie"] = cookie_str
        return result

    def get_cookies(self) -> dict[str, str]:
        return dict(self.cookies)

    def get_cookies_for_playwright(self) -> list[dict]:
        """Format cookies for Playwright's add_cookies API."""
        from urllib.parse import urlparse

        domain = ""
        if self.login_url:
            domain = urlparse(self.login_url).hostname or ""

        return [
            {"name": k, "value": v, "domain": domain, "path": "/"}
            for k, v in self.cookies.items()
        ]

    def to_dict(self) -> dict:
        return {
            "headers": self.headers,
            "cookies": self.cookies,
            "auth_type": self.auth_type,
            "login_url": self.login_url,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict, scan_id: str) -> "WebSession":
        session = cls(
            scan_id=scan_id,
            headers=data.get("headers", {}),
            cookies=data.get("cookies", {}),
            auth_type=data.get("auth_type", "none"),
            login_url=data.get("login_url", ""),
        )
        session.created_at = data.get("created_at", time.time())
        return session
