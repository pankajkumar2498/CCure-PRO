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
        Perform a login and capture whatever credential it issues.

        Config expected:
          {
            "type": "form_login",
            "login_url": "https://example.com/login",
            "username_field": "email",
            "password_field": "password",
            "username": "testuser",
            "password": "testpass",
            "success_indicator": "Dashboard",   # optional
            "content_type": "auto",             # auto | form | json
            "token_path": "authentication.token",  # optional, else auto-detected
            "extra_fields": {},                 # optional additional body fields
            "method": "POST"
          }

        Two assumptions in the original implementation made authenticated
        scanning fail silently against most modern applications, and both are
        corrected here.

        A session is not always a cookie. Applications with a JSON API answer a
        login with a bearer token in the response body and set no cookie at all.
        Looking only for cookies found nothing, the session was reported
        unauthenticated, and the scan continued as an anonymous user — so every
        authenticated area went untested and was reported as though it had been
        assessed.

        A 200 is not proof of a login. An application that re-renders the login
        page after rejecting the credentials answers 200, which was read as
        success. Success is now established by evidence: a credential was
        issued, or an explicitly configured success indicator was present.
        """
        login_url = config.get("login_url", "")
        username = config.get("username", "")
        password = config.get("password", "")
        username_field = config.get("username_field", "username")
        password_field = config.get("password_field", "password")
        success_indicator = config.get("success_indicator", "")
        content_type = str(config.get("content_type", "auto")).lower()
        method = config.get("method", "POST").upper()

        if not login_url or not username:
            log.warning("Incomplete form_login config for scan %s", scan_id)
            return WebSession(
                scan_id=scan_id, auth_error="Incomplete login configuration"
            )

        payload = {username_field: username, password_field: password}
        payload.update(config.get("extra_fields") or {})

        try:
            import httpx

            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=30.0,
            ) as client:
                attempts = (
                    ["json", "form"]
                    if content_type == "auto"
                    else [content_type if content_type in ("json", "form") else "form"]
                )

                resp = None
                last_error = ""
                for encoding in attempts:
                    if method == "GET":
                        resp = await client.get(login_url, params=payload)
                    elif encoding == "json":
                        resp = await client.post(login_url, json=payload)
                    else:
                        resp = await client.post(login_url, data=payload)

                    if resp.status_code < 400:
                        break
                    last_error = f"status {resp.status_code}"
                    log.debug(
                        "Login attempt (%s encoding) rejected with %d",
                        encoding,
                        resp.status_code,
                    )

                if resp is None:
                    return WebSession(
                        scan_id=scan_id, auth_error="Login request was not sent"
                    )

                cookies = self._collect_cookies(resp)
                token = self._extract_token(resp, config.get("token_path"))

                indicator_matched = bool(
                    success_indicator
                    and success_indicator.lower() in (resp.text or "").lower()
                )

                if resp.status_code >= 400:
                    return WebSession(
                        scan_id=scan_id,
                        auth_error=(
                            f"Login rejected by the application ({last_error}). "
                            f"Check the credentials and the field names in the "
                            f"scan's authentication settings."
                        ),
                    )

                if not (cookies or token or indicator_matched):
                    # Everything below this point would run as an anonymous
                    # user. Failing here — loudly — is the only way that fact
                    # reaches the report instead of being inferred from an
                    # unexplained absence of findings.
                    return WebSession(
                        scan_id=scan_id,
                        auth_error=(
                            "Login returned "
                            f"{resp.status_code} but issued no session cookie and "
                            "no recognisable token, so the scan could not be "
                            "authenticated. If this application signals login "
                            "another way, set success_indicator or token_path in "
                            "the authentication settings."
                        ),
                    )

                headers = {}
                if token:
                    header_name = config.get("token_header") or "Authorization"
                    prefix = config.get("token_prefix")
                    if prefix is None:
                        prefix = "Bearer "
                    headers[header_name] = f"{prefix}{token}"

                session = WebSession(
                    scan_id=scan_id,
                    headers=headers,
                    cookies=cookies,
                    auth_type="form_login",
                    login_url=login_url,
                )

                self._save_session(session)
                log.info(
                    "Login successful for scan %s (%d cookie(s), token=%s)",
                    scan_id,
                    len(cookies),
                    "yes" if token else "no",
                )
                return session

        except ImportError:
            log.error("httpx not installed — form login unavailable")
            return WebSession(scan_id=scan_id, auth_error="httpx not installed")
        except Exception as exc:
            log.warning("Form login error for scan %s: %s", scan_id, exc)
            return WebSession(scan_id=scan_id, auth_error=str(exc))

    @staticmethod
    def _collect_cookies(resp) -> dict[str, str]:
        """Every cookie the login exchange produced, including via redirects."""
        cookies = dict(resp.cookies)
        try:
            for cookie_header in resp.headers.get_list("set-cookie"):
                pair = cookie_header.split(";")[0]
                if "=" in pair:
                    name, value = pair.split("=", 1)
                    if name.strip():
                        cookies[name.strip()] = value.strip()
        except Exception:
            pass
        return cookies

    #: Response keys that hold a bearer credential across common frameworks.
    _TOKEN_KEYS = (
        "token",
        "access_token",
        "accesstoken",
        "id_token",
        "jwt",
        "auth_token",
        "authtoken",
        "session_token",
        "api_key",
    )

    @classmethod
    def _extract_token(cls, resp, token_path: str | None = None) -> str | None:
        """
        Pull a bearer credential out of a login response.

        ``token_path`` addresses it explicitly ("authentication.token"). Without
        one, the response is searched for the key names frameworks conventionally
        use, because requiring the operator to know the shape of their login
        response in advance is how authenticated scanning ends up unconfigured.
        """
        try:
            body = resp.json()
        except Exception:
            return None

        if token_path:
            node = body
            for part in str(token_path).split("."):
                if isinstance(node, dict) and part in node:
                    node = node[part]
                else:
                    node = None
                    break
            if isinstance(node, str) and node.strip():
                return node.strip()
            log.warning(
                "token_path '%s' did not resolve in the login response", token_path
            )

        def _search(node, depth=0):
            if depth > 4 or not isinstance(node, dict):
                return None
            for key, value in node.items():
                if (
                    key.lower() in cls._TOKEN_KEYS
                    and isinstance(value, str)
                    and len(value.strip()) >= 8
                ):
                    return value.strip()
            for value in node.values():
                found = _search(value, depth + 1)
                if found:
                    return found
            return None

        return _search(body)

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

    def get_cookies_for_playwright(self, target_url: str = "") -> list[dict]:
        """
        Format cookies for Playwright's add_cookies API.

        Playwright rejects a cookie that has neither a url nor a domain, and
        rejects the whole batch — so one cookie without a domain aborted the
        authenticated crawl entirely. That happened for every auth type except
        form_login, since only form_login sets login_url. Scoping by url avoids
        having to derive a domain at all, and the scan target is used when the
        session itself does not know where it came from.
        """
        from urllib.parse import urlparse

        origin = ""
        for candidate in (self.login_url, target_url):
            parsed = urlparse(candidate or "")
            if parsed.scheme and parsed.netloc:
                origin = f"{parsed.scheme}://{parsed.netloc}"
                break

        if not origin:
            log.warning(
                "No origin available for session cookies — they cannot be scoped "
                "to a domain and are not being applied to the crawl"
            )
            return []

        return [
            {"name": k, "value": v, "url": origin} for k, v in self.cookies.items() if k
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
