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

import base64
import hashlib
import hmac
import json
import logging
import re
import struct
import time
from typing import Optional
from urllib.parse import urljoin, urlparse

log = logging.getLogger("ccure.web.auth")


def _totp_now(secret: str, digits: int = 6, period: int = 30) -> str:
    """
    A current RFC 6238 TOTP code from a base32 shared secret, using only the
    standard library (SHA-1, the near-universal default). This lets a scan drive
    an MFA/OTP screen with the same shared secret an authenticator app holds,
    rather than a code that expires in seconds and cannot be pre-supplied.
    """
    key = base64.b32decode(re.sub(r"\s", "", secret).upper() + "=" * (-len(secret) % 8))
    counter = int(time.time()) // period
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (
        10**digits
    )
    return str(code).zfill(digits)


#: Hidden-field names conventionally used for anti-CSRF / anti-forgery tokens.
#: Extracting these is what makes CSRF-protected form logins (DVWA's
#: ``user_token``, Django's ``csrfmiddlewaretoken``, Rails'
#: ``authenticity_token``, ASP.NET's ``__RequestVerificationToken``) work — the
#: token is bound to the session cookie set when the login page is fetched, so
#: it must be read from that page and submitted on the same session.
_CSRF_FIELD_NAMES = {
    "csrf_token",
    "csrftoken",
    "_csrf",
    "_csrf_token",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "__requestverificationtoken",
    "user_token",
    "_token",
    "xsrf",
    "xsrf_token",
    "anti_csrf",
    "nonce",
}

_INPUT_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE | re.DOTALL)
_ATTR_RE = re.compile(
    r"""(\w[\w:-]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))""", re.IGNORECASE
)
_META_CSRF_RE = re.compile(
    r"""<meta\b[^>]*\bname\s*=\s*["']?(?:csrf-token|csrf_token|_csrf)["']?[^>]*"""
    r"""\bcontent\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE | re.DOTALL,
)

#: Signals a response is (or has redirected to) a login/unauthenticated page.
_LOGIN_MARKERS = (
    "please log in",
    "please login",
    "sign in to continue",
    "login failed",
    "invalid credentials",
    "authentication required",
    "session expired",
    "your session has expired",
    "you must be logged in",
)


def _input_attrs(tag: str) -> dict:
    attrs = {}
    for m in _ATTR_RE.finditer(tag):
        name = m.group(1).lower()
        value = (
            m.group(3)
            if m.group(3) is not None
            else (m.group(4) if m.group(4) is not None else (m.group(5) or ""))
        )
        attrs[name] = value
    return attrs


def _inspect_jwt(token: str):
    """
    Validate a JWT's shape and read its ``exp`` claim without verifying the
    signature (the scanner is the client, not the resource server).

    Returns (shape_ok, exp_or_None). Best-effort: a token that parses but has no
    exp returns (True, None).
    """
    import base64
    import json as _json

    if not token or token.count(".") != 2:
        return False, None
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # pad base64url
        payload = _json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
    except Exception:
        return False, None
    exp = payload.get("exp") if isinstance(payload, dict) else None
    try:
        exp = float(exp) if exp is not None else None
    except (TypeError, ValueError):
        exp = None
    return True, exp


def extract_form_tokens(
    html: str, csrf_field: str | None = None, extract_hidden: bool = True
) -> dict[str, str]:
    """
    Pull anti-CSRF / hidden form fields out of a login page.

    Returns a ``{field_name: value}`` mapping to merge into the login body.
    ``csrf_field`` names the token field explicitly; otherwise every hidden
    input is captured (``extract_hidden``) plus any field whose name matches a
    conventional CSRF name, plus a ``<meta name="csrf-token">`` value under its
    documented field name. Regex-based on purpose: no HTML parser dependency,
    and a login page is simple enough that this is reliable.
    """
    fields: dict[str, str] = {}
    if not html:
        return fields
    for tag in _INPUT_RE.findall(html):
        attrs = _input_attrs(tag)
        name = attrs.get("name")
        if not name:
            continue
        itype = (attrs.get("type") or "text").lower()
        value = attrs.get("value", "")
        if csrf_field and name == csrf_field:
            fields[name] = value
        elif extract_hidden and itype == "hidden":
            fields[name] = value
        elif name.lower() in _CSRF_FIELD_NAMES:
            fields[name] = value
        elif extract_hidden and itype == "submit" and value:
            # Many login handlers only process the form when the submit
            # button's field is present (DVWA's `Login`, classic PHP
            # `if(isset($_POST['Login']))`). Carrying it makes those logins
            # work without hand-configured extra_fields.
            fields[name] = value
    meta = _META_CSRF_RE.search(html)
    if meta and csrf_field and csrf_field not in fields:
        fields[csrf_field] = meta.group(1)
    return fields


def looks_like_login_page(text: str, url: str, config: dict) -> bool:
    """
    Whether a response looks unauthenticated — a redirect to login, an explicit
    failure indicator, or a recognisable login form / login marker.

    Used both to reject a failed login and to detect session loss mid-crawl. A
    configured ``failure_indicator`` is authoritative; the heuristics only fire
    when nothing was configured, to avoid guessing on a well-configured scan.
    """
    text_low = (text or "").lower()
    url_low = (url or "").lower()

    failure = (config or {}).get("failure_indicator")
    if failure and failure.lower() in text_low:
        return True

    login_url = (config or {}).get("login_url") or ""
    login_path = urlparse(login_url).path.lower() if login_url else ""
    if login_path and len(login_path) > 1 and login_path in url_low:
        return True
    if any(seg in url_low for seg in ("/login", "/signin", "/sign-in", "/auth/login")):
        return True

    if any(marker in text_low for marker in _LOGIN_MARKERS):
        return True
    return False


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
        # Per-scan re-authentication counter, so a lost session can be
        # re-established a bounded number of times and never in a loop.
        self._reauth_used: dict[str, int] = {}

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

        # A configured `login_steps` list is a multi-step workflow whatever the
        # declared type, so it takes precedence.
        if auth_config.get("login_steps"):
            session = await self._multi_step_login(auth_config, scan_id)
        elif auth_type == "none":
            log.info("No authentication configured for scan %s", scan_id)
            session = WebSession(scan_id=scan_id)
        elif auth_type == "bearer_token":
            session = self._create_bearer_session(auth_config, scan_id)
        elif auth_type == "jwt":
            session = self._create_jwt_session(auth_config, scan_id)
        elif auth_type == "api_key":
            session = self._create_api_key_session(auth_config, scan_id)
        elif auth_type == "oauth2":
            session = await self._oauth2_token_session(auth_config, scan_id)
        elif auth_type in ("oauth2_authcode", "oidc", "saml"):
            # Browser-driven redirect login: OAuth2 auth-code / OIDC / SAML
            # SP-initiated are one mechanism (drive the IdP form, capture the
            # returned app session).
            session = await self._oauth2_authcode_browser(auth_config, scan_id)
        elif auth_type == "recorded":
            # Replay a recorded browser login sequence and capture the session.
            session = await self._recorded_login(auth_config, scan_id)
        elif auth_type == "cookie":
            session = self._create_cookie_session(auth_config, scan_id)
        elif auth_type == "custom_header":
            session = self._create_header_session(auth_config, scan_id)
        elif auth_type in ("form_login", "multi_step"):
            session = (
                await self._multi_step_login(auth_config, scan_id)
                if auth_type == "multi_step"
                else await self._form_login(auth_config, scan_id)
            )
        else:
            log.warning("Unknown auth type '%s' for scan %s", auth_type, scan_id)
            session = WebSession(scan_id=scan_id)

        # Custom headers are additive to every auth type: an application may
        # need a bearer token *and* a tenant/API-version header, or a cookie
        # session *and* an anti-CSRF header echoed on each request.
        extra_headers = auth_config.get("headers")
        if isinstance(extra_headers, dict) and session.is_authenticated:
            session.headers.update({k: v for k, v in extra_headers.items() if k})
            self._save_session(session)

        return session

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

    def _create_jwt_session(self, config: dict, scan_id: str) -> "WebSession":
        """
        Static JWT bearer session (Phase 23). Validates the JWT shape and reads
        its ``exp`` claim (no signature verification — the scanner is the
        client, not the resource server) so an expired token is flagged rather
        than silently producing a whole scan of 401s that reads as "clean".
        """
        token = (config.get("token") or config.get("jwt") or "").strip()
        header_name = config.get("header", "Authorization")
        prefix = config.get("prefix", "Bearer ")
        auth_error = ""
        shape_ok, exp = _inspect_jwt(token)
        if not shape_ok:
            auth_error = "Configured JWT is not a well-formed token (expected 3 dot-separated parts)."
        elif exp is not None and exp < time.time():
            auth_error = (
                f"Configured JWT expired at {int(exp)} (before the scan started); "
                f"it will be rejected. Supply a current token."
            )
        session = WebSession(
            scan_id=scan_id,
            headers={header_name: f"{prefix}{token}"} if token else {},
            auth_type="jwt",
            auth_error=auth_error,
        )
        self._save_session(session)
        return session

    def _create_api_key_session(self, config: dict, scan_id: str) -> "WebSession":
        """
        API-key header session (Phase 23). The key is sent in a configurable
        header (default ``X-API-Key``); an optional ``prefix`` supports schemes
        like ``ApiKey <key>``. Header-based only, which is the common case and
        fits the header/cookie session model.
        """
        key = (
            config.get("key") or config.get("value") or config.get("token") or ""
        ).strip()
        header_name = config.get("header", "X-API-Key")
        prefix = config.get("prefix", "")
        session = WebSession(
            scan_id=scan_id,
            headers={header_name: f"{prefix}{key}"} if key else {},
            auth_type="api_key",
            auth_error="" if key else "No API key value configured.",
        )
        self._save_session(session)
        return session

    async def _oauth2_token_session(self, config: dict, scan_id: str) -> "WebSession":
        """
        OAuth 2.0 token-endpoint session (Phase 23).

        Obtains an access token from the configured token endpoint using the
        automatable grants — ``client_credentials`` and ``password`` — then uses
        it as a bearer token. The browser-redirect grants (authorization_code /
        OIDC / SAML) need IdP automation and are a separate follow-on; this
        covers what most API scanning uses (Acunetix/Invicti list OAuth 2.0,
        bearer and JWT as first-class API auth).
        """
        token_url = (config.get("token_url") or "").strip()
        grant = (config.get("grant_type") or "client_credentials").strip()
        if not token_url:
            return WebSession(
                scan_id=scan_id,
                auth_type="oauth2",
                auth_error="oauth2 requires token_url.",
            )
        data = {"grant_type": grant}
        for k in ("client_id", "client_secret", "scope", "audience"):
            if config.get(k):
                data[k] = config[k]
        if grant == "password":
            data["username"] = config.get("username", "")
            data["password"] = config.get("password", "")
        token_field = config.get("token_field", "access_token")
        try:
            import httpx

            async with httpx.AsyncClient(
                verify=False, timeout=30.0, follow_redirects=True
            ) as client:
                resp = await client.post(token_url, data=data)
                body = {}
                try:
                    body = resp.json()
                except Exception:
                    body = {}
                token = body.get(token_field)
                if resp.status_code >= 400 or not token:
                    return WebSession(
                        scan_id=scan_id,
                        auth_type="oauth2",
                        auth_error=(
                            f"OAuth2 token request to {token_url} failed "
                            f"(HTTP {resp.status_code}); no '{token_field}' returned."
                        ),
                    )
        except Exception as exc:
            return WebSession(
                scan_id=scan_id,
                auth_type="oauth2",
                auth_error=f"OAuth2 token request errored: {type(exc).__name__}.",
            )
        session = WebSession(
            scan_id=scan_id,
            headers={"Authorization": f"Bearer {token}"},
            auth_type="oauth2",
        )
        self._save_session(session)
        return session

    async def _oauth2_authcode_browser(
        self, config: dict, scan_id: str
    ) -> "WebSession":
        """
        Browser-driven redirect login (Phase 23): OAuth2 authorization_code /
        OIDC / SAML SP-initiated.

        From the scanner's point of view these are one mechanism: navigate the
        app's login start, follow the redirect to the identity provider, fill
        and submit the IdP login form, follow the callback back to the app, and
        capture the resulting authenticated session cookies. Field selectors are
        configurable with sensible defaults; success is confirmed by a text
        indicator and/or the post-login URL, and a flow that captures no session
        records an auth_error rather than proceeding unauthenticated.

        Real IdPs are rarely a single username+password+submit page, so the flow
        handles three common extra screens, each best-effort and skipped when its
        field is absent (so a plain one-page login still works unchanged):

          • **Identifier-first** (Microsoft/Google/Okta): username, a *Next*
            button, then password on a second screen. Driven by
            ``idp_next_submit`` — when set, the password field is filled after
            that click.
          • **MFA / OTP**: a one-time-code screen after the password. Driven by
            ``idp_mfa_field`` plus either a static ``mfa_code`` or a
            ``totp_secret`` (RFC 6238 TOTP is generated with the standard
            library — no new dependency).
          • **Consent / authorize**: an OAuth consent screen with an
            *Allow/Authorize/Continue* button before the callback. Driven by
            ``idp_consent_submit``.
        """
        start_url = config.get("start_url") or config.get("login_url")
        if not start_url:
            return WebSession(
                scan_id=scan_id,
                auth_type=config.get("type", "oauth2_authcode"),
                auth_error="Browser redirect login requires start_url (or login_url).",
            )
        user = config.get("username", "")
        pw = config.get("password", "")
        u_sel = config.get(
            "idp_username_field",
            "input[name='username'], input[type='email'], input[name='email'], #username",
        )
        p_sel = config.get(
            "idp_password_field",
            "input[name='password'], input[type='password'], #password",
        )
        submit_sel = config.get(
            "idp_submit", "button[type='submit'], input[type='submit'], button"
        )
        next_sel = config.get("idp_next_submit")  # identifier-first "Next"
        mfa_sel = config.get("idp_mfa_field")  # OTP/MFA code field
        consent_sel = config.get("idp_consent_submit")  # consent/authorize button
        mfa_code = self._resolve_mfa_code(config)
        success = config.get("success_indicator")
        success_url = config.get("success_url_contains")
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return WebSession(
                scan_id=scan_id,
                auth_type=config.get("type", "oauth2_authcode"),
                auth_error="Playwright not installed — browser redirect login unavailable.",
            )
        content = ""
        final_url = ""
        cookies: dict[str, str] = {}
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
                )
                ctx = await browser.new_context(ignore_https_errors=True)
                page = await ctx.new_page()
                await page.goto(start_url, wait_until="domcontentloaded", timeout=30000)
                # The IdP login form may be the current page after the redirect.
                try:
                    await page.fill(u_sel, user, timeout=8000)
                    # Identifier-first: click Next and wait for the password screen
                    # before filling the password.
                    if next_sel:
                        await self._click_and_settle(page, next_sel)
                        await self._wait_for_selector(page, p_sel)
                    await page.fill(p_sel, pw, timeout=8000)
                    await self._click_and_settle(page, submit_sel)
                    # MFA / OTP screen: fill the code and submit, best-effort.
                    if (
                        mfa_sel
                        and mfa_code
                        and await self._selector_ready(page, mfa_sel)
                    ):
                        await page.fill(mfa_sel, mfa_code, timeout=8000)
                        await self._click_and_settle(page, submit_sel)
                    # OAuth consent / authorize screen before the callback.
                    if consent_sel and await self._selector_ready(page, consent_sel):
                        await self._click_and_settle(page, consent_sel)
                except Exception as exc:
                    log.debug("IdP form fill/submit issue: %s", exc)
                try:
                    content = await page.content()
                    final_url = page.url
                    cookies = {c["name"]: c["value"] for c in await ctx.cookies()}
                except Exception:
                    pass
                await browser.close()
        except Exception as exc:
            return WebSession(
                scan_id=scan_id,
                auth_type=config.get("type", "oauth2_authcode"),
                auth_error=f"Browser redirect login errored: {type(exc).__name__}.",
            )
        err = ""
        if success and success not in (content or ""):
            err = "Login success indicator not found after the redirect flow."
        elif success_url and success_url not in (final_url or ""):
            err = "Did not land on the expected post-login URL after the flow."
        elif not cookies:
            err = "No session cookies captured after the redirect login."
        session = WebSession(
            scan_id=scan_id,
            cookies=cookies,
            auth_type=config.get("type", "oauth2_authcode"),
            login_url=start_url,
            auth_error=err,
        )
        self._save_session(session)
        return session

    async def _recorded_login(self, config: dict, scan_id: str) -> "WebSession":
        """
        Replay a recorded login sequence in a browser and capture the resulting
        session (Codex item 6 — login recorder).

        A recorded login is the industry-standard way to authenticate an app whose
        login a scanner cannot script from a form alone — a SPA login, a wizard, a
        widget. The *recording* is produced in a browser (devtools/extension) and
        stored as an ordered list of DOM actions; this is the backend that
        *replays* it and captures the authenticated cookies (and, optionally,
        bearer tokens the app left in localStorage), exactly as ZAP's "recorded"
        auth and Burp's recorded login sequence do.

        ``recorded_steps`` is a list of ``{action, ...}``:
          goto {url}                     navigate
          fill {selector, value}         type into a field
          click {selector}               click a control (waits for settle)
          select {selector, value}       choose an <option>
          press {selector, value}        press a key (e.g. "Enter")
          wait {timeout}                 pause N ms
          wait_for {selector}            wait for an element to appear
        Success is confirmed by ``success_url_contains`` / ``success_indicator``;
        a run that captures no session records an auth_error rather than
        proceeding unauthenticated.
        """
        steps = config.get("recorded_steps") or []
        if not steps:
            return WebSession(
                scan_id=scan_id,
                auth_type="recorded",
                auth_error="Recorded login requires a non-empty recorded_steps list.",
            )
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return WebSession(
                scan_id=scan_id,
                auth_type="recorded",
                auth_error="Playwright not installed — recorded login unavailable.",
            )
        success = config.get("success_indicator")
        success_url = config.get("success_url_contains")
        ls_keys = config.get("capture_local_storage") or []
        content = ""
        final_url = ""
        cookies: dict[str, str] = {}
        tokens: dict[str, str] = {}
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
                )
                ctx = await browser.new_context(ignore_https_errors=True)
                page = await ctx.new_page()
                for step in steps:
                    if not isinstance(step, dict):
                        continue
                    try:
                        await self._play_step(page, step)
                    except Exception as exc:
                        log.debug(
                            "recorded step %s failed: %s", step.get("action"), exc
                        )
                try:
                    content = await page.content()
                    final_url = page.url
                    cookies = {c["name"]: c["value"] for c in await ctx.cookies()}
                    for k in ls_keys:
                        try:
                            val = await page.evaluate(
                                "(k) => window.localStorage.getItem(k)", k
                            )
                            if val:
                                tokens[k] = val
                        except Exception:
                            pass
                except Exception:
                    pass
                await browser.close()
        except Exception as exc:
            return WebSession(
                scan_id=scan_id,
                auth_type="recorded",
                auth_error=f"Recorded login errored: {type(exc).__name__}.",
            )
        err = ""
        if success and success not in (content or ""):
            err = "Login success indicator not found after the recorded sequence."
        elif success_url and success_url not in (final_url or ""):
            err = "Did not land on the expected post-login URL after the sequence."
        elif not cookies and not tokens:
            err = "No session captured after the recorded login."
        headers: dict[str, str] = {}
        # A captured localStorage bearer token is presented as Authorization so an
        # SPA that authenticates by token (not cookie) is still scanned as logged in.
        for k, v in tokens.items():
            if "token" in k.lower() or "jwt" in k.lower() or "auth" in k.lower():
                headers["Authorization"] = (
                    v if v.lower().startswith("bearer ") else f"Bearer {v}"
                )
                break
        session = WebSession(
            scan_id=scan_id,
            cookies=cookies,
            headers=headers,
            auth_type="recorded",
            auth_error=err,
        )
        self._save_session(session)
        return session

    @staticmethod
    async def _play_step(page, step: dict) -> None:
        """Execute one recorded-login DOM action."""
        action = str(step.get("action") or "").lower()
        sel = step.get("selector")
        val = step.get("value")
        timeout = int(step.get("timeout") or 8000)
        if action == "goto" and step.get("url"):
            await page.goto(step["url"], wait_until="domcontentloaded", timeout=30000)
        elif action == "fill" and sel is not None:
            await page.fill(sel, str(val or ""), timeout=timeout)
        elif action == "click" and sel is not None:
            await page.click(sel, timeout=timeout)
            try:
                await page.wait_for_load_state("networkidle", timeout=20000)
            except Exception:
                pass
        elif action == "select" and sel is not None:
            await page.select_option(sel, str(val or ""), timeout=timeout)
        elif action == "press" and sel is not None:
            await page.press(sel, str(val or "Enter"), timeout=timeout)
        elif action == "wait":
            await page.wait_for_timeout(timeout)
        elif action == "wait_for" and sel is not None:
            await page.wait_for_selector(sel, timeout=timeout, state="visible")

    # ── browser-redirect helpers (MFA / consent / identifier-first) ───────────
    @staticmethod
    async def _click_and_settle(page, selector: str) -> None:
        """Click a selector and wait for the page to settle, tolerating a screen
        that does not trigger a full navigation (SPA IdPs)."""
        try:
            await page.click(selector, timeout=8000)
        except Exception as exc:
            log.debug("click %s: %s", selector, exc)
            return
        try:
            await page.wait_for_load_state("networkidle", timeout=20000)
        except Exception:
            pass

    @staticmethod
    async def _wait_for_selector(page, selector: str) -> None:
        try:
            await page.wait_for_selector(selector, timeout=15000, state="visible")
        except Exception:
            pass

    @staticmethod
    async def _selector_ready(page, selector: str) -> bool:
        """True when a selector is present and visible — lets an optional screen
        (MFA, consent) be skipped when the IdP did not present it."""
        try:
            el = await page.wait_for_selector(selector, timeout=8000, state="visible")
            return el is not None
        except Exception:
            return False

    @staticmethod
    def _resolve_mfa_code(config: dict) -> str:
        """A static ``mfa_code`` wins; otherwise derive a current TOTP from
        ``totp_secret`` (RFC 6238, stdlib only). Empty when neither is set."""
        code = config.get("mfa_code")
        if code:
            return str(code)
        secret = config.get("totp_secret")
        if not secret:
            return ""
        try:
            return _totp_now(secret)
        except Exception as exc:
            log.debug("TOTP generation failed: %s", exc)
            return ""

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

        base_payload = {username_field: username, password_field: password}

        try:
            import httpx

            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=30.0,
            ) as client:
                # Try each body encoding and keep the one that actually logs in.
                # A 200 is not success — an app re-renders the login page with a
                # 200 on failure — so each attempt is judged by _login_succeeded,
                # not by status. The anti-CSRF token is (re-)fetched on this same
                # client before every attempt: it binds to the session cookie the
                # fetch sets, and a failed login can rotate it. Without this a
                # CSRF-protected login (DVWA, Django, Rails, ASP.NET) never
                # succeeds and the scan silently runs anonymous.
                csrf_field = config.get("csrf_field")
                extract_hidden = config.get("extract_hidden", True)
                csrf_url = config.get("csrf_url") or login_url
                use_csrf = method != "GET" and (extract_hidden or csrf_field)

                attempts = (
                    ["json", "form"]
                    if content_type == "auto"
                    else [content_type if content_type in ("json", "form") else "form"]
                )

                resp = None
                token = None
                token_fields: dict[str, str] = {}
                success = False
                reason = "no login attempt was made"
                last_error = ""
                for encoding in attempts:
                    if use_csrf:
                        try:
                            page = await client.get(csrf_url)
                            token_fields = extract_form_tokens(
                                page.text, csrf_field, extract_hidden
                            )
                            if csrf_field and csrf_field not in token_fields:
                                log.warning(
                                    "csrf_field '%s' not found on the login page "
                                    "for scan %s",
                                    csrf_field,
                                    scan_id,
                                )
                        except Exception as exc:
                            log.debug("CSRF pre-fetch failed: %s", exc)

                    payload = dict(base_payload)
                    payload.update(token_fields)
                    payload.update(config.get("extra_fields") or {})

                    if method == "GET":
                        resp = await client.get(login_url, params=payload)
                    elif encoding == "json":
                        resp = await client.post(login_url, json=payload)
                    else:
                        resp = await client.post(login_url, data=payload)

                    if resp.status_code >= 400:
                        last_error = f"status {resp.status_code}"
                        log.debug(
                            "Login attempt (%s encoding) rejected with %d",
                            encoding,
                            resp.status_code,
                        )
                        continue

                    token = self._extract_token(resp, config.get("token_path"))
                    success, reason = self._login_succeeded(
                        config,
                        resp.text or "",
                        str(resp.url),
                        login_url,
                        token,
                        success_indicator,
                    )
                    if success:
                        break

                if resp is None:
                    return WebSession(
                        scan_id=scan_id, auth_error="Login request was not sent"
                    )

                # The cookie jar has aggregated cookies across the pre-fetch,
                # the login and any redirects — that is the session.
                cookies = self._collect_cookies(resp)
                cookies.update({k: v for k, v in dict(client.cookies).items() if k})

                if resp.status_code >= 400:
                    return WebSession(
                        scan_id=scan_id,
                        auth_error=(
                            f"Login rejected by the application ({last_error}). "
                            f"Check the credentials and the field names in the "
                            f"scan's authentication settings."
                        ),
                    )

                if not success:
                    return WebSession(
                        scan_id=scan_id,
                        auth_error=(
                            f"Login did not succeed: {reason}. If this "
                            f"application signals login another way, set "
                            f"success_indicator, failure_indicator, token_path "
                            f"or verify_url in the authentication settings."
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

                # 3. Optional independent verification: fetch a known
                #    authenticated URL and confirm it is not a login page.
                if config.get("verify_url"):
                    ok, vreason = await self._verify_on_client(client, config, headers)
                    session.verified = ok
                    if not ok:
                        return WebSession(
                            scan_id=scan_id,
                            auth_error=f"Session verification failed: {vreason}",
                        )

                self._save_session(session)
                log.info(
                    "Login successful for scan %s (%d cookie(s), token=%s, "
                    "csrf_fields=%d, verified=%s)",
                    scan_id,
                    len(cookies),
                    "yes" if token else "no",
                    len(token_fields),
                    session.verified,
                )
                return session

        except ImportError:
            log.error("httpx not installed — form login unavailable")
            return WebSession(scan_id=scan_id, auth_error="httpx not installed")
        except Exception as exc:
            log.warning("Form login error for scan %s: %s", scan_id, exc)
            return WebSession(scan_id=scan_id, auth_error=str(exc))

    @staticmethod
    def _login_succeeded(
        config, text, final_url, login_url, token, success_indicator
    ) -> tuple[bool, str]:
        """Decide login success from evidence, returning (ok, reason)."""
        text_low = (text or "").lower()
        if success_indicator:
            if success_indicator.lower() in text_low:
                return True, "success indicator present"
            return False, "configured success indicator was not present"
        failure = config.get("failure_indicator")
        if failure:
            if failure.lower() in text_low:
                return False, "configured failure indicator was present"
            return True, "configured failure indicator absent"
        if token:
            return True, "a session token was issued"
        # No indicators configured: a login that redirected away from the login
        # page and does not itself look like a login page is treated as success.
        redirected_away = login_url and urlparse(final_url).path.rstrip(
            "/"
        ) != urlparse(login_url).path.rstrip("/")
        if redirected_away and not looks_like_login_page(text, final_url, config):
            return True, "redirected away from the login page"
        if looks_like_login_page(text, final_url, config):
            return False, "the response still looks like a login page"
        # Fall back to cookie evidence only when nothing else is available.
        return True, "login returned without an error"

    async def _verify_on_client(self, client, config, headers) -> tuple[bool, str]:
        """Fetch verify_url on an authenticated client and judge the result."""
        verify_url = config.get("verify_url")
        try:
            resp = await client.get(verify_url, headers=headers or None)
        except Exception as exc:
            return False, f"could not reach verify_url ({exc})"
        if resp.status_code in (401, 403):
            return False, f"verify_url returned {resp.status_code}"
        text = resp.text or ""
        vind = config.get("verify_success_indicator") or config.get("success_indicator")
        if vind:
            return (vind.lower() in text.lower()), (
                "verify indicator present"
                if vind.lower() in text.lower()
                else "verify indicator absent"
            )
        if looks_like_login_page(text, str(resp.url), config):
            return False, "verify_url looks like a login page"
        return True, "verify_url reachable and not a login page"

    async def _multi_step_login(self, config: dict, scan_id: str) -> "WebSession":
        """
        Execute a configurable multi-step login/workflow on one session.

        ``config["login_steps"]`` is a list of steps run in order on a single
        httpx client, so cookies and extracted values carry forward:

            {
              "method": "GET"|"POST",
              "url": "https://app/login",          # absolute or relative
              "content_type": "form"|"json",       # for POST
              "fields": {"user": "admin", "csrf": "{{token}}"},
              "extract": {"token": {"hidden": "user_token"}},  # or {"json": "a.b"}
                                                    # or {"regex": "name=.(\\w+)."}
              "success_indicator": "Dashboard"      # optional per-step check
            }

        ``{{name}}`` placeholders in a step's fields/url are filled from values
        extracted by earlier steps, which is what expresses
        login → dashboard → select → act without hardcoding any one target.
        """
        steps = config.get("login_steps") or []
        if not steps:
            return WebSession(
                scan_id=scan_id, auth_error="multi_step login has no login_steps"
            )
        base = config.get("login_url") or (steps[0] or {}).get("url", "")
        try:
            import httpx

            captured: dict[str, str] = {}

            def _fill(value):
                if isinstance(value, str):
                    for k, v in captured.items():
                        value = value.replace("{{" + k + "}}", v)
                return value

            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=30.0
            ) as client:
                last_url = base
                for i, step in enumerate(steps):
                    if not isinstance(step, dict):
                        continue
                    url = urljoin(base, _fill(step.get("url") or last_url))
                    method = str(step.get("method", "GET")).upper()
                    fields = {
                        k: _fill(v) for k, v in (step.get("fields") or {}).items()
                    }
                    if method == "GET":
                        resp = await client.get(url, params=fields or None)
                    elif str(step.get("content_type", "form")).lower() == "json":
                        resp = await client.post(url, json=fields)
                    else:
                        resp = await client.post(url, data=fields)
                    last_url = str(resp.url)
                    body = resp.text or ""

                    if resp.status_code >= 400:
                        return WebSession(
                            scan_id=scan_id,
                            auth_error=(
                                f"multi-step login failed at step {i + 1} "
                                f"({method} {url}): status {resp.status_code}"
                            ),
                        )
                    ind = step.get("success_indicator")
                    if ind and ind.lower() not in body.lower():
                        return WebSession(
                            scan_id=scan_id,
                            auth_error=(
                                f"multi-step login step {i + 1} did not show its "
                                f"success indicator"
                            ),
                        )
                    captured.update(self._extract_step_values(step, body, resp))

                cookies = {k: v for k, v in dict(client.cookies).items() if k}
                token = None
                for name in ("token", "access_token", "jwt"):
                    if name in captured:
                        token = captured[name]
                        break
                headers = {}
                if token:
                    headers[config.get("token_header") or "Authorization"] = (
                        f"{config.get('token_prefix', 'Bearer ')}{token}"
                    )
                if not (cookies or headers):
                    return WebSession(
                        scan_id=scan_id,
                        auth_error="multi-step login issued no session",
                    )
                session = WebSession(
                    scan_id=scan_id,
                    headers=headers,
                    cookies=cookies,
                    auth_type="multi_step",
                    login_url=base,
                )
                if config.get("verify_url"):
                    ok, vreason = await self._verify_on_client(client, config, headers)
                    session.verified = ok
                    if not ok:
                        return WebSession(
                            scan_id=scan_id,
                            auth_error=f"Session verification failed: {vreason}",
                        )
                self._save_session(session)
                log.info(
                    "Multi-step login successful for scan %s (%d step(s), "
                    "%d cookie(s))",
                    scan_id,
                    len(steps),
                    len(cookies),
                )
                return session
        except Exception as exc:
            log.warning("Multi-step login error for scan %s: %s", scan_id, exc)
            return WebSession(scan_id=scan_id, auth_error=str(exc))

    @staticmethod
    def _extract_step_values(step: dict, body: str, resp) -> dict[str, str]:
        """Capture named values from a step response for later steps."""
        out: dict[str, str] = {}
        for name, spec in (step.get("extract") or {}).items():
            if not isinstance(spec, dict):
                continue
            try:
                if "hidden" in spec:
                    fields = extract_form_tokens(body, spec["hidden"], True)
                    if spec["hidden"] in fields:
                        out[name] = fields[spec["hidden"]]
                elif "regex" in spec:
                    m = re.search(spec["regex"], body)
                    if m:
                        out[name] = m.group(m.lastindex or 0)
                elif "json" in spec:
                    node = resp.json()
                    for part in str(spec["json"]).split("."):
                        node = node.get(part) if isinstance(node, dict) else None
                    if isinstance(node, str):
                        out[name] = node
            except Exception:
                continue
        return out

    async def reauthenticate(self, config: dict, scan_id: str) -> "WebSession":
        """
        Re-establish a session that was lost mid-scan, bounded by
        ``max_reauth`` (default 2). A separate counter per scan prevents an
        endless re-auth loop against an application that keeps rejecting the
        credentials.
        """
        cap = int(config.get("max_reauth", 2) or 0)
        used = self._reauth_used.get(scan_id, 0)
        if used >= cap:
            log.warning(
                "Re-authentication cap (%d) reached for scan %s — not retrying",
                cap,
                scan_id,
            )
            return WebSession(
                scan_id=scan_id, auth_error="re-authentication limit reached"
            )
        self._reauth_used[scan_id] = used + 1
        log.info("Re-authenticating scan %s (attempt %d/%d)", scan_id, used + 1, cap)
        return await self.authenticate(config, scan_id)

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
        #: True only when a verify_url check confirmed the session; None when no
        #: verification was configured. Never let None read as "verified".
        self.verified = None

    @property
    def is_authenticated(self) -> bool:
        return bool(self.headers or self.cookies) and not self.auth_error

    @staticmethod
    def looks_unauthenticated(
        status_code: int, url: str, text: str, config: dict
    ) -> bool:
        """
        Whether a response seen *during an authenticated scan* indicates the
        session was lost — a 401/403, a redirect to the login page, or a
        configured failure indicator / login marker. This is the session-expiry
        and auth-loss detector the crawler consults to decide whether to
        re-authenticate.
        """
        if status_code in (401, 403):
            return True
        return looks_like_login_page(text or "", url or "", config or {})

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
