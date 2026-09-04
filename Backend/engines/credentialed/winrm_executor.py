r"""
engines/credentialed/winrm_executor.py
──────────────────────────────────────────────────────────────────────────────
Native Windows command execution over WinRM.

Why this exists
───────────────
Windows credentialed collection previously required **OpenSSH Server installed
on every target**, with PowerShell configured as its default shell. That is not
an enterprise-appropriate requirement: it means installing and exposing a second
remote-administration service on managed Windows estates that already have one
built in, turned on by Group Policy, and audited. Asking a customer to deploy
OpenSSH to their domain in order to be scanned is asking them to widen their
attack surface for the scanner's convenience.

WinRM is that built-in service. It is what `Enter-PSSession`, `Invoke-Command`
and every Windows management tool already use, it is Kerberos-authenticated in a
domain, and it is already permitted through the firewall wherever remote
management is in use.

What this module is, and is not
───────────────────────────────
It is a **transport**, nothing more. It implements the ``BaseExecutor`` protocol
already declared in ``ssh_scanner.py`` — ``connect``, ``disconnect``,
``run(command, timeout) -> CommandResult`` — so
``WindowsCollector`` drives it without modification and the entire existing
PowerShell command catalogue, its parsers, and every downstream consumer
(evidence → vulnerability matching → finding → risk → reporting) are reused
exactly as they are.

That is the whole design: **swap the transport, keep the assessment.** There is
no second Windows collector and no second finding path.

Errors are classified, not flattened
────────────────────────────────────
"The scan failed" is useless to whoever has to fix it. A refused password, an
account without the rights to read the security log, a host that is not
listening on 5985 and a TLS certificate that does not validate need four
different actions, and this module distinguishes them —
:class:`WinRMAuthenticationError`, :class:`WinRMPermissionError`,
:class:`WinRMConnectionError`, :class:`WinRMConfigurationError`. Collapsing them
into one message is how a scan that is failing for a fixable reason gets
recorded as "host unreachable" and ignored.

Encryption
──────────
Over HTTPS (5986) the channel is TLS. Over HTTP (5985) **NTLM message
encryption still applies** — pywinrm negotiates it, so the payload is not
cleartext on the wire even on the plain port. Basic authentication has no such
protection, so it is refused over HTTP unless explicitly forced, because Basic
over 5985 puts the password on the wire in base64.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, Optional

from engines.credentialed.ssh_scanner import CommandResult

log = logging.getLogger("ccure.winrm")

__all__ = [
    "DEFAULT_HTTPS_PORT",
    "DEFAULT_HTTP_PORT",
    "WINRM_AVAILABLE",
    "WinRMAuthenticationError",
    "WinRMConfigurationError",
    "WinRMConnectionError",
    "WinRMError",
    "WinRMExecutor",
    "WinRMPermissionError",
]

DEFAULT_HTTP_PORT = 5985
DEFAULT_HTTPS_PORT = 5986

try:  # pragma: no cover - import guard
    import winrm  # type: ignore
    from winrm.exceptions import (  # type: ignore
        InvalidCredentialsError,
        WinRMOperationTimeoutError,
        WinRMTransportError,
    )

    WINRM_AVAILABLE = True
except ImportError:  # pragma: no cover - import guard
    winrm = None  # type: ignore
    InvalidCredentialsError = WinRMTransportError = WinRMOperationTimeoutError = ()
    WINRM_AVAILABLE = False

WINRM_INSTALL_HINT = (
    "pywinrm is not installed, so native Windows collection is unavailable. "
    "Run: pip install pywinrm==0.4.3"
)


class WinRMError(RuntimeError):
    """Base for every WinRM failure this module distinguishes."""


class WinRMConnectionError(WinRMError):
    """Nothing answered — host down, port closed, WinRM service not running."""


class WinRMAuthenticationError(WinRMError):
    """The credential was rejected."""


class WinRMPermissionError(WinRMError):
    """Authenticated, but not permitted to do what was asked."""


class WinRMConfigurationError(WinRMError):
    """WinRM answered but is configured in a way that prevents the scan."""


#: Authentication methods pywinrm supports that this product exposes.
#:
#: ``ntlm`` is the default rather than ``basic`` because it is what a
#: domain-managed estate actually uses, it does not require WinRM's
#: ``AllowUnencrypted``, and it encrypts the payload even over port 5985.
SUPPORTED_AUTH = ("ntlm", "basic", "certificate")

#: Methods pywinrm names but this build cannot perform, with the reason.
#:
#: ``kerberos`` was in ``SUPPORTED_AUTH`` while the runtime had none: the
#: session constructs, and the *first command* raises "requested auth method is
#: kerberos, but pykerberos is not installed". A credential saved with it
#: therefore failed on the customer's network rather than at the moment somebody
#: saved it. Refusing at construction moves that error to where it is
#: actionable. Implementing it needs a GSSAPI stack, a ticket cache and a domain
#: controller to validate against, none of which was available.
UNAVAILABLE_AUTH = {
    "kerberos": (
        "Kerberos needs the pywinrm[kerberos] extra and a ticket cache, neither "
        "of which this build has. Use ntlm, or ntlm_hash over the SMB transport."
    ),
}


class WinRMExecutor:
    """
    A WinRM connection that speaks the same protocol as :class:`SSHScanner`.

    Always use as a context manager so the session is released::

        with WinRMExecutor("10.0.0.5", "CORP\\svc_scan", password=pw) as w:
            result = w.run("Get-CimInstance Win32_OperatingSystem | ConvertTo-Json")
    """

    def __init__(
        self,
        ip: str,
        username: str,
        password: Optional[str] = None,
        *,
        port: Optional[int] = None,
        auth_method: str = "ntlm",
        use_tls: Optional[bool] = None,
        verify_cert: bool = False,
        timeout: int = 30,
        read_timeout: int = 60,
        winrm_path: str = "/wsman",
        allow_basic_over_http: bool = False,
    ):
        if not WINRM_AVAILABLE:
            raise WinRMConfigurationError(WINRM_INSTALL_HINT)

        method = (auth_method or "ntlm").strip().lower()
        # 'password' is the vocabulary the credential store uses for "a
        # password, however it is presented". On Windows that is NTLM: mapping
        # it to Basic instead would put the password on the wire in base64 and
        # require AllowUnencrypted on the target.
        if method == "password":
            method = "ntlm"
        if method in UNAVAILABLE_AUTH:
            raise WinRMConfigurationError(UNAVAILABLE_AUTH[method])
        if method not in SUPPORTED_AUTH:
            raise WinRMConfigurationError(
                f"unsupported WinRM auth method {auth_method!r}; "
                f"expected one of {', '.join(SUPPORTED_AUTH)}"
            )

        # TLS is inferred from the port when not stated, because the two are
        # conventionally locked together and a mismatch produces a confusing
        # handshake error rather than a clear one.
        if use_tls is None:
            use_tls = int(port or DEFAULT_HTTP_PORT) == DEFAULT_HTTPS_PORT
        resolved_port = int(
            port or (DEFAULT_HTTPS_PORT if use_tls else DEFAULT_HTTP_PORT)
        )

        if method == "basic" and not use_tls and not allow_basic_over_http:
            raise WinRMConfigurationError(
                "Basic authentication over plain HTTP would put the password on "
                "the wire in base64. Use NTLM (which encrypts the payload even "
                "on port 5985), or HTTPS on 5986."
            )

        self.ip = ip
        self.username = username
        self.port = resolved_port
        self.auth_method = method
        self.use_tls = bool(use_tls)
        self.verify_cert = bool(verify_cert)
        self.timeout = int(timeout)
        self.read_timeout = max(int(read_timeout), int(timeout) + 5)
        self.winrm_path = winrm_path or "/wsman"
        self._password = password
        self._session: Any = None
        #: Per-thread pywinrm sessions. See _session_for_thread for why one
        #: shared session cannot be used.
        self._local = threading.local()
        self._closed = False

    # ── Context manager ──────────────────────────────────────────────────────

    def __enter__(self) -> "WinRMExecutor":
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()

    @property
    def endpoint(self) -> str:
        scheme = "https" if self.use_tls else "http"
        return f"{scheme}://{self.ip}:{self.port}{self.winrm_path}"

    # ── BaseExecutor ─────────────────────────────────────────────────────────

    def _build_session(self) -> Any:
        try:
            return winrm.Session(
                self.endpoint,
                auth=(self.username, self._password or ""),
                transport=self.auth_method,
                server_cert_validation="validate" if self.verify_cert else "ignore",
                operation_timeout_sec=self.timeout,
                read_timeout_sec=self.read_timeout,
            )
        except Exception as exc:  # noqa: BLE001 — normalised below
            raise self._classify(exc) from exc

    def _session_for_thread(self) -> Any:
        """
        The calling thread's own WinRM session, created on first use.

        **A pywinrm NTLM session is not thread-safe, and this is not a
        theoretical concern.** ``WindowsCollector.collect_all`` runs its
        sections in a thread pool — which is correct over SSH, where paramiko
        opens a fresh channel per command — and sharing one session across
        those threads corrupts the NTLM security context. Measured against a
        real Windows 11 host:

            sequential, one session, 10 commands        10/10 succeeded
            concurrent, one shared session, 8 threads    0/8 succeeded
            concurrent, one session per thread           8/8 succeeded

        The failures arrive as ``SpnegoError (6): A token had an invalid
        Message Integrity Check (MIC)``, HTTP 400, and — most misleadingly —
        "the specified credentials were rejected by the server" on a credential
        that is perfectly valid. A scan hitting that reports every section as
        failed and looks exactly like a bad password.

        Thread-local sessions fix it without serialising collection: each
        thread performs its own NTLM handshake once and reuses it for every
        command it issues.
        """
        existing = getattr(self._local, "session", None)
        if existing is None:
            if self._closed:
                raise WinRMConnectionError("run() called after disconnect()")
            existing = self._build_session()
            self._local.session = existing
        return existing

    def connect(self) -> None:
        """
        Establish the connection and prove the credential works.

        pywinrm is lazy — constructing a ``Session`` performs no I/O — so a
        constructor that only built the object would report success for a host
        that is switched off, and the failure would surface later as an empty
        collection that reads like a clean host. One cheap round trip here
        turns that into an error naming the cause.
        """
        self._closed = False
        self._session = self._session_for_thread()

        probe = self.run("$PSVersionTable.PSVersion.Major", timeout=self.timeout)
        if not probe.success:
            raise WinRMConnectionError(
                f"WinRM connected to {self.endpoint} but the probe command "
                f"failed: {probe.stderr or 'no output'}"
            )

    def disconnect(self) -> None:
        # pywinrm opens a shell per command and closes it in run_ps, so there
        # is no long-lived handle to release. Dropping the references is
        # deliberate all the same: it drops the password with them.
        #
        # Only this thread's session is reachable from here — thread-local
        # storage is per-thread by construction. That is acceptable because
        # the worker threads are finished by the time the context manager
        # exits, and each holds nothing but an HTTP connection pool that its
        # own garbage collection closes.
        self._closed = True
        self._session = None
        self._local = threading.local()
        self._password = None

    def run(self, command: str, timeout: Optional[int] = None) -> CommandResult:
        """
        Execute a PowerShell command.

        Returns a :class:`CommandResult` — never raises for a command that ran
        and failed, because a non-zero exit is data the collector interprets
        (a registry key that does not exist on this SKU is not an error). Only
        transport and authentication problems raise.
        """
        session = self._session_for_thread()

        try:
            # run_ps base64-encodes as UTF-16-LE itself, which is the same
            # encoding trick the SSH path applies by hand in
            # WindowsCollector._wrap_ps. So the collector must be told the
            # shell is already PowerShell, or the command would be wrapped
            # twice.
            response = session.run_ps(command)
        except Exception as exc:  # noqa: BLE001 — normalised below
            raise self._classify(exc) from exc

        stdout = self._decode(response.std_out)
        stderr = self._decode(response.std_err)
        code = int(getattr(response, "status_code", 1) or 0)

        if code != 0 and self._looks_like_access_denied(stderr):
            # Surfaced rather than returned, because an access-denied result is
            # not a finding about the host: it is a finding about the scan
            # account, and reporting the section as "no data" would let a
            # under-privileged scan look like a clean host.
            raise WinRMPermissionError(
                f"the scan account is not permitted to run this command on "
                f"{self.ip}: {stderr.strip()[:300]}"
            )

        return CommandResult(
            stdout=stdout, stderr=stderr, exit_code=code, success=code == 0
        )

    def is_connected(self) -> bool:
        return self._session is not None

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _decode(raw: Any) -> str:
        if raw is None:
            return ""
        if isinstance(raw, bytes):
            # Windows emits UTF-8 for run_ps output; replace rather than raise
            # so one undecodable byte cannot lose an entire section.
            return raw.decode("utf-8", errors="replace")
        return str(raw)

    @staticmethod
    def _looks_like_access_denied(stderr: str) -> bool:
        text = (stderr or "").lower()
        return any(
            marker in text
            for marker in (
                "access is denied",
                "unauthorizedaccessexception",
                "requires elevation",
                "not authorized",
                "permissiondenied",
            )
        )

    def _classify(self, exc: Exception) -> WinRMError:
        """
        Turn a transport exception into one a person can act on.

        pywinrm surfaces authentication, connectivity and configuration
        problems through overlapping exception types and HTTP status codes, so
        the message is inspected as well as the class. Being wrong here is
        cheap — the original exception is chained — while being vague is not.
        """
        text = str(exc)
        lowered = text.lower()

        if WINRM_AVAILABLE and isinstance(exc, InvalidCredentialsError):
            return WinRMAuthenticationError(
                f"WinRM rejected the credential for {self.username} on "
                f"{self.ip}: {text}"
            )
        # "the specified credentials were rejected by the server" is the
        # literal string pywinrm emits, and it contains none of 401,
        # "unauthorized" or "authentication" — so without it here the most
        # common authentication failure of all fell through to
        # WinRMConnectionError and was reported as an unreachable host. Caught
        # by the classifier test, not by the live run, because live pywinrm
        # raised the typed InvalidCredentialsError that the branch above
        # already handles.
        if (
            "401" in text
            or "unauthorized" in lowered
            or "authentication" in lowered
            or "credentials were rejected" in lowered
            or "rejected by the server" in lowered
        ):
            return WinRMAuthenticationError(
                f"WinRM authentication failed for {self.username} on {self.ip}. "
                f"Check the username form (DOMAIN\\user for NTLM, "
                f"user@REALM for Kerberos), the password, and whether the "
                f"account is locked. ({text})"
            )
        if "403" in text or "forbidden" in lowered:
            return WinRMPermissionError(
                f"WinRM accepted the credential for {self.username} but "
                f"refused the request on {self.ip}. The account is likely not "
                f"in Remote Management Users or Administrators. ({text})"
            )
        if any(
            marker in lowered
            for marker in ("certificate", "ssl", "tls handshake", "sslerror")
        ):
            return WinRMConfigurationError(
                f"WinRM TLS to {self.endpoint} failed: {text}. A self-signed "
                f"listener certificate needs verify_cert disabled for this "
                f"credential, or its CA trusted by the scanner."
            )
        if any(
            marker in lowered
            for marker in (
                "connection refused",
                "timed out",
                "timeout",
                "unreachable",
                "connectionerror",
                "max retries",
                "no route",
                "actively refused",
            )
        ):
            return WinRMConnectionError(
                f"nothing answered WinRM at {self.endpoint}: {text}. Confirm "
                f"the WinRM service is running (winrm quickconfig), the "
                f"listener exists on this port, and the firewall permits it."
            )
        if "500" in text or isinstance(
            exc, WinRMTransportError if WINRM_AVAILABLE else ()
        ):
            return WinRMConfigurationError(
                f"WinRM at {self.endpoint} returned an error: {text}"
            )
        return WinRMConnectionError(f"WinRM error against {self.endpoint}: {text}")

    # ── Reachability probe ───────────────────────────────────────────────────

    @staticmethod
    def test_connectivity(
        ip: str, port: int = DEFAULT_HTTP_PORT, timeout: int = 5
    ) -> bool:
        """
        Is anything listening? A TCP probe only — deliberately not an
        authentication attempt, so it can be used against a host before a
        credential has been chosen without generating a failed-logon event.
        """
        import socket

        try:
            with socket.create_connection((ip, int(port)), timeout=timeout):
                return True
        except OSError:
            return False


def build_options(credential) -> Dict[str, Any]:
    """
    Translate a stored credential row into :class:`WinRMExecutor` arguments.

    Lives here rather than in the task so the mapping from stored fields to
    transport settings has one definition. ``credential.options`` carries the
    per-credential overrides; anything absent falls back to the safe default.
    """
    options = dict(getattr(credential, "options", None) or {})
    port = credential.port or None
    use_tls = options.get("use_tls")
    if use_tls is None and port:
        use_tls = int(port) == DEFAULT_HTTPS_PORT
    return {
        "port": port,
        "auth_method": credential.auth_method or "ntlm",
        "use_tls": use_tls,
        # Defaults to False because a Windows WinRM listener created by
        # `winrm quickconfig` carries a self-signed certificate. Requiring
        # validation by default would make the common case fail with a TLS
        # error, and the usual reaction to that is to disable TLS entirely —
        # a worse outcome than an unvalidated but encrypted channel.
        "verify_cert": bool(options.get("verify_cert", False)),
        "timeout": int(options.get("timeout", 30)),
        "read_timeout": int(options.get("read_timeout", 60)),
        "winrm_path": options.get("winrm_path", "/wsman"),
        "allow_basic_over_http": bool(options.get("allow_basic_over_http", False)),
    }
