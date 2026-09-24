"""
engines/credentialed/ssh_scanner.py
------------------------------------
Paramiko-based SSH wrapper for credentialed scanning.

Credentials are NEVER stored — they are used for the duration of the
connection and then discarded.  Option A by design.

Usage::

    from engines.credentialed.ssh_scanner import SSHScanner

    scanner = SSHScanner(ip="10.180.6.140", username="root", password="secret")
    with scanner:
        result = scanner.run("uname -r")
        print(result.stdout)
"""

import logging
import re
import socket
import threading
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("ccure.ssh_scanner")

# ---------------------------------------------------------------------------
# Optional import — paramiko must be installed for credentialed scans
# ---------------------------------------------------------------------------
try:
    import paramiko
    import paramiko.pkey
    import paramiko.ssh_exception

    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    log.warning(
        "paramiko not installed — credentialed scanning disabled. "
        "Run: pip install paramiko==3.4.0"
    )


@dataclass
class CommandResult:
    """Return value from SSHScanner.run()."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    success: bool = False


def _load_private_key(content: str, passphrase: Optional[str] = None):
    """
    Parse private key material, encrypted or not, whatever its algorithm.

    Paramiko has no auto-detecting loader for a *string*: ``PKey`` itself cannot
    be constructed from one, and each concrete class only recognises its own
    format. So the types are tried in turn — Ed25519 first because it is what
    modern hosts issue.

    This replaces a call to ``paramiko.pkey.load_private_key``, **which does not
    exist in paramiko 4**. Every key-content credential therefore failed with
    ``module 'paramiko.pkey' has no attribute 'load_private_key'``, re-raised as
    "Failed to parse private key content" — so the fault read as a malformed key
    supplied by the operator rather than as a call to a function that was never
    there. Found while adding passphrase support, which is what made anyone
    exercise this path.

    ``PasswordRequiredException`` is re-raised immediately rather than collected:
    it means the key is fine and locked, which is a different thing to tell an
    operator than "this is not a key I recognise".
    """
    import io

    last: list[str] = []
    for key_class in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return key_class.from_private_key(io.StringIO(content), password=passphrase)
        except paramiko.PasswordRequiredException:
            raise RuntimeError(
                "the private key is encrypted and no passphrase was supplied"
            ) from None
        except Exception as exc:  # noqa: BLE001 — try the next algorithm
            last.append(f"{key_class.__name__}: {type(exc).__name__}")

    raise RuntimeError(
        "not a recognised private key, or the passphrase is wrong "
        f"({'; '.join(last)})"
    )


#: One ``sudo`` invocation and the bundle of short flags immediately after it.
#: The flag group stops at the first token that does not begin with ``-``,
#: which is the command sudo is being asked to run.
_SUDO_INVOCATION = re.compile(r"\bsudo\b(?P<flags>(?:\s+-[A-Za-z]+)*)")

#: Elevation programs this scanner can drive, and how.
#:
#: ``stdin`` means the program reads its password from standard input, which is
#: the only shape this scanner will use: a password on the command line is
#: visible in ``ps`` to every local user on the target. ``none`` means the
#: program takes no password at all.
ELEVATION_METHODS = {
    # sudo(8). ``-S`` reads the password from stdin, ``-p ''`` silences the
    # prompt that would otherwise land in stderr and be read as command output.
    "sudo": {"binary": "sudo", "password": "stdin", "flags": ("-S", "-p", "''")},
    # Delinea/Centrify dzdo, documented as a drop-in sudo replacement with
    # compatible options, so the same rewrite drives it.
    "dzdo": {"binary": "dzdo", "password": "stdin", "flags": ("-S", "-p", "''")},
    # Solaris pfexec(1). Authorisation comes from the account's RBAC profile, so
    # there is no password to send and none is written — one would sit unread in
    # the command's stdin. It accepts none of sudo's options either, so they are
    # dropped rather than translated into something pfexec would reject.
    "pfexec": {"binary": "pfexec", "password": "none", "flags": ()},
}

#: Elevation programs this scanner deliberately does not drive, with the reason.
#: Named so an operator gets an explanation rather than a silent failure, and so
#: the phase that adds one starts from why it was left out.
UNSUPPORTED_ELEVATION = {
    # su(1) reads its password from the controlling terminal, not stdin, so
    # driving it needs a PTY — and a PTY merges stderr into stdout and echoes
    # the prompt into the output every command in the catalogue is parsed from.
    "su": (
        "su reads its password from the terminal rather than stdin, so it needs "
        "a PTY, which merges stderr into stdout and puts the prompt into the "
        "output the collectors parse"
    ),
    # BeyondTrust pbrun does not share sudo's option syntax, is driven by a
    # policy server, and no instance was available to validate against.
    # Shipping an untested translation of somebody's privilege-escalation
    # command is how a scanner runs the wrong thing as root.
    "pbrun": (
        "BeyondTrust pbrun does not share sudo's option syntax and no instance "
        "was available to validate against"
    ),
    # ksu(1) authenticates with a Kerberos ticket, and Kerberos is not supported
    # on any transport in this build — see USABLE_AUTH_METHODS.
    "ksu": (
        "ksu authenticates with a Kerberos ticket, and Kerberos is not "
        "supported on any transport in this build"
    ),
}


def _rewrite_sudo_for_stdin(command: str, method: str = "sudo") -> tuple[str, int]:
    """
    Rewrite every ``sudo`` in *command* to elevate through *method*.

    Returns ``(rewritten, password_lines)``. ``password_lines`` is how many lines
    the caller must write to stdin — one per invocation for a program that reads
    a password there, and **zero** for one that does not.

    ``-n`` is stripped wherever it appears, including inside a bundle such as
    ``-ln``. It means "never prompt", and sudo honours it over ``-S``: leaving it
    in place would make sudo refuse the password this rewrite exists to deliver,
    which reads on the target as a permission failure rather than as a scanner
    bug. ``-n`` is the right flag when there is no password, and that case never
    reaches here.

    The command catalogue is written in terms of ``sudo`` because that is the
    overwhelmingly common case; this substitutes the configured program, so a
    host using another one needs no second catalogue.
    """
    spec = ELEVATION_METHODS.get((method or "sudo").strip().lower())
    if spec is None:
        # An unsupported method elevates nothing rather than guessing. The
        # command still runs unprivileged, and whatever it could not read is
        # recorded as unavailable — never as a clean result.
        return command, 0

    count = 0

    def _replace(match: "re.Match[str]") -> str:
        nonlocal count
        count += 1
        flags: list[str] = []
        if spec["flags"]:
            for token in match.group("flags").split():
                # ``-n`` is the only sudo short flag containing the letter, so
                # removing it from a bundle cannot disturb another option.
                remaining = "-" + token[1:].replace("n", "")
                if remaining != "-":
                    flags.append(remaining)
        return " ".join([spec["binary"], *spec["flags"], *flags])

    rewritten = _SUDO_INVOCATION.sub(_replace, command)
    return rewritten, (count if spec["password"] == "stdin" else 0)


from typing import Protocol


class BaseExecutor(Protocol):
    """
    Protocol defining the common execution operations.
    """

    def connect(self) -> None:
        """Establish connection to the target asset."""
        ...

    def disconnect(self) -> None:
        """Close connection and clean up resources."""
        ...

    def run(self, command: str, timeout: int | None = None) -> CommandResult:
        """Execute a shell command on the target asset."""
        ...


class SSHScanner:
    """
    Thin SSH client around paramiko.

    Supports password auth and SSH key auth.
    Always call as a context manager so the connection is guaranteed to close::

        with SSHScanner(ip, username, password=pw) as s:
            out = s.run("hostname")

    Parameters
    ----------
    ip          : Target IP or hostname.
    username    : SSH username.
    password    : Plaintext password (used and discarded — never stored).
    key_path    : Path to private key file (alternative to password).
    port        : SSH port (default 22).
    timeout     : Connection + command timeout in seconds (default 10).
    """

    def __init__(
        self,
        ip: str,
        username: str,
        password: str | None = None,
        key_path: str | None = None,
        key_content: str | None = None,
        port: int = 22,
        timeout: int = 10,
        key_passphrase: str | None = None,
        elevation_method: str = "sudo",
    ):
        self.ip = ip
        self.username = username
        self._password = password  # leading underscore = not serialised
        self._key_path = key_path
        self._key_content = key_content
        #: Unlocks an encrypted private key. Held here for the same reason the
        #: password is — so no collector ever handles it — and wiped by
        #: ``disconnect`` alongside the others.
        self._key_passphrase = key_passphrase
        self.elevation_method = (elevation_method or "sudo").strip().lower()
        self.port = port
        self.timeout = timeout
        self._client: paramiko.SSHClient | None = None
        self._lock = threading.Lock()

    # ── Context manager ────────────────────────────────────────────────────

    def __enter__(self) -> "SSHScanner":
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()

    # ── Public API ─────────────────────────────────────────────────────────

    def connect(self) -> None:
        """Open SSH connection.  Raises RuntimeError on failure."""
        if not PARAMIKO_AVAILABLE:
            raise RuntimeError(
                "paramiko is not installed. Run: pip install paramiko==3.4.0"
            )

        client = paramiko.SSHClient()
        # ACCEPTED RISK, pending a decision — docs/ci/SECURITY_GATES.md
        # "Accepted risks". No host key is known for a customer host before
        # the first scan, so any key is accepted; an interceptor answering as
        # the target receives the password credential.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507

        connect_kwargs = {
            "hostname": self.ip,
            "port": self.port,
            "username": self.username,
            "timeout": self.timeout,
            "banner_timeout": self.timeout,
            "auth_timeout": self.timeout,
            "look_for_keys": False,
            "allow_agent": False,
        }

        if self._key_content:
            import io

            try:
                connect_kwargs["pkey"] = _load_private_key(
                    self._key_content, self._key_passphrase
                )
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to parse private key content: {self._redact(str(exc))}"
                ) from None
        elif self._key_path:
            connect_kwargs["key_filename"] = self._key_path
        elif self._password:
            connect_kwargs["password"] = self._password
        else:
            raise ValueError(
                "Either password, key_path, or key_content must be provided."
            )

        try:
            client.connect(**connect_kwargs)
            self._client = client
            log.info("SSH connected to %s:%s as %s", self.ip, self.port, self.username)
        except paramiko.AuthenticationException as exc:
            raise RuntimeError(
                f"SSH authentication failed for {self.username}@{self.ip}: {exc}"
            ) from exc
        except (TimeoutError, paramiko.ssh_exception.NoValidConnectionsError) as exc:
            raise RuntimeError(f"Cannot reach {self.ip}:{self.port} — {exc}") from exc
        except Exception as exc:
            raise RuntimeError(f"SSH connection error to {self.ip}: {exc}") from exc

    def disconnect(self) -> None:
        """Close the SSH connection and wipe credentials from memory."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        # Wipe credentials — Option A: never persist, actively clear
        self._password = None
        self._key_path = None
        self._key_content = None
        self._key_passphrase = None

    def run(
        self,
        command: str,
        timeout: int | None = None,
        *,
        stdin_data: str | None = None,
    ) -> CommandResult:
        """
        Execute a command on the remote host.

        Parameters
        ----------
        command : Shell command string.
        timeout : Per-command timeout (defaults to self.timeout).
        stdin_data :
            Written to the remote command's standard input, then EOF. This is
            the channel a secret travels on — ``sudo -S`` reads its password
            here — so it is **never logged, never echoed and never placed in
            the command string**. Anything a program can read from argv is
            visible in ``ps`` to every user on the target and is captured by an
            ``execve`` audit rule; stdin is not.

        Returns
        -------
        CommandResult with stdout, stderr, exit_code, success.
        Never raises — returns a failed CommandResult on error.
        """
        if self._client is None:
            return CommandResult(stderr="Not connected", exit_code=-1, success=False)

        with self._lock:
            try:
                _timeout = timeout or self.timeout
                stdin_fh, stdout_fh, stderr_fh = self._client.exec_command(
                    command, timeout=_timeout, get_pty=False
                )  # nosec B601
                if stdin_data is not None:
                    # Write, flush, then half-close. Without the shutdown the
                    # remote command waits on a stdin that never reaches EOF
                    # and the read below blocks until the timeout.
                    try:
                        stdin_fh.write(stdin_data)
                        stdin_fh.flush()
                    finally:
                        try:
                            stdin_fh.channel.shutdown_write()
                        except Exception:  # noqa: BLE001 — best effort
                            pass
                stdout_fh.channel.settimeout(_timeout)
                stderr_fh.channel.settimeout(_timeout)

                chunks = []
                while True:
                    chunk = stdout_fh.channel.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                stdout_data = b"".join(chunks).decode("utf-8", errors="replace").strip()
                stderr_data = stderr_fh.read().decode("utf-8", errors="replace").strip()
                exit_code = stdout_fh.channel.recv_exit_status()

                return CommandResult(
                    stdout=stdout_data,
                    stderr=stderr_data,
                    exit_code=exit_code,
                    success=(exit_code == 0),
                )
            except Exception as exc:
                # Redacted, not trusted to be clean. The command should never
                # carry a secret now that sudo reads its password from stdin,
                # but a log line is the one place a regression here would be
                # written to disk and kept, so it is filtered on the way out.
                log.debug(
                    "Command '%s' failed on %s: %s",
                    self._redact(command),
                    self.ip,
                    self._redact(str(exc)),
                )
                return CommandResult(
                    stderr=str(exc),
                    exit_code=-1,
                    success=False,
                )

    def is_connected(self) -> bool:
        """Return True if the SSH transport is alive."""
        if self._client is None:
            return False
        transport = self._client.get_transport()
        return transport is not None and transport.is_active()

    # ── Elevation ──────────────────────────────────────────────────────────

    @property
    def has_password(self) -> bool:
        """
        Can this session answer a sudo password prompt?

        Exposed so a collector can decide whether elevation is worth trying
        **without reading the password itself**. Callers used to reach for
        ``getattr(ssh, "_password", None)`` and build the sudo command by hand,
        which is how the secret ended up in the remote argv.
        """
        return bool(self._password)

    def run_sudo(self, command: str, timeout: int | None = None) -> CommandResult:
        """
        Run a command whose ``sudo`` invocations may need a password.

        The password is supplied on **stdin**, which is the whole point of this
        method. The previous implementation built
        ``echo 'PASSWORD' | sudo -S …`` and handed it to ``exec_command``; the
        remote shell then carried the customer's password in its argv, where
        ``ps`` shows it to every local user, an ``execve`` audit rule records
        it, and the shell may write it to history.

        With no password configured the command runs unchanged — a key-only
        session keeps whatever ``sudo -n`` behaviour the caller wrote — except
        under an elevation program that needs no password at all, where there is
        nothing to be missing.

        ``self.elevation_method`` selects the program. An unsupported one
        elevates nothing rather than guessing at its option syntax: the command
        still runs unprivileged, and whatever it could not read is recorded as
        unavailable rather than as a clean result.
        """
        spec = ELEVATION_METHODS.get(self.elevation_method)
        if spec is None:
            reason = UNSUPPORTED_ELEVATION.get(self.elevation_method)
            log.warning(
                "elevation method %r is not supported on %s, so the command "
                "runs unprivileged%s",
                self.elevation_method,
                self.ip,
                f" — {reason}" if reason else "",
            )
            return self.run(command, timeout=timeout)

        needs_password = spec["password"] == "stdin"
        if needs_password and not self._password:
            return self.run(command, timeout=timeout)

        elevated, password_lines = _rewrite_sudo_for_stdin(
            command, self.elevation_method
        )
        if elevated == command:
            return self.run(command, timeout=timeout)

        if not needs_password:
            # pfexec and its kind authorise from the account's own RBAC profile.
            # Writing a password here would leave it unread in the command's
            # stdin, where whatever the command runs could consume it.
            return self.run(elevated, timeout=timeout)

        # The rewrite reads sudo's option bundle up to the first token that is
        # not a flag, so a ``-n`` sitting *after* an option's value — as in
        # ``sudo -u postgres -n psql`` — is out of its reach. No shipped command
        # has that shape. If one is added, sudo will honour the surviving ``-n``
        # and refuse the password on stdin, which shows up on the target as a
        # permission failure; saying so here is what makes that findable.
        if re.search(r"\s-n(\s|$)", elevated):
            log.warning(
                "sudo elevation on %s left a -n flag in place, so sudo will "
                "refuse the password: %s",
                self.ip,
                elevated,
            )

        # One line per sudo invocation. A command such as
        # ``sudo -l || sudo -n -l`` runs at most one of them, but which one is
        # decided on the target: the first consumes a line, and a second that
        # runs because the first failed must find another waiting. Relying on
        # sudo's credential cache instead would break wherever
        # ``timestamp_timeout=0`` is set.
        payload = (self._password + "\n") * password_lines
        return self.run(elevated, timeout=timeout, stdin_data=payload)

    def _redact(self, text: str) -> str:
        """Mask every secret this session holds, anywhere it appears in *text*."""
        for secret in (self._password, self._key_passphrase):
            if secret and secret in text:
                text = text.replace(secret, "***REDACTED***")
        return text

    # ── Convenience ────────────────────────────────────────────────────────

    @staticmethod
    def test_connectivity(ip: str, port: int = 22, timeout: int = 5) -> bool:
        """
        Quick TCP check — does not attempt SSH handshake.
        Use before attempting a full credentialed scan to give a fast error.
        """
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except (TimeoutError, ConnectionRefusedError, OSError):
            return False
