"""
engines/credentialed/ssh_scanner.py
------------------------------------
Paramiko-based SSH wrapper for credentialed scanning.

Credentials are NEVER stored — they are used for the duration of the
connection and then discarded.  Option A by design.

Usage::

    from engines.credentialed.ssh_scanner import SSHScanner

    scanner = SSHScanner(ip="192.168.1.10", username="root", password="secret")
    with scanner:
        result = scanner.run("uname -r")
        print(result.stdout)
"""

import logging
import socket
import threading
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("ccure.ssh_scanner")

# ---------------------------------------------------------------------------
# Optional import — paramiko must be installed for credentialed scans
# ---------------------------------------------------------------------------
try:
    import paramiko
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
    stdout:     str  = ""
    stderr:     str  = ""
    exit_code:  int  = -1
    success:    bool = False


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
        ip:       str,
        username: str,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        port:     int = 22,
        timeout:  int = 10,
    ):
        self.ip       = ip
        self.username = username
        self._password = password        # leading underscore = not serialised
        self._key_path = key_path
        self.port     = port
        self.timeout  = timeout
        self._client: Optional["paramiko.SSHClient"] = None
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
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname":    self.ip,
            "port":        self.port,
            "username":    self.username,
            "timeout":     self.timeout,
            "banner_timeout": self.timeout,
            "auth_timeout":   self.timeout,
            "look_for_keys":  False,
            "allow_agent":    False,
        }

        if self._key_path:
            connect_kwargs["key_filename"] = self._key_path
        elif self._password:
            connect_kwargs["password"] = self._password
        else:
            raise ValueError("Either password or key_path must be provided.")

        try:
            client.connect(**connect_kwargs)
            self._client = client
            log.info("SSH connected to %s:%s as %s", self.ip, self.port, self.username)
        except paramiko.AuthenticationException as exc:
            raise RuntimeError(f"SSH authentication failed for {self.username}@{self.ip}: {exc}") from exc
        except (socket.timeout, paramiko.ssh_exception.NoValidConnectionsError) as exc:
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

    def run(self, command: str, timeout: Optional[int] = None) -> CommandResult:
        """
        Execute a command on the remote host.

        Parameters
        ----------
        command : Shell command string.
        timeout : Per-command timeout (defaults to self.timeout).

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
                _, stdout_fh, stderr_fh = self._client.exec_command(
                    command, timeout=_timeout, get_pty=False
                )
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
                exit_code   = stdout_fh.channel.recv_exit_status()

                return CommandResult(
                    stdout    = stdout_data,
                    stderr    = stderr_data,
                    exit_code = exit_code,
                    success   = (exit_code == 0),
                )
            except Exception as exc:
                log.debug("Command '%s' failed on %s: %s", command, self.ip, exc)
                return CommandResult(
                    stderr    = str(exc),
                    exit_code = -1,
                    success   = False,
                )

    def is_connected(self) -> bool:
        """Return True if the SSH transport is alive."""
        if self._client is None:
            return False
        transport = self._client.get_transport()
        return transport is not None and transport.is_active()

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
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
