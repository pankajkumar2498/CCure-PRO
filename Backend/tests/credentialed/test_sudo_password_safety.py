"""
The sudo password never reaches the target's argv, a log, or an exception.

The defect these exist for: ``LinuxCollector._run`` built
``echo 'PASSWORD' | sudo -S …`` and handed it to ``SSHScanner.run``, which
passes the string to ``exec_command``. The remote shell sshd spawns therefore
carried the customer's password in its argv — visible in ``ps`` to every local
user on the target, recorded permanently by any ``execve`` audit rule, and from
there into this scanner's own debug log, which logged the full command string on
failure.

These assert on the **command actually handed to the transport** and on
**captured log records**, not on the return value. A test that only checked
"sudo still works" passes just as well against the vulnerable implementation.
"""

import logging

import pytest
from engines.credentialed.ssh_scanner import (
    CommandResult,
    SSHScanner,
    _rewrite_sudo_for_stdin,
)

PASSWORD = "Sup3rS3cret!Passw0rd#42"

#: Verbatim from ``linux_collector.COMMANDS`` — the two entries that elevate.
DMI_SERIAL = (
    "ser=$(sudo -n dmidecode -s system-serial-number 2>/dev/null || "
    'cat /sys/class/dmi/id/product_serial 2>/dev/null); echo "$ser"'
)
SUDO_RULES = "sudo -ln 2>/dev/null || sudo -l 2>/dev/null"


class _FakeChannel:
    def __init__(self, payload=b""):
        self._payload = payload
        self._sent = False
        self.shutdown_write_called = False

    def settimeout(self, _t):
        pass

    def recv(self, _n):
        if self._sent:
            return b""
        self._sent = True
        return self._payload

    def recv_exit_status(self):
        return 0

    def shutdown_write(self):
        self.shutdown_write_called = True


class _FakeStdin:
    def __init__(self, channel):
        self.channel = channel
        self.written = []

    def write(self, data):
        self.written.append(data)

    def flush(self):
        pass


class _FakeStd:
    def __init__(self, channel, payload=b""):
        self.channel = channel
        self._payload = payload

    def read(self):
        return self._payload


class _RecordingClient:
    """Captures exactly what would be executed on the target."""

    def __init__(self, stdout=b"ok", raises=None):
        self.commands = []
        self.stdin_writes = []
        self._stdout = stdout
        self._raises = raises

    def exec_command(self, command, timeout=None, get_pty=False):
        self.commands.append(command)
        if self._raises:
            raise self._raises
        out_channel = _FakeChannel(self._stdout)
        stdin = _FakeStdin(_FakeChannel())
        self.stdin_writes.append(stdin)
        return stdin, _FakeStd(out_channel, self._stdout), _FakeStd(_FakeChannel(), b"")

    def close(self):
        pass


def _scanner(password=PASSWORD, client=None):
    s = SSHScanner(ip="10.0.0.5", username="svc", password=password)
    s._client = client if client is not None else _RecordingClient()
    return s


# ─────────────────────────────────────────────────────────────────────────────
# The rewrite itself
# ─────────────────────────────────────────────────────────────────────────────


def test_the_rewrite_never_pipes_anything_into_sudo():
    """``echo … | sudo -S`` is the shape that put the password in argv."""
    rewritten, _ = _rewrite_sudo_for_stdin(DMI_SERIAL)
    assert "| sudo" not in rewritten
    assert "echo '" not in rewritten


def test_the_rewrite_asks_sudo_to_read_stdin_and_stay_quiet():
    rewritten, count = _rewrite_sudo_for_stdin("sudo cat /etc/shadow")
    assert rewritten == "sudo -S -p '' cat /etc/shadow"
    assert count == 1


def test_non_interactive_is_stripped_because_it_overrides_stdin():
    """
    ``-n`` means "never prompt" and sudo honours it over ``-S``. Left in place
    it refuses the password this rewrite exists to deliver, which reads on the
    target as a permission failure rather than as a scanner bug.
    """
    rewritten, _ = _rewrite_sudo_for_stdin(DMI_SERIAL)
    assert "sudo -S -p '' dmidecode" in rewritten
    assert " -n " not in rewritten


def test_non_interactive_is_stripped_out_of_a_bundled_flag():
    """``-ln`` is ``-l -n``; only the ``-n`` half must go."""
    rewritten, count = _rewrite_sudo_for_stdin(SUDO_RULES)
    assert rewritten == "sudo -S -p '' -l 2>/dev/null || sudo -S -p '' -l 2>/dev/null"
    assert count == 2


def test_a_command_without_sudo_is_returned_untouched():
    original = "cat /etc/os-release"
    rewritten, count = _rewrite_sudo_for_stdin(original)
    assert rewritten == original
    assert count == 0


def test_other_sudo_flags_survive_the_rewrite():
    """``-n`` is the only sudo short flag with that letter; nothing else moves."""
    rewritten, _ = _rewrite_sudo_for_stdin("sudo -u root -H id")
    assert rewritten == "sudo -S -p '' -u root -H id"


# ─────────────────────────────────────────────────────────────────────────────
# The password never reaches the target's argv
# ─────────────────────────────────────────────────────────────────────────────


def test_the_password_is_absent_from_every_command_sent_to_the_target():
    """The core assertion. Anything in argv is visible in ``ps``."""
    client = _RecordingClient()
    scanner = _scanner(client=client)
    scanner.run_sudo(DMI_SERIAL)
    scanner.run_sudo(SUDO_RULES)

    assert client.commands, "nothing was executed"
    for command in client.commands:
        assert PASSWORD not in command


def test_the_password_travels_on_stdin_instead():
    client = _RecordingClient()
    scanner = _scanner(client=client)
    scanner.run_sudo("sudo cat /etc/shadow")

    written = "".join(client.stdin_writes[0].written)
    assert written == PASSWORD + "\n"


def test_one_password_line_is_written_per_sudo_invocation():
    """
    ``sudo -l || sudo -l`` runs at most one of them, but which is decided on the
    target: a second that runs because the first failed must find another line
    waiting. Relying on sudo's credential cache breaks under
    ``timestamp_timeout=0``.
    """
    client = _RecordingClient()
    scanner = _scanner(client=client)
    scanner.run_sudo(SUDO_RULES)

    written = "".join(client.stdin_writes[0].written)
    assert written == (PASSWORD + "\n") * 2


def test_stdin_is_half_closed_so_the_remote_command_sees_eof():
    """Without the shutdown the target blocks on stdin until the timeout."""
    client = _RecordingClient()
    scanner = _scanner(client=client)
    scanner.run_sudo("sudo id")
    assert client.stdin_writes[0].channel.shutdown_write_called is True


def test_an_ordinary_run_writes_nothing_to_stdin():
    client = _RecordingClient()
    scanner = _scanner(client=client)
    scanner.run("cat /etc/os-release")
    assert client.stdin_writes[0].written == []
    assert client.stdin_writes[0].channel.shutdown_write_called is False


# ─────────────────────────────────────────────────────────────────────────────
# A key-only session keeps working
# ─────────────────────────────────────────────────────────────────────────────


def test_a_session_with_no_password_runs_the_command_unchanged():
    """A key-only session keeps whatever ``sudo -n`` behaviour was written."""
    client = _RecordingClient()
    scanner = _scanner(password=None, client=client)
    scanner.run_sudo(DMI_SERIAL)

    assert client.commands == [DMI_SERIAL]
    assert client.stdin_writes[0].written == []


def test_has_password_reports_without_exposing_the_secret():
    assert _scanner().has_password is True
    assert _scanner(password=None).has_password is False


def test_a_command_with_no_sudo_is_not_rewritten_even_with_a_password():
    client = _RecordingClient()
    scanner = _scanner(client=client)
    scanner.run_sudo("cat /etc/os-release")
    assert client.commands == ["cat /etc/os-release"]
    assert client.stdin_writes[0].written == []


# ─────────────────────────────────────────────────────────────────────────────
# The password never reaches a log or an exception
# ─────────────────────────────────────────────────────────────────────────────


def test_a_failing_command_does_not_log_the_password(caplog):
    """
    ``run`` logs the full command string when execution raises. That line was
    the second half of the leak: the injected command reached the scanner's own
    log file, where it persists long after the scan.
    """
    client = _RecordingClient(raises=OSError("channel closed"))
    scanner = _scanner(client=client)
    with caplog.at_level(logging.DEBUG):
        result = scanner.run_sudo(DMI_SERIAL)

    assert result.success is False
    assert caplog.records, "nothing was logged"
    for record in caplog.records:
        assert PASSWORD not in record.getMessage()


def test_a_password_appearing_in_an_exception_is_redacted(caplog):
    """Belt and braces: the transport may quote back what it was given."""
    client = _RecordingClient(raises=OSError(f"refused: {PASSWORD}"))
    scanner = _scanner(client=client)
    with caplog.at_level(logging.DEBUG):
        scanner.run("id")

    joined = " ".join(r.getMessage() for r in caplog.records)
    assert PASSWORD not in joined
    assert "***REDACTED***" in joined


def test_redaction_leaves_ordinary_text_alone():
    scanner = _scanner()
    assert scanner._redact("nothing secret here") == "nothing secret here"


def test_redaction_is_a_no_op_without_a_password():
    scanner = _scanner(password=None)
    assert scanner._redact("plain text") == "plain text"


# ─────────────────────────────────────────────────────────────────────────────
# The collector never handles the secret at all
# ─────────────────────────────────────────────────────────────────────────────


class _SudoAwareExecutor:
    """Records every command and every elevation request."""

    ip = "10.0.0.5"

    def __init__(self, password=PASSWORD):
        self._password = password
        self.commands = []
        self.sudo_commands = []

    @property
    def has_password(self):
        return bool(self._password)

    def run(self, command, timeout=None, stdin_data=None):
        self.commands.append(command)
        return CommandResult(stdout="value", exit_code=0, success=True)

    def run_sudo(self, command, timeout=None):
        self.sudo_commands.append(command)
        self.commands.append(command)
        return CommandResult(stdout="value", exit_code=0, success=True)


def test_the_collector_routes_elevation_through_the_executor(caplog):
    from engines.credentialed.linux_collector import LinuxCollector

    executor = _SudoAwareExecutor()
    collector = LinuxCollector(executor)
    with caplog.at_level(logging.DEBUG):
        collector._run("sudo_rules")

    assert executor.sudo_commands, "elevation was not requested"
    for command in executor.commands:
        assert PASSWORD not in command
    for record in caplog.records:
        assert PASSWORD not in record.getMessage()


def test_the_collector_does_not_elevate_without_a_password():
    from engines.credentialed.linux_collector import LinuxCollector

    executor = _SudoAwareExecutor(password=None)
    LinuxCollector(executor)._run("sudo_rules")
    assert executor.sudo_commands == []


def test_the_collector_source_no_longer_builds_a_piped_sudo_command():
    """
    A source-level guard. The vulnerable shape was an f-string interpolating the
    password into ``echo '…' | sudo -S``; nothing in the collector may
    reconstruct it, and nothing may read the private attribute again.
    """
    import inspect
    import io
    import re
    import tokenize

    from engines.credentialed import linux_collector

    source = inspect.getsource(linux_collector)
    # Comments are stripped first. The comment above the fix quotes the
    # vulnerable shape in order to explain it, and a guard that cannot tell
    # code from prose would either fire on that or force the explanation out.
    code = "".join(
        token.string if token.type != tokenize.COMMENT else ""
        for token in tokenize.generate_tokens(io.StringIO(source).readline)
    )

    # A *single* pipe into sudo — the injection shape. ``|| sudo`` is an
    # ordinary shell fallback and appears legitimately in the command
    # catalogue, so the negative lookbehind is load-bearing.
    assert re.search(r"(?<!\|)\|\s*sudo", code) is None
    # The session's private password attribute, however it is reached.
    assert "._password" not in code
    assert '"_password"' not in code


@pytest.mark.parametrize("module", ["linux_collector", "windows_collector"])
def test_no_collector_reads_the_sessions_private_password(module):
    """
    A collector drives a transport; it has no business holding the secret. The
    executors themselves legitimately store one, so only collectors are checked.
    """
    import importlib
    import inspect

    mod = importlib.import_module(f"engines.credentialed.{module}")
    source = inspect.getsource(mod)
    assert "._password" not in source
    assert '"_password"' not in source


def test_a_sudo_flag_after_an_option_value_is_out_of_reach_and_says_so(caplog):
    """
    The rewrite reads sudo's option bundle up to the first non-flag token, so a
    ``-n`` after an option's *value* survives. No shipped command has that
    shape. Documented rather than parsed around: telling a ``-n`` that belongs
    to sudo from one that belongs to the command it runs needs a table of which
    sudo flags take a value, and getting that wrong mangles the command.

    What must not happen is silence — sudo would honour the surviving ``-n``,
    refuse the password, and the target would report a permission failure.
    """
    client = _RecordingClient()
    scanner = _scanner(client=client)
    with caplog.at_level(logging.WARNING):
        scanner.run_sudo("sudo -u postgres -n psql -c 'select 1'")

    assert any("refuse the password" in r.getMessage() for r in caplog.records)
    # Still no secret in the command, whatever else is true of it.
    for command in client.commands:
        assert PASSWORD not in command


def test_the_shipped_catalogue_has_no_command_the_rewrite_cannot_elevate():
    """
    The boundary above, pinned against real content. A command added with a
    ``-n`` sudo cannot see fails here rather than on a customer's host.
    """
    import re as _re

    from engines.credentialed.linux_collector import COMMANDS

    for key, command in COMMANDS.items():
        if "sudo" not in command:
            continue
        rewritten, count = _rewrite_sudo_for_stdin(command)
        assert count > 0, key
        assert _re.search(r"\s-n(\s|$)", rewritten) is None, key
