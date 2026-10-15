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


# ─────────────────────────────────────────────────────────────────────────────
# Every elevation path in the application, not only the collector
#
# The collector guard above inspects one module. Compliance remediation had its
# own copy of the vulnerable shape (``_inject_sudo_password`` in
# core/compliance_tasks.py) for weeks after the collector was fixed, because
# nothing looked anywhere else. These look everywhere.
# ─────────────────────────────────────────────────────────────────────────────

#: A single pipe into sudo. ``|| sudo`` is a shell fallback, not a pipe.
_PIPED_SUDO = r"(?<!\|)\|(?!\|)\s*sudo\b"


def _interpolated_piped_sudo(source: str) -> list[int]:
    """
    Lines where code *builds* a string that pipes into sudo out of a variable —
    an f-string, ``%`` formatting, ``+`` concatenation or ``.format``. That is
    the shape that carries a secret into the command line. A fixed literal (a
    redaction placeholder, a remediation catalogue entry) carries none, and is
    the catalogue test's business below.
    """
    import ast
    import re

    pattern = re.compile(_PIPED_SUDO)
    hits: list[int] = []

    def literal(node) -> str | None:
        return (
            node.value
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            else None
        )

    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.JoinedStr):
            text = "".join(
                v.value if isinstance(v, ast.Constant) else "{}" for v in node.values
            )
            if any(
                isinstance(v, ast.FormattedValue) for v in node.values
            ) and pattern.search(text):
                hits.append(node.lineno)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            sides = [literal(node.left), literal(node.right)]
            if any(s and pattern.search(s) for s in sides) and None in sides:
                hits.append(node.lineno)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and literal(node.func.value)
            and pattern.search(literal(node.func.value))
        ):
            hits.append(node.lineno)
    return sorted(set(hits))


def _application_sources():
    from testpaths import BACKEND_ROOT

    skip = {"tests", ".venv", "__pycache__", "alembic", "logs", "reports", "data"}
    for path in sorted(BACKEND_ROOT.rglob("*.py")):
        rel = path.relative_to(BACKEND_ROOT)
        if skip.intersection(rel.parts[:-1]) or any(
            p.startswith(".") for p in rel.parts[:-1]
        ):
            continue
        yield rel, path.read_text(encoding="utf-8")


def test_the_guard_recognises_the_shape_it_exists_for():
    """A guard that cannot see the vulnerability passes for the wrong reason."""
    vulnerable = (
        "def inject(command, password):\n"
        "    escaped = password.replace(\"'\", \"'\\\\''\")\n"
        "    replacement = f\"echo '{escaped}' | sudo -S\"\n"
        "    return replacement\n"
        "a = \"echo '%s' | sudo -S \" % password\n"
        'b = "echo \'" + password + "\' | sudo -S"\n'
        "c = \"echo '{}' | sudo -S\".format(password)\n"
    )
    assert _interpolated_piped_sudo(vulnerable) == [3, 5, 6, 7]
    # Fixed text is not interpolation, and ``||`` is not a pipe.
    assert (
        _interpolated_piped_sudo(
            "x = \"echo '[REDACTED_PASSWORD]' | sudo -S\"\n"
            'y = f"sudo -l || sudo -n {flag}"\n'
        )
        == []
    )


def test_no_module_interpolates_anything_into_a_piped_sudo_command():
    offenders = [
        f"{rel}:{line}"
        for rel, source in _application_sources()
        for line in _interpolated_piped_sudo(source)
    ]
    assert offenders == [], (
        "These build a command that pipes into sudo from a variable. A sudo "
        "password belongs on the remote command's stdin — SSHScanner.run_sudo — "
        f"never in the command text: {offenders}"
    )


#: Executors hold their own session's secret. Nothing else reads one.
_EXECUTORS_HOLDING_A_PASSWORD = {
    "engines/credentialed/ssh_scanner.py",
    "engines/credentialed/winrm_executor.py",
    "engines/credentialed/smb_executor.py",
    "engines/credentialed/database_executor.py",
}


def test_only_an_executor_touches_a_session_password_attribute():
    import ast

    offenders = []
    for rel, source in _application_sources():
        if rel.as_posix() in _EXECUTORS_HOLDING_A_PASSWORD:
            continue
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Attribute) and node.attr == "_password":
                offenders.append(f"{rel}:{node.lineno}")
            if isinstance(node, ast.Constant) and node.value == "_password":
                offenders.append(f"{rel}:{node.lineno}")
    assert offenders == [], offenders


# ─────────────────────────────────────────────────────────────────────────────
# Compliance remediation (core/compliance_tasks._execute_ssh_remediation)
#
# The maker-checker remediation path runs commands that *change* a customer's
# host, with sudo, over SSH. It used to rewrite every sudo as
# ``echo '<password>' | sudo -S``. These drive the real function against a
# recording transport and assert on what would have reached the target.
# ─────────────────────────────────────────────────────────────────────────────

#: Quotes, shell metacharacters, a command substitution and a backslash — every
#: character the old single-quote escaping had to get right.
HOSTILE_PASSWORDS = [
    PASSWORD,
    "it's-a-'quote'",
    'dbl"quote"',
    "$(id);rm -rf /tmp/x|&`whoami`",
    "back\\slash\\'mix",
    "spaces and *globs?",
]


class _Remediation:
    """Holds what the patched transport saw."""

    def __init__(self):
        self.scanners: list = []
        #: Kept here because the executor disconnects in ``finally``, which
        #: drops the session's own reference to its client.
        self.clients: list = []

    @property
    def commands(self):
        return [c for client in self.clients for c in client.commands]

    @property
    def stdin(self):
        return [
            "".join(w.written) for client in self.clients for w in client.stdin_writes
        ]


@pytest.fixture
def remediation(monkeypatch):
    """Patch the SSH transport the remediation executor constructs."""
    import engines.credentialed.ssh_scanner as ssh_scanner

    seen = _Remediation()
    stdout = {"value": b"done"}
    exec_raises = {"value": None}

    class _RecordingSSHScanner(ssh_scanner.SSHScanner):
        def connect(self):
            self._client = _RecordingClient(
                stdout=stdout["value"], raises=exec_raises["value"]
            )
            seen.scanners.append(self)
            seen.clients.append(self._client)

    monkeypatch.setattr(ssh_scanner, "SSHScanner", _RecordingSSHScanner)
    seen.stdout = stdout
    seen.exec_raises = exec_raises
    return seen


def _remediate(command, *, password=PASSWORD, key_content=None, platform="linux"):
    from core.compliance_tasks import _execute_ssh_remediation

    return _execute_ssh_remediation(
        ip="10.0.0.9",
        port=22,
        username="svc",
        password=password,
        key_content=key_content,
        command=command,
        target_platform=platform,
    )


@pytest.mark.parametrize("password", HOSTILE_PASSWORDS)
def test_remediation_never_puts_the_password_in_the_command(remediation, password):
    command = (
        "sudo ufw delete deny 139/tcp\n"
        "sudo iptables -D INPUT -p tcp --dport 139 -j DROP"
    )
    result = _remediate(command, password=password)

    assert result["success"] is True
    assert remediation.commands, "the command never reached the transport"
    for sent in remediation.commands:
        assert password not in sent
        assert "echo '" not in sent
        assert "sudo -S -p ''" in sent
    # One password line per sudo invocation, on stdin and nowhere else.
    assert remediation.stdin == [(password + "\n") * 2]
    # What the task stores as "the command run on target" is the operator's text.
    assert result["executed_command"] == command
    assert password not in repr(result)


def test_the_injection_helper_is_gone():
    import core.compliance_tasks as compliance_tasks

    assert not hasattr(compliance_tasks, "_inject_sudo_password")


def test_a_key_credential_runs_the_command_exactly_as_written(remediation):
    command = "sudo -n systemctl restart sshd"
    result = _remediate(command, password=None, key_content="KEY-MATERIAL")

    assert result["success"] is True
    assert remediation.commands == [command]
    assert remediation.stdin == [""]


def test_a_fallback_is_not_a_pipe_and_each_branch_gets_a_line(remediation):
    command = "sudo apt-get install -y aide || sudo yum install -y aide"
    result = _remediate(command)

    assert result["success"] is True
    assert PASSWORD not in remediation.commands[0]
    assert remediation.stdin == [(PASSWORD + "\n") * 2]


def test_a_command_piping_into_sudo_is_refused_before_connecting(remediation):
    """
    ``echo X | sudo tee F``: sudo's stdin is the pipe, so ``-S`` would read X as
    the password, and the real one could only travel on the command line. The
    old injection wrote the *password* into F wherever sudo needed none.
    """
    command = "echo 'APPROVED' | sudo tee /etc/ccure/policies/policy.txt"
    result = _remediate(command)

    assert result["success"] is False
    assert "pipes data into sudo" in result["error"]
    assert remediation.scanners == [], "nothing may reach the target"
    assert PASSWORD not in repr(result)


def test_piping_into_sudo_runs_unchanged_when_no_password_is_needed(remediation):
    command = "echo 'APPROVED' | sudo tee /etc/ccure/policies/policy.txt"
    result = _remediate(command, password=None, key_content="KEY-MATERIAL")

    assert result["success"] is True
    assert remediation.commands == [command]


def test_windows_remediation_carries_no_password(remediation):
    import base64

    command = "Set-Service -Name RemoteRegistry -StartupType Disabled"
    result = _remediate(command, platform="windows")

    assert result["success"] is True
    sent = remediation.commands[0]
    assert sent.startswith("powershell.exe")
    decoded = base64.b64decode(sent.rsplit(" ", 1)[1]).decode("utf-16le")
    assert decoded == command
    assert PASSWORD not in sent and PASSWORD not in decoded
    assert remediation.stdin == [""]


def test_output_that_echoes_the_password_is_redacted(remediation):
    """
    A sudo branch that never runs (``a || sudo b`` when ``a`` succeeds) leaves
    its password line unread on stdin, where a later command could read and
    print it — into the execution log the task stores. Redacted on the way out.
    """
    remediation.stdout["value"] = f"read from stdin: {PASSWORD}".encode()
    result = _remediate("sudo systemctl restart smbd")

    assert PASSWORD not in result["stdout"]
    assert "***REDACTED***" in result["stdout"]


def test_a_transport_error_that_carries_the_password_is_redacted(remediation):
    remediation.exec_raises["value"] = RuntimeError(f"channel closed near {PASSWORD}")
    result = _remediate("sudo systemctl restart smbd")

    assert result["success"] is False
    assert PASSWORD not in repr(result)


def _shipped_remediation_commands():
    """
    Every Linux remediation the product ships: the rollback table, and the fix
    catalogue ``scripts/seed_real_rules.py`` writes into compliance_remediations
    (a literal inside the seeding function, so it is read from the source).
    """
    import ast

    from core.compliance_tasks import ROLLBACK_COMMANDS, _extract_platform_commands
    from testpaths import SCRIPTS_DIR

    tree = ast.parse((SCRIPTS_DIR / "seed_real_rules.py").read_text(encoding="utf-8"))
    fix_commands = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "FIX_COMMANDS" for t in node.targets
        ):
            fix_commands = ast.literal_eval(node.value)
    assert fix_commands, "FIX_COMMANDS not found in seed_real_rules.py"

    for source, table in (("rollback", ROLLBACK_COMMANDS), ("fix", fix_commands)):
        for key, text in table.items():
            linux = _extract_platform_commands(text, "linux")
            if "sudo" in linux:
                yield f"{source}:{key}", linux


#: Shipped remediations that pipe into sudo. Each is refused when a password
#: would be needed (above) and must be rewritten as ``sudo sh -c '…'`` before
#: it can run with a password credential. Add nothing here: rewrite it instead.
KNOWN_PIPED_SUDO_REMEDIATIONS = {
    "fix:NIS2-GOV-RISK",
    "fix:NIS2-INC-LOGS",
    "fix:NIS2-SEC-CVD",
}


def test_every_shipped_remediation_elevates_through_stdin():
    import re

    piped = set()
    for key, command in _shipped_remediation_commands():
        if re.search(_PIPED_SUDO, command):
            piped.add(key)
            continue
        rewritten, count = _rewrite_sudo_for_stdin(command)
        assert count > 0, key
        assert "echo '" not in rewritten or "| sudo" not in rewritten, key
        assert re.search(r"\s-n(\s|$)", rewritten) is None, key
    assert piped == KNOWN_PIPED_SUDO_REMEDIATIONS
