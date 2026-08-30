"""
tests/scans/test_ftp_write_safety.py
─────────────────────────────────────────────────────────────────────────────
The one probe in this product that writes to a scanned host, and the gate that
keeps it off.

Why this file exists
────────────────────
``ftp_checker._test_write_access`` issues ``MKD`` and ``RMD`` against the
target. It is the only place in the product that changes a host it is
assessing, and this product scans production networks and OT segments. Phase 6
flagged it "for a decision"; four phases later there was still no gate, and a
default scan of a customer's FTP server created a directory on it.

Three properties are asserted here, and the third is the one that is easy to
get wrong:

1. A default scan **never** sends MKD or RMD.
2. An operator who opts in gets the detection back, unchanged.
3. "Not tested" is **not** "not writable". ``write_access`` is tri-state, and a
   Critical finding is emitted only on a positive reading — because reporting
   False for a test that never ran is a false negative on the most severe
   condition this plugin can find.
"""

import socket

import pytest

from core.checks.intrusive import allow_intrusive_probes, intrusive_probes_allowed
from engines.vulnerability.network_checks import NETWORK_CHECKS
from engines.vulnerability.plugins import ftp_checker


# ── A socket that records every command it is sent ───────────────────────────


class RecordingSocket:
    """Stands in for a connection to an FTP server and remembers the dialogue."""

    def __init__(self, script, sent):
        self._script = list(script)
        self.sent = sent

    def settimeout(self, _timeout):
        pass

    def sendall(self, payload):
        self.sent.append(payload.decode("utf-8", "replace").strip())

    def recv(self, _size):
        if self._script:
            return self._script.pop(0).encode()
        return b"221 Bye\r\n"

    def close(self):
        pass


@pytest.fixture()
def ftp_server(monkeypatch):
    """
    A cooperative FTP server that accepts anonymous login and allows MKD.

    Returns the list of commands the plugin sent, so a test can assert on what
    reached the wire rather than only on the verdict. A gate that is bypassed
    still produces the right verdict; only the transcript shows it was bypassed.
    """
    sent: list[str] = []
    replies = {
        "USER": "331 Please specify the password.\r\n",
        "PASS": "230 Login successful.\r\n",
        "PASV": "227 Entering Passive Mode (127,0,0,1,200,1).\r\n",
        "MKD": '257 "/ccure_probe_test" created.\r\n',
        "RMD": "250 Remove directory operation successful.\r\n",
    }

    class Server(RecordingSocket):
        def __init__(self):
            super().__init__(["220 (vsFTPd 3.0.5)\r\n"], sent)

        def sendall(self, payload):
            text = payload.decode("utf-8", "replace").strip()
            sent.append(text)
            verb = text.split(" ", 1)[0].upper()
            self._script.append(replies.get(verb, "500 Unknown.\r\n"))

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: Server())
    return sent


def wrote_to_target(sent):
    """True if anything in the transcript changes the target."""
    return [
        cmd
        for cmd in sent
        if cmd.split(" ", 1)[0].upper() in ("MKD", "RMD", "STOR", "DELE")
    ]


# ── 1. The default never writes ──────────────────────────────────────────────


def test_intrusive_probes_are_forbidden_by_default():
    """
    The gate's default is the whole safety property. If this flips, nothing
    else in this file protects anybody.
    """
    assert intrusive_probes_allowed() is False


def test_a_default_scan_sends_no_mkd_or_rmd(ftp_server):
    result = ftp_checker._test_write_access("192.0.2.10", 21)
    assert result is None, "an untested condition must not be reported as a verdict"
    assert not wrote_to_target(
        ftp_server
    ), f"a default scan wrote to the target: {wrote_to_target(ftp_server)}"


def test_a_default_probe_of_a_writable_server_still_writes_nothing(ftp_server):
    """
    End to end through ``_probe_ftp``, against a server that *would* allow the
    write. The plugin must come away having established anonymous login and
    nothing about writability.
    """
    with allow_intrusive_probes(False):
        info = ftp_checker._probe_ftp("192.0.2.10", 21)
    assert info["anonymous_login"] is True
    assert info["write_access"] is None
    assert not wrote_to_target(ftp_server)


def test_the_operator_is_told_the_write_test_was_skipped(ftp_server):
    """
    A silently omitted check is indistinguishable from a check that passed.
    The reason, and the switch that enables it, both have to be in the report.
    """
    with allow_intrusive_probes(False):
        info = ftp_checker._probe_ftp("192.0.2.10", 21)
    skipped = [i for i in info["issues"] if "NOT assessed" in i]
    assert skipped, info["issues"]
    assert "SCAN_ALLOW_INTRUSIVE" in skipped[0]


# ── 2. Opting in restores the detection ──────────────────────────────────────


def test_an_opted_in_scan_performs_the_write_test(ftp_server):
    with allow_intrusive_probes(True):
        result = ftp_checker._test_write_access("192.0.2.10", 21)
    assert result is True
    verbs = [cmd.split(" ", 1)[0].upper() for cmd in ftp_server]
    assert "MKD" in verbs, "the detection must still be reachable when enabled"
    assert "RMD" in verbs, "what the probe created must be removed again"


def test_an_opted_in_probe_reports_write_access_and_emits_the_finding(ftp_server):
    with allow_intrusive_probes(True):
        info = ftp_checker._probe_ftp("192.0.2.10", 21)
    assert info["write_access"] is True
    assert any("WRITE access" in i for i in info["issues"])


def test_the_finding_is_emitted_only_on_a_positive_reading():
    """
    ``None`` is falsy, so a truthiness test would already suppress the finding
    — but only by accident. This pins the intent: a Critical finding rests on
    something established, and the same code must not start emitting if the
    sentinel ever changes.
    """
    for value, expected in ((True, True), (False, False), (None, False)):
        info = {
            "port": 21,
            "banner": "220 (vsFTPd 3.0.5)",
            "anonymous_login": True,
            "write_access": value,
            "weak_credentials": [],
            "cleartext_risk": True,
            "cves": [],
            "issues": [],
        }
        emitted = _areas_for(info)
        assert (
            "ftp.anonymous_write" in emitted
        ) is expected, f"write_access={value!r} produced {emitted}"


def _areas_for(info):
    """The finding areas ``run`` emits for a given probe result."""
    from unittest.mock import patch

    with patch.object(ftp_checker, "_probe_ftp", return_value=info):
        result = ftp_checker.run("192.0.2.10", [21])
    return {f.get("area") or f.get("check_area") for f in result.get("cves", [])}


# ── 3. Failures are handled, and never become verdicts ───────────────────────


def test_a_server_that_refuses_anonymous_login_is_a_real_negative(monkeypatch):
    """
    No anonymous session means no anonymous write access — that *is*
    established, and False is the right answer rather than None.
    """
    sent: list[str] = []

    class Refusing(RecordingSocket):
        def __init__(self):
            super().__init__(["220 ready\r\n"], sent)

        def sendall(self, payload):
            text = payload.decode().strip()
            sent.append(text)
            verb = text.split(" ", 1)[0].upper()
            self._script.append(
                "530 Login incorrect.\r\n" if verb == "PASS" else "331 pw\r\n"
            )

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: Refusing())
    with allow_intrusive_probes(True):
        assert ftp_checker._test_write_access("192.0.2.10", 21) is False
    assert not wrote_to_target(sent)


def test_a_connection_failure_is_unknown_not_not_writable(monkeypatch):
    def explode(*_args, **_kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(socket, "create_connection", explode)
    with allow_intrusive_probes(True):
        assert ftp_checker._test_write_access("192.0.2.10", 21) is None


def test_a_refused_mkd_is_a_real_negative(monkeypatch):
    sent: list[str] = []

    class Readonly(RecordingSocket):
        def __init__(self):
            super().__init__(["220 ready\r\n"], sent)

        def sendall(self, payload):
            text = payload.decode().strip()
            sent.append(text)
            verb = text.split(" ", 1)[0].upper()
            self._script.append(
                {
                    "USER": "331 pw\r\n",
                    "PASS": "230 ok\r\n",
                    "PASV": "227 pasv\r\n",
                    "MKD": "550 Permission denied.\r\n",
                }.get(verb, "500 no\r\n")
            )

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: Readonly())
    with allow_intrusive_probes(True):
        assert ftp_checker._test_write_access("192.0.2.10", 21) is False
    assert "RMD" not in [
        c.split(" ", 1)[0].upper() for c in sent
    ], "nothing was created, so nothing should be removed"


def test_a_failed_cleanup_is_logged_rather_than_swallowed(monkeypatch, caplog):
    """
    The finding still stands, but a directory was left on somebody's host and
    they have to be told which one.
    """
    sent: list[str] = []

    class NoCleanup(RecordingSocket):
        def __init__(self):
            super().__init__(["220 ready\r\n"], sent)

        def sendall(self, payload):
            text = payload.decode().strip()
            sent.append(text)
            verb = text.split(" ", 1)[0].upper()
            self._script.append(
                {
                    "USER": "331 pw\r\n",
                    "PASS": "230 ok\r\n",
                    "PASV": "227 pasv\r\n",
                    "MKD": '257 "/ccure_probe_test" created.\r\n',
                    "RMD": "550 Permission denied.\r\n",
                }.get(verb, "500 no\r\n")
            )

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: NoCleanup())
    with caplog.at_level("WARNING", logger="ccure.plugin.ftp"):
        with allow_intrusive_probes(True):
            assert ftp_checker._test_write_access("192.0.2.10", 21) is True
    assert any("ccure_probe_test" in r.message for r in caplog.records), caplog.text


# ── The policy vocabulary this hangs off ─────────────────────────────────────


def test_the_catalogue_declares_exactly_one_intrusive_check():
    """
    The flag connects this probe to the vocabulary the rest of the product
    already speaks — ``CheckSpec.intrusive``,
    ``CheckRegistry.select(allow_intrusive=...)`` and
    ``select_checks(include_intrusive=...)``. A second check acquiring it
    silently is a second thing that writes to hosts.
    """
    intrusive = sorted(c.area for c in NETWORK_CHECKS if c.intrusive)
    assert intrusive == ["ftp.anonymous_write"]


def test_the_flag_reaches_the_check_spec():
    check = next(c for c in NETWORK_CHECKS if c.area == "ftp.anonymous_write")
    assert check.spec().intrusive is True
    other = next(c for c in NETWORK_CHECKS if c.area == "ftp.anonymous_login")
    assert other.spec().intrusive is False


def test_the_registry_withholds_intrusive_checks_unless_asked():
    """The selection default that every caller relies on."""
    from core.checks.contract import CheckSpec
    from core.checks.registry import CheckRegistry

    registry = CheckRegistry()
    spec = next(c for c in NETWORK_CHECKS if c.area == "ftp.anonymous_write").spec()
    registry.register(spec, lambda _ctx: None)
    assert [e.spec.check_id for e in registry.select()] == []
    assert [e.spec.check_id for e in registry.select(allow_intrusive=True)] == [
        spec.check_id
    ]


def test_the_override_is_restored_even_when_the_block_raises():
    """A scan that fails must not leave the scanner permitted to write."""
    before = intrusive_probes_allowed()
    with pytest.raises(RuntimeError):
        with allow_intrusive_probes(True):
            raise RuntimeError("boom")
    assert intrusive_probes_allowed() is before
