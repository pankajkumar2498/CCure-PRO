"""
tests/scans/test_middleware_collector.py
─────────────────────────────────────────────────────────────────────────────
The ``structured_config`` collector. Phase 8 (GAP-09).

The collector's job is to turn "we read a file and looked for a thing" into one
of the four collection states, and every test here is really the same question:
did this path earn the state it returned?

Two of those decisions are load-bearing and both were reached against real
containers:

* **A missing configuration file is UNSUPPORTED, not ABSENT.** A Linux host
  that does not run Apache is not failing Apache's hardening rules. Getting
  this wrong hands every host in the estate a pile of findings about software
  it does not have — which is how a configuration report gets ignored
  wholesale.

* **An unresolved include poisons an absence.** The stock layouts of nginx and
  Apache both put the interesting settings in *included* files, so a directive
  missing from the file the rule names may simply be somewhere we did not look.
  Reporting ABSENT there is a verdict about a configuration that was never
  read.
"""

import pytest

from core.checks.contract import CheckOutcome
from core.config_audit.collection import CollectionContext, CollectionStatus
from core.config_audit.collectors import collector_registry, register_builtin_collectors
from core.config_audit.engine import ConfigAuditEngine
from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

register_builtin_collectors()

COLLECTOR = collector_registry.resolve("structured_config", "linux")

_VALUE = "CCURE::VALUE::"
_ABSENT = "CCURE::ABSENT::"


class Result:
    def __init__(self, stdout="", exit_code=0):
        self.stdout = stdout
        self.stderr = ""
        self.exit_code = exit_code
        self.success = exit_code == 0


class FakeShell:
    """
    A target whose filesystem is a dict.

    It answers the collector's own read and list commands by looking for the
    quoted path inside them, which keeps the test honest about the command the
    collector actually issues rather than stubbing the method that builds it.
    """

    def __init__(self, files=None, dirs=None, fail=False):
        self.files = files or {}
        self.dirs = dirs or {}
        self.fail = fail
        self.commands = []

    def run(self, command, timeout=None):
        self.commands.append(command)
        if self.fail:
            return Result(exit_code=1)

        # `shlex.quote` leaves an ordinary path unquoted, so the path is
        # matched bare. Longest match wins because a directory is a prefix of
        # the files inside it.
        if "find " in command:
            hit = self._longest(self.dirs, command)
            if hit is not None:
                return Result(_VALUE + "\n" + "\n".join(self.dirs[hit]))
            return Result(_ABSENT + "directory does not exist")

        hit = self._longest(self.files, command)
        if hit is not None:
            return Result(_VALUE + self.files[hit])
        return Result(_ABSENT + "file does not exist")

    @staticmethod
    def _longest(table, command):
        matches = [key for key in table if key in command]
        return max(matches, key=len) if matches else None


def _check(**collect):
    return ConfigCheck(
        check_id="ccure.mw.test.example",
        title="Example middleware check",
        check_type="structured_config",
        platforms=("linux",),
        collect=collect,
        expect=Expectation("is_true"),
        absent=AbsencePolicy.MANUAL_REVIEW,
    )


def _ctx(shell):
    return CollectionContext(
        target="host", platform="linux", executor=shell, timeout=10
    )


# ── Registration ─────────────────────────────────────────────────────────────


def test_registered_on_both_host_platforms():
    for platform in ("linux", "windows"):
        assert collector_registry.resolve("structured_config", platform) is not None


def test_not_registered_on_the_database_platform():
    assert collector_registry.resolve("structured_config", "database") is None


# ── The state a missing file earns ───────────────────────────────────────────


def test_a_missing_config_file_is_unsupported_not_absent():
    state = COLLECTOR.collect(
        _check(path="/etc/nginx/nginx.conf", format="nginx", directive="user"),
        _ctx(FakeShell()),
    )
    assert state.status is CollectionStatus.UNSUPPORTED
    assert "does not appear to be installed" in state.detail


def test_a_missing_config_file_becomes_not_applicable_at_the_engine():
    """
    The end-to-end consequence: a host without the product leaves the score
    rather than failing.
    """
    result = ConfigAuditEngine().run_check(
        _check(path="/etc/nginx/nginx.conf", format="nginx", directive="user"),
        _ctx(FakeShell()),
    )
    assert result.outcome is CheckOutcome.NOT_APPLICABLE


def test_missing_file_absent_policy_is_a_reading_for_products_that_have_defaults():
    """
    The Docker daemon: most hosts have no daemon.json at all, and that means
    every setting is at its default — a real state, not a missing product.
    """
    state = COLLECTOR.collect(
        _check(
            path="/etc/docker/daemon.json",
            format="json",
            pointer="icc",
            missing_file="absent",
        ),
        _ctx(FakeShell()),
    )
    assert state.status is CollectionStatus.ABSENT
    assert "built-in defaults" in state.detail


def test_an_unknown_missing_file_policy_is_unavailable():
    state = COLLECTOR.collect(
        _check(path="/x", format="json", pointer="a", missing_file="pretend_it_passed"),
        _ctx(FakeShell()),
    )
    assert state.status is CollectionStatus.UNAVAILABLE


def test_a_transport_failure_is_never_read_as_a_missing_product():
    """
    A host we could not reach has not told us anything about what it runs.
    Rendering that as "not installed" would silently drop the check.
    """
    state = COLLECTOR.collect(
        _check(path="/etc/nginx/nginx.conf", format="nginx", directive="user"),
        _ctx(FakeShell(fail=True)),
    )
    assert state.status is CollectionStatus.UNAVAILABLE


def test_no_session_is_unavailable():
    state = COLLECTOR.collect(
        _check(path="/etc/nginx/nginx.conf", format="nginx", directive="user"),
        _ctx(None),
    )
    assert state.status is CollectionStatus.UNAVAILABLE


def test_output_with_no_sentinel_is_unavailable_not_content():
    """
    A shell diagnostic parsed as configuration would produce a verdict about a
    file nobody read.
    """

    class Noisy(FakeShell):
        def run(self, command, timeout=None):
            return Result("sh: permission denied")

    state = COLLECTOR.collect(
        _check(path="/etc/nginx/nginx.conf", format="nginx", directive="user"),
        _ctx(Noisy()),
    )
    assert state.status is CollectionStatus.UNAVAILABLE


# ── Path candidates ──────────────────────────────────────────────────────────


def test_the_first_existing_candidate_path_wins():
    shell = FakeShell(files={"/etc/httpd/conf/httpd.conf": "ServerTokens Prod\n"})
    state = COLLECTOR.collect(
        _check(
            path=[
                "/etc/apache2/apache2.conf",
                "/etc/httpd/conf/httpd.conf",
                "/usr/local/apache2/conf/httpd.conf",
            ],
            format="apache",
            directive="ServerTokens",
        ),
        _ctx(shell),
    )
    assert state.status is CollectionStatus.COLLECTED
    assert state.value == "Prod"


def test_no_candidate_path_existing_is_unsupported():
    state = COLLECTOR.collect(
        _check(
            path=["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf"],
            format="apache",
            directive="ServerTokens",
        ),
        _ctx(FakeShell()),
    )
    assert state.status is CollectionStatus.UNSUPPORTED


# ── Include expansion ────────────────────────────────────────────────────────


NGINX_MAIN = "http {\n  include /etc/nginx/conf.d/*.conf;\n}\n"
NGINX_CHILD = "server {\n  listen 80;\n  server_tokens off;\n}\n"


def test_an_include_is_expanded_and_grafted_onto_its_parent_block():
    shell = FakeShell(
        files={
            "/etc/nginx/nginx.conf": NGINX_MAIN,
            "/etc/nginx/conf.d/default.conf": NGINX_CHILD,
        },
        dirs={"/etc/nginx/conf.d": ["default.conf"]},
    )
    state = COLLECTOR.collect(
        _check(
            path="/etc/nginx/nginx.conf",
            format="nginx",
            directive="server_tokens",
            scope=["http", "server"],
        ),
        _ctx(shell),
    )
    assert state.status is CollectionStatus.COLLECTED
    assert state.value == "off"


def test_an_unresolved_include_turns_an_absence_into_unavailable():
    """
    The property that keeps an absence honest. The directive is genuinely not
    in the file we read — but there is a file we could not read, so "not set"
    is not something this scan established.
    """
    shell = FakeShell(files={"/etc/nginx/nginx.conf": NGINX_MAIN})
    state = COLLECTOR.collect(
        _check(path="/etc/nginx/nginx.conf", format="nginx", directive="ssl_protocols"),
        _ctx(shell),
    )
    assert state.status is CollectionStatus.UNAVAILABLE
    assert "could not be expanded" in state.detail


def test_a_fully_expanded_tree_gives_a_trustworthy_absence():
    shell = FakeShell(
        files={
            "/etc/nginx/nginx.conf": NGINX_MAIN,
            "/etc/nginx/conf.d/default.conf": NGINX_CHILD,
        },
        dirs={"/etc/nginx/conf.d": ["default.conf"]},
    )
    state = COLLECTOR.collect(
        _check(path="/etc/nginx/nginx.conf", format="nginx", directive="ssl_protocols"),
        _ctx(shell),
    )
    assert state.status is CollectionStatus.ABSENT


def test_include_globs_are_matched_in_python_not_by_a_shell():
    """
    Include patterns come out of the *target's* configuration, so they are
    attacker-influenced in a way rule parameters are not. A glob handed to a
    shell for expansion is command execution on the target during an audit.
    """
    shell = FakeShell(
        files={
            "/etc/nginx/nginx.conf": "http {\n  include /etc/nginx/conf.d/*.conf;\n}\n",
            "/etc/nginx/conf.d/a.conf": "server { listen 80; }\n",
        },
        dirs={"/etc/nginx/conf.d": ["a.conf", "b.txt", "notes.md"]},
    )
    COLLECTOR.collect(
        _check(path="/etc/nginx/nginx.conf", format="nginx", directive="listen"),
        _ctx(shell),
    )
    # The directory is listed; the pattern itself never reaches a command.
    assert any("find " in c for c in shell.commands)
    assert not any("*.conf" in c for c in shell.commands)


def test_expansion_can_be_switched_off():
    shell = FakeShell(files={"/etc/nginx/nginx.conf": NGINX_MAIN})
    state = COLLECTOR.collect(
        _check(
            path="/etc/nginx/nginx.conf",
            format="nginx",
            directive="ssl_protocols",
            expand_includes=False,
        ),
        _ctx(shell),
    )
    # Still UNAVAILABLE, because the includes are recorded as unresolved.
    assert state.status is CollectionStatus.UNAVAILABLE


def test_reads_are_memoised_across_checks_on_one_context():
    """
    A middleware rule set reads the same handful of files many times over.
    Without memoisation the audit pays for the transport once per rule.
    """
    shell = FakeShell(files={"/etc/nginx/nginx.conf": "user nginx;\n"})
    ctx = _ctx(shell)
    for _ in range(5):
        COLLECTOR.collect(
            _check(path="/etc/nginx/nginx.conf", format="nginx", directive="user"),
            ctx,
        )
    assert len(shell.commands) == 1


# ── Result shapes ────────────────────────────────────────────────────────────


def test_value_takes_the_last_matching_directive():
    """nginx and Apache both let a later directive replace an earlier one."""
    shell = FakeShell(files={"/etc/nginx/nginx.conf": "user a;\nuser b;\n"})
    state = COLLECTOR.collect(
        _check(path="/etc/nginx/nginx.conf", format="nginx", directive="user"),
        _ctx(shell),
    )
    assert state.value == "b"


def test_values_returns_every_match():
    shell = FakeShell(files={"/etc/nginx/nginx.conf": "user a;\nuser b;\n"})
    state = COLLECTOR.collect(
        _check(
            path="/etc/nginx/nginx.conf",
            format="nginx",
            directive="user",
            result="values",
        ),
        _ctx(shell),
    )
    assert state.value == ["a", "b"]


def test_count_never_reports_absent():
    shell = FakeShell(files={"/etc/nginx/nginx.conf": "user a;\n"})
    state = COLLECTOR.collect(
        _check(
            path="/etc/nginx/nginx.conf",
            format="nginx",
            directive="nothing_here",
            result="count",
        ),
        _ctx(shell),
    )
    assert state.status is CollectionStatus.COLLECTED
    assert state.value == 0


def test_an_unknown_format_is_unavailable():
    state = COLLECTOR.collect(
        _check(path="/x", format="yaml", directive="a"),
        _ctx(FakeShell(files={"/x": ""})),
    )
    assert state.status is CollectionStatus.UNAVAILABLE


def test_an_unknown_result_shape_is_unavailable():
    shell = FakeShell(files={"/etc/nginx/nginx.conf": "user a;\n"})
    state = COLLECTOR.collect(
        _check(
            path="/etc/nginx/nginx.conf",
            format="nginx",
            directive="user",
            result="histogram",
        ),
        _ctx(shell),
    )
    assert state.status is CollectionStatus.UNAVAILABLE


def test_a_rule_missing_its_address_is_unavailable():
    shell = FakeShell(files={"/x": "user a;\n"})
    for collect in (
        {"path": "/x", "format": "nginx"},
        {"path": "/x", "format": "xml"},
        {"path": "/x", "format": "json"},
    ):
        state = COLLECTOR.collect(_check(**collect), _ctx(shell))
        assert state.status is CollectionStatus.UNAVAILABLE


def test_unparseable_content_is_unavailable_not_a_verdict():
    shell = FakeShell(files={"/x": "http { server {"})
    state = COLLECTOR.collect(
        _check(path="/x", format="nginx", directive="listen"), _ctx(shell)
    )
    assert state.status is CollectionStatus.UNAVAILABLE
    assert "could not be parsed" in state.detail


# ── Evidence ─────────────────────────────────────────────────────────────────


def test_evidence_names_the_file_and_the_includes_that_were_read():
    shell = FakeShell(
        files={
            "/etc/nginx/nginx.conf": NGINX_MAIN,
            "/etc/nginx/conf.d/default.conf": NGINX_CHILD,
        },
        dirs={"/etc/nginx/conf.d": ["default.conf"]},
    )
    state = COLLECTOR.collect(
        _check(
            path="/etc/nginx/nginx.conf",
            format="nginx",
            directive="server_tokens",
            scope=["http", "server"],
        ),
        _ctx(shell),
    )
    assert "/etc/nginx/nginx.conf" in state.raw
    assert "default.conf" in state.raw
