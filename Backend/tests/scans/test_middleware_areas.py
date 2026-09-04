"""
tests/scans/test_middleware_areas.py
─────────────────────────────────────────────────────────────────────────────
Every GAP-09 area this build claims, exercised in both directions. Phase 8.

The area names below are literals on purpose.
``scripts/measure_middleware_coverage.py`` reads these test sources to decide
which areas count as *tested*, so an area whose test is deleted loses its
coverage credit rather than keeping it until somebody remembers to update a
hand-maintained list. Same construction as Phases 5, 6 and 7, and for the same
reason: a coverage figure that cannot go down is not a measurement.

Each area is driven through the real :class:`ConfigAuditEngine` against a
fake filesystem, twice: once with configuration that violates the rule, which
must produce a FAIL carrying evidence and remediation, and once with
configuration that satisfies it, which must produce a PASS.

A check that can never fail is indistinguishable from a clean estate; a check
that fails on everything reaches a customer as a false positive. Both have
shipped in this product before.
"""

import pytest

from core.checks.contract import CheckOutcome
from core.config_audit.builtin import MIDDLEWARE_CHECKS
from core.config_audit.collection import CollectionContext
from core.config_audit.engine import ConfigAuditEngine
from scripts.measure_middleware_coverage import SCOPE

IMPLEMENTED_AREAS = [
    "mw.disclosure.version_tokens",
    "mw.disclosure.status_endpoint",
    "mw.disclosure.default_content",
    "mw.access.override_files",
    "mw.access.default_accounts",
    "mw.access.admin_interface",
    "mw.process.run_as_user",
    "mw.process.file_permissions",
    "mw.process.privilege_flags",
    "mw.tls.protocols_configured",
    "mw.tls.ciphers_configured",
    "mw.tls.server_preference",
    "mw.tls.daemon_socket",
    "mw.log.access_log",
    "mw.log.error_log",
    "mw.log.log_level",
    "mw.log.driver_configured",
    "mw.limits.request_body",
    "mw.limits.timeouts",
    "mw.limits.ulimits",
    "mw.exposure.management_port",
    "mw.exposure.daemon_socket_tcp",
    "mw.exposure.inter_container",
    "mw.exposure.insecure_registry",
]

_VALUE = "CCURE::VALUE::"
_ABSENT = "CCURE::ABSENT::"


class _Result:
    def __init__(self, stdout="", exit_code=0):
        self.stdout = stdout
        self.stderr = ""
        self.exit_code = exit_code
        self.success = exit_code == 0


class _Filesystem:
    """A target whose files and directories are dictionaries."""

    def __init__(self, files, dirs=None, present_dirs=()):
        self.files = files
        self.dirs = dirs or {}
        self.present_dirs = set(present_dirs)

    def run(self, command, timeout=None):
        if "find " in command:
            hit = self._longest(self.dirs, command)
            if hit is not None:
                return _Result(_VALUE + "\n" + "\n".join(self.dirs[hit]))
            return _Result(_ABSENT + "directory does not exist")
        if "-d " in command or "PathType Container" in command:
            hit = self._longest({d: d for d in self.present_dirs}, command)
            if hit is not None:
                return _Result(_VALUE + "present")
            return _Result(_ABSENT + "directory does not exist")
        hit = self._longest(self.files, command)
        if hit is not None:
            return _Result(_VALUE + self.files[hit])
        return _Result(_ABSENT + "file does not exist")

    @staticmethod
    def _longest(table, command):
        matches = [k for k in table if k in command]
        return max(matches, key=len) if matches else None


class _Stat:
    """A target that answers only the permission collector's stat command."""

    def __init__(self, mode):
        self.mode = mode

    def run(self, command, timeout=None):
        if "stat" in command:
            return _Result(_VALUE + self.mode)
        return _Result(_ABSENT + "file does not exist")


# ── Per-product fixtures ─────────────────────────────────────────────────────

NGINX_WEAK = """
user root;
error_log /var/log/nginx/error.log crit;
http {
    server_tokens on;
    access_log off;
    keepalive_timeout 0;
    client_max_body_size 0;
    ssl_protocols TLSv1 TLSv1.1;
    ssl_ciphers HIGH:aNULL:MD5;
    ssl_prefer_server_ciphers off;
    server { location /s { stub_status; } }
}
"""

NGINX_STRONG = """
user nginx;
error_log /var/log/nginx/error.log warn;
http {
    server_tokens off;
    access_log /var/log/nginx/access.log;
    keepalive_timeout 65;
    client_max_body_size 8m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
}
"""

APACHE_WEAK = """
ServerRoot "/etc/apache2"
ServerTokens Full
Timeout 600
LogLevel error
User root
<Location /server-status>
    SetHandler server-status
</Location>
<Directory />
    AllowOverride All
</Directory>
"""

APACHE_STRONG = """
ServerRoot "/etc/apache2"
ServerTokens Prod
Timeout 60
LogLevel warn
User www-data
ErrorLog logs/error_log
CustomLog logs/access_log combined
<Directory />
    AllowOverride None
</Directory>
"""

SERVER_XML_WEAK = """<?xml version="1.0"?>
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector server="Apache-Coyote/1.1" port="8080"/>
  </Service>
</Server>
"""

SERVER_XML_STRONG = """<?xml version="1.0"?>
<Server port="-1" shutdown="a-long-random-word">
  <Service name="Catalina">
    <Connector server="web" port="8080"/>
    <Engine name="Catalina">
      <Host name="localhost">
        <Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"/>
      </Host>
    </Engine>
  </Service>
</Server>
"""

USERS_XML_WEAK = """<?xml version="1.0"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml">
  <user username="tomcat" password="tomcat" roles="manager-gui"/>
</tomcat-users>
"""

USERS_XML_STRONG = """<?xml version="1.0"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"/>
"""

DAEMON_WEAK = """{
  "hosts": ["tcp://0.0.0.0:2375"],
  "tlsverify": false,
  "icc": true,
  "insecure-registries": ["registry:5000"],
  "no-new-privileges": false,
  "userns-remap": "",
  "log-driver": "",
  "log-level": "error"
}"""

DAEMON_STRONG = """{
  "hosts": ["unix:///var/run/docker.sock"],
  "tlsverify": true,
  "icc": false,
  "insecure-registries": [],
  "no-new-privileges": true,
  "userns-remap": "default",
  "log-driver": "json-file",
  "log-level": "info",
  "default-ulimits": {"nofile": {"Hard": 4096}}
}"""

_NGINX = "/etc/nginx/nginx.conf"
_APACHE = "/etc/apache2/apache2.conf"
_SERVER = "/usr/local/tomcat/conf/server.xml"
_USERS = "/usr/local/tomcat/conf/tomcat-users.xml"
_DAEMON = "/etc/docker/daemon.json"

_WEBAPPS = "/usr/local/tomcat/webapps"
_DEPLOYED = (
    f"{_WEBAPPS}/manager",
    f"{_WEBAPPS}/host-manager",
    f"{_WEBAPPS}/examples",
    f"{_WEBAPPS}/docs",
)


def _executor(product: str, *, weak: bool):
    """A target configured either badly or well, for the given product."""
    if product == "nginx":
        return _Filesystem({_NGINX: NGINX_WEAK if weak else NGINX_STRONG})
    if product == "apache":
        return _Filesystem({_APACHE: APACHE_WEAK if weak else APACHE_STRONG})
    if product == "tomcat":
        return _Filesystem(
            {
                _SERVER: SERVER_XML_WEAK if weak else SERVER_XML_STRONG,
                _USERS: USERS_XML_WEAK if weak else USERS_XML_STRONG,
            },
            present_dirs=_DEPLOYED if weak else (),
        )
    return _Filesystem({_DAEMON: DAEMON_WEAK if weak else DAEMON_STRONG})


def _run(check, executor):
    return ConfigAuditEngine().run_check(
        check,
        CollectionContext(
            target="host", platform="linux", executor=executor, timeout=10
        ),
    )


def _checks_for(area):
    return [c for c in MIDDLEWARE_CHECKS if c.metadata.get("gap09_area") == area]


def _target(check, *, weak: bool):
    product = check.metadata["middleware"]
    if check.check_type == "permission":
        # The permission rules read a mode, not a document.
        return _Stat("646" if weak else "640")
    return _executor(product, weak=weak)


@pytest.mark.parametrize("area", IMPLEMENTED_AREAS)
def test_area_is_in_the_frozen_denominator(area):
    assert area in {a for a, _t, _d in SCOPE}


@pytest.mark.parametrize("area", IMPLEMENTED_AREAS)
def test_area_has_at_least_one_shipped_rule(area):
    assert _checks_for(area), f"no shipped rule claims area {area!r}"


@pytest.mark.parametrize("area", IMPLEMENTED_AREAS)
def test_area_can_produce_a_finding(area):
    """A check that never fires is indistinguishable from a clean estate."""
    for check in _checks_for(area):
        result = _run(check, _target(check, weak=True))
        assert result.outcome is CheckOutcome.FAIL, (
            f"{check.check_id} did not fail against deliberately weak "
            f"configuration; it produced {result.outcome.value}"
        )
        assert result.evidence, f"{check.check_id} failed with no evidence"
        assert result.evidence[0].observed, (
            f"{check.check_id} produced no observed value, so the finding "
            f"cannot say what is wrong"
        )
        assert (
            result.remediation
        ), f"{check.check_id} produced a finding with no remediation"


@pytest.mark.parametrize("area", IMPLEMENTED_AREAS)
def test_area_passes_on_hardened_configuration(area):
    """The direction that reaches a customer as a false positive."""
    for check in _checks_for(area):
        result = _run(check, _target(check, weak=False))
        assert result.outcome is CheckOutcome.PASS, (
            f"{check.check_id} did not pass against hardened configuration; "
            f"it produced {result.outcome.value}"
        )


def test_every_shipped_rule_belongs_to_a_claimed_area():
    """
    A rule whose area is not listed above is a rule nothing exercises, and it
    would still count as *implemented* in the coverage harness.
    """
    claimed = set(IMPLEMENTED_AREAS)
    for check in MIDDLEWARE_CHECKS:
        assert (
            check.metadata.get("gap09_area") in claimed
        ), f"{check.check_id} claims an area no test in this file exercises"


def test_a_host_without_the_product_produces_no_findings():
    """
    The property that keeps this rule set usable across a mixed estate: a Linux
    host that runs none of these products must not acquire a pile of findings
    about software it does not have.

    Asserted as "no FAIL" rather than "all NOT_APPLICABLE", because four rules
    legitimately land on PASS — see the test below for why.
    """
    empty = _Filesystem({})
    outcomes = {c.check_id: _run(c, empty).outcome for c in MIDDLEWARE_CHECKS}
    assert outcomes
    failures = {k: v.value for k, v in outcomes.items() if v is CheckOutcome.FAIL}
    assert not failures, failures


def test_configuration_rules_leave_the_score_on_a_host_without_the_product():
    """
    Every rule that *reads a configuration file* reports NOT_APPLICABLE when
    the file is absent, so it leaves the compliance score rather than
    contributing a vacuous pass to it.
    """
    empty = _Filesystem({})
    for check in MIDDLEWARE_CHECKS:
        if check.check_type != "structured_config":
            continue
        if check.collect.get("missing_file") == "absent":
            continue  # the Docker daemon: absent means "at defaults"
        assert _run(check, empty).outcome is CheckOutcome.NOT_APPLICABLE, check.check_id


def test_the_deployed_application_rules_pass_vacuously_and_that_is_recorded():
    """
    A known and accepted limitation, asserted so it stays visible.

    The four "is this bundled application deployed" rules are directory
    existence checks, and a directory that is not there looks the same whether
    Tomcat is installed without the manager application or not installed at
    all. They therefore report PASS on a host with no Tomcat — a vacuous truth
    that adds four passes to that host's score.

    The alternative is worse: making absence NOT_APPLICABLE would also discard
    the genuine pass on a real Tomcat host that has correctly removed them,
    which is the verdict most worth having.
    """
    empty = _Filesystem({})
    vacuous = [
        c.check_id
        for c in MIDDLEWARE_CHECKS
        if c.check_type == "directory" and _run(c, empty).outcome is CheckOutcome.PASS
    ]
    assert sorted(vacuous) == [
        "ccure.mw.tomcat.docs_app",
        "ccure.mw.tomcat.examples_app",
        "ccure.mw.tomcat.host_manager_app",
        "ccure.mw.tomcat.manager_app",
    ]
