"""
core/config_audit/builtin/middleware_docker.py
─────────────────────────────────────────────────────────────────────────────
Docker daemon configuration checks. Phase 8 (GAP-09).

Read against a live dockerd container through the real collector before the
rules were written, and that immediately settled the most important question in
this file.

**Most Docker installations have no ``daemon.json`` at all.** The dind image
ships without one; so do the packages for every major distribution. The daemon
runs entirely on its built-in defaults, and those defaults are a mixture: some
are the secure state and some are not.

So these rules are the one place in this phase where ``missing_file: absent``
is set. Everywhere else a missing configuration file means the product is not
installed, and the collector reports UNSUPPORTED so a host that does not run
nginx is not handed nginx findings. Here a missing file is a *reading* — "every
setting is at its default" — and each rule then declares what that default
means for it:

* no ``hosts`` entry means no TCP socket, which is the secure state → **PASS**
* no ``insecure-registries`` means none are configured → **PASS**
* no ``icc`` means inter-container communication is *on* → **MANUAL_REVIEW**,
  because the insecure default is extremely common and reporting it as a
  failure on every Docker host in the estate is how a finding stops being read

That split is the whole reason ``AbsencePolicy`` has no default value.
"""

from __future__ import annotations

from typing import List

from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

__all__ = ["DOCKER_CHECKS", "docker_checks"]

_PATHS = ("/etc/docker/daemon.json",)
_DOC = "https://docs.docker.com/reference/cli/dockerd/"


def _json(pointer: str, result: str = "value") -> dict:
    return {
        "path": list(_PATHS),
        "format": "json",
        "pointer": pointer,
        "result": result,
        # See the module docstring: an absent daemon.json is a reading, not a
        # missing product.
        "missing_file": "absent",
    }


def _check(
    *,
    suffix: str,
    title: str,
    severity: str,
    collect: dict,
    expect: Expectation,
    absent: AbsencePolicy,
    description: str,
    rationale: str,
    remediation: str,
    area: str,
    references=(_DOC,),
) -> ConfigCheck:
    return ConfigCheck(
        check_id=f"ccure.mw.docker.{suffix}",
        title=title,
        check_type="structured_config",
        platforms=("linux", "windows"),
        severity=severity,
        collect=collect,
        expect=expect,
        absent=absent,
        description=description,
        rationale=rationale,
        remediation=remediation,
        references=tuple(references),
        tags=("middleware", "docker"),
        metadata={"gap09_area": area, "middleware": "docker"},
    )


DOCKER_CHECKS: List[ConfigCheck] = [
    _check(
        suffix="tcp_socket",
        title="The Docker daemon does not listen on a TCP socket",
        severity="critical",
        collect=_json("hosts", result="values"),
        expect=Expectation("not_matches", r"tcp://", description="unix socket only"),
        # No `hosts` entry means the unix socket only, which is what we want.
        absent=AbsencePolicy.PASS,
        description=(
            "The sockets dockerd binds. Unset, it listens only on "
            "/var/run/docker.sock."
        ),
        rationale=(
            "The Docker API is root-equivalent by design: anyone who can reach "
            "it can start a privileged container that mounts the host "
            "filesystem. Exposed over TCP without mutual TLS it is an "
            "unauthenticated root shell on the host, reachable from anywhere "
            "the port is."
        ),
        remediation=(
            "Remove the tcp:// entry from 'hosts'. Where remote access is "
            "genuinely needed, use an SSH context rather than a TCP socket."
        ),
        references=("https://docs.docker.com/engine/security/protect-access/",),
        area="mw.exposure.daemon_socket_tcp",
    ),
    _check(
        suffix="socket_tls",
        title="The Docker daemon requires TLS client certificates",
        severity="critical",
        collect=_json("tlsverify"),
        expect=Expectation("is_true", description="true"),
        # Absent is deferred rather than failed because it is only a finding
        # when a TCP socket exists, and the rule above is what establishes
        # that. Failing here as well would report one exposure twice.
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Whether dockerd verifies client certificates. Unset, Docker "
            "defaults to false. Only meaningful alongside a TCP socket; on a "
            "unix-socket-only daemon it is not used, which is why an absent "
            "reading defers rather than failing."
        ),
        rationale=(
            "With a TCP socket and no 'tlsverify', the API accepts any client "
            "that can reach the port. 'tls' alone encrypts the channel without "
            "authenticating the caller, which is the configuration people "
            "reach for and is not sufficient."
        ),
        remediation=(
            "Set 'tlsverify': true with 'tlscacert', 'tlscert' and 'tlskey', "
            "and issue a client certificate per operator."
        ),
        references=("https://docs.docker.com/engine/security/protect-access/",),
        area="mw.tls.daemon_socket",
    ),
    _check(
        suffix="inter_container_communication",
        title="Docker restricts traffic between containers on the default bridge",
        severity="medium",
        collect=_json("icc"),
        expect=Expectation("is_false", description="false"),
        # The default is `true`, and it is the default on effectively every
        # Docker host. Reporting a failure on all of them would bury the
        # findings that matter.
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Whether unrelated containers on the default bridge may reach each "
            "other. Unset, Docker defaults to true."
        ),
        rationale=(
            "With icc on, one compromised container can reach every other "
            "container's ports on the default bridge, including ones never "
            "published to the host. Lateral movement inside the estate needs "
            "no further access."
        ),
        remediation=(
            "Set '\"icc\": false' and connect containers that must talk to "
            "each other on an explicit user-defined network."
        ),
        area="mw.exposure.inter_container",
    ),
    _check(
        suffix="insecure_registries",
        title="Docker trusts no registry over plain HTTP",
        severity="high",
        collect=_json("insecure-registries", result="values"),
        expect=Expectation("is_empty", description="no insecure registry"),
        absent=AbsencePolicy.PASS,
        description=(
            "Registries the daemon will contact without TLS, or whose "
            "certificate it will not verify."
        ),
        rationale=(
            "An image pulled over plain HTTP can be replaced in transit, and "
            "the daemon runs whatever it receives as the container's contents. "
            "A single entry here undermines image provenance for everything "
            "pulled from that host."
        ),
        remediation=(
            "Remove the entry and give the registry a certificate the daemon " "trusts."
        ),
        area="mw.exposure.insecure_registry",
    ),
    _check(
        suffix="no_new_privileges",
        title="Docker containers cannot gain new privileges by default",
        severity="medium",
        collect=_json("no-new-privileges"),
        expect=Expectation("is_true", description="true"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Whether the daemon applies no-new-privileges to every container "
            "by default. Unset, Docker defaults to false."
        ),
        rationale=(
            "Without it, a setuid binary inside a container can still raise "
            "privileges, so a container escape that depends on one stays "
            "available even where the container itself runs as a non-root "
            "user."
        ),
        remediation="Set '\"no-new-privileges\": true' and restart the daemon.",
        area="mw.process.privilege_flags",
    ),
    _check(
        suffix="userns_remap",
        title="Docker remaps container root to an unprivileged host user",
        severity="medium",
        collect=_json("userns-remap"),
        expect=Expectation("not_empty", description="a remap user, commonly 'default'"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "User-namespace remapping. Unset, root inside a container is root "
            "on the host."
        ),
        rationale=(
            "Without remapping, uid 0 in a container is uid 0 on the host, so "
            "any escape from the namespace lands as root. Remapping makes the "
            "same escape land as an unprivileged account."
        ),
        remediation=(
            'Set \'"userns-remap": "default"\' and restart. Note this breaks '
            "containers that need host-uid parity on bind mounts, so stage it."
        ),
        references=("https://docs.docker.com/engine/security/userns-remap/",),
        area="mw.process.privilege_flags",
    ),
    _check(
        suffix="log_driver",
        title="Docker sends container output to a defined log driver",
        severity="low",
        collect=_json("log-driver"),
        expect=Expectation("not_empty", description="a named driver"),
        # Unset means json-file, which is a real and adequate driver.
        absent=AbsencePolicy.PASS,
        description=(
            "The default logging driver. Unset, Docker uses json-file, which "
            "writes to the host's disk."
        ),
        rationale=(
            "Container output is the only record of what an application did. "
            "A driver that ships it off the host is what keeps that record "
            "when the host itself is the thing being investigated."
        ),
        remediation=(
            "Set 'log-driver' to the collector your estate uses, and pair it "
            "with 'log-opts' limits so a chatty container cannot fill the disk."
        ),
        area="mw.log.driver_configured",
    ),
    _check(
        suffix="log_level",
        title="The Docker daemon logs at a usable level",
        severity="low",
        collect=_json("log-level"),
        expect=Expectation(
            "not_in", ["fatal", "panic", "error"], description="info, warn or debug"
        ),
        absent=AbsencePolicy.PASS,
        description=(
            "The daemon's own log verbosity. Unset, Docker defaults to 'info'."
        ),
        rationale=(
            "At 'error' and above the daemon records only its own failures. "
            "Container starts, image pulls and API calls — the entries that "
            "show what was run on the host — are logged at 'info'."
        ),
        remediation='Set \'"log-level": "info"\' and restart the daemon.',
        area="mw.log.log_level",
    ),
    _check(
        suffix="default_ulimits",
        title="Docker applies default resource limits to containers",
        severity="low",
        collect=_json("default-ulimits", result="count"),
        expect=Expectation("gte", 1, description="at least one default ulimit"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Resource limits applied to every container unless overridden. "
            "Unset, containers inherit the daemon's own limits. This counts "
            "entries, so it never reports an absent reading and the absence "
            "policy below is unreachable; it is declared because ConfigCheck "
            "requires a choice."
        ),
        rationale=(
            "Without a default, one container can exhaust file descriptors or "
            "processes for the whole host, taking every other container with "
            "it. The limit is what keeps a runaway workload a single-container "
            "incident."
        ),
        remediation=(
            "Set 'default-ulimits', for example nofile and nproc, to values "
            "your workloads fit inside."
        ),
        area="mw.limits.ulimits",
    ),
]


def docker_checks() -> List[ConfigCheck]:
    return list(DOCKER_CHECKS)
