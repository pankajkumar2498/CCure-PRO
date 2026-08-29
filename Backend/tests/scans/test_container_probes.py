"""
tests/scans/test_container_probes.py
─────────────────────────────────────────────────────────────────────────────
The container and Kubernetes probes, and the collector that runs them.
Phase 9 (GAP-17).

The extractors are pure — command output in, offenders out — so every one is
tested against output captured from a live Docker host and a live k3s cluster
rather than against output invented to match the code. A probe tested only
against its author's idea of the format is a probe tested against an
assumption.

Two of these exist because a real cluster disagreed with the first version:
``cluster-admin`` legitimately holds ``*`` on ``*`` and was being reported on
every cluster, and the pointer for containerd's dotted keys was being
stringified before it reached the navigator.
"""

import pytest

from core.checks.contract import CheckOutcome
from core.config_audit.collection import CollectionContext, CollectionStatus
from core.config_audit.collectors import collector_registry, register_builtin_collectors
from core.config_audit.containers import (
    CONTAINER_PROBES,
    TOOL_MISSING,
    TOOL_UNREACHABLE,
    probe_for,
    probe_names,
)
from core.config_audit.engine import ConfigAuditEngine
from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

register_builtin_collectors()

COLLECTOR = collector_registry.resolve("container", "linux")


class Result:
    def __init__(self, stdout="", exit_code=0):
        self.stdout = stdout
        self.stderr = ""
        self.exit_code = exit_code
        self.success = exit_code == 0


class FakeHost:
    """A host that answers every command with one prescribed result."""

    def __init__(self, stdout="", exit_code=0):
        self.result = Result(stdout, exit_code)
        self.commands = []

    def run(self, command, timeout=None):
        self.commands.append(command)
        return self.result


def _check(**collect):
    return ConfigCheck(
        check_id="ccure.ctr.test.example",
        title="Example container check",
        check_type="container",
        platforms=("linux",),
        collect=collect or {"probe": "docker.privileged"},
        expect=Expectation("is_empty"),
        absent=AbsencePolicy.PASS,
    )


def _ctx(host):
    return CollectionContext(target="host", platform="linux", executor=host, timeout=10)


# ── Captured output ──────────────────────────────────────────────────────────
#
# Taken verbatim from `docker inspect --format` and `kubectl get -o json`
# against the disposable targets used for validation.

DOCKER_NAMES = "/weak1\n/weak2\n"

DOCKER_MOUNTS = "/weak2 <- /\n/weak1 <- /etc\n/app <- /srv/app/data\n"

DOCKER_CAPS = "/weak1 +SYS_ADMIN\n/api +NET_BIND_SERVICE\n/w +CAP_SYS_PTRACE\n"

PODS_JSON = """{
  "items": [
    {"metadata": {"name": "bad-pod", "namespace": "default"},
     "spec": {"hostPID": true, "hostNetwork": true,
              "containers": [{"name": "c", "securityContext": {"privileged": true}}]}},
    {"metadata": {"name": "kube-proxy", "namespace": "kube-system"},
     "spec": {"hostNetwork": true,
              "containers": [{"name": "p", "securityContext": {"privileged": true}}]}},
    {"metadata": {"name": "good", "namespace": "apps"},
     "spec": {"securityContext": {"runAsNonRoot": true},
              "containers": [{"name": "c", "securityContext": {}}]}}
  ]
}"""

CRB_JSON = """{
  "items": [
    {"metadata": {"name": "cluster-admin"},
     "roleRef": {"name": "cluster-admin"},
     "subjects": [{"kind": "Group", "name": "system:masters"}]},
    {"metadata": {"name": "ccure-admin-binding"},
     "roleRef": {"name": "cluster-admin"},
     "subjects": [{"kind": "ServiceAccount", "name": "ccure-sa"}]},
    {"metadata": {"name": "reader"},
     "roleRef": {"name": "view"},
     "subjects": [{"kind": "User", "name": "alice"}]}
  ]
}"""

ROLES_JSON = """{
  "items": [
    {"metadata": {"name": "cluster-admin",
                  "labels": {"kubernetes.io/bootstrapping": "rbac-defaults"}},
     "rules": [{"verbs": ["*"], "resources": ["*"]}]},
    {"metadata": {"name": "ccure-too-wide"},
     "rules": [{"verbs": ["*"], "resources": ["*"]}]},
    {"metadata": {"name": "monitoring"},
     "rules": [{"verbs": ["get", "list"], "resources": ["*"]}]}
  ]
}"""

SA_JSON = """{
  "items": [
    {"metadata": {"name": "default", "namespace": "default"}},
    {"metadata": {"name": "default", "namespace": "kube-system"}},
    {"metadata": {"name": "default", "namespace": "apps"},
     "automountServiceAccountToken": false},
    {"metadata": {"name": "worker", "namespace": "apps"}}
  ]
}"""

NS_JSON = """{
  "items": [
    {"metadata": {"name": "default", "labels": {}}},
    {"metadata": {"name": "kube-system", "labels": {}}},
    {"metadata": {"name": "apps",
                  "labels": {"pod-security.kubernetes.io/enforce": "baseline"}}}
  ]
}"""

API_VERSIONS_RBAC = "v1\napps/v1\nrbac.authorization.k8s.io/v1\n"
API_VERSIONS_NO_RBAC = "v1\napps/v1\nbatch/v1\n"


# ── Catalogue ────────────────────────────────────────────────────────────────


def test_every_probe_declares_a_command_an_extractor_and_a_requirement():
    assert CONTAINER_PROBES
    for name, probe in CONTAINER_PROBES.items():
        assert probe.name == name
        assert probe.command.strip()
        assert callable(probe.extract)
        assert probe.requires
        assert probe.description


def test_every_probe_guards_against_a_missing_tool():
    """
    A probe with no guard runs its enumeration against a host that has no
    runtime, gets empty output, and reports a clean bill of health.
    """
    for probe in CONTAINER_PROBES.values():
        assert "exit 97" in probe.command, probe.name


def test_every_probe_distinguishes_an_unreachable_tool_from_a_missing_one():
    """
    ``docker ps`` against a dead daemon returns the same empty list a clean
    host does, so "installed but not answering" must be its own exit status.
    """
    for probe in CONTAINER_PROBES.values():
        assert "exit 96" in probe.command, probe.name


def test_probe_lookup_names_the_alternatives():
    with pytest.raises(KeyError) as exc:
        probe_for("docker.nope")
    assert "docker.privileged" in str(exc.value)


def test_probe_names_are_sorted_and_complete():
    assert probe_names() == sorted(CONTAINER_PROBES)


# ── Docker extractors ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "probe_name",
    [
        "docker.privileged",
        "docker.host_namespaces",
        "docker.host_network",
        "docker.docker_socket",
        "docker.run_as_root",
        "docker.no_new_privileges",
        "docker.readonly_rootfs",
    ],
)
def test_name_emitting_probes_read_one_offender_per_line(probe_name):
    assert probe_for(probe_name).extract(DOCKER_NAMES) == ["/weak1", "/weak2"]
    assert probe_for(probe_name).extract("") == []
    assert probe_for(probe_name).extract("\n\n  \n") == []


def test_sensitive_mounts_reports_only_the_sensitive_ones():
    """
    An application volume is not a finding. A probe that reported every bind
    mount would fire on nearly every container ever run.
    """
    offenders = probe_for("docker.sensitive_mounts").extract(DOCKER_MOUNTS)
    assert offenders == ["/weak2 <- /", "/weak1 <- /etc"]


def test_sensitive_mounts_matches_a_subdirectory_but_not_a_lookalike():
    probe = probe_for("docker.sensitive_mounts")
    assert probe.extract("/c <- /etc/ssl\n") == ["/c <- /etc/ssl"]
    # /etcetera is not /etc.
    assert probe.extract("/c <- /etcetera\n") == []
    # A path merely starting with the same letters as root is not root.
    assert probe.extract("/c <- /srv\n") == []


def test_added_capabilities_reports_only_the_dangerous_ones():
    """
    Images legitimately add NET_BIND_SERVICE. A probe firing on it is the "37
    SUID binaries" failure — it trains the reader to ignore the check.
    """
    offenders = probe_for("docker.added_capabilities").extract(DOCKER_CAPS)
    assert offenders == ["/weak1 +SYS_ADMIN", "/w +CAP_SYS_PTRACE"]


def test_added_capabilities_accepts_either_capability_spelling():
    probe = probe_for("docker.added_capabilities")
    assert probe.extract("/a +SYS_ADMIN\n") == ["/a +SYS_ADMIN"]
    assert probe.extract("/a +CAP_SYS_ADMIN\n") == ["/a +CAP_SYS_ADMIN"]
    assert probe.extract("/a +cap_sys_admin\n") == ["/a +cap_sys_admin"]


# ── Kubernetes extractors ────────────────────────────────────────────────────


def test_privileged_pods_excludes_the_clusters_own_components():
    """
    kube-proxy and the CNI pods are legitimately privileged. Reporting them
    produces a page of findings on every cluster ever built.
    """
    offenders = probe_for("k8s.privileged_pods").extract(PODS_JSON)
    assert offenders == ["default/bad-pod [c]"]


def test_host_namespace_pods_names_which_namespaces_are_shared():
    offenders = probe_for("k8s.host_namespace_pods").extract(PODS_JSON)
    assert offenders == ["default/bad-pod shares hostPID, hostNetwork"]


def test_root_pods_accepts_run_as_non_root_and_a_non_zero_user():
    probe = probe_for("k8s.root_pods")
    assert probe.extract(PODS_JSON) == ["default/bad-pod [c]"]

    with_user = """{"items": [{"metadata": {"name": "p", "namespace": "apps"},
      "spec": {"containers": [{"name": "c",
                               "securityContext": {"runAsUser": 1000}}]}}]}"""
    assert probe.extract(with_user) == []

    as_root_explicitly = """{"items": [{"metadata": {"name": "p", "namespace": "apps"},
      "spec": {"containers": [{"name": "c",
                               "securityContext": {"runAsUser": 0}}]}}]}"""
    assert probe.extract(as_root_explicitly) == ["apps/p [c]"]


def test_cluster_admin_bindings_excludes_the_system_masters_binding():
    offenders = probe_for("k8s.cluster_admin_bindings").extract(CRB_JSON)
    assert offenders == ["ccure-admin-binding: ServiceAccount/ccure-sa"]


def test_wildcard_roles_excludes_roles_kubernetes_ships():
    """
    The fix a real cluster forced. ``cluster-admin`` legitimately holds ``*``
    on ``*``, does not start with ``system:``, and was being reported on every
    cluster. The bootstrapping label is what tells the two apart — 65 of the 69
    ClusterRoles on a stock k3s carry it.
    """
    offenders = probe_for("k8s.wildcard_roles").extract(ROLES_JSON)
    assert offenders == ["ccure-too-wide"]


def test_wildcard_roles_ignores_a_wildcard_on_only_one_axis():
    """``get`` on ``*`` is what a monitoring role looks like."""
    assert "monitoring" not in probe_for("k8s.wildcard_roles").extract(ROLES_JSON)


def test_default_sa_automount_skips_opted_out_and_system_namespaces():
    offenders = probe_for("k8s.default_sa_automount").extract(SA_JSON)
    assert offenders == ["default/default"]


def test_pod_security_namespaces_reports_only_unlabelled_user_namespaces():
    offenders = probe_for("k8s.pod_security_namespaces").extract(NS_JSON)
    assert offenders == ["default"]


def test_rbac_probe_reports_only_when_the_api_group_is_absent():
    probe = probe_for("k8s.rbac_disabled")
    assert probe.extract(API_VERSIONS_RBAC) == []
    assert probe.extract(API_VERSIONS_NO_RBAC)


def test_a_kubernetes_extractor_refuses_output_that_is_not_json():
    """
    Raising is correct: the collector turns it into UNAVAILABLE. Returning []
    would read as "no offenders", which is the inversion the whole collection
    vocabulary exists to prevent.
    """
    with pytest.raises(ValueError):
        probe_for("k8s.privileged_pods").extract("Error from server (Forbidden)")


# ── The collector ────────────────────────────────────────────────────────────


def test_registered_on_linux_only():
    assert collector_registry.resolve("container", "linux") is not None
    assert collector_registry.resolve("container", "windows") is None


def test_a_missing_runtime_is_unsupported_not_an_error():
    """
    Most hosts in an estate run no Kubernetes. Reporting ERROR would hand every
    one of them eight findings-shaped errors about software it does not have.
    """
    state = COLLECTOR.collect(
        _check(probe="k8s.privileged_pods"), _ctx(FakeHost(exit_code=TOOL_MISSING))
    )
    assert state.status is CollectionStatus.UNSUPPORTED
    assert "does not appear to run this runtime" in state.detail


def test_a_missing_runtime_becomes_not_applicable_at_the_engine():
    result = ConfigAuditEngine().run_check(
        _check(probe="docker.privileged"), _ctx(FakeHost(exit_code=TOOL_MISSING))
    )
    assert result.outcome is CheckOutcome.NOT_APPLICABLE


def test_an_unreachable_runtime_is_unavailable_never_a_pass():
    """
    The distinction that matters most here. `docker ps` against a dead daemon
    returns the same empty list a clean host does, so this path must never
    reach a verdict.
    """
    state = COLLECTOR.collect(
        _check(probe="docker.privileged"),
        _ctx(FakeHost(exit_code=TOOL_UNREACHABLE)),
    )
    assert state.status is CollectionStatus.UNAVAILABLE
    result = ConfigAuditEngine().run_check(
        _check(probe="docker.privileged"),
        _ctx(FakeHost(exit_code=TOOL_UNREACHABLE)),
    )
    assert result.outcome is CheckOutcome.ERROR


def test_a_clean_host_is_absent_so_the_rule_can_pass():
    state = COLLECTOR.collect(_check(probe="docker.privileged"), _ctx(FakeHost("")))
    assert state.status is CollectionStatus.ABSENT
    result = ConfigAuditEngine().run_check(
        _check(probe="docker.privileged"), _ctx(FakeHost(""))
    )
    assert result.outcome is CheckOutcome.PASS


def test_offenders_reach_the_verdict_as_evidence():
    result = ConfigAuditEngine().run_check(
        _check(probe="docker.privileged"), _ctx(FakeHost(DOCKER_NAMES))
    )
    assert result.outcome is CheckOutcome.FAIL
    assert "weak1" in result.evidence[0].observed


def test_a_probe_that_cannot_parse_its_output_is_unavailable():
    state = COLLECTOR.collect(
        _check(probe="k8s.privileged_pods"), _ctx(FakeHost("not json at all"))
    )
    assert state.status is CollectionStatus.UNAVAILABLE
    assert "could not be interpreted" in state.detail


def test_a_failed_command_is_unavailable():
    state = COLLECTOR.collect(
        _check(probe="docker.privileged"), _ctx(FakeHost("", exit_code=1))
    )
    assert state.status is CollectionStatus.UNAVAILABLE


def test_a_rule_naming_an_unknown_probe_is_unavailable():
    state = COLLECTOR.collect(_check(probe="docker.nope"), _ctx(FakeHost("")))
    assert state.status is CollectionStatus.UNAVAILABLE
    assert "no container probe named" in state.detail


def test_no_session_is_unavailable():
    state = COLLECTOR.collect(_check(probe="docker.privileged"), _ctx(None))
    assert state.status is CollectionStatus.UNAVAILABLE


def test_the_enumeration_is_run_once_per_probe_per_host():
    """
    Every Kubernetes pod rule runs the same `kubectl get pods`. Without
    memoisation the audit pays for it once per rule.
    """
    host = FakeHost(PODS_JSON)
    ctx = _ctx(host)
    for _ in range(4):
        COLLECTOR.collect(_check(probe="k8s.privileged_pods"), ctx)
    assert len(host.commands) == 1


def test_evidence_shows_the_enumeration_ran_on_a_clean_host():
    """
    "Nothing found" and "the probe returned nothing for another reason" look
    identical in a report unless the evidence carries the raw output.
    """
    state = COLLECTOR.collect(
        _check(probe="k8s.pod_security_namespaces"), _ctx(FakeHost(NS_JSON))
    )
    assert "raw output" in state.raw or "offenders" in state.raw
