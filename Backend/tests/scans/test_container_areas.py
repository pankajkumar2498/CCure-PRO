"""
tests/scans/test_container_areas.py
─────────────────────────────────────────────────────────────────────────────
Every GAP-17 area this build claims, exercised in both directions. Phase 9.

The area names below are literals on purpose.
``scripts/measure_container_coverage.py`` reads these test sources to decide
which areas count as *tested*, so an area whose test is deleted loses its
coverage credit rather than keeping it until somebody remembers to update a
hand-maintained list. Same construction as Phases 5 through 8, and for the same
reason: a coverage figure that cannot go down is not a measurement.

Each area is driven through the real :class:`ConfigAuditEngine` twice — once
against a target configured badly, which must FAIL with evidence and
remediation, and once against one configured well, which must PASS.

A check that can never fail is indistinguishable from a clean estate; one that
fails on everything reaches a customer as a false positive. Both have shipped
in this product before.
"""

import pytest

from core.checks.contract import CheckOutcome
from core.config_audit.builtin import CONTAINER_CHECKS
from core.config_audit.collection import CollectionContext
from core.config_audit.engine import ConfigAuditEngine
from scripts.measure_container_coverage import SCOPE

IMPLEMENTED_AREAS = [
    "ctr.runtime.privileged",
    "ctr.runtime.host_namespaces",
    "ctr.runtime.host_network",
    "ctr.runtime.docker_socket",
    "ctr.runtime.sensitive_mounts",
    "ctr.runtime.run_as_root",
    "ctr.runtime.added_capabilities",
    "ctr.runtime.no_new_privileges",
    "ctr.runtime.readonly_rootfs",
    "ctr.containerd.config_readable",
    "ctr.containerd.insecure_mirrors",
    "k8s.kubelet.anonymous_auth",
    "k8s.kubelet.authorization_mode",
    "k8s.kubelet.readonly_port",
    "k8s.kubelet.client_ca",
    "k8s.kubelet.rotate_certificates",
    "k8s.apiserver.authorization_mode",
    "k8s.rbac.cluster_admin",
    "k8s.rbac.wildcards",
    "k8s.rbac.default_sa_automount",
    "k8s.workload.privileged",
    "k8s.workload.host_namespaces",
    "k8s.workload.run_as_nonroot",
    "k8s.workload.pod_security",
]

_VALUE = "CCURE::VALUE::"
_ABSENT = "CCURE::ABSENT::"


class _Result:
    def __init__(self, stdout="", exit_code=0):
        self.stdout = stdout
        self.stderr = ""
        self.exit_code = exit_code
        self.success = exit_code == 0


class _Host:
    """
    A host that answers probe commands from a table and file reads from files.

    Probe commands are matched on the probe's own guard fragments, so the test
    exercises the command the collector actually issues.
    """

    def __init__(self, probe_output=None, files=None):
        self.probe_output = probe_output or {}
        self.files = files or {}

    def run(self, command, timeout=None):
        for marker, output in self.probe_output.items():
            if marker in command:
                return _Result(output)
        for path, content in self.files.items():
            if path in command:
                return _Result(_VALUE + content)
        if "docker" in command or "kubectl" in command or "$K " in command:
            # No runtime here.
            return _Result(exit_code=97)
        return _Result(_ABSENT + "file does not exist")


# ── Probe output, weak and hardened ──────────────────────────────────────────

_NAMES = "/weak1\n"
_MOUNTS = "/weak1 <- /etc\n"
_CAPS = "/weak1 +SYS_ADMIN\n"

_PODS_BAD = """{"items": [{"metadata": {"name": "bad", "namespace": "default"},
  "spec": {"hostPID": true,
           "containers": [{"name": "c", "securityContext": {"privileged": true}}]}}]}"""
_PODS_GOOD = """{"items": [{"metadata": {"name": "ok", "namespace": "apps"},
  "spec": {"securityContext": {"runAsNonRoot": true},
           "containers": [{"name": "c", "securityContext": {}}]}}]}"""

_CRB_BAD = """{"items": [{"metadata": {"name": "b"}, "roleRef": {"name": "cluster-admin"},
  "subjects": [{"kind": "ServiceAccount", "name": "sa"}]}]}"""
_CRB_GOOD = """{"items": []}"""

_ROLES_BAD = """{"items": [{"metadata": {"name": "wide"},
  "rules": [{"verbs": ["*"], "resources": ["*"]}]}]}"""
_ROLES_GOOD = """{"items": []}"""

_SA_BAD = """{"items": [{"metadata": {"name": "default", "namespace": "default"}}]}"""
_SA_GOOD = """{"items": [{"metadata": {"name": "default", "namespace": "default"},
  "automountServiceAccountToken": false}]}"""

_NS_BAD = """{"items": [{"metadata": {"name": "default", "labels": {}}}]}"""
_NS_GOOD = """{"items": [{"metadata": {"name": "default",
  "labels": {"pod-security.kubernetes.io/enforce": "baseline"}}}]}"""

_API_RBAC = "v1\nrbac.authorization.k8s.io/v1\n"
_API_NO_RBAC = "v1\nbatch/v1\n"

#: ``clientCAFile: ""`` rather than omitting the key.
#:
#: Both are real states a kubelet configuration can be in, and they mean
#: different things to the rule: an explicitly empty path is a configured
#: absence of x509 client authentication and fails, while a wholly missing key
#: may mean the kubelet was given a client CA by flag instead, so the rule
#: defers. The FAIL direction is exercised here; the deferral is asserted
#: separately below.
_KUBELET_BAD = """
authentication:
  anonymous: {enabled: true}
  x509: {clientCAFile: ""}
authorization: {mode: AlwaysAllow}
readOnlyPort: 10255
rotateCertificates: false
"""
_KUBELET_GOOD = """
authentication:
  anonymous: {enabled: false}
  x509: {clientCAFile: /etc/kubernetes/pki/ca.crt}
authorization: {mode: Webhook}
readOnlyPort: 0
rotateCertificates: true
"""

_CONTAINERD_BAD = """
version = 1
[plugins."io.containerd.grpc.v1.cri".registry.configs."reg:5000".tls]
  insecure_skip_verify = true
"""
_CONTAINERD_GOOD = """
version = 2
[plugins."io.containerd.grpc.v1.cri"]
  sandbox_image = "pause:3.9"
"""

_KUBELET_PATH = "/var/lib/kubelet/config.yaml"
_CONTAINERD_PATH = "/etc/containerd/config.toml"


def _probe_table(*, weak: bool):
    """Probe output keyed on a fragment unique to each probe's command."""
    if weak:
        return {
            ".HostConfig.Privileged": _NAMES,
            ".HostConfig.PidMode": _NAMES,
            ".HostConfig.NetworkMode": _NAMES,
            "/var/run/docker.sock": _NAMES,
            'eq .Type "bind"': _MOUNTS,
            ".Config.User": _NAMES,
            ".HostConfig.CapAdd": _CAPS,
            "no-new-privileges:true": _NAMES,
            ".HostConfig.ReadonlyRootfs": _NAMES,
            "get pods": _PODS_BAD,
            "clusterrolebindings": _CRB_BAD,
            "clusterroles,roles": _ROLES_BAD,
            "serviceaccounts": _SA_BAD,
            "get namespaces": _NS_BAD,
            "api-versions": _API_NO_RBAC,
        }
    return {
        ".HostConfig.Privileged": "",
        ".HostConfig.PidMode": "",
        ".HostConfig.NetworkMode": "",
        "/var/run/docker.sock": "",
        'eq .Type "bind"': "/app <- /srv/data\n",
        ".Config.User": "",
        ".HostConfig.CapAdd": "/api +NET_BIND_SERVICE\n",
        "no-new-privileges:true": "",
        ".HostConfig.ReadonlyRootfs": "",
        "get pods": _PODS_GOOD,
        "clusterrolebindings": _CRB_GOOD,
        "clusterroles,roles": _ROLES_GOOD,
        "serviceaccounts": _SA_GOOD,
        "get namespaces": _NS_GOOD,
        "api-versions": _API_RBAC,
    }


def _host(weak: bool) -> _Host:
    return _Host(
        probe_output=_probe_table(weak=weak),
        files={
            _KUBELET_PATH: _KUBELET_BAD if weak else _KUBELET_GOOD,
            _CONTAINERD_PATH: _CONTAINERD_BAD if weak else _CONTAINERD_GOOD,
        },
    )


def _run(check, weak: bool):
    return ConfigAuditEngine().run_check(
        check,
        CollectionContext(
            target="host", platform="linux", executor=_host(weak), timeout=10
        ),
    )


def _checks_for(area):
    return [c for c in CONTAINER_CHECKS if c.metadata.get("gap17_area") == area]


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
        result = _run(check, weak=True)
        assert result.outcome is CheckOutcome.FAIL, (
            f"{check.check_id} did not fail against a deliberately weak "
            f"target; it produced {result.outcome.value}"
        )
        assert result.evidence, f"{check.check_id} failed with no evidence"
        assert result.evidence[0].observed, (
            f"{check.check_id} produced no observed value, so the finding "
            f"cannot say what is wrong"
        )
        assert result.remediation, f"{check.check_id} has no remediation"


@pytest.mark.parametrize("area", IMPLEMENTED_AREAS)
def test_area_passes_on_a_hardened_target(area):
    """The direction that reaches a customer as a false positive."""
    for check in _checks_for(area):
        result = _run(check, weak=False)
        assert result.outcome is CheckOutcome.PASS, (
            f"{check.check_id} did not pass against a hardened target; it "
            f"produced {result.outcome.value}"
        )


def test_every_shipped_rule_belongs_to_a_claimed_area():
    claimed = set(IMPLEMENTED_AREAS)
    for check in CONTAINER_CHECKS:
        assert (
            check.metadata.get("gap17_area") in claimed
        ), f"{check.check_id} claims an area no test in this file exercises"


def test_a_host_with_no_runtime_produces_no_findings():
    """
    The property that keeps this rule set usable across a mixed estate. Most
    hosts run no containers and no Kubernetes, and they must not acquire
    findings — or errors — about software they do not have.
    """
    bare = _Host()
    outcomes = {}
    for check in CONTAINER_CHECKS:
        outcomes[check.check_id] = (
            ConfigAuditEngine()
            .run_check(
                check,
                CollectionContext(
                    target="host", platform="linux", executor=bare, timeout=10
                ),
            )
            .outcome
        )

    assert outcomes
    assert not [k for k, v in outcomes.items() if v is CheckOutcome.FAIL]
    assert not [k for k, v in outcomes.items() if v is CheckOutcome.ERROR], {
        k: v.value for k, v in outcomes.items() if v is CheckOutcome.ERROR
    }
    assert all(v is CheckOutcome.NOT_APPLICABLE for v in outcomes.values())


def test_a_wholly_absent_kubelet_key_defers_rather_than_failing_or_passing():
    """
    The other half of the client-CA fixture above.

    A key that is simply not in the file may mean the kubelet was configured by
    flag instead, so the rule defers — but it must never PASS, which would
    report a kubelet with no client CA as correctly configured.
    """
    no_key = """
authentication:
  anonymous: {enabled: false}
  x509: {}
authorization: {mode: Webhook}
readOnlyPort: 0
rotateCertificates: true
"""
    host = _Host(files={_KUBELET_PATH: no_key})
    check = next(
        c for c in CONTAINER_CHECKS if c.check_id.endswith("kubelet.client_ca")
    )
    result = ConfigAuditEngine().run_check(
        check,
        CollectionContext(target="host", platform="linux", executor=host, timeout=10),
    )
    assert result.outcome is CheckOutcome.MANUAL_REVIEW
    assert result.outcome is not CheckOutcome.PASS
