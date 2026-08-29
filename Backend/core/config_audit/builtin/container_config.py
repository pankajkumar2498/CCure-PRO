"""
core/config_audit/builtin/container_config.py
─────────────────────────────────────────────────────────────────────────────
kubelet and containerd configuration checks. Phase 9 (GAP-17).

These read *files*, so they use the Phase 8 ``structured_config`` collector
with the two formats this phase added to it: YAML for the kubelet, TOML for
containerd. No new collector, and the absence semantics come along unchanged —
a host with no kubelet config reports UNSUPPORTED and leaves the score rather
than failing rules about software it does not run.

A limitation that has to be stated plainly
──────────────────────────────────────────
**k3s does not use a kubelet configuration file.** It passes the kubelet its
settings as process flags, so on the only Kubernetes cluster that could be
stood up disposably here these rules correctly report NOT_APPLICABLE — and
that means they were *not* validated against a live kubelet consuming them.

They were validated against a real kubeadm-shaped ``config.yaml`` written to
the kubeadm path on a real host, in both directions. That proves the rule, the
path, the parser and the verdict; it does not prove that a kubeadm kubelet
reads the file the way these rules assume. The distinction is recorded in the
tracker rather than papered over, and it is the reason the control-plane areas
were left unimplemented entirely instead of being written blind.

containerd is the opposite case: k3s ships a real ``config.toml`` at its own
path, and the checks were validated against it.
"""

from __future__ import annotations

from typing import List

from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

__all__ = ["CONTAINER_CONFIG_CHECKS", "container_config_checks"]

#: kubeadm's path first, then the two k3s agent locations. The collector takes
#: the first that exists and reports UNSUPPORTED when none does.
_KUBELET_CONFIG = (
    "/var/lib/kubelet/config.yaml",
    "/etc/kubernetes/kubelet/kubelet-config.yaml",
    "/var/lib/rancher/k3s/agent/kubelet.config.yaml",
)

#: The distribution path and k3s's own bundled containerd.
_CONTAINERD_CONFIG = (
    "/etc/containerd/config.toml",
    "/var/lib/rancher/k3s/agent/etc/containerd/config.toml",
)

_KUBELET_DOC = (
    "https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/"
)
_CONTAINERD_DOC = (
    "https://github.com/containerd/containerd/blob/main/docs/cri/config.md"
)


def _kubelet(
    *,
    suffix: str,
    pointer,
    title: str,
    severity: str,
    expect: Expectation,
    absent: AbsencePolicy,
    description: str,
    rationale: str,
    remediation: str,
    area: str,
) -> ConfigCheck:
    return ConfigCheck(
        check_id=f"ccure.ctr.kubelet.{suffix}",
        title=title,
        check_type="structured_config",
        platforms=("linux",),
        severity=severity,
        collect={
            "path": list(_KUBELET_CONFIG),
            "format": "yaml",
            "pointer": pointer,
        },
        expect=expect,
        absent=absent,
        description=description,
        rationale=rationale,
        remediation=remediation,
        references=(_KUBELET_DOC,),
        tags=("container", "kubernetes", "kubelet"),
        metadata={"gap17_area": area, "runtime": "kubernetes"},
    )


CONTAINER_CONFIG_CHECKS: List[ConfigCheck] = [
    _kubelet(
        suffix="anonymous_auth",
        pointer="authentication.anonymous.enabled",
        title="The kubelet refuses anonymous requests",
        severity="critical",
        expect=Expectation("is_false", description="false"),
        # Absent means the kubelet's compiled default, which is `true` for the
        # flag form and `false` under kubeadm's generated config. Deferring is
        # the honest answer rather than guessing which produced this file.
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Whether the kubelet accepts unauthenticated requests to its API. "
            "Unset, the kubelet's own default is true; kubeadm writes false."
        ),
        rationale=(
            "The kubelet API can list pods, read their logs and — with "
            "authorization also permissive — exec into containers. Anonymous "
            "access to it is unauthenticated access to every workload on the "
            "node."
        ),
        remediation=(
            "Set authentication.anonymous.enabled: false in the kubelet "
            "configuration and restart the kubelet."
        ),
        area="k8s.kubelet.anonymous_auth",
    ),
    _kubelet(
        suffix="authorization_mode",
        pointer="authorization.mode",
        title="The kubelet authorizes requests through the API server",
        severity="critical",
        expect=Expectation("equals", "Webhook", description="Webhook"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The kubelet's authorization mode. Unset, the kubelet defaults to "
            "AlwaysAllow; kubeadm writes Webhook."
        ),
        rationale=(
            "AlwaysAllow means every request the kubelet authenticates is also "
            "authorised, so anyone who can present any valid credential gets "
            "everything the kubelet API offers. Webhook delegates the decision "
            "to the API server's RBAC."
        ),
        remediation=("Set authorization.mode: Webhook and restart the kubelet."),
        area="k8s.kubelet.authorization_mode",
    ),
    _kubelet(
        suffix="readonly_port",
        pointer="readOnlyPort",
        title="The kubelet read-only port is disabled",
        severity="high",
        expect=Expectation("equals", 0, description="0 (disabled)"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The unauthenticated read-only kubelet port. Unset, the kubelet's "
            "own default is 10255 in older releases and 0 in current ones."
        ),
        rationale=(
            "The read-only port serves pod and node state with no "
            "authentication at all. It is a complete inventory of what runs on "
            "the node, including environment variables, to anyone who can "
            "reach the port."
        ),
        remediation="Set readOnlyPort: 0 and restart the kubelet.",
        area="k8s.kubelet.readonly_port",
    ),
    _kubelet(
        suffix="client_ca",
        pointer="authentication.x509.clientCAFile",
        title="The kubelet verifies client certificates against a CA",
        severity="high",
        expect=Expectation("not_empty", description="a CA file path"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The certificate authority the kubelet validates client "
            "certificates against. Unset, x509 client authentication is not "
            "available and the kubelet falls back to its other authenticators."
        ),
        rationale=(
            "Without a client CA the kubelet cannot distinguish the API server "
            "from anything else presenting a certificate, so certificate-based "
            "authentication to it establishes nothing."
        ),
        remediation=(
            "Set authentication.x509.clientCAFile to the cluster CA and "
            "restart the kubelet."
        ),
        area="k8s.kubelet.client_ca",
    ),
    _kubelet(
        suffix="rotate_certificates",
        pointer="rotateCertificates",
        title="The kubelet rotates its client certificate",
        severity="medium",
        expect=Expectation("is_true", description="true"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Whether the kubelet requests a new client certificate as the "
            "current one approaches expiry. Unset, the kubelet defaults to "
            "true in current releases."
        ),
        rationale=(
            "Without rotation the node's credential is long-lived, so a copy "
            "taken from a compromised node stays usable for the life of the "
            "certificate rather than for hours."
        ),
        remediation="Set rotateCertificates: true and restart the kubelet.",
        area="k8s.kubelet.rotate_certificates",
    ),
    # ── containerd ───────────────────────────────────────────────────────────
    ConfigCheck(
        check_id="ccure.ctr.containerd.config_readable",
        title="The containerd configuration is present and parseable",
        check_type="structured_config",
        platforms=("linux",),
        severity="low",
        collect={
            "path": list(_CONTAINERD_CONFIG),
            "format": "toml",
            "pointer": "version",
        },
        expect=Expectation("gte", 2, description="config schema version 2 or later"),
        # A host with no containerd is not failing containerd's rules.
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "containerd's configuration schema version. Version 1 was removed "
            "in containerd 2.0, so a host still on it is running a "
            "configuration the current daemon will not read."
        ),
        rationale=(
            "A configuration the daemon silently ignores means every setting "
            "in it — including the registry and sandbox settings the checks "
            "below read — is not in force, while looking as though it is."
        ),
        remediation=(
            "Migrate the configuration to version 2 with "
            "'containerd config migrate', or regenerate it with "
            "'containerd config default'."
        ),
        references=(_CONTAINERD_DOC,),
        tags=("container", "containerd"),
        metadata={
            "gap17_area": "ctr.containerd.config_readable",
            "runtime": "containerd",
        },
    ),
    ConfigCheck(
        check_id="ccure.ctr.containerd.insecure_mirrors",
        title="containerd verifies TLS for every registry mirror",
        check_type="structured_config",
        platforms=("linux",),
        severity="high",
        collect={
            "path": list(_CONTAINERD_CONFIG),
            "format": "toml",
            # A *list* pointer, not a dotted string. containerd's quoted keys
            # contain dots — `[plugins."io.containerd.grpc.v1.cri"]` parses to
            # a key literally named io.containerd.grpc.v1.cri — and a dotted
            # path splits it into five segments that resolve to nothing, which
            # would report every containerd host as unconfigured.
            "pointer": [
                "plugins",
                "io.containerd.grpc.v1.cri",
                "registry",
                "configs",
            ],
            "result": "values",
        },
        expect=Expectation(
            "is_empty", description="no per-registry TLS override configured"
        ),
        absent=AbsencePolicy.PASS,
        description=(
            "Registries with a per-registry TLS configuration block. Such a "
            "block is where insecure_skip_verify is set, and its absence means "
            "containerd verifies every mirror normally."
        ),
        rationale=(
            "A registry configured with insecure_skip_verify accepts any "
            "certificate, so an image pulled from it can be replaced in "
            "transit — and containerd runs whatever it receives as the "
            "container's contents."
        ),
        remediation=(
            "Remove the per-registry TLS override and give the registry a "
            "certificate the host trusts. Where a private CA is used, add it "
            "to the host trust store rather than disabling verification."
        ),
        references=(_CONTAINERD_DOC,),
        tags=("container", "containerd"),
        metadata={
            "gap17_area": "ctr.containerd.insecure_mirrors",
            "runtime": "containerd",
        },
    ),
]


def container_config_checks() -> List[ConfigCheck]:
    return list(CONTAINER_CONFIG_CHECKS)
