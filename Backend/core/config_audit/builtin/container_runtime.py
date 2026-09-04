"""
core/config_audit/builtin/container_runtime.py
─────────────────────────────────────────────────────────────────────────────
Container runtime and Kubernetes checks. Phase 9 (GAP-17).

Every probe here was run against a live Docker host and a live k3s cluster
before its rule was written, in both directions — a deliberately weakened
container and a hardened one, a stock cluster and a breached one.

What these deliberately do *not* check
──────────────────────────────────────
The Docker **daemon** configuration — ``daemon.json``, the TCP socket, ``icc``,
``userns-remap``, insecure registries, the log driver. All ten of those were
built and validated in **GAP-09**, which owns them. These rules are about what
the daemon is *running*, not how the daemon itself is set up.

The absence policy is PASS throughout, and that is the point
────────────────────────────────────────────────────────────
Every runtime rule is an enumeration: the probe reports offenders, and finding
none is a real result rather than a missing reading. So a clean host passes.

Two states must **not** collapse into that, and the probes keep them apart with
two different exit statuses:

* **No runtime installed** (exit 97) — most hosts in an estate. UNSUPPORTED →
  NOT_APPLICABLE: the check was never in scope, and reporting an error would
  hand every such host a page of findings-shaped noise about software it does
  not have.
* **Runtime installed but not answering** (exit 96) — UNAVAILABLE → ERROR. The
  probes require ``docker info`` and ``kubectl version`` to succeed, not merely
  that a binary exists, because ``docker ps`` against an unreachable daemon
  returns an *empty container list* that is byte-identical to a clean host.
"""

from __future__ import annotations

from typing import List

from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

__all__ = ["CONTAINER_RUNTIME_CHECKS", "container_runtime_checks"]

_DOCKER_DOC = "https://docs.docker.com/engine/security/"
_K8S_DOC = "https://kubernetes.io/docs/concepts/security/"


def _probe_check(
    *,
    suffix: str,
    probe: str,
    title: str,
    severity: str,
    description: str,
    rationale: str,
    remediation: str,
    area: str,
    runtime: str,
    references,
) -> ConfigCheck:
    return ConfigCheck(
        check_id=f"ccure.ctr.{suffix}",
        title=title,
        check_type="container",
        platforms=("linux",),
        severity=severity,
        collect={"probe": probe, "result": "rows"},
        expect=Expectation("is_empty", description="nothing offending"),
        # An enumeration that returned nothing is a real result, unlike a
        # missing file. Same reasoning as the Phase 5 privilege probes.
        absent=AbsencePolicy.PASS,
        description=description,
        rationale=rationale,
        remediation=remediation,
        references=tuple(references),
        tags=("container", runtime),
        metadata={"gap17_area": area, "runtime": runtime},
    )


CONTAINER_RUNTIME_CHECKS: List[ConfigCheck] = [
    # ── Docker runtime ───────────────────────────────────────────────────────
    _probe_check(
        suffix="docker.privileged",
        probe="docker.privileged",
        title="No container runs with --privileged",
        severity="critical",
        description=(
            "Running containers started with --privileged, which disables "
            "essentially every isolation the runtime provides."
        ),
        rationale=(
            "A privileged container gets all capabilities, unrestricted device "
            "access and no seccomp or AppArmor confinement. Escaping it to the "
            "host is not an exploit, it is a documented feature — mounting the "
            "host disk and chrooting into it takes two commands."
        ),
        remediation=(
            "Remove --privileged and grant only the specific capabilities or "
            "device the workload needs, with --cap-add and --device."
        ),
        area="ctr.runtime.privileged",
        runtime="docker",
        references=(_DOCKER_DOC,),
    ),
    _probe_check(
        suffix="docker.host_namespaces",
        probe="docker.host_namespaces",
        title="No container shares the host PID, IPC or UTS namespace",
        severity="high",
        description=("Containers started with --pid=host, --ipc=host or --uts=host."),
        rationale=(
            "Sharing the host PID namespace lets the container see and signal "
            "every process on the machine, and read their memory through "
            "/proc if it has the capability. Shared IPC exposes host shared "
            "memory. Each removes a boundary the container was meant to have."
        ),
        remediation=(
            "Drop the --pid, --ipc and --uts host flags. Where a monitoring "
            "agent genuinely needs process visibility, run it on the host "
            "rather than in a container pretending to be isolated."
        ),
        area="ctr.runtime.host_namespaces",
        runtime="docker",
        references=(_DOCKER_DOC,),
    ),
    _probe_check(
        suffix="docker.host_network",
        probe="docker.host_network",
        title="No container shares the host network namespace",
        severity="medium",
        description="Containers started with --network=host.",
        rationale=(
            "The container binds directly onto the host's interfaces, so port "
            "publishing and network policy no longer apply to it and it can "
            "reach anything the host can, including services bound to "
            "loopback that were never meant to be reachable."
        ),
        remediation=(
            "Use a user-defined network and publish only the ports the service "
            "needs."
        ),
        area="ctr.runtime.host_network",
        runtime="docker",
        references=(_DOCKER_DOC,),
    ),
    _probe_check(
        suffix="docker.socket_mount",
        probe="docker.docker_socket",
        title="No container has the Docker socket mounted into it",
        severity="critical",
        description=(
            "Containers with /var/run/docker.sock bind-mounted, which grants "
            "them the Docker API."
        ),
        rationale=(
            "The Docker API is root-equivalent on the host by design. A "
            "container holding the socket can start a privileged container "
            "that mounts the host filesystem, so this is a container escape "
            "requiring no vulnerability at all — and it is the single most "
            "common one, because CI runners and monitoring agents ask for it."
        ),
        remediation=(
            "Remove the bind mount. Where a workload must talk to the daemon, "
            "put a proxy in front of it that permits only the specific calls "
            "it needs."
        ),
        area="ctr.runtime.docker_socket",
        runtime="docker",
        references=("https://docs.docker.com/engine/security/protect-access/",),
    ),
    _probe_check(
        suffix="docker.sensitive_mounts",
        probe="docker.sensitive_mounts",
        title="No container bind-mounts a sensitive host path",
        severity="high",
        description=(
            "Containers bind-mounting /, /etc, /proc, /sys, /boot, /dev, "
            "/root or the Docker data directory from the host."
        ),
        rationale=(
            "A writable mount of /etc rewrites the host's accounts and cron; "
            "a mount of / is the host filesystem. Even read-only, these hand "
            "over credentials and configuration the container had no reason "
            "to see."
        ),
        remediation=(
            "Mount only the specific directory the workload needs, read-only "
            "where possible."
        ),
        area="ctr.runtime.sensitive_mounts",
        runtime="docker",
        references=(_DOCKER_DOC,),
    ),
    _probe_check(
        suffix="docker.run_as_root",
        probe="docker.run_as_root",
        title="No container runs its process as uid 0",
        severity="medium",
        description=(
            "Containers whose configured user is root, or which declare no "
            "user at all and therefore inherit the image's default of root."
        ),
        rationale=(
            "Root in the container is root on the host the moment any "
            "isolation boundary fails, and it makes every other weakness — a "
            "writable mount, an added capability — worth more to an attacker."
        ),
        remediation=(
            "Set USER in the image or --user at run time. Combine with "
            "--read-only and a dropped capability set."
        ),
        area="ctr.runtime.run_as_root",
        runtime="docker",
        references=(_DOCKER_DOC,),
    ),
    _probe_check(
        suffix="docker.added_capabilities",
        probe="docker.added_capabilities",
        title="No container is granted a capability that reaches the host",
        severity="high",
        description=(
            "Containers granted SYS_ADMIN, SYS_PTRACE, SYS_MODULE, SYS_RAWIO, "
            "DAC_READ_SEARCH, NET_ADMIN or ALL. Capabilities images "
            "legitimately add, such as NET_BIND_SERVICE, are not reported."
        ),
        rationale=(
            "SYS_ADMIN is close to privileged on its own — it permits mounting "
            "and much of what --privileged grants. SYS_PTRACE reaches into "
            "other processes, SYS_MODULE loads kernel code, and "
            "DAC_READ_SEARCH bypasses file permission checks entirely."
        ),
        remediation=(
            "Drop the capability. Where one is genuinely required, record the "
            "exception and pair it with a read-only root filesystem and a "
            "non-root user."
        ),
        area="ctr.runtime.added_capabilities",
        runtime="docker",
        references=("https://man7.org/linux/man-pages/man7/capabilities.7.html",),
    ),
    _probe_check(
        suffix="docker.no_new_privileges",
        probe="docker.no_new_privileges",
        title="Containers are started with no-new-privileges",
        severity="medium",
        description=("Containers without --security-opt no-new-privileges:true."),
        rationale=(
            "Without it a setuid binary inside the image can still raise "
            "privileges, so a container running as a non-root user is not "
            "actually confined to that user's authority."
        ),
        remediation=(
            "Add --security-opt no-new-privileges:true, or set it as a daemon "
            "default so every container inherits it."
        ),
        area="ctr.runtime.no_new_privileges",
        runtime="docker",
        references=(_DOCKER_DOC,),
    ),
    _probe_check(
        suffix="docker.readonly_rootfs",
        probe="docker.readonly_rootfs",
        title="Containers run with a read-only root filesystem",
        severity="low",
        description="Containers whose root filesystem is writable.",
        rationale=(
            "A writable root filesystem lets an attacker who reaches code "
            "execution drop tooling and persist inside the container. A "
            "read-only root with explicit writable volumes removes that "
            "without changing what the application can legitimately do."
        ),
        remediation=(
            "Add --read-only and mount tmpfs or a volume at the specific "
            "paths the application writes to."
        ),
        area="ctr.runtime.readonly_rootfs",
        runtime="docker",
        references=(_DOCKER_DOC,),
    ),
    # ── Kubernetes ───────────────────────────────────────────────────────────
    _probe_check(
        suffix="k8s.privileged_pods",
        probe="k8s.privileged_pods",
        title="No workload pod runs a privileged container",
        severity="critical",
        description=(
            "Pods outside kube-system whose containers set "
            "securityContext.privileged. The cluster's own components are "
            "excluded because several of them legitimately require it."
        ),
        rationale=(
            "A privileged pod has the node, not just the pod. It is the "
            "standard first step from an application compromise to control of "
            "the worker and everything scheduled on it."
        ),
        remediation=(
            "Remove securityContext.privileged and grant the specific "
            "capability the workload needs. Enforce it with Pod Security "
            "admission so it cannot be reintroduced."
        ),
        area="k8s.workload.privileged",
        runtime="kubernetes",
        references=(_K8S_DOC,),
    ),
    _probe_check(
        suffix="k8s.host_namespace_pods",
        probe="k8s.host_namespace_pods",
        title="No workload pod shares a host namespace",
        severity="high",
        description=(
            "Pods outside kube-system setting hostPID, hostIPC or hostNetwork."
        ),
        rationale=(
            "hostNetwork puts the pod on the node's interfaces, bypassing "
            "NetworkPolicy entirely; hostPID exposes every process on the "
            "node. Both remove a boundary the cluster's other controls assume "
            "is there."
        ),
        remediation=(
            "Remove the host namespace flags and enforce the 'baseline' or "
            "'restricted' Pod Security standard on the namespace."
        ),
        area="k8s.workload.host_namespaces",
        runtime="kubernetes",
        references=(_K8S_DOC,),
    ),
    _probe_check(
        suffix="k8s.root_pods",
        probe="k8s.root_pods",
        title="Workload pods declare that they do not run as root",
        severity="medium",
        description=(
            "Pods outside kube-system that set neither runAsNonRoot nor a "
            "non-zero runAsUser, at pod or container level."
        ),
        rationale=(
            "A pod that says nothing runs as whatever uid the image declares, "
            "which for most images is 0. Declaring runAsNonRoot makes the "
            "kubelet refuse to start a container that would run as root, which "
            "turns an image regression into a failed deployment rather than a "
            "silent privilege increase."
        ),
        remediation=(
            "Set securityContext.runAsNonRoot: true and a runAsUser, and "
            "enforce it through Pod Security admission."
        ),
        area="k8s.workload.run_as_nonroot",
        runtime="kubernetes",
        references=(_K8S_DOC,),
    ),
    _probe_check(
        suffix="k8s.pod_security",
        probe="k8s.pod_security_namespaces",
        title="Namespaces enforce a Pod Security standard",
        severity="high",
        description=(
            "Namespaces with no pod-security.kubernetes.io/enforce label. The "
            "cluster's own namespaces are excluded."
        ),
        rationale=(
            "Pod Security admission is opt-in per namespace. Without the "
            "enforce label the namespace admits privileged pods, host "
            "namespaces and host path mounts regardless of any other policy, "
            "so every workload rule above becomes advisory."
        ),
        remediation=(
            "Label the namespace "
            "pod-security.kubernetes.io/enforce=baseline (or restricted), "
            "after checking existing workloads against it with the warn label."
        ),
        area="k8s.workload.pod_security",
        runtime="kubernetes",
        references=(
            "https://kubernetes.io/docs/concepts/security/pod-security-admission/",
        ),
    ),
    _probe_check(
        suffix="k8s.cluster_admin",
        probe="k8s.cluster_admin_bindings",
        title="cluster-admin is not bound beyond the cluster's own bindings",
        severity="high",
        description=(
            "Subjects bound to the cluster-admin ClusterRole, excluding the "
            "binding Kubernetes creates for system:masters."
        ),
        rationale=(
            "cluster-admin is unbounded authority over every resource in every "
            "namespace, including secrets and the RBAC rules themselves. A "
            "ServiceAccount holding it turns any pod running under it into "
            "full cluster control."
        ),
        remediation=(
            "Remove the binding and grant a role scoped to what the subject "
            "actually needs, namespaced where possible."
        ),
        area="k8s.rbac.cluster_admin",
        runtime="kubernetes",
        references=("https://kubernetes.io/docs/reference/access-authn-authz/rbac/",),
    ),
    _probe_check(
        suffix="k8s.wildcard_roles",
        probe="k8s.wildcard_roles",
        title="No custom role grants wildcard verbs on wildcard resources",
        severity="high",
        description=(
            "Roles and ClusterRoles granting '*' verbs on '*' resources. Roles "
            "Kubernetes ships are excluded by their bootstrapping label — "
            "cluster-admin legitimately holds exactly this."
        ),
        rationale=(
            "A wildcard on both axes is authority over resource kinds that do "
            "not exist yet: install a CRD next month and the role covers it. "
            "It cannot be reasoned about from a review of what exists today."
        ),
        remediation=(
            "Enumerate the apiGroups, resources and verbs the subject needs. "
            "Where a wildcard is unavoidable, confine it to one apiGroup."
        ),
        area="k8s.rbac.wildcards",
        runtime="kubernetes",
        references=("https://kubernetes.io/docs/reference/access-authn-authz/rbac/",),
    ),
    _probe_check(
        suffix="k8s.default_sa_automount",
        probe="k8s.default_sa_automount",
        title="Default ServiceAccounts do not automount their token",
        severity="medium",
        description=(
            "Default ServiceAccounts outside the cluster's own namespaces that "
            "have not set automountServiceAccountToken: false."
        ),
        rationale=(
            "The default ServiceAccount exists in every namespace and its "
            "token is projected into any pod that does not opt out. A "
            "container compromise therefore hands over an API credential the "
            "workload never asked for and probably does not use."
        ),
        remediation=(
            "Set automountServiceAccountToken: false on the default "
            "ServiceAccount in each namespace, and mount a token explicitly "
            "for the workloads that genuinely call the API."
        ),
        area="k8s.rbac.default_sa_automount",
        runtime="kubernetes",
        references=(
            "https://kubernetes.io/docs/tasks/configure-pod-container/"
            "configure-service-account/",
        ),
    ),
    _probe_check(
        suffix="k8s.rbac_enabled",
        probe="k8s.rbac_disabled",
        title="The cluster enforces RBAC authorization",
        severity="critical",
        description=(
            "Whether the API server serves the rbac.authorization.k8s.io "
            "group. It does not when RBAC is disabled, which is the "
            "observable — the API server's own flags are not readable on every "
            "distribution."
        ),
        rationale=(
            "Without RBAC the API server authorises by another mode, and the "
            "common alternative on a misconfigured cluster is AlwaysAllow: "
            "every authenticated request succeeds, and every role and binding "
            "in the cluster is decoration."
        ),
        remediation=(
            "Start the API server with --authorization-mode including RBAC. "
            "On a managed or embedded distribution this is a cluster setting "
            "rather than a flag."
        ),
        area="k8s.apiserver.authorization_mode",
        runtime="kubernetes",
        references=("https://kubernetes.io/docs/reference/access-authn-authz/rbac/",),
    ),
]


def container_runtime_checks() -> List[ConfigCheck]:
    return list(CONTAINER_RUNTIME_CHECKS)
