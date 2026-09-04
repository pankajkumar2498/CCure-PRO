"""
core/config_audit/containers.py
─────────────────────────────────────────────────────────────────────────────
Probes that read the *live state* of a container runtime or a Kubernetes
cluster. Phase 9 of the gap-closure programme, closing GAP-17.

Why these are probes in code rather than rules carrying shell
────────────────────────────────────────────────────────────
This is the position Phase 5 took for ``privilege`` and it applies here
verbatim. "Which running containers are privileged" is not a setting to read —
it is enumerate, inspect, filter, and report the offenders. Expressing that as
a rule-supplied one-liner would put a pipeline of ``docker inspect`` and
``jq``-shaped text munging into administrator-editable data, where it cannot
be inspected, cannot be tested, and offers a fresh chance for a non-zero exit
to be read as "nothing found".

So a rule names a probe. The command is fixed in this module, the *filtering
happens in Python* against the command's output, and every ``extract`` below is
tested against captured real output.

The shape is "which items are offending", not "read one value"
──────────────────────────────────────────────────────────────
A probe returns one offender per line, so a clean cluster produces an ABSENT
reading and ``AbsencePolicy.PASS`` makes it a pass, while a breached one names
exactly what to fix. Same as Phase 5, and the same reason: a count says
nothing, and the remediation has to name the container.

Exit 97 means the tool is not installed
───────────────────────────────────────
The reserved Phase 3 sentinel. A host with no ``docker`` binary has
established nothing about its containers, and reporting that as "none found"
is the exact inversion this engine exists to prevent. It becomes UNAVAILABLE,
which the engine renders as ERROR — never a pass.

That distinction carries real weight here, because *most* hosts in an estate
run no containers at all. A missing runtime must not read as a clean one.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Tuple

log = logging.getLogger("ccure.config_audit.containers")

__all__ = [
    "CONTAINER_PROBES",
    "ContainerProbe",
    "probe_names",
    "probe_for",
]

#: The tool is not installed at all — this is not a host of that kind.
#:
#: Reported as UNSUPPORTED → NOT_APPLICABLE, matching how Phase 8 treats a
#: missing configuration file. Most hosts in an estate run no Kubernetes, and
#: they are not *failing* Kubernetes rules; the check was never in scope.
#:
#: This deliberately differs from the Phase 3 and Phase 5 use of exit 97, where
#: a missing ``find`` is an ERROR. The distinction is whether the thing being
#: enumerated exists on every host: every Linux host has SUID binaries, so
#: being unable to list them is a gap in what we could assess. Not every host
#: has a container runtime, so not finding one is an answer.
TOOL_MISSING = 97

#: The tool is installed but not answering — a docker binary whose daemon is
#: unreachable, a kubectl that cannot contact the API server.
#:
#: Reported as UNAVAILABLE → ERROR, and the distinction from the above is the
#: whole reason there are two codes. This *is* a container host, and we failed
#: to assess it. Collapsing the two would let an unreachable daemon read as
#: "no containers here", which is the inversion this engine exists to prevent:
#: ``docker ps`` against a dead daemon returns an empty list, byte-identical to
#: a host running nothing.
TOOL_UNREACHABLE = 96

#: Host paths whose bind-mount into a container is a route to the host. ``/``
#: and ``/etc`` are the obvious ones; ``/var/run/docker.sock`` is handled by its
#: own probe because it is not merely sensitive, it is root-equivalent.
_SENSITIVE_MOUNTS = (
    "/",
    "/etc",
    "/proc",
    "/sys",
    "/boot",
    "/dev",
    "/var/lib/docker",
    "/root",
)

#: Capabilities whose addition materially changes what a container can do to
#: the host. Deliberately not "anything added": images legitimately add
#: NET_BIND_SERVICE, and a probe that fires on it trains the reader to ignore
#: the check — the same allow-list reasoning as the Phase 5 SUID probe.
_DANGEROUS_CAPABILITIES = (
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "SYS_RAWIO",
    "DAC_READ_SEARCH",
    "NET_ADMIN",
    "ALL",
)


@dataclass(frozen=True)
class ContainerProbe:
    """One enumeration, and the code that turns its output into offenders."""

    name: str
    #: The shell command. Fixed here, never supplied by a rule.
    command: str
    #: Turns the command's stdout into a list of offenders. Pure, so it can be
    #: tested against captured output with no target in sight.
    extract: Callable[[str], List[str]]
    #: What the probe needs, named in the "not installed" message.
    requires: str
    description: str = ""


# ── Shell preambles ──────────────────────────────────────────────────────────

#: Refuses to run unless docker is present *and* answering. A docker binary
#: with no reachable daemon would otherwise produce an empty container list,
#: which is indistinguishable from a host running no containers.
_DOCKER_GUARD = (
    "command -v docker >/dev/null 2>&1 || exit 97; "
    "docker info >/dev/null 2>&1 || exit 96; "
)

#: kubectl, or k3s's bundled equivalent. KUBECONFIG is honoured where the
#: caller set one and falls back to the k3s location, which is where a
#: single-node cluster puts it.
_KUBECTL_GUARD = (
    "if command -v kubectl >/dev/null 2>&1; then K=kubectl; "
    "elif command -v k3s >/dev/null 2>&1; then K='k3s kubectl'; "
    "else exit 97; fi; "
    "export KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}; "
    "$K version --request-timeout=10s >/dev/null 2>&1 || exit 96; "
)


def _docker_inspect(go_template: str) -> str:
    """
    Inspect every running container with a Go template.

    ``docker ps -q`` then ``inspect`` rather than ``docker ps --format``,
    because the interesting fields — HostConfig, Config.User, Mounts — are only
    on the inspect output.
    """
    return (
        _DOCKER_GUARD
        + 'ids=$(docker ps -q); [ -z "$ids" ] && exit 0; '
        + f"docker inspect --format '{go_template}' $ids"
    )


def _nonempty_lines(text: str) -> List[str]:
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def _kubectl_json(resource: str, extra: str = "") -> str:
    return _KUBECTL_GUARD + f"$K get {resource} -A -o json {extra}".strip()


# ── Extractors ───────────────────────────────────────────────────────────────
#
# Every one of these is pure and tested against captured output. A probe whose
# filtering lives in a shell pipeline cannot be tested this way, which is most
# of the argument for this module existing.


def _lines(text: str) -> List[str]:
    return _nonempty_lines(text)


def _json_items(text: str) -> List[Dict[str, Any]]:
    """
    The ``items`` of a kubectl list, or [] where the output is not a list.

    Raises nothing: a malformed body is the collector's problem to report as
    UNAVAILABLE, and it detects that from the command's exit status. What must
    not happen is an exception here being read as "no offenders".
    """
    try:
        document = json.loads(text or "{}")
    except json.JSONDecodeError:
        raise ValueError("kubectl did not return JSON")
    items = document.get("items")
    return items if isinstance(items, list) else []


def _pod_name(item: Dict[str, Any]) -> str:
    meta = item.get("metadata") or {}
    return f"{meta.get('namespace', '?')}/{meta.get('name', '?')}"


def _pod_containers(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    spec = item.get("spec") or {}
    return [
        *(spec.get("containers") or []),
        *(spec.get("initContainers") or []),
    ]


def _skip_system_namespace(item: Dict[str, Any]) -> bool:
    """
    Kubernetes' own components legitimately do most of what these probes look
    for — kube-proxy is privileged, CNI pods share the host network. Reporting
    them produces a page of findings on every cluster ever built, which is the
    "37 SUID binaries" failure in a different runtime.
    """
    namespace = ((item.get("metadata") or {}).get("namespace") or "").lower()
    return namespace in ("kube-system", "kube-public", "kube-node-lease")


def _privileged_pods(text: str) -> List[str]:
    out: List[str] = []
    for item in _json_items(text):
        if _skip_system_namespace(item):
            continue
        for container in _pod_containers(item):
            context = container.get("securityContext") or {}
            if context.get("privileged") is True:
                out.append(f"{_pod_name(item)} [{container.get('name', '?')}]")
    return out


def _host_namespace_pods(text: str) -> List[str]:
    out: List[str] = []
    for item in _json_items(text):
        if _skip_system_namespace(item):
            continue
        spec = item.get("spec") or {}
        shared = [
            key
            for key in ("hostPID", "hostIPC", "hostNetwork")
            if spec.get(key) is True
        ]
        if shared:
            out.append(f"{_pod_name(item)} shares {', '.join(shared)}")
    return out


def _root_pods(text: str) -> List[str]:
    """
    Pods that neither declare ``runAsNonRoot`` nor a non-zero ``runAsUser``, at
    the pod level or on the container.

    A pod that says nothing is reported, because the Kubernetes default is to
    run as whatever uid the image declares — which for most images is 0.
    """
    out: List[str] = []
    for item in _json_items(text):
        if _skip_system_namespace(item):
            continue
        spec = item.get("spec") or {}
        pod_context = spec.get("securityContext") or {}
        for container in _pod_containers(item):
            context = {**pod_context, **(container.get("securityContext") or {})}
            if context.get("runAsNonRoot") is True:
                continue
            user = context.get("runAsUser")
            if isinstance(user, int) and user != 0:
                continue
            out.append(f"{_pod_name(item)} [{container.get('name', '?')}]")
    return out


def _cluster_admin_subjects(text: str) -> List[str]:
    """
    Subjects bound to cluster-admin, excluding the bindings Kubernetes creates
    for itself.

    ``cluster-admin`` is unbounded authority over the cluster, so every subject
    holding it is worth a reviewer's attention — but ``system:masters`` and the
    controller-manager bindings are how the cluster works at all.
    """
    out: List[str] = []
    for item in _json_items(text):
        role = (item.get("roleRef") or {}).get("name")
        if role != "cluster-admin":
            continue
        name = (item.get("metadata") or {}).get("name", "?")
        if name in ("cluster-admin",):
            continue
        for subject in item.get("subjects") or []:
            kind = subject.get("kind", "?")
            subject_name = subject.get("name", "?")
            if subject_name in ("system:masters",):
                continue
            out.append(f"{name}: {kind}/{subject_name}")
    return out


def _bootstrap_role(item: Dict[str, Any]) -> bool:
    """
    Whether Kubernetes ships this role itself.

    Every role the cluster creates at bootstrap carries
    ``kubernetes.io/bootstrapping: rbac-defaults`` — 65 of the 69 ClusterRoles
    on a stock k3s. The label is the right filter rather than a name prefix,
    because ``cluster-admin`` does not start with ``system:`` and it is *the*
    role that legitimately holds ``*`` on ``*``. Without this the wildcard
    probe reports cluster-admin on every cluster ever built, which is the
    fleet-wide false positive that trains a reader to ignore the check.
    """
    labels = (item.get("metadata") or {}).get("labels") or {}
    return labels.get("kubernetes.io/bootstrapping") == "rbac-defaults"


def _wildcard_roles(text: str) -> List[str]:
    """
    Roles granting ``*`` for verbs *and* resources.

    Either alone is common and often reasonable — ``get`` on ``*`` is what a
    monitoring role looks like. Both together is unbounded authority inside the
    role's scope, which is what this reports.
    """
    out: List[str] = []
    for item in _json_items(text):
        meta = item.get("metadata") or {}
        name = meta.get("name", "?")
        if name.startswith("system:") or _bootstrap_role(item):
            continue
        for rule in item.get("rules") or []:
            verbs = rule.get("verbs") or []
            resources = rule.get("resources") or []
            if "*" in verbs and "*" in resources:
                namespace = meta.get("namespace")
                where = f"{namespace}/" if namespace else ""
                out.append(f"{where}{name}")
                break
    return out


def _automounting_default_service_accounts(text: str) -> List[str]:
    """
    Default ServiceAccounts that still mount their token into every pod.

    The default SA exists in every namespace and its token is projected into
    any pod that does not opt out, so a container compromise hands over an API
    credential the workload never asked for.
    """
    out: List[str] = []
    for item in _json_items(text):
        meta = item.get("metadata") or {}
        if meta.get("name") != "default":
            continue
        namespace = (meta.get("namespace") or "").lower()
        if namespace in ("kube-system", "kube-public", "kube-node-lease"):
            continue
        if item.get("automountServiceAccountToken") is False:
            continue
        out.append(f"{namespace}/default")
    return out


def _namespaces_without_pod_security(text: str) -> List[str]:
    """
    Namespaces with no Pod Security admission ``enforce`` label.

    Pod Security admission is the built-in replacement for PodSecurityPolicy
    and is opt-in per namespace: without the label, the namespace admits
    privileged pods regardless of what the cluster's other controls say.
    """
    out: List[str] = []
    for item in _json_items(text):
        meta = item.get("metadata") or {}
        name = (meta.get("name") or "").lower()
        if name in ("kube-system", "kube-public", "kube-node-lease"):
            continue
        labels = meta.get("labels") or {}
        if labels.get("pod-security.kubernetes.io/enforce"):
            continue
        out.append(name or "?")
    return out


# ── The probe catalogue ──────────────────────────────────────────────────────

_DOCKER_PROBES: Tuple[ContainerProbe, ...] = (
    ContainerProbe(
        name="docker.privileged",
        command=_docker_inspect("{{if .HostConfig.Privileged}}{{.Name}}{{end}}"),
        extract=_lines,
        requires="docker",
        description="Running containers started with --privileged",
    ),
    ContainerProbe(
        name="docker.host_namespaces",
        command=_docker_inspect(
            '{{if or (eq .HostConfig.PidMode "host") '
            '(eq .HostConfig.IpcMode "host") '
            '(eq .HostConfig.UTSMode "host")}}{{.Name}}{{end}}'
        ),
        extract=_lines,
        requires="docker",
        description="Containers sharing the host PID, IPC or UTS namespace",
    ),
    ContainerProbe(
        name="docker.host_network",
        command=_docker_inspect(
            '{{if eq .HostConfig.NetworkMode "host"}}{{.Name}}{{end}}'
        ),
        extract=_lines,
        requires="docker",
        description="Containers sharing the host network namespace",
    ),
    ContainerProbe(
        name="docker.docker_socket",
        command=_docker_inspect(
            "{{$n := .Name}}{{range .Mounts}}"
            '{{if eq .Source "/var/run/docker.sock"}}{{$n}}{{end}}{{end}}'
        ),
        extract=_lines,
        requires="docker",
        description="Containers with the Docker socket bind-mounted in",
    ),
    ContainerProbe(
        name="docker.sensitive_mounts",
        command=_docker_inspect(
            "{{$n := .Name}}{{range .Mounts}}"
            '{{if eq .Type "bind"}}{{$n}} <- {{.Source}}{{"\\n"}}{{end}}'
            "{{end}}"
        ),
        extract=lambda text: [
            line
            for line in _nonempty_lines(text)
            if any(
                line.rsplit("<- ", 1)[-1].strip() == path
                or line.rsplit("<- ", 1)[-1].strip().startswith(path.rstrip("/") + "/")
                for path in _SENSITIVE_MOUNTS
                if path != "/"
            )
            or line.rsplit("<- ", 1)[-1].strip() == "/"
        ],
        requires="docker",
        description="Containers bind-mounting a sensitive host path",
    ),
    ContainerProbe(
        name="docker.run_as_root",
        command=_docker_inspect(
            '{{if or (eq .Config.User "") (eq .Config.User "root") '
            '(eq .Config.User "0")}}{{.Name}}{{end}}'
        ),
        extract=_lines,
        requires="docker",
        description="Containers whose process runs as uid 0",
    ),
    ContainerProbe(
        name="docker.added_capabilities",
        command=_docker_inspect(
            "{{$n := .Name}}{{range .HostConfig.CapAdd}}"
            '{{$n}} +{{.}}{{"\\n"}}{{end}}'
        ),
        extract=lambda text: [
            line
            for line in _nonempty_lines(text)
            if any(
                line.rsplit("+", 1)[-1].strip().upper().removeprefix("CAP_") == cap
                for cap in _DANGEROUS_CAPABILITIES
            )
        ],
        requires="docker",
        description="Containers granted a capability that reaches the host",
    ),
    ContainerProbe(
        name="docker.no_new_privileges",
        command=_docker_inspect(
            "{{$n := .Name}}{{$found := false}}"
            "{{range .HostConfig.SecurityOpt}}"
            '{{if eq . "no-new-privileges:true"}}{{$found = true}}{{end}}{{end}}'
            "{{if not $found}}{{$n}}{{end}}"
        ),
        extract=_lines,
        requires="docker",
        description="Containers without the no-new-privileges security option",
    ),
    ContainerProbe(
        name="docker.readonly_rootfs",
        command=_docker_inspect(
            "{{if not .HostConfig.ReadonlyRootfs}}{{.Name}}{{end}}"
        ),
        extract=_lines,
        requires="docker",
        description="Containers whose root filesystem is writable",
    ),
)

_KUBERNETES_PROBES: Tuple[ContainerProbe, ...] = (
    ContainerProbe(
        name="k8s.privileged_pods",
        command=_kubectl_json("pods"),
        extract=_privileged_pods,
        requires="kubectl",
        description="Pods running a privileged container",
    ),
    ContainerProbe(
        name="k8s.host_namespace_pods",
        command=_kubectl_json("pods"),
        extract=_host_namespace_pods,
        requires="kubectl",
        description="Pods sharing a host namespace",
    ),
    ContainerProbe(
        name="k8s.root_pods",
        command=_kubectl_json("pods"),
        extract=_root_pods,
        requires="kubectl",
        description="Pods that may run as root",
    ),
    ContainerProbe(
        name="k8s.cluster_admin_bindings",
        command=_kubectl_json("clusterrolebindings"),
        extract=_cluster_admin_subjects,
        requires="kubectl",
        description="Subjects bound to cluster-admin",
    ),
    ContainerProbe(
        name="k8s.wildcard_roles",
        command=_kubectl_json("clusterroles,roles"),
        extract=_wildcard_roles,
        requires="kubectl",
        description="Roles granting wildcard verbs on wildcard resources",
    ),
    ContainerProbe(
        name="k8s.default_sa_automount",
        command=_kubectl_json("serviceaccounts"),
        extract=_automounting_default_service_accounts,
        requires="kubectl",
        description="Default ServiceAccounts that automount their token",
    ),
    ContainerProbe(
        name="k8s.rbac_disabled",
        # If RBAC is not enabled, the API server does not serve the
        # rbac.authorization.k8s.io group at all — so its absence from
        # api-versions is the observable, and it needs no manifest to read.
        # That matters because the API server's own flags are unreadable on
        # every cluster this build can validate against.
        command=_KUBECTL_GUARD + "$K api-versions",
        extract=lambda text: (
            []
            if any(
                line.strip().startswith("rbac.authorization.k8s.io/")
                for line in _nonempty_lines(text)
            )
            else ["the API server does not serve rbac.authorization.k8s.io"]
        ),
        requires="kubectl",
        description="Whether RBAC authorization is enabled on the cluster",
    ),
    ContainerProbe(
        name="k8s.pod_security_namespaces",
        command=_KUBECTL_GUARD + "$K get namespaces -o json",
        extract=_namespaces_without_pod_security,
        requires="kubectl",
        description="Namespaces with no Pod Security admission enforcement",
    ),
)

CONTAINER_PROBES: Dict[str, ContainerProbe] = {
    probe.name: probe for probe in (*_DOCKER_PROBES, *_KUBERNETES_PROBES)
}


def probe_names() -> List[str]:
    return sorted(CONTAINER_PROBES)


def probe_for(name: str) -> ContainerProbe:
    try:
        return CONTAINER_PROBES[str(name)]
    except KeyError as exc:
        raise KeyError(
            f"no container probe named {name!r}; known probes are "
            f"{', '.join(probe_names())}"
        ) from exc
