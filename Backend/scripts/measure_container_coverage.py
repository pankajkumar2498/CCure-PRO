"""
scripts/measure_container_coverage.py
─────────────────────────────────────────────────────────────────────────────
Measures GAP-17 coverage — container runtime and Kubernetes configuration
assessment.

    python -m scripts.measure_container_coverage

Run before and after a change to get a comparable number.

What this denominator covers, and what it deliberately does not
──────────────────────────────────────────────────────────────
**The configuration of a container runtime and an orchestrator, read over a
credentialed session with the host that runs them.** What the containers are
*configured to be able to do*, and what the cluster is *configured to allow*.

It does **not** cover the Docker **daemon** configuration — ``daemon.json``,
the TCP socket, ``icc``, ``userns-remap``, insecure registries, the log driver.
All ten of those checks were built and validated in **GAP-09**, which owns
them. Counting them again here would inflate this figure by a quarter before a
line of the phase was written, and misattributing coverage between gaps is a
mistake this programme has had to correct twice already.

That boundary is why GAP-17 measures **0/42 before this phase** while the gap
matrix carried "5% [estimated]". The residual credit the matrix was giving is
for detecting that a container runtime is *installed*, which the Phase 3
``package`` and ``service`` collectors already do.

Three exclusions the brief made explicit, and they are real scope
─────────────────────────────────────────────────────────────────
Image vulnerability scanning, registry scanning and managed-cloud Kubernetes
integration are **out of the denominator entirely**, not merely unimplemented.
They are a different product shape — Tenable splits them into Tenable.cs rather
than Nessus — and they need a Trivy/Grype-class toolchain and cloud
credentials, neither of which this engine has or should grow.

Why the denominator includes things we did not build
────────────────────────────────────────────────────
Eighteen of the forty-two areas below are real container and Kubernetes audit
checks this build does **not** perform. Most of the Kubernetes control-plane
ones need a cluster whose API server runs from a static manifest, which k3s —
the only cluster that can be stood up disposably here — does not use. Each
carries its reason.

A coverage figure is only worth reading if it can go down.

Three things are counted separately and must never be conflated
──────────────────────────────────────────────────────────────
``implemented``   a check exists and the engine can execute it
``tested``        an automated test names the area and exercises it
``validated``     it has produced a correct result against a real runtime

**The headline coverage figure is implemented *and* tested.**
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

#: The runtimes this phase set out to support.
SUPPORTED_RUNTIMES: Tuple[str, ...] = ("docker", "containerd", "kubernetes")

#: (area id, theme, description). Frozen at the start of Phase 9 and not to be
#: edited to match what was built.
SCOPE: Tuple[Tuple[str, str, str], ...] = (
    # ── Container runtime: what a running container may do ───────────────────
    ("ctr.runtime.privileged", "runtime", "Containers running privileged"),
    ("ctr.runtime.host_namespaces", "runtime", "Host PID/IPC/UTS namespace shared"),
    ("ctr.runtime.host_network", "runtime", "Host network namespace shared"),
    ("ctr.runtime.docker_socket", "runtime", "Docker socket mounted into a container"),
    ("ctr.runtime.sensitive_mounts", "runtime", "Sensitive host paths bind-mounted"),
    ("ctr.runtime.run_as_root", "runtime", "Containers running as uid 0"),
    ("ctr.runtime.added_capabilities", "runtime", "Capabilities added beyond default"),
    ("ctr.runtime.no_new_privileges", "runtime", "no-new-privileges not set"),
    ("ctr.runtime.readonly_rootfs", "runtime", "Root filesystem writable"),
    ("ctr.runtime.seccomp_apparmor", "runtime", "Default seccomp/AppArmor disabled"),
    ("ctr.runtime.memory_limit", "runtime", "No memory limit"),
    ("ctr.runtime.cpu_limit", "runtime", "No CPU limit"),
    ("ctr.runtime.restart_policy", "runtime", "Unbounded restart policy"),
    ("ctr.runtime.healthcheck", "runtime", "No container healthcheck"),
    # ── containerd ───────────────────────────────────────────────────────────
    ("ctr.containerd.config_readable", "containerd", "Config present and parseable"),
    ("ctr.containerd.socket_permissions", "containerd", "CRI socket permissions"),
    ("ctr.containerd.insecure_mirrors", "containerd", "Registry mirrors without TLS"),
    ("ctr.containerd.userns", "containerd", "User-namespace remapping"),
    # ── Kubernetes: kubelet ──────────────────────────────────────────────────
    ("k8s.kubelet.anonymous_auth", "kubelet", "Anonymous authentication enabled"),
    ("k8s.kubelet.authorization_mode", "kubelet", "Authorization mode AlwaysAllow"),
    ("k8s.kubelet.readonly_port", "kubelet", "Read-only port enabled"),
    ("k8s.kubelet.client_ca", "kubelet", "Client CA not configured"),
    ("k8s.kubelet.streaming_timeout", "kubelet", "Streaming idle timeout"),
    ("k8s.kubelet.rotate_certificates", "kubelet", "Certificate rotation"),
    ("k8s.kubelet.protect_kernel_defaults", "kubelet", "Kernel defaults protected"),
    ("k8s.kubelet.tls_ciphers", "kubelet", "TLS cipher policy"),
    # ── Kubernetes: control plane ────────────────────────────────────────────
    ("k8s.apiserver.anonymous_auth", "controlplane", "API server anonymous auth"),
    ("k8s.apiserver.authorization_mode", "controlplane", "RBAC not enabled"),
    ("k8s.apiserver.admission_plugins", "controlplane", "Admission plugins enabled"),
    ("k8s.apiserver.audit_log", "controlplane", "API server audit logging"),
    ("k8s.apiserver.insecure_port", "controlplane", "Insecure API port"),
    ("k8s.apiserver.etcd_tls", "controlplane", "etcd peer/client TLS"),
    # ── Kubernetes: RBAC ─────────────────────────────────────────────────────
    ("k8s.rbac.cluster_admin", "rbac", "Subjects bound to cluster-admin"),
    ("k8s.rbac.wildcards", "rbac", "Roles granting wildcard verbs or resources"),
    ("k8s.rbac.secrets_access", "rbac", "Roles able to read all secrets"),
    ("k8s.rbac.default_sa_automount", "rbac", "Default ServiceAccount automounts"),
    # ── Kubernetes: workloads and network ────────────────────────────────────
    ("k8s.workload.privileged", "workload", "Privileged pods"),
    ("k8s.workload.host_namespaces", "workload", "Pods sharing host namespaces"),
    ("k8s.workload.run_as_nonroot", "workload", "Pods without runAsNonRoot"),
    ("k8s.workload.pod_security", "workload", "Pod Security admission enforced"),
    ("k8s.workload.default_namespace", "workload", "Workloads in default namespace"),
    ("k8s.network.default_deny", "workload", "Namespaces without default-deny policy"),
)

#: Areas inside the denominator that this phase did not set out to implement,
#: each with the reason.
NOT_PLANNED: Dict[str, str] = {
    # Control plane: k3s runs the API server as flags on a single process
    # rather than from /etc/kubernetes/manifests/*.yaml, so none of these can
    # be read the way a kubeadm cluster exposes them — and k3s is the only
    # cluster that can be stood up disposably in this environment. Shipping
    # them unvalidated is what this programme refuses to do.
    "k8s.apiserver.anonymous_auth": (
        "needs a kubeadm-style static manifest; k3s runs the API server from "
        "process flags and no validatable cluster here exposes them"
    ),
    "k8s.apiserver.admission_plugins": (
        "same as k8s.apiserver.anonymous_auth — no static manifest to read"
    ),
    "k8s.apiserver.audit_log": (
        "audit policy lives in a file the API server is started with; k3s does "
        "not ship one and enabling it is a cluster rebuild"
    ),
    "k8s.apiserver.insecure_port": (
        "removed from Kubernetes entirely in 1.24; a check would pass on every "
        "supported cluster and mean nothing"
    ),
    "k8s.apiserver.etcd_tls": (
        "k3s embeds SQLite or an embedded etcd whose TLS is not configurable "
        "the way a separate etcd cluster's is"
    ),
    "ctr.containerd.socket_permissions": (
        "answered already by the Phase 3 permission collector against the "
        "socket path; a containerd-specific rule would report one condition "
        "twice"
    ),
    "ctr.containerd.userns": (
        "containerd user-namespace support is configured per-runtime-handler "
        "and its shape changed across 1.x; a rule would be version-specific "
        "in a way this phase cannot validate"
    ),
    "ctr.runtime.cpu_limit": (
        "CPU shares are a sizing decision with no defensible expected value; a "
        "rule asserting one would fail on correctly tuned hosts"
    ),
    "ctr.runtime.healthcheck": (
        "a missing healthcheck is an availability concern rather than a "
        "security one, and it fires on most correctly built images"
    ),
    "ctr.runtime.restart_policy": (
        "an unbounded restart policy is a denial-of-service concern only in "
        "combination with a crash loop; on its own it is the common and "
        "correct setting for a service container"
    ),
    "k8s.kubelet.tls_ciphers": (
        "unset on every distribution default including k3s, so the check would "
        "defer everywhere and establish nothing"
    ),
    "k8s.kubelet.streaming_timeout": (
        "k3s does not expose it in the kubelet config file, and reading it "
        "from process flags is the control-plane problem above"
    ),
    "k8s.kubelet.protect_kernel_defaults": (
        "k3s sets kernel parameters itself at startup, so the flag is absent "
        "and its absence does not mean what it means on kubeadm"
    ),
    "k8s.rbac.secrets_access": (
        "requires resolving role rules transitively through bindings and "
        "aggregated ClusterRoles to be meaningful; a flat listing is noise"
    ),
    "k8s.workload.default_namespace": (
        "a workload in the default namespace is a hygiene signal, not a "
        "security finding, and fires on most development clusters"
    ),
    "k8s.network.default_deny": (
        "k3s ships without a NetworkPolicy controller enforcing it by default, "
        "so the check could not be validated in either direction here"
    ),
    "ctr.runtime.seccomp_apparmor": (
        "the effective profile is reported inconsistently between Docker "
        "versions and is empty on a host whose kernel lacks AppArmor, which "
        "cannot be told apart from a disabled profile"
    ),
    "ctr.runtime.memory_limit": (
        "an absent memory limit is the Docker default and fires on nearly "
        "every container; it is a sizing decision rather than a posture one"
    ),
}

#: Named so the exclusion is visible rather than silent.
OUT_OF_SCOPE = (
    "Docker daemon configuration (daemon.json, icc, userns-remap, TCP socket, "
    "insecure registries, log driver) — GAP-09, ten validated checks",
    "container image vulnerability scanning — a different product shape",
    "registry scanning and image provenance",
    "managed-cloud Kubernetes integration (EKS, AKS, GKE control planes)",
    "the host operating system underneath the runtime — GAP-03",
    "unauthenticated network exposure of the API server or kubelet — GAP-06",
)


def _implemented() -> Dict[str, object]:
    try:
        from core.config_audit.builtin import BUILTIN_CHECKS
    except Exception as exc:  # pragma: no cover - import guard
        print(f"could not import the built-in checks: {exc}")
        return {}
    found: Dict[str, object] = {}
    for check in BUILTIN_CHECKS:
        area = str(check.metadata.get("gap17_area") or "")
        if area:
            found.setdefault(area, check)
    return found


def _runtimes_per_area() -> Dict[str, Set[str]]:
    try:
        from core.config_audit.builtin import BUILTIN_CHECKS
    except Exception:  # pragma: no cover
        return {}
    by_area: Dict[str, Set[str]] = {}
    for check in BUILTIN_CHECKS:
        area = str(check.metadata.get("gap17_area") or "")
        runtime = str(check.metadata.get("runtime") or "")
        if area and runtime:
            by_area.setdefault(area, set()).add(runtime)
    return by_area


def _tested() -> Set[str]:
    """
    Areas an automated test names.

    Read from the test sources rather than a hand-maintained list — a list
    keeps saying "tested" until somebody updates it, which is exactly the
    failure a coverage figure must not have.
    """
    root = Path(__file__).resolve().parents[1] / "tests"
    corpus = ""
    for path in root.rglob("test_container*.py"):
        corpus += path.read_text(encoding="utf-8")
    return {area for area, _t, _d in SCOPE if area in corpus}


def main() -> int:
    implemented = _implemented()
    tested = _tested()
    runtimes = _runtimes_per_area()

    print("=" * 78)
    print("GAP-17 — CONTAINER & KUBERNETES CONFIGURATION COVERAGE")
    print("=" * 78)
    print(f"\n{'area':36} {'theme':13} {'impl':5} {'test':5} {'runtime':12}")
    print("-" * 78)

    by_theme: Dict[str, List[bool]] = {}
    for area, theme, _description in SCOPE:
        has = area in implemented
        has_test = area in tested
        by_theme.setdefault(theme, []).append(has and has_test)
        covered = sorted(runtimes.get(area, set()))
        marker = "" if has else ("  (not planned)" if area in NOT_PLANNED else "")
        print(
            f"{area:36} {theme:13} {'yes' if has else 'NO':5} "
            f"{'yes' if has_test else 'NO':5} "
            f"{','.join(covered) if covered else '-':12}{marker}"
        )

    total = len(SCOPE)
    done = sum(1 for area, _t, _d in SCOPE if area in implemented)
    proven = sum(1 for area, _t, _d in SCOPE if area in implemented and area in tested)

    print("-" * 78)
    for theme, flags in by_theme.items():
        print(
            f"  {theme:13} proven: {sum(flags)}/{len(flags)} "
            f"({round(100.0 * sum(flags) / len(flags), 1)}%)"
        )

    print(
        f"\n  implemented          : {done}/{total} = "
        f"{round(100.0 * done / total, 1)}%"
    )
    print(
        f"  implemented + tested : {proven}/{total} = "
        f"**{round(100.0 * proven / total, 1)}%**   <- GAP-17 coverage"
    )
    print("  real-target validated: reported separately, never folded in")

    if done != proven:
        print(
            f"\n  {done - proven} area(s) have a check no automated test names. "
            f"Implemented is not proven, and only proven counts."
        )

    unplanned_but_built = sorted(set(implemented) & set(NOT_PLANNED))
    if unplanned_but_built:
        print(
            f"\n  NOTE: {len(unplanned_but_built)} area(s) marked not-planned "
            f"were built after all: {unplanned_but_built}"
        )
        print("  Update NOT_PLANNED — a stale reason is worse than none.")

    orphans = sorted(set(implemented) - {a for a, _t, _d in SCOPE})
    if orphans:
        print(
            f"\n  WARNING: {len(orphans)} check(s) claim a gap17_area outside "
            f"the scope: {orphans}"
        )
        print("  The denominator is fixed; an area outside it counts for nothing.")

    print("\n  Not implemented, with the reason recorded:")
    for area in sorted(NOT_PLANNED):
        if area not in implemented:
            print(f"    - {area}: {NOT_PLANNED[area]}")

    print("\n  Deliberately out of scope (not in the denominator):")
    for item in OUT_OF_SCOPE:
        print(f"    - {item}")

    print("\n" + "-" * 78)
    print("RUNTIME BREADTH — reported separately, never folded into the headline")
    per_runtime: Dict[str, int] = {}
    try:
        from core.config_audit.builtin import BUILTIN_CHECKS

        for check in BUILTIN_CHECKS:
            runtime = str(check.metadata.get("runtime") or "")
            if runtime:
                per_runtime[runtime] = per_runtime.get(runtime, 0) + 1
    except Exception as exc:  # pragma: no cover
        print(f"  (could not measure runtime breadth: {exc})")

    for runtime in SUPPORTED_RUNTIMES:
        areas_here = sum(1 for _a, r in runtimes.items() if runtime in r)
        print(
            f"  {runtime:12} checks: {per_runtime.get(runtime, 0):3}   "
            f"areas answered: {areas_here}/{len(SCOPE)}"
        )

    print("\n" + "-" * 78)
    print("SUPPORTING MEASUREMENTS")
    try:
        from core.config_audit.collectors import collector_registry

        print(
            "  check types on linux: "
            f"{collector_registry.supported_check_types('linux')}"
        )
    except Exception as exc:  # pragma: no cover
        print(f"  (could not read the collector registry: {exc})")

    try:
        from core.config_audit.builtin import BUILTIN_CHECKS

        gap09 = len([c for c in BUILTIN_CHECKS if c.metadata.get("gap09_area")])
        print(f"  GAP-09 middleware checks (not counted here): {gap09}")
        docker_daemon = len(
            [c for c in BUILTIN_CHECKS if c.metadata.get("middleware") == "docker"]
        )
        print(f"  of which Docker *daemon* config, owned by GAP-09: {docker_daemon}")
    except Exception as exc:  # pragma: no cover
        print(f"  (could not measure the GAP-09 boundary: {exc})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
