"""
core/config_audit/builtin/middleware_common.py
─────────────────────────────────────────────────────────────────────────────
Checks that apply to a middleware product's configuration file itself rather
than to anything inside it. Phase 8 (GAP-09).

These use the Phase 3 ``permission`` collector unchanged. Reaching for the new
structured collector because this phase added one would have been the wrong
instinct twice over: the question here is about the file's mode, not its
contents, and ``permission`` already answers it on both platforms.

Why the mode matters more for these files than for most
───────────────────────────────────────────────────────
A middleware configuration file names TLS private keys, upstream credentials,
database connection strings and the paths of everything the service serves.
World-readable, it hands all of that to any account on the host — including the
unprivileged account the *service itself* drops to, which is the account an
exploit of that service lands in.

``AbsencePolicy.NOT_APPLICABLE``, deliberately
──────────────────────────────────────────────
A host that does not run the product has no such file, and it is not failing a
rule about one. This is the same reasoning the structured collector applies
when it reports UNSUPPORTED for a missing configuration file, expressed here
through the rule instead, because the ``permission`` collector reports a
missing path as ABSENT and cannot know why it is missing.
"""

from __future__ import annotations

from typing import List

from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

__all__ = ["MIDDLEWARE_COMMON_CHECKS", "middleware_common_checks"]

#: Modes with no bits set for "other". `stat -c %a` prints these without a
#: leading zero, and the built-in Phase 3 rules already compare with `in`
#: against the spellings that actually occur rather than padding here.
_NO_WORLD_ACCESS = [
    "600",
    "640",
    "660",
    "400",
    "440",
    "460",
    "700",
    "740",
    "750",
    "770",
    "500",
    "540",
    "550",
]


def _permission_check(
    *, suffix: str, product: str, path: str, title: str
) -> ConfigCheck:
    return ConfigCheck(
        check_id=f"ccure.mw.{suffix}",
        title=title,
        check_type="permission",
        platforms=("linux",),
        severity="medium",
        collect={"path": path, "attribute": "mode"},
        expect=Expectation(
            "in", list(_NO_WORLD_ACCESS), description="no access for 'other'"
        ),
        absent=AbsencePolicy.NOT_APPLICABLE,
        description=(
            f"The mode of {path}. A host that does not run {product} has no "
            f"such file and is not in scope for this rule."
        ),
        rationale=(
            "The configuration names private keys, upstream credentials and "
            "every path the service exposes. World-readable, it hands those to "
            "any local account — including the unprivileged account the "
            "service itself runs as, which is exactly where an exploit of the "
            "service lands."
        ),
        remediation=(
            f"chmod o-rwx {path} and confirm the service account can still "
            f"read it, through group ownership if necessary."
        ),
        references=(),
        tags=("middleware", product, "filesystem"),
        metadata={
            "gap09_area": "mw.process.file_permissions",
            "middleware": product,
        },
    )


MIDDLEWARE_COMMON_CHECKS: List[ConfigCheck] = [
    _permission_check(
        suffix="nginx.config_permissions",
        product="nginx",
        path="/etc/nginx/nginx.conf",
        title="The nginx configuration file is not world-readable",
    ),
    _permission_check(
        suffix="apache.config_permissions",
        product="apache",
        path="/etc/apache2/apache2.conf",
        title="The Apache configuration file is not world-readable",
    ),
    _permission_check(
        suffix="tomcat.config_permissions",
        product="tomcat",
        path="/usr/local/tomcat/conf/tomcat-users.xml",
        title="The Tomcat users file is not world-readable",
    ),
    _permission_check(
        suffix="docker.config_permissions",
        product="docker",
        path="/etc/docker/daemon.json",
        title="The Docker daemon configuration is not world-writable",
    ),
]


def middleware_common_checks() -> List[ConfigCheck]:
    return list(MIDDLEWARE_COMMON_CHECKS)
