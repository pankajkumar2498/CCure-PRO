"""
core/config_audit/builtin
─────────────────────────────────────────────────────────────────────────────
The rules that ship with the engine.

Deliberately small. Their job is to prove the pipeline works against real
Windows and Linux hosts, not to be a compliance benchmark — CIS and STIG
content arrives in Phases 4 and 5 as data loaded into ``compliance_rules``,
and neither needs anything from this package.

Check ids are namespaced ``ccure.<platform>.<area>.<setting>`` so that a
benchmark rule and a built-in rule covering the same setting stay distinct
catalogue rows. ``definition_id_for_check`` folds dots and underscores to one
spelling, so ``ccure.win.uac.enabled`` and ``ccure_win_uac_enabled`` cannot
become two rows for one control — but two *different* sources checking the
same registry value legitimately are two rules, and the namespace keeps them
apart.
"""

from __future__ import annotations

from typing import Dict, List

from core.config_audit.builtin.database_mssql import MSSQL_CHECKS, mssql_checks
from core.config_audit.builtin.database_mysql import MYSQL_CHECKS, mysql_checks
from core.config_audit.builtin.database_postgresql import (
    POSTGRESQL_CHECKS,
    postgresql_checks,
)
from core.config_audit.builtin.linux_host import LINUX_HOST_CHECKS, linux_host_checks
from core.config_audit.builtin.middleware_apache import (
    APACHE_CHECKS,
    apache_checks,
)
from core.config_audit.builtin.middleware_common import (
    MIDDLEWARE_COMMON_CHECKS,
    middleware_common_checks,
)
from core.config_audit.builtin.middleware_docker import (
    DOCKER_CHECKS,
    docker_checks,
)
from core.config_audit.builtin.middleware_nginx import NGINX_CHECKS, nginx_checks
from core.config_audit.builtin.middleware_tomcat import (
    TOMCAT_CHECKS,
    tomcat_checks,
)
from core.config_audit.builtin.privilege_linux import (
    LINUX_PRIVILEGE_CHECKS,
    linux_privilege_checks,
)
from core.config_audit.builtin.privilege_windows import (
    WINDOWS_PRIVILEGE_CHECKS,
    windows_privilege_checks,
)
from core.config_audit.builtin.windows_host import (
    WINDOWS_HOST_CHECKS,
    windows_host_checks,
)
from core.config_audit.spec import ConfigCheck

__all__ = [
    "APACHE_CHECKS",
    "BUILTIN_CHECKS",
    "DATABASE_CHECKS",
    "DOCKER_CHECKS",
    "HARDENING_CHECKS",
    "LINUX_HOST_CHECKS",
    "LINUX_PRIVILEGE_CHECKS",
    "MIDDLEWARE_CHECKS",
    "MIDDLEWARE_COMMON_CHECKS",
    "MSSQL_CHECKS",
    "MYSQL_CHECKS",
    "NGINX_CHECKS",
    "POSTGRESQL_CHECKS",
    "PRIVILEGE_CHECKS",
    "TOMCAT_CHECKS",
    "WINDOWS_HOST_CHECKS",
    "WINDOWS_PRIVILEGE_CHECKS",
    "apache_checks",
    "builtin_checks",
    "builtin_checks_by_id",
    "docker_checks",
    "linux_host_checks",
    "linux_privilege_checks",
    "middleware_common_checks",
    "mssql_checks",
    "mysql_checks",
    "nginx_checks",
    "postgresql_checks",
    "tomcat_checks",
    "windows_host_checks",
    "windows_privilege_checks",
]

#: The Phase 3 hardening baseline — configuration judged against an expected
#: state. These mint ``CCURE-CFG-…``.
HARDENING_CHECKS: List[ConfigCheck] = [*WINDOWS_HOST_CHECKS, *LINUX_HOST_CHECKS]

#: The Phase 5 local privilege and host-exposure checks (GAP-08). These mint
#: ``CCURE-PRV-…`` and group separately in the report, because "deviates from a
#: baseline" and "has a path to SYSTEM" are different things to a triager.
PRIVILEGE_CHECKS: List[ConfigCheck] = [
    *WINDOWS_PRIVILEGE_CHECKS,
    *LINUX_PRIVILEGE_CHECKS,
]

#: The Phase 7 database checks (GAP-10). Platform ``database``, so
#: ``select_checks(platform="linux")`` never returns one and a host audit is
#: unchanged by their presence — the same platform filter that already keeps
#: Windows rules off Linux hosts.
#:
#: They mint ``CCURE-CFG-…`` like the hardening checks rather than
#: ``CCURE-PRV-…``, including the privilege and grant rules. ``privilege_check``
#: was considered and rejected: it files a finding under the report family
#: "Local Privilege", and an over-granted role on a remote database server is
#: not a local privilege-escalation condition on the scanning host. The
#: identifier segment has to describe the finding, and CFG does.
DATABASE_CHECKS: List[ConfigCheck] = [
    *POSTGRESQL_CHECKS,
    *MYSQL_CHECKS,
    *MSSQL_CHECKS,
]

#: The Phase 8 middleware checks (GAP-09). Platform ``linux``/``windows``,
#: so they run inside the ordinary credentialed host audit alongside the
#: OS hardening rules — a web server's configuration is part of the host's
#: posture, not a separate scan.
#:
#: They mint ``CCURE-CFG-…`` like every other hardening check. A host that
#: does not run the product reports NOT_APPLICABLE rather than a pile of
#: findings, which the collector decides by whether the configuration file
#: exists at all.
MIDDLEWARE_CHECKS: List[ConfigCheck] = [
    *NGINX_CHECKS,
    *APACHE_CHECKS,
    *TOMCAT_CHECKS,
    *DOCKER_CHECKS,
    *MIDDLEWARE_COMMON_CHECKS,
]

BUILTIN_CHECKS: List[ConfigCheck] = [
    *HARDENING_CHECKS,
    *PRIVILEGE_CHECKS,
    *DATABASE_CHECKS,
    *MIDDLEWARE_CHECKS,
]


def builtin_checks() -> List[ConfigCheck]:
    return list(BUILTIN_CHECKS)


def builtin_checks_by_id() -> Dict[str, ConfigCheck]:
    return {check.check_id: check for check in BUILTIN_CHECKS}
