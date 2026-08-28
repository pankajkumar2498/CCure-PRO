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

from core.config_audit.builtin.linux_host import LINUX_HOST_CHECKS, linux_host_checks
from core.config_audit.builtin.windows_host import (
    WINDOWS_HOST_CHECKS,
    windows_host_checks,
)
from core.config_audit.spec import ConfigCheck

__all__ = [
    "BUILTIN_CHECKS",
    "LINUX_HOST_CHECKS",
    "WINDOWS_HOST_CHECKS",
    "builtin_checks",
    "builtin_checks_by_id",
    "linux_host_checks",
    "windows_host_checks",
]

BUILTIN_CHECKS: List[ConfigCheck] = [*WINDOWS_HOST_CHECKS, *LINUX_HOST_CHECKS]


def builtin_checks() -> List[ConfigCheck]:
    return list(BUILTIN_CHECKS)


def builtin_checks_by_id() -> Dict[str, ConfigCheck]:
    return {check.check_id: check for check in BUILTIN_CHECKS}
