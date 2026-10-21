"""
core/checks/
─────────────────────────────────────────────────────────────────────────────
The common assessment contract.

Every assessment this product performs — a network probe, a credentialed
package match, a CIS configuration control, a database privilege review, a
network-device configuration audit — answers the same question about a target
and must answer it in the same vocabulary. This package holds that vocabulary
so a capability added next month plugs into the existing finding, evidence,
risk, remediation and reporting pipeline instead of arriving with a parallel
one.

What lives here
───────────────
  contract.py        CheckOutcome / CheckSeverity / Evidence / CheckResult / CheckSpec
  registry.py        Registration with signature validation at registration time
  legacy_plugins.py  The contract the existing vulnerability plugins already
                     speak, expressed so it can be verified rather than assumed.
                     The engine that owns the plugins registers them here
  definitions.py     Namespaced identifiers for findings that are not CVEs

What deliberately does not live here
────────────────────────────────────
Collection. A check says what "good" looks like and how to judge what was
collected; it does not own the transport that collected it. SSH, WinRM, SNMP
and database sessions stay in their own engines so one check can be evaluated
against evidence gathered several different ways.
"""

from core.checks.contract import (
    CheckOutcome,
    CheckResult,
    CheckSpec,
    Evidence,
    normalize_severity,
)
from core.checks.definitions import (
    DEFINITION_TYPE_CONFIG_CHECK,
    DEFINITION_TYPE_CVE,
    DEFINITION_TYPE_PLUGIN_CHECK,
    definition_id_for_check,
    is_cve_id,
)
from core.checks.registry import CheckRegistry, RegistrationError, registry

__all__ = [
    "DEFINITION_TYPE_CONFIG_CHECK",
    "DEFINITION_TYPE_CVE",
    "DEFINITION_TYPE_PLUGIN_CHECK",
    "CheckOutcome",
    "CheckRegistry",
    "CheckResult",
    "CheckSpec",
    "Evidence",
    "RegistrationError",
    "definition_id_for_check",
    "is_cve_id",
    "normalize_severity",
    "registry",
]
