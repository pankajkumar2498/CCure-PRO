"""
core/tasks.py
─────────────
A compatibility facade. Since G1 (C2, docs/architecture/MODULAR_REFACTORING_LOG.md
§6) the Celery tasks of every scan phase live in ``scans/tasks/``, one module
per area; this was the 5,717-line hub that held them all.

Every name the hub defined is still importable from here, and is the same
object as in the module that defines it, so ``from core.tasks import X`` keeps
working for operator scripts and for the mail tasks' legacy path. The
application does not import this module (layer_rules: ``task-hub-is-a-leaf``)
and the worker does not load it: ``core/celery_app.py`` names the
``scans.tasks`` modules.

**Do not patch through this module.** It holds names its own code never reads,
so replacing one here changes nothing the task code sees, and a test that did
so would run the real code believing it had replaced it. Setting or deleting
an attribute here raises ``AttributeError`` naming the module to patch, and
``tests/repo/test_task_modules.py`` refuses such a patch statically.
"""

import sys
import types


# ── Outgoing mail ─────────────────────────────────────────────────────────────
#
# The mail tasks live in ccure_platform/identity/mail_tasks.py (legacy path
# auth/mail_tasks.py). Re-exported so existing callers keep resolving to the
# same task objects; patch them where they are defined.
from auth.mail_tasks import (  # noqa: E402,F401
    send_account_approved_email_task,
    send_mfa_otp_task,
    send_password_changed_email_task,
    send_password_reset_email_task,
    send_verification_email_task,
)

from scans.tasks.common import (  # noqa: E402,F401
    _bind_scan_scope,
    _check_cancelled,
    _finalize_cancelled,
    _new_orchestrator,
    _run_async,
    _settle_failure,
    _strip_nul,
    _update_task_id,
    log,
)

# The credentialed audit's findings writes moved to the findings writer in G3.
from core.findings.writer import (  # noqa: E402,F401
    _assessed_config_definition_ids,
    _first_advisory,
    _sync_credentialed_vulnerabilities,
)
from scans.tasks.credentialed_sync import (  # noqa: E402,F401
    _clean_text,
    _credentialed_sections_with_identity,
    _extract_credentialed_identity_names,
    _normalize_mac,
    _port_int,
    _sync_credentialed_asset_identity,
    _sync_credentialed_services,
)
from scans.tasks.credentialed import (  # noqa: E402,F401
    _apply_credentialed_enrichment,
    _as_credentialed_findings,
    _audit_host_over_transport,
    _classify_credentialed_failure,
    _credential_for_host,
    _credentialed_hardening_audits,
    _credentialed_plan_for_scan,
    _hardening_row,
    _is_transport_failure,
    _ports_probed_in_phase2,
    _resolve_stored_credential,
    _restate_findings_for_corrected_ports,
    _run_configuration_audit,
    _sync_configuration_compliance,
    _unique_lines,
    _upgrade_network_fingerprints,
    audit_credentialed_host,
    audit_database_target,
    run_credentialed_scan_task,
)
from scans.tasks.topology import (  # noqa: E402,F401
    _chain_topology_if_needed,
    _should_chain_topology,
    run_topology_mapping_task,
)
from scans.tasks.phases import (  # noqa: E402,F401
    _merge_host_identity,
    run_asset_discovery_task,
    run_host_discovery_task,
    run_traditional_scan_task,
    run_vulnerability_audit_task,
    sync_asset_discovery_task,
    sync_host_discovery_task,
    sync_vulnerability_audit_task,
)
from scans.tasks.maintenance import (  # noqa: E402,F401
    expire_risk_acceptances,
    reconcile_amt_inventory_task,
    update_mac_vendor_registry_task,
)
from scans.tasks.schedules import (  # noqa: E402,F401
    _SCAN_SCHEDULER_LOCK_KEY,
    run_due_scan_schedules,
)
from scans.tasks.reapers import (  # noqa: E402,F401
    reap_stalled_scans,
    reap_stalled_web_scans,
)

# The credentialed target ceiling moved to the scan-creation service in C1.
from scans.scan_creation import MAX_CREDENTIALED_TARGETS  # noqa: E402,F401


class _Facade(types.ModuleType):
    """This module's type: reading works as usual; replacing a name does not."""

    def __setattr__(self, name, value):
        if name.startswith("__") and name.endswith("__"):
            # The import system's own bookkeeping (__spec__, __loader__ …),
            # which a reload sets again.
            return super().__setattr__(name, value)
        raise AttributeError(_refusal(name))

    def __delattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            return super().__delattr__(name)
        raise AttributeError(_refusal(name))


def _refusal(name: str) -> str:
    value = vars(sys.modules[__name__]).get(name)
    owner = getattr(value, "__module__", None) or "its scans.tasks module"
    return (
        f"core.tasks is a compatibility facade: it re-exports {name!r} and its "
        f"own code never reads it, so replacing it here changes nothing the "
        f"task code sees. Patch the module whose code reads it — {owner} "
        f"defines it, and a scans.tasks module that imports it reads its own "
        f"binding (scans/tasks/__init__.py)."
    )


sys.modules[__name__].__class__ = _Facade
