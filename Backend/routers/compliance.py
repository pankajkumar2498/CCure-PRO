"""
routers/compliance.py
─────────────────────────────────────────────────────────────────────────────
The compliance API, under ``/compliance``. Since G6 (C8 of
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md) its routes live in parts,
moved unchanged out of what was a 7,481-line module:

* ``compliance_catalogue``: the marketplace, policy baselines and their rules,
  and the control register;
* ``compliance_assessment``: starting a scan, its findings, its runs and the
  dashboard summary;
* ``compliance_attestation``: attestation, evidence files and exception
  waivers;
* ``compliance_schedules``: recurring scans;
* ``compliance_remediation``: the credentials remediation connects with,
  applying a fix and rolling one back;
* ``compliance_reports``: the Statement of Applicability, the executive
  report, gap analysis and the NIST CSF profile, and
  ``compliance_framework_reports``: the other framework reports; their
  documents are rendered by ``reporting/compliance/``;
* ``compliance_common``: what they share.

**The API is the one it was.** Each part declares its sections on routers of
their own, and this module mounts them in the order the routes were always
listed, so the route table, the OpenAPI document and the gateway's route
policy (``gateway/policy/``) are unchanged. Each part sets its ``__name__``
to this module's, the way the platform's moved modules adopt their legacy
names (``ccure_platform/_legacy.py``): a route's limiter key, its endpoint in
the gateway policy, the RBAC inventory's view of its guards aside, and its
models' module stay ``routers.compliance``. Renaming them is its own change.

**Do not patch through this module.** It re-exports what the old module
defined, for the code and tests that import it; a part reads its own
bindings, so replacing a name here changes nothing a route sees. Setting or
deleting an attribute here raises ``AttributeError`` naming the part to
patch, as ``core/tasks.py`` does.
"""

import sys
import types

from fastapi import APIRouter

from routers import compliance_common
from routers import compliance_assessment
from routers import compliance_attestation
from routers import compliance_catalogue
from routers import compliance_framework_reports
from routers import compliance_remediation
from routers import compliance_reports
from routers import compliance_schedules

from core.rate_limiter import (  # noqa: F401
    limiter,
)
from reporting.compliance.common import (  # noqa: F401
    _verdict_of,
)
from reporting.compliance.iec_62443 import (  # noqa: F401
    _generate_iec_62443_docx,
    _generate_iec_62443_pdf,
)
from reporting.compliance.nerc_cip import (  # noqa: F401
    _generate_nerc_cip_docx,
    _generate_nerc_cip_pdf,
)
from reporting.compliance.nis2 import (  # noqa: F401
    _generate_nis2_docx,
    _generate_nis2_pdf,
)
from reporting.compliance.nist_800_53 import (  # noqa: F401
    _generate_nist_800_53_docx,
    _generate_nist_800_53_pdf,
)
from reporting.compliance.nist_800_82 import (  # noqa: F401
    _generate_nist_800_82_docx,
    _generate_nist_800_82_pdf,
)
from reporting.compliance.nist_csf import (  # noqa: F401
    _CSF_VERDICT_DISPLAY,
    _csf_verdict,
    _generate_nist_csf_docx,
    _generate_nist_csf_pdf,
)
from reporting.compliance.pci_dss import (  # noqa: F401
    _generate_pci_dss_docx,
    _generate_pci_dss_pdf,
)
from reporting.compliance.privacy import (  # noqa: F401
    _generate_privacy_docx,
    _generate_privacy_pdf,
)
from reporting.compliance.soa import (  # noqa: F401
    _SOA_APPLICABILITY,
    _generate_soa_detailed_docx,
    _generate_soa_detailed_pdf,
    _generate_soa_docx,
    _generate_soa_pdf,
    _soa_row,
)
from routers.compliance_assessment import (  # noqa: F401
    ScanTrigger,
    _serialize_run,
    get_dashboard_summary,
    get_scan_run,
    list_findings,
    list_scan_runs,
    trigger_compliance_scan,
)
from routers.compliance_attestation import (  # noqa: F401
    AttestationRequest,
    ExceptionApproval,
    ExceptionRequest,
    _ALLOWED_EVIDENCE_TYPES,
    _MAX_EVIDENCE_BYTES,
    _MAX_EVIDENCE_BYTES_PER_TENANT,
    _evidence_root,
    _lock_tenant_evidence_quota,
    approve_exception_waiver,
    attest_manual_control,
    delete_control_evidence,
    download_control_evidence,
    list_control_evidence,
    request_exception_waiver,
    sanitize_filename,
    scan_for_malware,
    upload_control_evidence,
)
from routers.compliance_catalogue import (  # noqa: F401
    PolicyCreate,
    RuleUpdatePayload,
    create_policy_baseline,
    get_marketplace_frameworks,
    get_policy_rules,
    install_marketplace_framework,
    list_framework_controls,
    list_policies,
    uninstall_marketplace_framework,
    update_compliance_rule,
)
from routers.compliance_common import (  # noqa: F401
    HTTPException,
    RolledFinding,
    SOA_EXCLUDED_THEME,
    _THEME_ORDER,
    _audit_refusal,
    _latest_run_id,
    _may_bypass_maker_checker,
    _ordered_themes,
    control_sort_key,
    log,
    log_audit_event,
    require_active_framework,
    rolled_up_control_findings,
    rolled_up_control_status,
)
from routers.compliance_framework_reports import (  # noqa: F401
    download_cert_in_2022_report,
    download_cis_v8_1_report,
    download_dpdp_2023_report,
    download_gdpr_report,
    download_iec_62443_report,
    download_nerc_cip_report,
    download_nis2_report,
    download_nist_800_53_r5_report,
    download_nist_800_82_report,
    download_pci_dss_v4_report,
    download_soc2_type2_report,
)
from routers.compliance_remediation import (  # noqa: F401
    CredentialCreate,
    CredentialResponse,
    JITCredentials,
    RemediationApprovalPayload,
    RemediationRequest,
    RollbackRequest,
    apply_remediation,
    approve_remediation_request,
    cancel_remediation_request,
    create_credential,
    delete_credential,
    list_credentials,
    list_remediation_requests,
    rollback_remediation_request,
)
from routers.compliance_reports import (  # noqa: F401
    _csf_group,
    download_executive_compliance_report,
    download_nist_csf_report,
    download_statement_of_applicability,
    get_compliance_gap_analysis,
)
from routers.compliance_schedules import (  # noqa: F401
    ScheduleCreate,
    ScheduleUpdate,
    create_scan_schedule,
    delete_scan_schedule,
    list_scan_schedules,
    update_scan_schedule,
)

router = APIRouter(prefix="/compliance", tags=["Compliance"])
for _section in (
    compliance_catalogue.marketplace,
    compliance_catalogue.baselines,
    compliance_assessment.scans,
    compliance_assessment.findings,
    compliance_attestation.attestation,
    compliance_catalogue.register,
    compliance_attestation.evidence,
    compliance_assessment.runs,
    compliance_schedules.schedules,
    compliance_remediation.credentials,
    compliance_remediation.execution,
    compliance_remediation.queue,
    compliance_attestation.exceptions,
    compliance_assessment.summary,
    compliance_reports.reports,
    compliance_framework_reports.framework_reports,
):
    router.include_router(_section)
del _section


_PARTS = (
    compliance_assessment,
    compliance_attestation,
    compliance_catalogue,
    compliance_framework_reports,
    compliance_remediation,
    compliance_reports,
    compliance_schedules,
    compliance_common,
)


class _Facade(types.ModuleType):
    """This module's type: reading works as usual; replacing a name does not."""

    def __setattr__(self, name, value):
        if name.startswith("__") and name.endswith("__"):
            return super().__setattr__(name, value)
        raise AttributeError(_refusal(name))

    def __delattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            return super().__delattr__(name)
        raise AttributeError(_refusal(name))


def _refusal(name: str) -> str:
    owners = [p.__spec__.name for p in _PARTS if name in vars(p)]
    where = " or ".join(owners) if owners else "the part whose code reads it"
    return (
        f"routers.compliance mounts the compliance router's parts and re-exports "
        f"{name!r}; no route reads it from here, so replacing it here changes "
        f"nothing. Patch {where}."
    )


sys.modules[__name__].__class__ = _Facade
