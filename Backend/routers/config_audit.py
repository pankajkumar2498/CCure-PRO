"""
routers/config_audit.py
─────────────────────────────────────────────────────────────────────────────
The configuration audit engine's read surface, plus a rule validator.

Endpoints
─────────
  GET   /config-audit/checks           the check catalogue, filterable
  GET   /config-audit/capabilities     what this build can actually check
  GET   /config-audit/checks/{id}      one check, in full
  POST  /config-audit/validate         validate a rule definition, no target

What is deliberately not here
─────────────────────────────
**There is no "run a configuration audit" endpoint.** Configuration checks run
inside the credentialed scan, on the session the collectors already opened —
``core.tasks.audit_credentialed_host``. A separate dispatch endpoint would be a
second way to start a scan against a caller-named target, needing its own
scope check, its own quota check, its own rate limit and its own audit entry,
and it would produce a scan row that Scan History and the reports would have to
learn about. Phase 1 made the same call for scheduling: reuse the dispatch
path, do not build another.

**There is no write surface for rules.** Rules live in ``compliance_rules``
and are authored through the seeders. A CRUD API for them is a Phase 12 (scan
policy) question, and building it now would fix the shape of something whose
requirements are not yet known.

Why ``/capabilities`` exists
────────────────────────────
``check_type`` admits ``api`` and ``database_query``, and ``target_platform``
admits ``database`` and ``container``, ahead of the phases that implement them
— so a rule can be written today that nothing can execute. The engine reports
that as ERROR rather than skipping it, which is correct but only visible after
a scan. This endpoint answers it beforehand: it reports the check types that
genuinely have a collector on each platform, read from the live registry rather
than from a hand-maintained list that would drift the first time one was added.
"""

import logging
import re
from typing import Any, Dict, List, Optional

from ccure_platform.api import CurrentUser, require_authorized
from core.config_audit import (
    CHECK_TYPES,
    COMPARISON_OPERATORS,
    PLATFORMS,
    AbsencePolicy,
    ConfigCheck,
    SpecError,
    collector_registry,
)
from core.config_audit.builtin import builtin_checks, builtin_checks_by_id
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from scan_helpers import limiter

log = logging.getLogger("ccure.config_audit.api")

router = APIRouter(prefix="/config-audit", tags=["Configuration Audit"])


# ─────────────────────────────────────────────────────────────────────────────
# Body / response models
#
# Prefixed ``ConfigAudit`` for the reason Phases 1 and 2 learned twice: FastAPI
# keys OpenAPI component schemas by class name, so a plain ``CheckOut`` here
# would silently replace any other router's class of that name in the generated
# contract — and the CI contract gate reports it as deletions in a file nobody
# edited.
# ─────────────────────────────────────────────────────────────────────────────


class ConfigAuditCheckOut(BaseModel):
    check_id: str
    title: str
    check_type: str
    platforms: List[str]
    domain: str
    severity: str
    description: str = ""
    rationale: str = ""
    remediation: str = ""
    references: List[str] = Field(default_factory=list)
    requires_credentials: bool = True
    intrusive: bool = False
    qod: int = 95
    tags: List[str] = Field(default_factory=list)
    #: What a successful reading of "the item is not present" means for this
    #: check. Surfaced because it is the field a reviewer most often needs to
    #: understand a MANUAL_REVIEW result.
    absent_policy: str
    expected: str


class ConfigAuditCapabilitiesOut(BaseModel):
    #: check types that have a collector, per platform
    supported: Dict[str, List[str]]
    #: declared in the vocabulary but with no collector on any platform yet
    declared_without_collector: List[str]
    check_types: List[str]
    platforms: List[str]
    operators: List[str]
    absence_policies: List[str]


class ConfigAuditValidateIn(BaseModel):
    check_id: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=255)
    check_type: str
    platforms: List[str] = Field(default_factory=lambda: ["any"])
    collect: Dict[str, Any]
    operator: str
    expected: Any = None
    absent: str
    severity: str = "medium"
    domain: str = "host_configuration"


class ConfigAuditValidateOut(BaseModel):
    valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    #: The stored JSONB this rule would produce, when it validates.
    check_definition: Optional[Dict[str, Any]] = None


def _serialize(check: ConfigCheck) -> ConfigAuditCheckOut:
    return ConfigAuditCheckOut(
        check_id=check.check_id,
        title=check.title,
        check_type=check.check_type,
        platforms=list(check.platforms),
        domain=check.domain,
        severity=check.severity,
        description=check.description,
        rationale=check.rationale,
        remediation=check.remediation,
        references=list(check.references),
        requires_credentials=check.requires_credentials,
        intrusive=check.intrusive,
        qod=check.qod,
        tags=list(check.tags),
        absent_policy=check.absent.value,
        expected=check.expect.render(),
    )


@router.get("/checks", response_model=List[ConfigAuditCheckOut])
@limiter.limit("60/minute")
def list_checks(
    request: Request,
    response: Response,
    platform: Optional[str] = Query(None),
    check_type: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.scan.read")),
):
    """
    The configuration checks this build can run.

    Filtering by ``platform`` uses the check's own targeting rule, so a check
    declared for ``any`` is returned for every platform rather than only for a
    literal "any" query.
    """
    checks = builtin_checks()
    if platform:
        checks = [c for c in checks if c.applies_to_platform(platform)]
    if check_type:
        checks = [c for c in checks if c.check_type == check_type]
    if domain:
        checks = [c for c in checks if c.domain == domain]
    return [_serialize(c) for c in checks]


@router.get("/capabilities", response_model=ConfigAuditCapabilitiesOut)
@limiter.limit("60/minute")
def capabilities(
    request: Request,
    response: Response,
    user: CurrentUser = Depends(require_authorized("audit.scan.read")),
):
    """
    Which check types actually have a collector, per platform.

    Read from the live registry. A hand-maintained list here would be wrong the
    first time a collector was added and nobody would notice, because the
    symptom is an endpoint under-reporting a capability the product has.
    """
    supported = {
        platform: collector_registry.supported_check_types(platform)
        for platform in PLATFORMS
        if platform != "any"
    }
    implemented = {ct for types in supported.values() for ct in types}
    return ConfigAuditCapabilitiesOut(
        supported=supported,
        declared_without_collector=sorted(set(CHECK_TYPES) - implemented),
        check_types=list(CHECK_TYPES),
        platforms=list(PLATFORMS),
        operators=list(COMPARISON_OPERATORS),
        absence_policies=[p.value for p in AbsencePolicy],
    )


@router.get("/checks/{check_id}", response_model=ConfigAuditCheckOut)
@limiter.limit("60/minute")
def get_check(
    request: Request,
    response: Response,
    check_id: str,
    user: CurrentUser = Depends(require_authorized("audit.scan.read")),
):
    check = builtin_checks_by_id().get(check_id)
    if check is None:
        raise HTTPException(status_code=404, detail="Check not found")
    return _serialize(check)


@router.post("/validate", response_model=ConfigAuditValidateOut)
@limiter.limit("30/minute")
def validate_rule(
    request: Request,
    response: Response,
    body: ConfigAuditValidateIn,
    user: CurrentUser = Depends(require_authorized("audit.scan.read")),
):
    """
    Check that a rule definition is executable, without contacting any target.

    Answers 200 with ``valid: false`` rather than 422 for a rule that does not
    validate: the caller asked whether it is valid, and the errors are the
    answer to that question, not a fault in the request.

    A ``matches`` pattern is compiled but never executed against anything. That
    is the safe half — compilation is bounded, matching a hostile pattern
    against attacker-influenced text is not, and the engine only ever matches
    against output it collected from a host the operator chose to scan.
    """
    errors: List[str] = []
    warnings: List[str] = []

    if body.operator in ("matches", "not_matches"):
        try:
            re.compile(str(body.expected or ""))
        except re.error as exc:
            errors.append(f"expected is not a valid regular expression: {exc}")

    check: Optional[ConfigCheck] = None
    try:
        check = ConfigCheck.from_check_definition(
            {
                "check_id": body.check_id,
                "title": body.title,
                "check_type": body.check_type,
                "collect": body.collect,
                "operator": body.operator,
                "expected": body.expected,
                "absent": body.absent,
                "domain": body.domain,
                "platforms": body.platforms,
            },
            severity=body.severity,
        )
    except (SpecError, ValueError) as exc:
        errors.append(str(exc))

    if check is not None:
        for platform in check.platforms:
            if platform == "any":
                continue
            if collector_registry.resolve(check.check_type, platform) is None:
                # A warning rather than an error: the rule is well-formed and
                # will be executable when that phase lands. Reporting it as
                # invalid would block authoring content ahead of the collector,
                # which is a legitimate thing to do.
                warnings.append(
                    f"no collector implements check_type "
                    f"{check.check_type!r} on platform {platform!r} in this "
                    f"build; the check would report an error rather than a "
                    f"verdict"
                )

    return ConfigAuditValidateOut(
        valid=not errors,
        errors=errors,
        warnings=warnings,
        check_definition=check.to_check_definition() if check and not errors else None,
    )
