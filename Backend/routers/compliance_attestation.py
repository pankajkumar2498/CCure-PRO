"""
routers/compliance_attestation.py
─────────────────────────────────────────────────────────────────────────────
Attestation and evidence: a person's verdict on a control, the evidence
files behind it, and exception waivers.

Part of the compliance router, split out of ``routers/compliance.py`` (G6,
C8 of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md) and moved
unchanged; that module mounts the parts' sections in the order the API has
always listed them.
"""

import os
import uuid
from ccure_platform.api import CurrentUser, log_audit_event, require_authorized
from core.rate_limiter import limiter
from core.upload_guard import (
    MalwareDetected,
    MalwareScanUnavailable,
    UploadTooLarge,
    UploadTypeRejected,
    assert_content_matches,
    content_disposition,
    read_capped_async,
    sanitize_filename,
    scan_for_malware,
)
from datetime import datetime, timezone
from db.base import get_db
from db.models.compliance import (
    ComplianceControl,
    ComplianceEvidenceFile,
    ComplianceException,
    ComplianceFinding,
    ComplianceFindingHistory,
    ComplianceTenantFramework,
)
from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, model_validator
from routers.compliance_common import _audit_refusal, _latest_run_id, log
from sqlalchemy import func
from sqlalchemy.orm import Session

# Served as ``routers.compliance``: its routes' limiter keys, logger, gateway
# policy entries and model names are that module's, as they were before the
# split (see routers/compliance.py).
__name__ = "routers.compliance"  # noqa: A001


attestation = router = APIRouter()


class AttestationRequest(BaseModel):
    status: str = Field(..., pattern="^(pass|fail|not_applicable)$")
    note: str | None = None
    evidence_file_ids: list[str] | None = None
    # ISO/IEC 27001:2022 clause 6.1.3(d) requires the SoA to justify both the
    # inclusion of every applicable control and the exclusion of every
    # inapplicable one. `not_applicable` without a reason is not an exclusion
    # an auditor can accept.
    justification: str | None = Field(None, max_length=2000)
    owner: str | None = None
    next_review_at: datetime | None = None

    # A model validator, not a field validator: Pydantic v2 does not run a
    # field validator when the field is absent from the payload, which is
    # exactly the case this rule exists to reject — an exclusion submitted with
    # no justification key at all.
    @model_validator(mode="after")
    def _require_justification_for_exclusion(self):
        if self.status == "not_applicable" and not (self.justification or "").strip():
            raise ValueError(
                "A justification is required when a control is excluded as not "
                "applicable (ISO/IEC 27001:2022 clause 6.1.3 d)."
            )
        return self


@router.post("/controls/{control_id}/attest")
def attest_manual_control(
    control_id: str,
    payload: AttestationRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.attest")),
):
    """Submit manual audit evidence and notes for process controls."""
    ctrl = (
        db.query(ComplianceControl).filter(ComplianceControl.id == control_id).first()
    )
    if not ctrl:
        raise HTTPException(status_code=404, detail="Control not found")

    tf = (
        db.query(ComplianceTenantFramework)
        .filter_by(
            tenant_id=user.org_id, framework_id=ctrl.framework_id, is_enabled=True
        )
        .first()
    )
    if not tf:
        raise HTTPException(
            status_code=400,
            detail="Cannot attest controls for disabled or uninstalled frameworks.",
        )

    # The *same* id the scan derives for this control's org-level placeholder.
    # These used to be two different ids, so attesting a control produced a
    # second org-level row rather than updating the placeholder, and the two
    # then competed in the score rollup — where `manual_review` outranked
    # `pass`, so the attestation was silently discarded. For ISO, where 63 of
    # 93 controls are attestation-only, that made most of the framework
    # impossible to comply with.
    from core.compliance_tasks import org_finding_id_for

    finding_id = org_finding_id_for(user.org_id, control_id)

    finding = (
        db.query(ComplianceFinding).filter(ComplianceFinding.id == finding_id).first()
    )
    now = datetime.now(timezone.utc)

    # Evidence files must belong to this tenant and this control. Without the
    # check a caller could attach another organisation's evidence to their own
    # attestation by guessing an id.
    file_ids = list(payload.evidence_file_ids or [])
    if file_ids:
        owned = {
            row[0]
            for row in db.query(ComplianceEvidenceFile.id)
            .filter(
                ComplianceEvidenceFile.id.in_(file_ids),
                ComplianceEvidenceFile.tenant_id == user.org_id,
                ComplianceEvidenceFile.control_id == control_id,
            )
            .all()
        }
        unknown = [fid for fid in file_ids if fid not in owned]
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Evidence files not found for this control: " + ", ".join(unknown)
                ),
            )

    evidence_payload = {
        "note": payload.note or "",
        "justification": payload.justification or "",
        "attested_at": now.isoformat(),
        "attested_by": user.id,
    }

    if not finding:
        finding = ComplianceFinding(
            id=finding_id,
            tenant_id=user.org_id,
            control_id=control_id,
            source="manual_attestation",
            status=payload.status,
            evidence=evidence_payload,
            evidence_file_ids=file_ids,
            justification=payload.justification,
            owner=payload.owner or user.id,
            next_review_at=payload.next_review_at,
            attested_by=user.id,
            reviewed_at=now,
            first_seen=now,
            last_seen=now,
        )
        db.add(finding)
    else:
        finding.source = "manual_attestation"
        finding.status = payload.status
        finding.evidence = evidence_payload
        finding.evidence_file_ids = file_ids
        finding.justification = payload.justification
        finding.owner = payload.owner or finding.owner or user.id
        finding.next_review_at = payload.next_review_at or finding.next_review_at
        finding.attested_by = user.id
        finding.reviewed_at = now
        finding.last_seen = now

    # Bind the uploaded files to the finding they now support.
    if file_ids:
        db.query(ComplianceEvidenceFile).filter(
            ComplianceEvidenceFile.id.in_(file_ids),
            ComplianceEvidenceFile.tenant_id == user.org_id,
        ).update({"finding_id": finding_id}, synchronize_session=False)

    # Log history trail
    history = ComplianceFindingHistory(
        id=f"cfh_{uuid.uuid4().hex[:24]}",
        finding_id=finding_id,
        status=payload.status,
        changed_by=user.id,
        source="manual_attestation",
        note=payload.note or "Manual attestation updated",
    )
    db.add(history)
    db.commit()

    # Recalculate cached framework score immediately upon attestation update.
    # The run id is carried over from the score row rather than nulled: passing
    # None used to overwrite `scan_run_id` with NULL, so an attestation erased
    # the score's link to the scan that produced the rest of it.
    from core.compliance_tasks import _calculate_compliance_score

    _calculate_compliance_score(
        db,
        user.org_id,
        ctrl.framework_id,
        None,
        _latest_run_id(db, user.org_id, ctrl.framework_id),
    )
    log_audit_event(db, user, "attest_control", "finding", finding_id, status="success")
    db.commit()

    return {"message": "Attestation recorded successfully", "finding_id": finding_id}


evidence = router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# 4.3. Attestation Evidence Files
# ─────────────────────────────────────────────────────────────────────────────

# Deliberately conservative. Evidence is policy documents, screenshots, signed
# records and exported reports; nothing here needs to be executable, and an
# archive would let a caller smuggle content past the type check.
_ALLOWED_EVIDENCE_TYPES = {
    "application/pdf": ".pdf",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "text/plain": ".txt",
    "text/csv": ".csv",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
}


_MAX_EVIDENCE_BYTES = 25 * 1024 * 1024


# A per-tenant ceiling, because the per-file cap alone bounds nothing: an
# account holding `compliance:attest` could upload 25 MB in a loop until the
# API host's disk filled. Evidence is policy documents and screenshots, so 2 GB
# is far above any real workspace and still a bound. Raise it deliberately for
# a tenant that legitimately needs more.
_MAX_EVIDENCE_BYTES_PER_TENANT = int(
    os.environ.get("COMPLIANCE_EVIDENCE_TENANT_QUOTA_BYTES", 2 * 1024 * 1024 * 1024)
)


def _lock_tenant_evidence_quota(db: Session, tenant_id: str) -> None:
    """
    Take a transaction-scoped advisory lock covering one tenant's quota check.

    Postgres only. SQLite — which `config.py` falls back to when DATABASE_URL is
    unset — serialises writers at the database level anyway, so there is nothing
    to add there and nothing to fail over. Any other backend gets no lock and
    the pre-existing race; that is stated here rather than hidden, because a
    silent no-op is how a concurrency guard stops guarding.
    """
    if db.bind is None or db.bind.dialect.name != "postgresql":
        return
    from sqlalchemy import text

    # hashtext() gives a stable 32-bit key; the constant namespaces this lock
    # so it cannot collide with an advisory lock taken elsewhere.
    db.execute(
        text("SELECT pg_advisory_xact_lock(:ns, hashtext(:tenant))"),
        {"ns": 0x0E71DE17, "tenant": str(tenant_id)},
    )


def _evidence_root() -> str:
    """Base directory for stored evidence, configurable per deployment."""
    import os

    return os.environ.get(
        "COMPLIANCE_EVIDENCE_DIR", os.path.join("/app", "data", "compliance_evidence")
    )


@router.post("/controls/{control_id}/evidence", status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def upload_control_evidence(
    request: Request,
    response: Response,
    control_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.attest")),
):
    """Attach an audit evidence document to a control."""
    import hashlib

    ctrl = (
        db.query(ComplianceControl).filter(ComplianceControl.id == control_id).first()
    )
    if not ctrl:
        raise HTTPException(status_code=404, detail="Control not found")

    tf = (
        db.query(ComplianceTenantFramework)
        .filter_by(
            tenant_id=user.org_id, framework_id=ctrl.framework_id, is_enabled=True
        )
        .first()
    )
    if not tf:
        raise HTTPException(
            status_code=400,
            detail="Cannot attach evidence for a disabled or uninstalled framework.",
        )

    content_type = (file.content_type or "").split(";")[0].strip().lower()
    if content_type not in _ALLOWED_EVIDENCE_TYPES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{content_type or 'unknown'}' is not an accepted evidence type. "
                "Upload a PDF, image, text, CSV, Word or Excel document."
            ),
        )

    # Read with a cap rather than trusting a declared length: the size is only
    # known once the bytes are in hand, and an unbounded read is how an upload
    # endpoint becomes a memory exhaustion primitive.
    try:
        payload = await read_capped_async(file, _MAX_EVIDENCE_BYTES)
    except UploadTooLarge:
        raise HTTPException(
            status_code=413,
            detail=f"Evidence files are limited to {_MAX_EVIDENCE_BYTES // (1024 * 1024)} MB.",
        )
    if not payload:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")

    # The content type above is the one the *client* declared in the multipart
    # part header. Nothing derived it from the bytes, so `malware.exe` renamed
    # to `malware.pdf` arrives declared `application/pdf` and satisfied the
    # whitelist. Confirm the payload's own signature agrees before storing it.
    try:
        assert_content_matches(payload, content_type)
    except UploadTypeRejected as exc:
        raise HTTPException(status_code=400, detail=exc.message)

    # Evidence is handed back to other people in the tenant, which makes this a
    # file-sharing surface whether or not it was designed as one. No-ops unless
    # CLAMAV_HOST is configured; see core/upload_guard.py for the fail-open
    # rationale and how to make it fail closed.
    try:
        av_verdict = scan_for_malware(payload, context=f"evidence upload by {user.id}")
    except MalwareDetected as exc:
        _audit_refusal(
            user, "upload_evidence", "evidence", control_id, "blocked_malware"
        )
        raise HTTPException(
            status_code=400,
            detail=f"The uploaded file was rejected by malware scanning: {exc.signature}",
        )
    except MalwareScanUnavailable as exc:
        # 503, not 400: the file is not accused of anything — the scanner this
        # deployment requires could not answer, so the upload is refused rather
        # than stored unscanned. Distinct status so a client can retry.
        _audit_refusal(
            user, "upload_evidence", "evidence", control_id, "scanner_unavailable"
        )
        raise HTTPException(
            status_code=503,
            detail=(
                "Evidence cannot be accepted right now: malware scanning is "
                f"unavailable ({exc}). Try again shortly."
            ),
        )

    # A per-file cap bounds one request; it does not bound a loop of them.
    #
    # Serialise the check per tenant before summing. SUM-then-compare-then-write
    # is read-modify-write across three statements: two concurrent uploads each
    # read the same total, each conclude they fit, and the quota is exceeded by
    # whatever the second one carried. A transaction-scoped advisory lock keyed
    # on the tenant makes the read and the write one critical section; Postgres
    # releases it at COMMIT or ROLLBACK, so no unlock path can be missed.
    #
    # Evidence upload is a low-frequency operation, so serialising a tenant's
    # concurrent uploads costs nothing measurable.
    _lock_tenant_evidence_quota(db, user.org_id)

    used = (
        db.query(func.coalesce(func.sum(ComplianceEvidenceFile.size_bytes), 0))
        .filter(ComplianceEvidenceFile.tenant_id == user.org_id)
        .scalar()
        or 0
    )
    if used + len(payload) > _MAX_EVIDENCE_BYTES_PER_TENANT:
        raise HTTPException(
            status_code=413,
            detail=(
                "This workspace has reached its evidence storage quota of "
                f"{_MAX_EVIDENCE_BYTES_PER_TENANT // (1024 * 1024)} MB. "
                "Remove superseded evidence or ask an administrator to raise it."
            ),
        )

    file_id = f"cef_{uuid.uuid4().hex[:24]}"
    digest = hashlib.sha256(payload).hexdigest()

    # The stored name is derived entirely from the generated id and the
    # extension implied by the accepted content type — never from the
    # user-supplied filename, which is attacker-controlled and would otherwise
    # let `../` escape the tenant directory.
    extension = _ALLOWED_EVIDENCE_TYPES[content_type]
    tenant_dir = os.path.join(_evidence_root(), user.org_id)
    os.makedirs(tenant_dir, exist_ok=True)
    storage_path = os.path.join(tenant_dir, f"{file_id}{extension}")
    # Nothing above this line has touched the disk. Every rejection — wrong
    # type, wrong content, malware detected, scanner unavailable, over quota —
    # returns before the first byte is written, so a refused upload is never
    # briefly present in storage. Scan-then-persist, never persist-then-scan.
    with open(storage_path, "wb") as fh:
        fh.write(payload)

    try:
        record = ComplianceEvidenceFile(
            id=file_id,
            tenant_id=user.org_id,
            control_id=control_id,
            # A display name only — the storage path above is UUID-derived and
            # never touches this. `os.path.basename()` alone was not enough: the
            # API runs on Linux, where `\` is not a separator, and it strips
            # neither quotes nor control characters, both of which reach a
            # response header on download.
            filename=sanitize_filename(file.filename, fallback=f"evidence{extension}"),
            content_type=content_type,
            size_bytes=len(payload),
            sha256=digest,
            storage_path=storage_path,
            uploaded_by=user.id,
            uploaded_at=datetime.now(timezone.utc),
        )
        db.add(record)
        db.commit()
    except Exception:
        # The bytes are on disk and the row that points at them does not exist.
        # An orphan here is worse than it looks: it is unreachable through the
        # API, and the quota sums `size_bytes` over *rows*, so it consumes disk
        # that nothing accounts for and nothing will ever reclaim.
        db.rollback()
        try:
            os.unlink(storage_path)
        except OSError:
            log.warning(
                "Orphaned evidence file left on disk after a failed commit: %s",
                storage_path,
            )
        raise

    # Committed explicitly. The commit above persisted the evidence row and
    # ended that transaction, so this event begins a new one that nothing else
    # would ever close — the handler returns straight after, and `get_db`
    # closes without committing, discarding it.
    log_audit_event(db, user, "upload_evidence", "evidence", file_id, status="success")
    db.commit()

    if av_verdict != "clean":
        # An auditor reading this trail needs to know the difference between
        # "scanned and clean" and "never scanned".
        log.info(
            "Evidence %s stored with malware scan verdict: %s", file_id, av_verdict
        )
    return {
        "id": file_id,
        "filename": record.filename,
        "content_type": content_type,
        "size_bytes": record.size_bytes,
        "sha256": digest,
        "malware_scan": av_verdict,
        "uploaded_at": record.uploaded_at.isoformat(),
    }


@router.get("/controls/{control_id}/evidence")
def list_control_evidence(
    control_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.read")),
):
    """List the evidence documents attached to a control."""
    files = (
        db.query(ComplianceEvidenceFile)
        .filter(
            ComplianceEvidenceFile.tenant_id == user.org_id,
            ComplianceEvidenceFile.control_id == control_id,
        )
        .order_by(ComplianceEvidenceFile.uploaded_at.desc())
        .all()
    )
    return {
        "data": [
            {
                "id": f.id,
                "filename": f.filename,
                "content_type": f.content_type,
                "size_bytes": f.size_bytes,
                "sha256": f.sha256,
                "uploaded_by": f.uploaded_by,
                "uploaded_at": f.uploaded_at.isoformat(),
            }
            for f in files
        ]
    }


@router.get("/evidence/{file_id}/download")
def download_control_evidence(
    file_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.read")),
):
    """Download one evidence document."""
    import os

    record = (
        db.query(ComplianceEvidenceFile)
        .filter(
            ComplianceEvidenceFile.id == file_id,
            ComplianceEvidenceFile.tenant_id == user.org_id,
        )
        .first()
    )
    if not record or not os.path.exists(record.storage_path):
        raise HTTPException(status_code=404, detail="Evidence file not found")

    # FileResponse streams from disk rather than reading the whole file into
    # memory first. One 25 MB read is survivable; a dozen concurrent auditors
    # downloading evidence at once is what made this worth changing.
    #
    # The Content-Disposition is built by upload_guard, not by f-string. The
    # filename is user-supplied, and interpolating it into a quoted-string
    # header let a `"` in the name reshape the header.
    return FileResponse(
        path=record.storage_path,
        media_type=record.content_type,
        headers={
            "Content-Disposition": content_disposition(record.filename),
            "X-Evidence-SHA256": record.sha256,
        },
    )


@router.delete("/evidence/{file_id}", status_code=status.HTTP_200_OK)
def delete_control_evidence(
    file_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.attest")),
):
    """Remove an evidence document."""
    import os

    record = (
        db.query(ComplianceEvidenceFile)
        .filter(
            ComplianceEvidenceFile.id == file_id,
            ComplianceEvidenceFile.tenant_id == user.org_id,
        )
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Evidence file not found")

    try:
        if os.path.exists(record.storage_path):
            os.remove(record.storage_path)
    except OSError:
        log.warning("Could not remove evidence file from disk: %s", record.storage_path)

    db.delete(record)
    log_audit_event(db, user, "delete_evidence", "evidence", file_id, status="success")
    db.commit()
    return {"message": "Evidence file removed"}


exceptions = router = APIRouter()


class ExceptionRequest(BaseModel):
    reason: str = Field(..., min_length=10, max_length=1000)
    compensating_control: str | None = None
    expires_at: datetime


class ExceptionApproval(BaseModel):
    status: str = Field(..., pattern="^(approved|rejected)$")


# ─────────────────────────────────────────────────────────────────────────────
# 6. Exception Waivers & Approvals
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/findings/{id}/exception", status_code=status.HTTP_201_CREATED)
def request_exception_waiver(
    id: str,
    payload: ExceptionRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.attest")),
):
    """Request a temporary waiver exception for a failing control."""
    finding = (
        db.query(ComplianceFinding)
        .filter(ComplianceFinding.id == id, ComplianceFinding.tenant_id == user.org_id)
        .first()
    )

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Verify associated framework is active and installed
    ctrl = db.query(ComplianceControl).filter_by(id=finding.control_id).first()
    if ctrl:
        tf = (
            db.query(ComplianceTenantFramework)
            .filter_by(
                tenant_id=user.org_id, framework_id=ctrl.framework_id, is_enabled=True
            )
            .first()
        )
        if not tf:
            raise HTTPException(
                status_code=400,
                detail="Cannot request exceptions for disabled or uninstalled frameworks.",
            )

    exc_id = f"cex_{user.org_id}_{datetime.now().strftime('%M%S%f')}"
    new_exception = ComplianceException(
        id=exc_id,
        tenant_id=user.org_id,
        control_id=finding.control_id,
        finding_id=finding.id,
        reason=payload.reason,
        compensating_control=payload.compensating_control,
        requested_by=user.id,
        status="pending",
        expires_at=payload.expires_at,
    )
    db.add(new_exception)
    log_audit_event(db, user, "request_waiver", "exception", exc_id, status="success")
    db.commit()

    return {"message": "Exception request submitted", "exception_id": exc_id}


@router.patch("/exceptions/{id}")
def approve_exception_waiver(
    id: str,
    payload: ExceptionApproval,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(
        require_authorized("audit.compliance.approve_exception")
    ),
):
    """Approve or reject a pending waiver request (Compliance Officer only)."""
    exc = (
        db.query(ComplianceException)
        .filter(
            ComplianceException.id == id, ComplianceException.tenant_id == user.org_id
        )
        .first()
    )

    if not exc or exc.status != "pending":
        raise HTTPException(status_code=400, detail="No pending waiver matching ID")

    exc.status = payload.status
    exc.approved_by = user.id

    if payload.status == "approved":
        # Transition finding status
        finding = (
            db.query(ComplianceFinding)
            .filter(ComplianceFinding.id == exc.finding_id)
            .first()
        )
        if finding:
            finding.status = "exception"
            # Append timeline log
            history = ComplianceFindingHistory(
                id=f"cfh_{user.org_id}_{datetime.now().strftime('%M%S%f')}",
                finding_id=finding.id,
                status="exception",
                changed_by=user.id,
                source="exception_granted",
                note=f"Approved exception waiver: {exc.reason[:100]}",
            )
            db.add(history)

    log_audit_event(db, user, "approve_waiver", "exception", id, status="success")
    db.commit()
    return {"message": f"Waiver request {payload.status} successfully"}
