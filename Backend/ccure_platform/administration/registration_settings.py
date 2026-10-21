"""Govern the platform-wide registration policy."""

from typing import Literal

from ccure_platform.audit_log.writer import log_platform_event
from ccure_platform.identity import reauth
from ccure_platform.identity.registration_policy import policy_view, read_policy
from ccure_platform.rbac.dependencies import require_authorized
from db.base import get_db, utcnow
from ccure_platform.models import RegistrationPolicy, User
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy.orm import Session

router = APIRouter(prefix="/admin/registration-settings", tags=["Admin: Registration"])


class RegistrationSettings(BaseModel):
    self_registration_enabled: bool
    deployment_default: bool
    source: Literal["deployment", "administrator"]
    revision: int
    administrator_approval_required: bool


class RegistrationSettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    self_registration_enabled: StrictBool | None
    revision: int = Field(ge=0, strict=True)


@router.get("", response_model=RegistrationSettings)
def get_registration_settings(
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.registration.read")),
):
    """Read the effective registration policy and deployment default."""
    response.headers["Cache-Control"] = "no-store"
    return read_policy(db)


@router.patch("", response_model=RegistrationSettings)
def update_registration_settings(
    payload: RegistrationSettingsUpdate,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.registration.manage")),
):
    """Save a registration override, or use null to follow the deployment default."""
    try:
        step_up = reauth.check(current_user, request)
    except HTTPException as exc:
        log_platform_event(
            db,
            "registration.policy_change_refused",
            actor=current_user,
            request=request,
            resource_type="registration_policy",
            resource_id="1",
            changes={"reason": exc.detail.get("code")},
            severity="medium",
        )
        db.commit()
        raise

    try:
        # Fresh installs build metadata and stamp Alembic without seeding the
        # singleton. This insert is safe for concurrent first saves too.
        if db.get_bind().dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:
            from sqlalchemy.dialects.sqlite import insert

        db.execute(
            insert(RegistrationPolicy)
            .values(id=1, revision=0)
            .on_conflict_do_nothing(index_elements=["id"])
        )
        row = (
            db.query(RegistrationPolicy)
            .filter_by(id=1)
            .populate_existing()
            .with_for_update()
            .first()
        )
        if row is None:
            raise HTTPException(
                status_code=503, detail="Registration settings are not initialized."
            )
        if row.revision != payload.revision:
            raise HTTPException(
                status_code=409,
                detail="Registration settings changed. Reload them before saving again.",
            )
        before = policy_view(row)
        row.self_registration_enabled = payload.self_registration_enabled
        row.revision += 1
        row.updated_by = current_user.id
        row.updated_at = utcnow()
        after = policy_view(row)
        log_platform_event(
            db,
            "registration.policy_changed",
            actor=current_user,
            request=request,
            resource_type="registration_policy",
            resource_id="1",
            changes={"before": before, "after": after, "reauth": step_up},
            severity="high",
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    response.headers["Cache-Control"] = "no-store"
    return after
