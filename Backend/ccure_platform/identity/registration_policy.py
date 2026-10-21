"""One registration policy for public signup and platform administration."""

from config import AppConfig
from ccure_platform.models import RegistrationPolicy
from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError


def read_policy(db):
    try:
        # Query every time: no process-local flag cache can outlive a UI change.
        row = db.query(RegistrationPolicy).filter_by(id=1).populate_existing().first()
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=503, detail="Registration settings are unavailable."
        ) from exc
    return policy_view(row)


def policy_view(row):
    override = row.self_registration_enabled if row is not None else None
    default = AppConfig.ALLOW_SELF_REGISTRATION
    return {
        "self_registration_enabled": default if override is None else override,
        "deployment_default": default,
        "source": "deployment" if override is None else "administrator",
        "revision": row.revision if row is not None else 0,
        "administrator_approval_required": not AppConfig.SELF_REGISTRATION_AUTO_APPROVE,
    }
