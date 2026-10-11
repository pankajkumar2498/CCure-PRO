"""Platform-wide registration policy; NULL follows the deployment default."""

from db.base import TIMESTAMPTZ, Base
from sqlalchemy import Boolean, CheckConstraint, Column, Integer, String, text


class RegistrationPolicy(Base):
    __tablename__ = "platform_registration_policy"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_registration_policy_singleton"),
        CheckConstraint("revision >= 0", name="ck_registration_policy_revision"),
    )

    id = Column(Integer, primary_key=True)
    self_registration_enabled = Column(Boolean, nullable=True)
    revision = Column(Integer, nullable=False, server_default=text("0"))
    updated_at = Column(TIMESTAMPTZ, nullable=True)
    # Attribution survives account deletion; the policy belongs to no tenant.
    updated_by = Column(String(150), nullable=True)
