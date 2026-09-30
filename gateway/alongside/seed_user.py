"""
Create the one throwaway sign-in the alongside validation uses. ALONGSIDE ONLY.

Runs inside the alongside ``api`` container against the alongside database
(never the live one). The password comes from ALONGSIDE_USER_PASSWORD, which
run.sh generates for the run and never prints. The account is a superadmin in
the default organisation so that no permission check stands between the
tests and the authentication behaviour they are about.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, "/app")

from ccure_platform.identity.jwt_handler import hash_password  # noqa: E402
from db.base import SessionLocal, gen_user_id  # noqa: E402
from db.email_canonical import canonicalize_email  # noqa: E402
from db.models import Organization, Role, User  # noqa: E402

EMAIL = "alongside@example.test"
USERNAME = "alongside_probe"


def main() -> int:
    password = os.environ["ALONGSIDE_USER_PASSWORD"]
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == USERNAME).first():
            print("alongside user already present")
            return 0
        org = db.query(Organization).filter(Organization.slug == "default").first() or db.query(Organization).first()
        role = db.query(Role).filter(Role.name == "superadmin").first()
        if not org or not role:
            print("default organisation or superadmin role missing", file=sys.stderr)
            return 1
        user = User(
            id=gen_user_id(org.slug, USERNAME),
            username=USERNAME,
            email=EMAIL,
            password_hash=hash_password(password),
            org_id=org.id,
            role_id=role.id,
            is_active=True,
            is_verified=True,
            approved_at=datetime.now(timezone.utc),
        )
        if hasattr(User, "email_canonical"):
            user.email_canonical = canonicalize_email(EMAIL)
        db.add(user)
        db.flush()
        # ISO/IEC 27001 enabled for the organisation, so evidence can be
        # uploaded and downloaded: the real application's large-body round trip
        # (Phase 10.4). Only if the catalogue was seeded at start-up.
        from db.models import ComplianceFramework, ComplianceTenantFramework

        if db.query(ComplianceFramework).filter_by(id="cfw_iso27001_2022").first() and not (
            db.query(ComplianceTenantFramework)
            .filter_by(tenant_id=org.id, framework_id="cfw_iso27001_2022")
            .first()
        ):
            db.add(ComplianceTenantFramework(
                id=f"ctf_{org.id}_iso27001_alongside"[:100], tenant_id=org.id,
                framework_id="cfw_iso27001_2022", is_enabled=True, enabled_by=user.id,
            ))
        db.commit()
        print(f"alongside user created in organisation {org.id}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
