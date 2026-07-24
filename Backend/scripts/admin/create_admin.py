import os
import sys

# Add Backend to path
from pathlib import Path

_BACKEND = str(Path(__file__).resolve().parents[2])
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from auth.email_utils import email_matches, normalize_email
from auth.jwt_handler import hash_password
from db.base import SessionLocal, gen_user_id
from db.models.rbac import Organization, Role
from db.models.users import User
from sqlalchemy.orm import Session


def create_admin():
    email = normalize_email("admin@ccurepro.com")
    username = "admin"
    password = "AdminCdac@123"

    db: Session = SessionLocal()
    try:
        # 1. Check if user already exists
        existing = db.query(User).filter(email_matches(User.email, email)).first()
        if existing:
            print(f"User {email} already exists.")
            return

        # 2. Get default org and admin role
        org = (
            db.query(Organization)
            .filter((Organization.slug == "default") | (Organization.slug == "king"))
            .first()
        )
        if not org:
            org = db.query(Organization).first()
        role = db.query(Role).filter(Role.name == "superadmin").first()

        if not org or not role:
            print(
                "Error: Default Organization or superadmin Role not found. Please run migrations first."
            )
            return

        # 3. Create user
        new_user = User(
            id=gen_user_id(org.slug, username),  # e.g. usr_def_admin_x9v1
            username=username,
            email=email,
            password_hash=hash_password(password),
            org_id=org.id,
            role_id=role.id,
            is_active=True,
            is_verified=True,
        )
        db.add(new_user)
        db.commit()
        print(f"Successfully created admin user: {email}")

    except Exception as e:
        db.rollback()
        print(f"Error creating user: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    create_admin()
