
import sys
import os

# Add Backend to path
_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_HERE)
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from sqlalchemy.orm import Session
from db.base import SessionLocal
from db.models.users import User
from db.models.rbac import Organization, Role
from auth.jwt_handler import hash_password

def create_admin():
    email = "admin@ccurepro.com"
    username = "admin"
    password = "AdminCdac@123"
    
    db: Session = SessionLocal()
    try:
        # 1. Check if user already exists
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            print(f"User {email} already exists.")
            return

        # 2. Get default org and admin role
        org = db.query(Organization).filter(Organization.slug == "default").first()
        role = db.query(Role).filter(Role.name == "superadmin").first()
        
        if not org or not role:
            print("Error: Default Organization or superadmin Role not found. Please run migrations first.")
            return

        # 3. Create user
        new_user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            org_id=org.id,
            role_id=role.id,
            is_active=True,
            is_verified=True
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
