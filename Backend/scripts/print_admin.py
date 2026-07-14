import os
import sys

# Ensure the root of the project is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.base import SessionLocal
from db.models import User

db = SessionLocal()
try:
    # Query user named "admin"
    u = db.query(User).filter(User.username == "admin").first()
    if u:
        print(f"Username: {u.username}")
        print(f"Email:    {u.email}")
        print(f"Org ID:   {u.org_id}")
    else:
        print("User 'admin' not found. Checking all active users:")
        users = db.query(User).all()
        for idx, usr in enumerate(users):
            print(
                f"{idx+1}. Username: {usr.username} | Email: {usr.email} | Org: {usr.org_id}"
            )
except Exception as e:
    print(f"Error querying user: {str(e)}")
finally:
    db.close()
