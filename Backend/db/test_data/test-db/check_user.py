"""
Check if user exists in database with correct password
"""

import sqlite3
from pathlib import Path
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def check_user():
    """Check test user in database."""
    db_path = Path("ccure_users.db")
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    try:
        # Get user
        cursor.execute("SELECT id, username, email, password_hash FROM users WHERE email = ?", 
                      ("test@ccure.com",))
        user = cursor.fetchone()
        
        if not user:
            print("✗ User not found in database!")
            return
        
        user_id, username, email, password_hash = user
        print(f"✓ User found:")
        print(f"  ID: {user_id}")
        print(f"  Username: {username}")
        print(f"  Email: {email}")
        print(f"  Password Hash: {password_hash[:50]}...")
        
        # Test password verification
        print(f"\n→ Testing password verification...")
        test_password = "Test@123"
        try:
            is_valid = pwd_context.verify(test_password, password_hash)
            if is_valid:
                print(f"✓ Password is CORRECT - verification passed!")
            else:
                print(f"✗ Password is WRONG - verification failed!")
        except Exception as e:
            print(f"✗ Error verifying password: {e}")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()

if __name__ == "__main__":
    check_user()
