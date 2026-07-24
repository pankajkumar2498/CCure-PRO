"""
Update existing user password with proper argon2 hash
"""

import sqlite3
from pathlib import Path

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def update_user_password():
    """Update test user password to proper argon2 hash."""
    db_path = Path("ccure_users.db")

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    try:
        # Generate proper argon2 hash for "Test@123"
        password_hash = pwd_context.hash("Test@123")

        # Update user
        cursor.execute(
            """
            UPDATE users SET password_hash = ? WHERE email = ?
        """,
            (password_hash, "test@ccure.com"),
        )
        conn.commit()

        print("✓ Password updated successfully!")
        print("  Email:    test@ccure.com")
        print("  Password: Test@123")
        print("\n→ Try logging in now at http://localhost:3000/login")

    except Exception as e:
        print(f"✗ Error updating password: {e}")
        import traceback

        traceback.print_exc()
    finally:
        conn.close()


if __name__ == "__main__":
    update_user_password()
