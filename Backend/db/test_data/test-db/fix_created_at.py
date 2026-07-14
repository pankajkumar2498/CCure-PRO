"""
Fix the created_at field in the user record
"""

import sqlite3
from pathlib import Path
from datetime import datetime, timezone


def fix_user_created_at():
    """Fix the created_at field."""
    db_path = Path("ccure_users.db")

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    try:
        # Update user with current timestamp
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            UPDATE users SET created_at = ?, updated_at = ? WHERE email = ?
        """,
            (now, now, "test@ccure.com"),
        )
        conn.commit()

        print("✓ Updated created_at field successfully!")

        # Verify
        cursor.execute(
            "SELECT email, created_at FROM users WHERE email = ?", ("test@ccure.com",)
        )
        user = cursor.fetchone()
        if user:
            print(f"  Email: {user[0]}")
            print(f"  Created At: {user[1]}")

    except Exception as e:
        print(f"✗ Error: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    fix_user_created_at()
