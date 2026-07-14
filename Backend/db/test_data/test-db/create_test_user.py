"""
create_test_user.py
-------------------
Quick script to create a test user directly in the database using raw SQL.
Run this from the Backend folder: python create_test_user.py
"""

import sqlite3
from pathlib import Path


def create_test_user():
    """Create a test user directly in SQLite database."""
    db_path = Path("ccure_users.db")

    # Ensure database exists with proper schema
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    try:
        # Create users table if not exists
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR UNIQUE NOT NULL,
                email VARCHAR UNIQUE NOT NULL,
                password_hash VARCHAR NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """
        )
        conn.commit()

        # Check if user exists
        cursor.execute("SELECT * FROM users WHERE email = ?", ("test@ccure.com",))
        if cursor.fetchone():
            print("✓ User already exists: testuser (test@ccure.com)")
            print("  Try: test@ccure.com / Test@123")
            return

        # Generate proper bcrypt hash for "Test@123"
        # Using bcrypt.hashpw directly
        try:
            import bcrypt

            password_hash = bcrypt.hashpw(
                "Test@123".encode("utf-8"), bcrypt.gensalt(12)
            ).decode("utf-8")
        except Exception as e:
            print(f"⚠ Bcrypt failed: {e}")
            print("  Using fallback method...")
            # Fallback: Use passlib directly
            from passlib.context import CryptContext

            pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
            password_hash = pwd_context.hash("Test@123", rounds=4)

        # Insert user
        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
        """,
            ("testuser", "test@ccure.com", password_hash),
        )
        conn.commit()

        print("✓ Test user created successfully!")
        print("  Username: testuser")
        print("  Email:    test@ccure.com")
        print("  Password: Test@123")
        print("\n→ Use these credentials to login at http://localhost:3000/login")

    except sqlite3.IntegrityError as e:
        print(f"✗ Database error: {e}")
    except Exception as e:
        print(f"✗ Error creating user: {e}")
        import traceback

        traceback.print_exc()
    finally:
        conn.close()


if __name__ == "__main__":
    create_test_user()
