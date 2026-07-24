"""
Test the login endpoint directly
"""

import json

import requests


def test_login():
    """Test login endpoint."""
    base_url = "http://localhost:8000"

    credentials = {"email": "test@ccure.com", "password": "Test@123"}

    try:
        print(f"→ Testing login endpoint at {base_url}/auth/login...")
        print(f"  Credentials: {json.dumps(credentials, indent=2)}")

        response = requests.post(
            f"{base_url}/auth/login",
            json=credentials,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )

        print(f"\n✓ Response Status: {response.status_code}")
        print(f"  Response Headers: {dict(response.headers)}")
        print(f"  Response Body: {response.text}")

        if response.status_code == 200:
            data = response.json()
            print("\n✓ Login SUCCESS!")
            print(f"  Access Token: {data.get('access_token', '')[:50]}...")
            print(f"  Token Type: {data.get('token_type', '')}")
            print(f"  User: {data.get('user', {})}")
        else:
            print("\n✗ Login FAILED!")
            try:
                error = response.json()
                print(f"  Error: {error}")
            except:
                print(f"  Raw response: {response.text}")

    except requests.exceptions.ConnectionError:
        print(f"✗ Cannot connect to backend at {base_url}")
        print("  Make sure backend is running: uvicorn main:app --reload")
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    test_login()
