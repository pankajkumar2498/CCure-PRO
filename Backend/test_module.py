import sys
import os
import requests

# Add current path to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy.orm import Session
from db.base import SessionLocal
from db.models.web_scans import WebScan, WebAsset, WebFinding

def run_diagnostics():
    print("=== CCure-Audit-PRO Web Scanning Diagnostic ===")
    
    # 1. Check Database State
    print("\n1. Checking Database State...")
    try:
        db: Session = SessionLocal()
        scans = db.query(WebScan).order_by(WebScan.created_at.desc()).limit(5).all()
        if not scans:
            print("  No web scans found in the database.")
        else:
            for s in scans:
                print(f"  Scan ID: {s.id} | Target: {s.target_url} | Status: {s.status} | Phase: {s.pipeline_phase}")
                assets = db.query(WebAsset).filter(WebAsset.web_scan_id == s.id).count()
                findings = db.query(WebFinding).filter(WebFinding.web_scan_id == s.id).count()
                print(f"    - Assets Discovered: {assets}")
                print(f"    - Findings Detected: {findings}")
    except Exception as e:
        print(f"  [ERROR] Database query failed: {e}")
    finally:
        db.close()

    # 2. Test API Connectivity
    print("\n2. Testing API Connectivity...")
    try:
        # Assuming the API runs on port 8000
        res = requests.get("http://localhost:8000/api/health", timeout=2)
        if res.status_code == 200:
            print("  API is reachable on port 8000.")
        else:
            print(f"  API returned status {res.status_code}.")
    except Exception as e:
        print(f"  [WARNING] Could not reach API on localhost:8000: {e}")

    # 3. Instruction for Celery
    print("\n3. Next Steps to Verify the Pipeline")
    print("  To ensure the background tasks are actually running, you must check the Celery worker logs.")
    print("  Run this command in a new terminal window:")
    print("    docker-compose logs web-worker --tail=50 -f")
    print("  If you are running locally without docker, check the terminal where you ran 'celery -A core.celery_app worker'.")

if __name__ == "__main__":
    run_diagnostics()
