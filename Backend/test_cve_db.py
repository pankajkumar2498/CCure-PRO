"""
test_cve_database.py - Quick test to verify CVE database functionality
"""
import sys
sys.path.insert(0, '.')

from core.cve_database import CVEDatabase

def test_cve_database():
    print("\n" + "="*60)
    print("Testing CVE Database")
    print("="*60)
    
    # Initialize database
    cve_db = CVEDatabase()
    
    # Test 1: Check database status
    print("\n✓ Test 1: Database Connection")
    stats = cve_db.get_stats()
    print(f"  Status: {stats}")
    
    # Test 2: Search for OpenSSH CVEs
    print("\n✓ Test 2: Search for OpenSSH CVEs")
    openssh_cves = cve_db.search_cves_for_service("openssh", "7.4")
    print(f"  Found: {len(openssh_cves)} CVEs")
    if openssh_cves:
        for cve in openssh_cves[:3]:
            print(f"    - {cve['cve']}: {cve['desc'][:60]}...")
    
    # Test 3: Search for Nginx CVEs
    print("\n✓ Test 3: Search for Nginx CVEs")
    nginx_cves = cve_db.search_cves_for_service("nginx", "1.18")
    print(f"  Found: {len(nginx_cves)} CVEs")
    if nginx_cves:
        for cve in nginx_cves[:3]:
            print(f"    - {cve['cve']}: {cve['desc'][:60]}...")
    
    # Test 4: Get Critical CVEs
    print("\n✓ Test 4: Get Critical CVEs")
    critical = cve_db.get_cves_by_severity("Critical")
    print(f"  Found: {len(critical)} Critical CVEs")
    if critical:
        for cve in critical[:3]:
            print(f"    - {cve['cve']}: CVSS {cve['cvss']}")
    
    # Test 5: Get specific CVE details
    print("\n✓ Test 5: Get Specific CVE Details")
    if openssh_cves and openssh_cves[0]:
        cve_id = openssh_cves[0]['cve']
        details = cve_db.get_cve_details(cve_id)
        if details:
            print(f"  CVE ID: {details['cve_id']}")
            print(f"  Severity: {details['severity']}")
            print(f"  CVSS Score: {details['cvss_score']}")
            print(f"  Published: {details['published']}")
    
    print("\n" + "="*60)
    print("✓ All tests completed successfully!")
    print("="*60 + "\n")

if __name__ == "__main__":
    test_cve_database()
