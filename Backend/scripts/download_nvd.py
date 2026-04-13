"""
download_nvd.py
---------------
Downloads recent CVEs from NVD API and caches them in SQLite database.
This allows the scanning engine to query CVEs from local DB instead of hardcoding.

Usage:
    python Scripts/download_nvd.py                    # Default: fetch 500 recent CVEs
    python Scripts/download_nvd.py --limit 1000       # Fetch 1000 CVEs
    python Scripts/download_nvd.py --skip-ssl         # Skip SSL verification (dev only)
"""

import json
import sqlite3
import requests
import argparse
import time
import sys
from pathlib import Path
from datetime import datetime

# SQLite DB location
DB_PATH = Path(__file__).parent.parent / "cves.db"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def create_database():
    """Create CVE database schema"""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    # Main CVE table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            cvss_score REAL,
            severity TEXT,
            affected_software TEXT,
            reference_urls TEXT,
            published_date TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Index for faster queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON cves(severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cvss ON cves(cvss_score)')
    
    conn.commit()
    conn.close()
    print(f"✓ Database schema ready at {DB_PATH}")


def download_nvd_cves(limit=500, skip_ssl=False, offset=0):
    """
    Download CVEs from NVD API.
    
    Args:
        limit: Number of CVEs to download
        skip_ssl: Skip SSL verification (dev only)
        offset: Start index (0 = newest, increment to get older CVEs)
    """
    print(f"\n📥 Downloading CVEs from NVD API (limit: {limit}, offset: {offset})...")
    
    # NVD API allows 20,000 results per page but rate limits to ~2000 queries/hour
    # We'll fetch in batches of 100
    batch_size = 100
    total_fetched = 0
    all_cves = []
    
    session = requests.Session()
    if skip_ssl:
        session.verify = False
    
    current_index = offset  # Start from offset
    
    while total_fetched < limit:
        remaining = limit - total_fetched
        results_per_page = min(batch_size, remaining)
        
        params = {
            "resultsPerPage": results_per_page,
            "startIndex": current_index
        }
        
        try:
            print(f"  Fetching batch: {current_index}-{current_index + results_per_page}...", end=" ")
            response = session.get(NVD_API, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                if not vulnerabilities:
                    print("✓ (No more data)")
                    break
                
                all_cves.extend(vulnerabilities)
                total_fetched += len(vulnerabilities)
                current_index += len(vulnerabilities)
                print(f"✓ Got {len(vulnerabilities)}")
                
                # Rate limiting: NVD requests max 5 requests per 30 seconds (sleep 6s between)
                time.sleep(0.5)
                
            else:
                print(f"✗ HTTP {response.status_code}")
                print(f"  Response: {response.text[:200]}")
                break
                
        except requests.exceptions.RequestException as e:
            print(f"✗ Error: {e}")
            break
    
    print(f"\n✓ Downloaded {len(all_cves)} total CVEs (offset: {offset})")
    return all_cves, current_index


def parse_and_store_cves(cves):
    """Parse NVD CVE data and store in SQLite"""
    print(f"\n💾 Storing {len(cves)} CVEs in SQLite...")
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    stored = 0
    skipped = 0
    
    for cve in cves:
        try:
            cve_item = cve['cve']
            cve_id = cve_item['id']
            
            # Extract CVSS score (prefer v3.1, fallback to v3.0 or v2.0)
            cvss = 0
            severity = "Low"
            
            if 'metrics' in cve_item:
                if 'cvssV3_1' in cve_item['metrics'] and cve_item['metrics']['cvssV3_1']:
                    cvss = cve_item['metrics']['cvssV3_1'][0]['cvssData']['baseScore']
                elif 'cvssV3_0' in cve_item['metrics'] and cve_item['metrics']['cvssV3_0']:
                    cvss = cve_item['metrics']['cvssV3_0'][0]['cvssData']['baseScore']
                elif 'cvssV2_0' in cve_item['metrics'] and cve_item['metrics']['cvssV2_0']:
                    cvss = cve_item['metrics']['cvssV2_0'][0]['cvssData']['baseScore']
            
            # Calculate severity based on CVSS
            if cvss >= 9.0:
                severity = "Critical"
            elif cvss >= 7.0:
                severity = "High"
            elif cvss >= 4.0:
                severity = "Medium"
            elif cvss > 0:
                severity = "Low"
            
            # Extract description (first English description)
            description = ""
            for desc in cve_item.get('descriptions', []):
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')[:1000]  # Limit to 1000 chars
                    break
            
            # Store affected configurations
            affected = json.dumps(cve_item.get('configurations', []))
            
            # Store references
            references = json.dumps([r['url'] for r in cve_item.get('references', [])])
            
            published = cve_item.get('published', '')
            
            # Insert or replace
            cursor.execute('''
                INSERT OR REPLACE INTO cves 
                (cve_id, description, cvss_score, severity, affected_software, reference_urls, published_date)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (cve_id, description, cvss, severity, affected, references, published))
            
            stored += 1
            
        except (KeyError, IndexError, ValueError) as e:
            skipped += 1
            continue
    
    conn.commit()
    conn.close()
    
    print(f"  ✓ Stored: {stored}")
    if skipped:
        print(f"  ⚠ Skipped: {skipped} (malformed entries)")
    
    return stored


def display_stats():
    """Display database statistics"""
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        
        # Total CVEs
        cursor.execute("SELECT COUNT(*) FROM cves")
        total = cursor.fetchone()[0]
        
        # By severity
        cursor.execute("""
            SELECT severity, COUNT(*) FROM cves 
            GROUP BY severity ORDER BY 
            CASE 
                WHEN severity='Critical' THEN 1
                WHEN severity='High' THEN 2
                WHEN severity='Medium' THEN 3
                WHEN severity='Low' THEN 4
            END
        """)
        
        severity_counts = cursor.fetchall()
        
        conn.close()
        
        print(f"\n📊 Database Statistics:")
        print(f"  Total CVEs: {total:,}")
        print(f"  By Severity:")
        for severity, count in severity_counts:
            print(f"    - {severity}: {count}")
        
    except sqlite3.Error as e:
        print(f"Error querying database: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Download CVEs from NVD and cache in SQLite"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=500,
        help="Number of CVEs to download (default: 500)"
    )
    parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Starting index for NVD API (default: 0 = newest). Increment to get older CVEs"
    )
    parser.add_argument(
        "--skip-ssl",
        action="store_true",
        help="Skip SSL verification (dev only, not recommended)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("NVD CVE Database Downloader")
    print("=" * 60)
    
    try:
        # Step 1: Create database
        create_database()
        
        # Step 2: Download from NVD
        cves, next_offset = download_nvd_cves(limit=args.limit, skip_ssl=args.skip_ssl, offset=args.offset)
        
        if not cves:
            print("\n✗ No CVEs downloaded. Check your internet connection.")
            sys.exit(1)
        
        # Step 3: Parse and store
        stored = parse_and_store_cves(cves)
        
        if stored == 0:
            print("\n✗ No CVEs were stored. The data format may have changed.")
            sys.exit(1)
        
        # Step 4: Show stats
        display_stats()
        
        # Step 5: Show next offset for continued downloads
        print(f"\n💡 To download the next batch of CVEs, use:")
        print(f"   python scripts/download_nvd.py --limit {args.limit} --offset {next_offset}")
        
        print(f"\n✓ CVE database ready at: {DB_PATH}")
        print("  Use CVEDatabase class in Backend/core/cve_database.py to query")
        
    except KeyboardInterrupt:
        print("\n\n⚠ Download interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
