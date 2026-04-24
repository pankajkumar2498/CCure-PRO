"""
cve_database.py
---------------
CVE Database Query Wrapper

Provides efficient queries to the local SQLite CVE database.
Replaces hardcoded CVE lookups with dynamic database queries.

Example:
    cve_db = CVEDatabase()
    
    # Search for CVEs by service
    cves = cve_db.search_cves_for_service("openssh", "7.4")
    
    # Get details for a single CVE
    details = cve_db.get_cve_details("CVE-2023-38408")
    
    # Get all critical CVEs
    critical = cve_db.get_cves_by_severity("Critical")
"""

import sqlite3
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class CVEDatabase:
    """
    Query interface for local SQLite CVE database.
    Automatically falls back to hardcoded CVEs if database doesn't exist.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize CVE database connection.
        
        Args:
            db_path: Path to SQLite database. Defaults to Backend/cves.db
        """
        if db_path is None:
            # Look for cves.db in Backend directory
            db_path = Path(__file__).parent.parent / "cves.db"
        
        self.db_path = Path(db_path)
        self.db_available = self.db_path.exists()
        
        if self.db_available:
            logger.info(f"CVE Database: Using SQLite at {self.db_path}")
        else:
            logger.warning(f"CVE Database: SQLite not found at {self.db_path}")
            logger.warning("CVE Database: Falling back to limited hardcoded CVEs")
    
    def search_cves_for_service(self, service_name: str, version: str = "") -> List[Dict]:
        """
        Find CVEs affecting a detected service.
        
        Args:
            service_name: Service name (e.g., "openssh", "nginx", "apache")
            version: Service version (optional, used for ranking)
        
        Returns:
            List of CVE dictionaries sorted by CVSS score (highest first)
        """
        if not self.db_available:
            return self._fallback_search(service_name, version)
        
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Search for CVEs mentioning this service
            # Case-insensitive search in affected_software and description
            search_term = f"%{service_name}%"
            
            query = '''
                SELECT cve_id, description, cvss_score, severity 
                FROM cves 
                WHERE affected_software LIKE ? OR description LIKE ?
                ORDER BY cvss_score DESC
                LIMIT 20
            '''
            
            cursor.execute(query, (search_term, search_term))
            results = cursor.fetchall()
            conn.close()
            
            cves = [
                {
                    "cve": row[0],
                    "desc": row[1][:500],  # Truncate description
                    "cvss": row[2],
                    "severity": row[3]
                }
                for row in results
            ]
            
            logger.debug(f"Found {len(cves)} CVEs for {service_name}")
            return cves
            
        except sqlite3.Error as e:
            logger.error(f"Database error searching for {service_name}: {e}")
            return self._fallback_search(service_name, version)
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """
        Get full details for a specific CVE.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-38408")
        
        Returns:
            Dictionary with CVE details or None if not found
        """
        if not self.db_available:
            return None
        
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM cves WHERE cve_id = ?
            ''', (cve_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return None
            
            return {
                "cve_id": row[0],
                "description": row[1],
                "cvss_score": row[2],
                "severity": row[3],
                "affected": json.loads(row[4]) if row[4] else [],
                "references": json.loads(row[5]) if row[5] else [],
                "published": row[6],
                "updated_at": row[7]
            }
            
        except (sqlite3.Error, json.JSONDecodeError) as e:
            logger.error(f"Error fetching details for {cve_id}: {e}")
            return None
    
    def get_cves_by_severity(self, severity: str) -> List[Dict]:
        """
        Get all CVEs of a specific severity level.
        
        Args:
            severity: "Critical", "High", "Medium", or "Low"
        
        Returns:
            List of CVE dictionaries sorted by CVSS score
        """
        if not self.db_available:
            return []
        
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            query = '''
                SELECT cve_id, description, cvss_score, severity 
                FROM cves 
                WHERE severity = ?
                ORDER BY cvss_score DESC
            '''
            
            cursor.execute(query, (severity,))
            results = cursor.fetchall()
            conn.close()
            
            cves = [
                {
                    "cve": row[0],
                    "desc": row[1][:500],
                    "cvss": row[2],
                    "severity": row[3]
                }
                for row in results
            ]
            
            return cves
            
        except sqlite3.Error as e:
            logger.error(f"Database error fetching {severity} CVEs: {e}")
            return []
        
    def _fallback_search(self, service_name: str, version: str) -> List[Dict]:
        """
        Fallback to hardcoded CVE hints when database is unavailable.
        This maintains backward compatibility during testing/setup.
        
        Args:
            service_name: Service name
            version: Service version
        
        Returns:
            List of CVE hints from hardcoded dictionary
        """
        from core.constants import CVE_HINTS
        
        service_name_lower = service_name.lower()
        cves = []
        
        # Try exact matches and partial matches
        for key, hints in CVE_HINTS.items():
            if service_name_lower in key.lower():
                cves.extend(hints)
        
        # Sort by CVSS (highest first)
        cves.sort(key=lambda x: x.get("cvss", 0), reverse=True)
        
        logger.debug(f"Fallback: Found {len(cves)} hardcoded CVEs for {service_name}")
        return cves[:20]  # Return top 20


# Global instance
_cve_db = None


def get_cve_database() -> CVEDatabase:
    """
    Get global CVE database instance (singleton pattern).
    
    Returns:
        CVEDatabase instance
    """
    global _cve_db
    if _cve_db is None:
        _cve_db = CVEDatabase()
    return _cve_db
