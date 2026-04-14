# CCure Audit PRO — CVE Integration

**Version:** 1.0.0

---

## Overview

CCure Audit PRO uses a two-tier CVE matching strategy:

1. **Banner-based CVE matching** — used during unauthenticated network scans (Phase 3). Service banners are correlated against a local NVD-sourced SQLite database.
2. **Package-version CVE matching** — used during credentialed scans. Exact package names and versions from the package manager are matched against NVD CPE constraints.

Both strategies query the same `cves.db` SQLite database. The credentialed approach is significantly more accurate because it works with verified package manager data rather than banner guesses.

---

## CVE Database (`cves.db`)

### Location
`Backend/cves.db`

### Schema

```sql
CREATE TABLE cves (
    cve_id            TEXT PRIMARY KEY,   -- e.g., "CVE-2023-38408"
    description       TEXT,               -- NVD description (up to 500 chars used in queries)
    cvss_score        REAL,               -- CVSS v3 base score (0.0 – 10.0)
    severity          TEXT,               -- "Critical" | "High" | "Medium" | "Low"
    affected_software TEXT,               -- JSON blob of NVD CPE match data
    references        TEXT,               -- JSON array of reference URLs
    published         TEXT,               -- ISO date string
    updated_at        TEXT                -- ISO date string
);
```

### Population
The database is populated by `Backend/scripts/download_nvd.py`. This script fetches NVD JSON feeds and inserts/updates rows in `cves.db`. Run this script periodically to keep CVE data current.

```bash
cd Backend
python scripts/download_nvd.py
```

### Fallback Mode
If `cves.db` does not exist, the scanner falls back to a hardcoded `CVE_HINTS` dictionary in `core/constants.py`. This fallback covers a small set of high-profile CVEs for common services (OpenSSH, Apache, OpenSSL, etc.) but is far less comprehensive than the NVD database.

---

## Banner-Based CVE Matching (`cve_engine.py`)

### When Used
Phase 3 (Advanced Scan) — after the port scanner has collected service banners.

### Matching Logic

For each open port on a host:
1. Extract `service` and `version` from the `PortResult` dict
2. Call `CVEDatabase.search_cves_for_service(service_name, version)`
3. The query performs a `LIKE` search against both `affected_software` and `description` columns:

```sql
SELECT cve_id, description, cvss_score, severity
FROM cves
WHERE affected_software LIKE '%openssh%' OR description LIKE '%openssh%'
ORDER BY cvss_score DESC
LIMIT 20
```

4. Returns up to 20 CVEs per service, sorted by CVSS score descending

### Accuracy Limitations
Banner-based matching has inherent limitations:
- Banners may be suppressed or falsified by the target
- Version extraction from banners is regex-based and may miss edge cases
- The `LIKE` match is broad — some results may not apply to the exact installed version

For precise results, use the credentialed scan which matches against exact package manager data.

---

## Package-Version CVE Matching (`vuln_matcher.py`)

### When Used
Credentialed scans — after `LinuxCollector` or `WindowsCollector` retrieves the full package list via SSH.

### Matching Algorithm

For each installed package:

**Step 1: Database Query**
```sql
SELECT cve_id, description, cvss_score, severity, affected_software
FROM cves
WHERE affected_software LIKE '%openssh%' OR description LIKE '%openssh%'
LIMIT 50
```

**Step 2: CPE Constraint Extraction**
The `affected_software` column contains a JSON blob in NVD CPE match format. The matcher parses each `cpeMatch` entry to extract:
- `versionStartIncluding` / `versionStartExcluding`
- `versionEndIncluding` / `versionEndExcluding`
- Exact version from CPE URI (position 5 in colon-split string)

**Step 3: Version Range Check**
The installed version is compared against the constraint using a custom version parser:

```python
def _parse_version(ver: str) -> Tuple[int, ...]:
    # Strips Debian epoch: "1:7.6p1" → "7.6p1"
    # Strips distro suffixes: "8.2p1-4ubuntu0.5" → "8.2p1"
    # Handles letter suffixes: "1.1.1f" → (1, 1, 1, 6)
    # Returns numeric tuple for comparison
```

A finding is emitted only if:
```
min_ver ≤ installed_version AND installed_version < max_ver
```

**Step 4: Deduplication**
A `seen_cves` set prevents the same CVE ID from appearing twice, even if matched by multiple packages.

### Output Format

```python
CredentialedCVE(
    cve_id="CVE-2023-38408",
    severity="Critical",
    cvss_score=9.8,
    description="...",
    package_name="openssh-server",
    installed_ver="8.2p1",
    fixed_ver="9.3p2",
    source="package_version_match"
)
```

Converted to dict for the API response via `VulnMatcher.to_report_format()`.

---

## CVE Normalization

All CVE entries are normalized through `core.risk.normalize_cve()` before being included in host results or risk scoring. This ensures consistent field names regardless of whether the CVE came from the database, a plugin, or the fallback hints.

**Normalization contract:**

| Input Key                    | Output Key      | Notes                                       |
|------------------------------|-----------------|---------------------------------------------|
| `cve_id` or `cve`            | `cve_id`, `cve` | Both aliases preserved                      |
| `cvss_score` or `cvss`       | `cvss_score`, `cvss` | Both aliases preserved                 |
| `description` or `desc`      | `description`, `desc` | Both aliases preserved                |
| `severity` (if missing)      | Derived from CVSS: ≥9.0=Critical, ≥7.0=High, ≥4.0=Medium |

---

## CVE Severity Classification

| Severity  | CVSS Range  |
|-----------|-------------|
| Critical  | 9.0 – 10.0  |
| High      | 7.0 – 8.9   |
| Medium    | 4.0 – 6.9   |
| Low       | 0.1 – 3.9   |
| Info      | 0.0         |

---

## CVSS Score → Risk Score Contribution

CVE findings contribute to the host risk score as follows:

| CVSS Range | Score Added per CVE |
|------------|---------------------|
| ≥ 9.0      | +20                 |
| 7.0–8.9    | +10                 |
| 4.0–6.9    | +5                  |
| < 4.0      | +2                  |

Risk score is capped at 100. See `SCAN_ENGINE_DESIGN.md` for the full scoring formula.

---

## CVE Deduplication

Before risk scoring, all CVEs across all plugins are deduplicated using `core.risk.deduplicate_cves()`. The CVE ID is used as the deduplication key. This prevents a single CVE from being counted multiple times if both the CVE engine and a service-specific plugin (e.g., `ssh_probe`) identify the same vulnerability.

---

## Keeping CVE Data Current

The NVD publishes daily and weekly JSON feed updates. To refresh `cves.db`:

```bash
cd Backend
python scripts/download_nvd.py
```

This script should be run:
- On initial setup (after cloning the repo)
- Weekly in production environments
- After any major NVD feed update notification

Without a current `cves.db`, the scanner will operate in fallback mode with a limited CVE set from `core/constants.py`. The scanner logs a warning at startup when this occurs:

```
WARNING  ccure.cve_db — CVE Database: SQLite not found at .../cves.db
WARNING  ccure.cve_db — CVE Database: Falling back to limited hardcoded CVEs
```
