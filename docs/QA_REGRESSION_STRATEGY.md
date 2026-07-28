# CCure Audit PRO — QA & Regression Validation Strategy

This document establishes the official quality assurance framework, regression check routines, module ownership assignments, and production release criteria for **CCure Audit PRO**.

---

## 1. Module Ownership Matrix

To ensure clear accountability, each core module of CCure Audit PRO has a designated owner who is responsible for reviewing code changes impacting their module and validating core workflows before release.

| Module                                | Scope / Key Files                                      | Primary Owner          | Backup Validator      |
| ------------------------------------- | ------------------------------------------------------ | ---------------------- | --------------------- |
| **Authentication & Authorization**    | `Backend/auth/*`, MFA (`test_mfa.py`), JWT logic       | Lead Backend Engineer  | Security Architect    |
| **Asset Management**                  | `Backend/routers/assets.py`, DHCP hijack protections   | Lead Backend Engineer  | Fullstack Developer   |
| **Network Discovery & Scanning**      | `Backend/core/discovery/`, Scapy ARP/ICMP probes, Nmap | Scanning Specialist    | Lead Backend Engineer |
| **DAST Web Scanning**                 | `Backend/core/web/`, Nuclei, SQLMap, crawl queue       | Security Architect     | Scanning Specialist   |
| **Compliance Engine & Maker-Checker** | `Backend/routers/compliance.py`, Fernet rules          | Compliance Specialist  | Security Architect    |
| **PDF & Word Reporting Exporters**    | `Backend/pdf_generator.py`, python-docx scripts        | Fullstack Developer    | Frontend Engineer     |
| **Frontend UI & Visual Topology**     | `Frontend/src/*`, Vis-Network, dashboard maps          | Lead Frontend Engineer | Fullstack Developer   |

---

## 2. Core Regression Modules & Checklists

Before merging any code change, the developer and module owner must run through these validation checklists.

### Module 1: Authentication & Authorization (Auth/Authz)

- [ ] **Standard Login:** Verify username/password combination authenticate correctly.
- [ ] **MFA Validation:** Enable MFA, verify OTP code checks, and ensure no screen redirect occurs on toggle.
- [ ] **Token Expiration:** Confirm access tokens expire in 30 minutes, and refresh tokens correctly fetch fresh access tokens.
- [ ] **Session Revocation:** Verify that a password change or logout invalidates all active access and refresh tokens.

### Module 2: Dashboard Analytics

- [ ] **Analytical Widgets:** Ensure dashboard telemetry counts (vuln counts, compliance scores) render correctly.
- [ ] **Compliance Score Classification:** Verify compliance scores are color-coded dynamically (Low = Red, Medium = Orange, High = Green) and match SQL database averages.
- [ ] **Asset Scoping:** Verify dashboard only reflects assets belonging to the active organization (or all orgs if superadmin).

### Module 3: Asset Management & Reconciliation

- [ ] **Asset Reconciliation (MAC-First):** Verify host scans match existing asset rows based on MAC address first, preventing duplicate host creation.
- [ ] **DHCP Hijack Protection:** Ensure scanning does not overwrite a stable asset profile if an IP changes (reconciliation binds the new IP to the existing MAC).
- [ ] **Inventory Export:** Validate CSV/JSON asset inventory downloads work without JSONB rendering crashes.

### Module 4: Network Discovery (Phase 1)

- [ ] **Scapy Scan Sweep:** Verify Host Discovery (`core/discovery/engine.py`) correctly probes active IPs.
- [ ] **Intensity Fallbacks:** Test `normal` intensity fallbacks (from fast ARP to balanced ping probes) if targets don't respond immediately.
- [ ] **CI Socket Fallback:** Ensure scanning degrades to standard socket connect scans when execution lacks root capabilities (`CAP_NET_RAW`).

### Module 5: Vulnerability Scanning (Phase 2 & 3)

- [ ] **Nmap Port Scans:** Verify asset port sweeps start within timeout boundaries.
- [ ] **Vulnerability Audits:** Verify correct matching of CPE/CVE identifiers.
- [ ] **Live Progress Tracking:** Confirm Celery tasks publish status updates over Redis Pub/Sub, and the UI progress bar animates smoothly.

### Module 6: DAST Web Scanning

- [ ] **Recon & Spidering:** Verify crawler (Playwright) correctly maps page links up to the maximum depth constraint.
- [ ] **Security Audits:** Validate Nuclei triggers on target URLs and outputs vulnerabilities correctly.
- [ ] **Crawl Rate Limiting:** Verify that scan rates are throttled when a WAF (Web Application Firewall) is detected.

### Module 7: Policy Compliance Engine

- [ ] **Framework Installation:** Verify frameworks (e.g. ISO 27001) install from the marketplace to the tenant profile.
- [ ] **Evidence Upload:** Verify manual evidence files upload correctly and bind to the correct control finding.
- [ ] **Maker-Checker Execution:** Verify remediation scripts enter the approval queue and **cannot** be approved by the Maker who created them.
- [ ] **Exception Waivers:** Verify exception requests require comments, expiration dates, and compliance officer approval.

### Module 8: Notifications

- [ ] **SSE Stream Broadcast:** Verify real-time alerts appear instantly on user creation, status suspension, and scan completions.
- [ ] **Role Scoping:** Confirm notifications target only specified roles within the organization, respecting notification preferences.

### Module 9: Reports & Exporter Engine

- [ ] **PDF Reports:** Export executive summary PDFs and verify ReportLab layout grid doesn't crash on long target names.
- [ ] **Word Exporter:** Export Statement of Applicability (SoA) documents and confirm `python-docx` templates output correctly.

### Module 10: User Management & Admin Console

- [ ] **Quiet Pagination:** Ensure search and paging on the user management board do not unmount or cause visual flickering.
- [ ] **Tenant Isolation Guard:** Confirm organization-scoped admins cannot suspensions or view users in other organizations.

---

## 3. Manual Regression Validation Flow

For changes that cannot be fully automated (such as visual graphing or manual file uploads), developers must follow this manual verification cycle:

```
[Define Test Environment] ──> [Seed Standard Catalog] ──> [Run Action Flow] ──> [Confirm Audit Log]
```

1. **Clean DB Reset:** Initialize a fresh database with:
   ```bash
   python db/migrate_production_schema.py
   python -m scripts.seed_compliance
   ```
2. **Execute Workflow:** Manually perform the specific actions (e.g. upload an asset JSON, trigger a credentialed scan).
3. **Verify State:** Query the database or inspect the UI to verify assets or findings were correctly persisted.
4. **Audit Log Inspection:** Check the `/admin/audit-logs` feed to ensure the action was recorded with the correct client IP address.

---

## 4. Release Criteria & Freeze Window

Before every production release:

1. **Code Freeze:** All feature branch merges are halted. Only release hotfixes are permitted.
2. **Automated Run:** Execute the full test suite in the Docker test sandbox.
3. **Manual Validation:** Execute the Manual Regression checklist for the impacted modules.
4. **Sign-off:** The designated Module Owner must sign off on the Pull Request.
5. **Alembic Reversibility check:** Validate that backward migrations execute cleanly.
