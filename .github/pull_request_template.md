## Description

Please include a summary of the changes and the related issue/ticket. Include any design trade-offs made or context needed to review.

Fixes # (issue)

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Database migration (Alembic change)
- [ ] Documentation update

## Regression & Verification Checklist

Please verify that you have completed the following checks before requesting review:

### Automated Validation
- [ ] **Unit & Integration Tests:** Pytest suite passes locally (`pytest`).
- [ ] **Alembic Reversibility:** Database migrations have been tested forward and backward (`alembic upgrade head && alembic downgrade -1`).
- [ ] **Static Code Analysis:** Pre-commit hooks run cleanly with no linter/formatter or Bandit security warnings.
- [ ] **OpenAPI Diff Check:** OpenAPI schema generates successfully and has no undocumented breaking changes.

### Core Module Verification (Check all affected modules)
- [ ] **Authentication & RBAC:** Session revocation, login, token refresh, and MFA.
- [ ] **Dashboard & Analytics:** Correct score styling, colors, and asset query boundaries.
- [ ] **Asset Management:** MAC-first reconciliation and DHCP IP updates.
- [ ] **Scanning Engines:** Discovery (Scapy), Port (Nmap), and Credentialed (SSH/Paramiko) execution.
- [ ] **Web Scanner (DAST):** Playwright crawl, WAF detection, and Nuclei rules.
- [ ] **Compliance Engine:** Framework installation, exception waivers, and Maker-Checker safety.
- [ ] **Exporters:** PDF (ReportLab) and Word (python-docx) formatting.
- [ ] **User Administration:** Admin operations and tenant isolation logs.

### Security Review
- [ ] Input parameters are explicitly typed and validated.
- [ ] Sensitive logs (credentials, JWT tokens, PII) are strictly avoided.
- [ ] No raw SQL statements are introduced (all use parameterized SQLAlchemy).
- [ ] Maker-Checker queue logic has been preserved and is not bypassed.

## Module Owner Sign-off
*Signed off by:* @username (Designated Module Owner)
