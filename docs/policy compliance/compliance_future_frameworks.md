# CCure Audit PRO — Future Framework Extension Guide

This guide describes how to add new security standards and compliance frameworks (e.g., CIS Benchmarks, NIST 800-53, PCI-DSS, HIPAA, or IEC 62443) to the CCure Audit PRO platform without modifying the core database schema or application code.

---

## 1. Dynamic Framework Design Principles

The compliance engine is designed to be completely metadata-driven:

- **Decoupled Checks**: A rule definition (e.g., checking password length) exists independently of the controls it satisfies.
- **Junction Mapping**: The `compliance_rule_controls` table maps rules to controls. One rule can satisfy multiple controls across distinct frameworks (e.g. A rule checking TLS version maps to ISO 8.24, PCI-DSS 4.2, and NIST SC-13).
- **Zero Code Releases**: Seeding a framework only requires executing database insert queries, not releasing new code.

---

## 2. Walkthrough: Adding a New Framework (e.g., PCI-DSS 4.0)

Adding a framework is completed in four steps:

### Step 1: Create the Framework Row

Insert the standard definition into `compliance_frameworks`:

```sql
INSERT INTO compliance_frameworks (id, tenant_id, code, name, version, is_active)
VALUES ('cfw_pci_dss_4_0', NULL, 'PCI_DSS_4_0', 'PCI DSS v4.0', '4.0', TRUE);
```

### Step 2: Seed the Controls

Map the standard's requirements into `compliance_controls`:

```sql
INSERT INTO compliance_controls (id, framework_id, control_number, theme, title, description, scannability)
VALUES
('cct_pci4_0_2_2', 'cfw_pci_dss_4_0', '2.2', 'TECH', 'System Hardening Standards', 'Apply system hardening standards to all assets.', 'auto'),
('cct_pci4_0_4_2', 'cfw_pci_dss_4_0', '4.2', 'TECH', 'Encrypt transmission of cardholder data', 'Strong cryptography and security protocols are used.', 'auto');
```

### Step 3: Reuse Existing Rules

If the platform already has rules verifying TLS 1.2+ configuration or registry keys, map them to the new PCI controls using the `compliance_rule_controls` junction table:

```sql
-- Map existing TLS rule to PCI 4.2 control
INSERT INTO compliance_rule_controls (rule_id, control_id)
VALUES ('crl_net_tls_001_v1', 'cct_pci4_0_4_2');
```

### Step 4: Add New Custom Rules (Optional)

If a PCI control requires a check that does not exist in the library, insert the check definition into `compliance_rules` and link it:

```sql
-- Insert a check verifying default password change enforcement
INSERT INTO compliance_rules (id, rule_family_code, version_number, check_type, target_platform, check_definition, severity, status)
VALUES (
  'crl_auth_default_pwd_v1',
  'AUTH-DEFAULT-PWD',
  1,
  'registry',
  'windows',
  '{"key": "UserMustChangePassword", "operator": "equals", "expected": 1}',
  'high',
  'active'
);

-- Link the new rule to PCI 2.2 control
INSERT INTO compliance_rule_controls (rule_id, control_id)
VALUES ('crl_auth_default_pwd_v1', 'cct_pci4_0_2_2');
```

---

## 3. Summary of Seeding Files

When introducing a new framework, package it as a JSON seed file:

```json
{
  "framework": {
    "code": "PCI_DSS_4_0",
    "name": "PCI DSS v4.0",
    "version": "4.0"
  },
  "controls": [
    {
      "id": "2.2",
      "theme": "TECH",
      "title": "System Hardening Standards",
      "scannability": "auto"
    },
    {
      "id": "4.2",
      "theme": "TECH",
      "title": "Encrypt cardholder data transmission",
      "scannability": "auto"
    }
  ],
  "mappings": [
    { "rule_family_code": "NET-TLS-001", "control_number": "4.2" },
    { "rule_family_code": "AUTH-DEFAULT-PWD", "control_number": "2.2" }
  ]
}
```

The platform's command-line seeding utility `seed_compliance` reads this file, creates the tables rows, resolves the rule mappings, and makes the framework instantly available for install in the **Marketplace**.
