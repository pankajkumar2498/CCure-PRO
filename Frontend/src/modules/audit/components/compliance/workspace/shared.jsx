/**
 * Helpers shared by the compliance workspace's tabs: score bands, theme
 * labels and badges, and the paging control the list tabs use. Moved from
 * `pages/ComplianceWorkspace.jsx` (F1) unchanged.
 */

import { CcurePagination, CcureButton } from "../../../../../design-system";

export const getScoreClass = (score) => {
  const val = Number(score) || 0;
  if (val >= 80) return "radial-score--high";
  if (val >= 50) return "radial-score--medium";
  return "radial-score--low";
};

export const THEME_LABELS = {
  // ISO 27001
  ORG: "Organizational Controls (ORG)",
  PPL: "People Controls (PPL)",
  PHY: "Physical Controls (PHY)",
  TECH: "Technological Controls (TECH)",
  ISMS: "Management-System Clauses 4–10 (ISMS)",

  // HIPAA Security Rule (45 CFR Part 164 Subpart C)
  HIPAA_ADM: "Administrative Safeguards (§164.308)",
  HIPAA_PHY: "Physical Safeguards (§164.310)",
  HIPAA_TEC: "Technical Safeguards (§164.312)",
  HIPAA_ORG: "Organizational Requirements (§164.314)",
  HIPAA_DOC: "Policies, Procedures and Documentation (§164.316)",

  // NIST CSF v2.0
  GV: "Govern (GV)",
  ID: "Identify (ID)",
  PR: "Protect (PR)",
  DE: "Detect (DE)",
  RS: "Respond (RS)",
  RC: "Recover (RC)",

  // CIS Controls v8.1
  CIS_01: "Control 1: Enterprise Assets",
  CIS_02: "Control 2: Software Assets",
  CIS_03: "Control 3: Data Protection",
  CIS_04: "Control 4: Secure Configuration",
  CIS_05: "Control 5: Account Management",
  CIS_06: "Control 6: Access Control",
  CIS_07: "Control 7: Vulnerability Management",
  CIS_08: "Control 8: Audit Log Management",
  CIS_09: "Control 9: Email & Web Protections",
  CIS_10: "Control 10: Malware Defenses",
  CIS_11: "Control 11: Data Recovery",
  CIS_12: "Control 12: Network Infrastructure",
  CIS_13: "Control 13: Network Monitoring",
  CIS_14: "Control 14: Security Awareness",
  CIS_15: "Control 15: Service Provider Mgmt",
  CIS_16: "Control 16: Application Security",
  CIS_17: "Control 17: Incident Response",
  CIS_18: "Control 18: Penetration Testing",

  // SOC 2 Type II
  SOC2_CC: "Common Criteria / Security (CC)",
  SOC2_A: "Availability (A)",
  SOC2_PI: "Processing Integrity (PI)",
  SOC2_C: "Confidentiality (C)",
  SOC2_P: "Privacy (P)",

  // CERT-In Directions 2022
  CERT_IR: "Incident Reporting & Response (CERT_IR)",
  CERT_LOG: "System Log Retention & Time Sync (CERT_LOG)",
  CERT_AM: "Asset & VPN Log Retention (CERT_AM)",
  CERT_VM: "Vulnerability Management & ICT Audits (CERT_VM)",
  CERT_AC: "Access Control & MFA (CERT_AC)",
  CERT_DP: "Data Protection & Encryption (CERT_DP)",

  // PCI-DSS v4.0
  PCI_01: "Req 1: Network Security Controls",
  PCI_02: "Req 2: Secure Configurations",
  PCI_03: "Req 3: Account Data Protection",
  PCI_04: "Req 4: Cryptography in Transit",
  PCI_05: "Req 5: Malware Protection",
  PCI_06: "Req 6: Secure Systems & Software",
  PCI_07: "Req 7: Access Restriction",
  PCI_08: "Req 8: Identification & Auth",
  PCI_09: "Req 9: Physical Access",
  PCI_10: "Req 10: Log Monitoring",
  PCI_11: "Req 11: Security Testing & FIM",
  PCI_12: "Req 12: Security Policies & TRA",

  // DPDP Act 2023
  DPDP_CN: "Consent & Notice (Art. 5 & 6)",
  DPDP_PL: "Purpose Limitation & Minimization (Art. 7)",
  DPDP_DR: "Data Principal Rights (Art. 11-14)",
  DPDP_BN: "Breach Notification to DPBI (Art. 8(6))",
  DPDP_PS: "Security Safeguards & Enc (Art. 8(5))",
  DPDP_GV: "SDF Governance & DPO (Art. 10)",

  // EU GDPR
  GDPR_LT: "Lawfulness & Transparency (Art. 5(1)(a))",
  GDPR_PL: "Purpose Limitation (Art. 5(1)(b))",
  GDPR_DM: "Data Minimization (Art. 5(1)(c))",
  GDPR_AY: "Accuracy & Rectification (Art. 5(1)(d))",
  GDPR_SL: "Storage Limitation (Art. 5(1)(e))",
  GDPR_IC: "Integrity & Confidentiality (Art. 5(1)(f))",
  GDPR_AC: "Accountability & Governance (Art. 5(2))",

  // NIST SP 800-53 Rev. 5
  SP53_AC: "Access Control (AC)",
  SP53_AT: "Awareness & Training (AT)",
  SP53_AU: "Audit & Accountability (AU)",
  SP53_CA: "Assessment, Auth & Monitoring (CA)",
  SP53_CM: "Configuration Management (CM)",
  SP53_CP: "Contingency Planning (CP)",
  SP53_IA: "Identification & Auth (IA)",
  SP53_IR: "Incident Response (IR)",
  SP53_MA: "Maintenance (MA)",
  SP53_MP: "Media Protection (MP)",
  SP53_PE: "Physical & Environmental (PE)",
  SP53_PL: "Planning (PL)",
  SP53_PM: "Program Management (PM)",
  SP53_PS: "Personnel Security (PS)",
  SP53_PT: "PII Processing & Transparency (PT)",
  SP53_RA: "Risk Assessment (RA)",
  SP53_SA: "System & Services Acquisition (SA)",
  SP53_SC: "System & Comms Protection (SC)",
  SP53_SI: "System & Information Integrity (SI)",
  SP53_SR: "Supply Chain Risk Management (SR)",

  // IEC 62443 (OT/ICS)
  IEC_2_1: "Security Program - Asset Owners (2-1)",
  IEC_2_3: "OT Patch Management (2-3)",
  IEC_2_4: "Security Program - Service Providers (2-4)",
  FR1_IAC: "FR1: Identification & Auth (3-3)",
  FR2_UC: "FR2: Use Control (3-3)",
  FR3_SI: "FR3: System Integrity (3-3)",
  FR4_DC: "FR4: Data Confidentiality (3-3)",
  FR5_RDF: "FR5: Restricted Data Flow - Conduits (3-3)",
  FR6_TRE: "FR6: Timely Response to Events (3-3)",
  FR7_RA: "FR7: Resource Availability (3-3)",

  // NIST SP 800-82 Rev. 3 (OT Security)
  SP82_AC: "Access Control for OT Systems",
  SP82_AU: "Audit & Accountability for ICS/SCADA",
  SP82_CM: "Configuration Management & OT Baselines",
  SP82_IA: "Identification & Authentication",
  SP82_IR: "Incident Response & Safety Protection",
  SP82_SC: "System & Communications Protection",
  SP82_SI: "System & Information Integrity",
  SP82_RA: "Risk Assessment & Hazard Analysis",
  SP82_SA: "System & Services Acquisition",

  // EU NIS 2 Directive (Directive (EU) 2022/2555)
  NIS2_GOV: "Governance & Risk Analysis Policies (Art. 21.2a)",
  NIS2_INC: "Incident Handling & 24h CSIRT Warning (Art. 21.2b)",
  NIS2_BC: "Business Continuity & Backups (Art. 21.2c)",
  NIS2_SUPPLY: "Supply Chain & Vendor Risk (Art. 21.2d)",
  NIS2_SEC: "Vulnerability Management & CVD (Art. 21.2e)",
  NIS2_AUDIT: "Security Effectiveness & Audits (Art. 21.2f)",
  NIS2_HYGIENE: "Cyber Hygiene & Security Training (Art. 21.2g)",
  NIS2_CRYPTO: "Cryptography & Data Encryption (Art. 21.2h)",
  NIS2_IAM: "Access Control & Least Privilege (Art. 21.2i)",
  NIS2_MFA: "Multi-Factor Authentication & Comms (Art. 21.2j)",
};

// The dashboard's score colour follows the bands `getScoreClass` already
// decides; this only names them for the stylesheet.
export const SCORE_TONE = {
  "radial-score--high": "high",
  "radial-score--medium": "medium",
  "radial-score--low": "low",
};

// NIST CSF 2.0 Functions keep a distinct badge each on the theme breakdown.
export const NIST_FUNCTION_BADGE = {
  GV: "primary",
  ID: "info",
  PR: "success",
  DE: "warning",
  RS: "danger",
  RC: "neutral",
};

// Paging for the Policies and Findings tabs: CcurePagination, plus the first
// and last page buttons the tabs have always offered, which it has no control
// for.
export function PagingControls({
  pagination,
  total,
  loading,
  label,
  itemNoun,
  sizes,
}) {
  const { page, setPage, pageSize, setPageSize, totalPages, displayPage } =
    pagination;
  return (
    <div className="cwv-paging">
      <CcurePagination
        page={page}
        pageSize={pageSize}
        total={total}
        onPageChange={setPage}
        onPageSizeChange={(size) => {
          setPageSize(size);
          setPage(1);
        }}
        pageSizeOptions={sizes}
        label={label}
        itemNoun={itemNoun}
        disabled={loading}
      />
      <div className="cwv-paging__jump" role="group" aria-label="Jump to page">
        <CcureButton
          variant="ghost"
          size="sm"
          disabled={loading || displayPage === 1}
          onClick={() => setPage(1)}
        >
          First page
        </CcureButton>
        <CcureButton
          variant="ghost"
          size="sm"
          disabled={loading || displayPage === totalPages}
          onClick={() => setPage(totalPages)}
        >
          Last page
        </CcureButton>
      </div>
    </div>
  );
}
