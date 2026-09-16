/**
 * src/pages/ComplianceWorkspace.jsx
 * Compliance baselines, controls, rules, exceptions, and scoring dashboards.
 */

import React, { useState, useEffect, useMemo, useRef, useId } from "react";
import axiosInstance from "../api/axiosInstance";
import AppLayout from "../components/layout/AppLayout";
import { useAuth } from "../context/AuthContext";
import { useToasts, ToastContainer } from "../components/common/Toast";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureCard,
  CcureConfirmDialog,
  CcureField,
  CcureInput,
  CcureLoader,
  CcureModal,
  CcurePagination,
  CcurePasswordField,
  CcureProgress,
  CcureSelect,
  CcureSeverityBadge,
  CcureTable,
  CcureTableStatus,
  CcureTabPanel,
  CcureTabs,
  useCcureTabs,
} from "../design-system";
import "../styles/dashboard.css";
import "../styles/compliance.css";
import "../styles/scan.css";
import "../styles/compliance-exceptions.css";
import "../styles/compliance-views.css";
import "../styles/compliance-writes.css";
import "../styles/compliance-attestation.css";
import "../styles/compliance-credentials.css";
import "../styles/compliance-execution.css";
import "../styles/compliance-gap.css";
import "../styles/compliance-workspace.css";

function useClientPagination(items, initialPageSize = 25) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(initialPageSize);
  const cardRef = useRef(null);

  const totalPages = useMemo(
    () => Math.max(1, Math.ceil(items.length / pageSize)),
    [items.length, pageSize],
  );

  const displayPage = useMemo(
    () => Math.min(page, totalPages),
    [page, totalPages],
  );

  const paginatedItems = useMemo(
    () => items.slice((displayPage - 1) * pageSize, displayPage * pageSize),
    [items, displayPage, pageSize],
  );

  // Out-of-bounds guard
  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages);
    }
  }, [page, totalPages]);

  // Tab switch scroll guard
  const prevPageRef = useRef(page);
  useEffect(() => {
    if (prevPageRef.current !== page) {
      if (cardRef.current) {
        cardRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
      }
      prevPageRef.current = page;
    }
  }, [page]);

  return {
    page,
    setPage,
    pageSize,
    setPageSize,
    cardRef,
    totalPages,
    displayPage,
    paginatedItems,
  };
}

const getScoreClass = (score) => {
  const val = Number(score) || 0;
  if (val >= 80) return "radial-score--high";
  if (val >= 50) return "radial-score--medium";
  return "radial-score--low";
};

const THEME_LABELS = {
  // ISO 27001
  ORG: "Organizational Controls (ORG)",
  PPL: "People Controls (PPL)",
  PHY: "Physical Controls (PHY)",
  TECH: "Technological Controls (TECH)",

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

// One catalogue for every framework selector in this workspace.
//
// The same thirteen frameworks were previously listed in four separate places
// — the framework dropdown, the gap-analysis pair, the cross-framework score
// chart and the report menu — each with its own labels and its own order, so a
// framework could appear in one and not another and nothing kept them in step.
// `reportSlug` is the `/compliance/reports/<slug>` path where one exists;
// ISO 27001's report is the Statement of Applicability, which is addressed by
// `framework_id` instead and so carries no slug.
const FRAMEWORK_CATALOGUE = [
  {
    id: "cfw_iso27001_2022",
    name: "ISO/IEC 27001:2022",
    longName: "ISO 27001:2022 (Information Security)",
    reportSlug: "soa",
    reportLabel: "Statement of Applicability (SoA — ISO 27001)",
  },
  {
    id: "cfw_nist_csf_v2",
    name: "NIST CSF v2.0",
    longName: "NIST CSF 2.0 (Cybersecurity Framework)",
    reportSlug: "nist_csf",
    reportLabel: "NIST CSF v2.0 Current Profile",
  },
  {
    id: "cfw_cis_v8_1",
    name: "CIS Controls v8.1",
    longName: "CIS Controls v8.1 (Critical Controls)",
    reportSlug: "cis_v8_1",
    reportLabel: "CIS Controls v8.1 Executive Report",
  },
  {
    id: "cfw_soc2_type2",
    name: "SOC 2 Type II (Trust Services Criteria)",
    longName: "SOC 2 Type II (Trust Services)",
    reportSlug: "soc2_type2",
    reportLabel: "SOC 2 Type II Trust Services Report",
  },
  {
    id: "cfw_cert_in_2022",
    name: "CERT-In Directions 2022 & CCMP",
    longName: "CERT-In 2022 (Cyber Incident Directives)",
    reportSlug: "cert_in_2022",
    reportLabel: "CERT-In 2022 Cyber Incident Directive",
  },
  {
    id: "cfw_pci_dss_v4",
    name: "PCI-DSS v4.0 (Cardholder Data Security)",
    longName: "PCI-DSS v4.0 (Payment Card Security)",
    reportSlug: "pci_dss_v4",
    reportLabel: "PCI-DSS v4.0 Assessment Ledger",
  },
  {
    id: "cfw_dpdp_2023",
    name: "DPDP Act 2023 (Digital Personal Data Protection)",
    longName: "DPDP Act 2023 (Data Protection)",
    reportSlug: "dpdp_2023",
    reportLabel: "DPDP Act 2023 Compliance Report",
  },
  {
    id: "cfw_gdpr",
    name: "GDPR (EU General Data Protection Regulation)",
    longName: "EU GDPR (General Data Protection)",
    reportSlug: "gdpr",
    reportLabel: "EU GDPR 2016/679 Privacy Report",
  },
  {
    id: "cfw_nist_800_53_r5",
    name: "NIST SP 800-53 Rev. 5 (U.S. Federal & Defense)",
    longName: "NIST SP 800-53 R5 (Federal & Defense)",
    reportSlug: "nist_800_53_r5",
    reportLabel: "NIST SP 800-53 Rev. 5 Federal Audit",
  },
  {
    id: "cfw_iec_62443",
    name: "IEC 62443 (Industrial Communication Networks & OT/ICS)",
    longName: "IEC 62443 (Industrial & OT/ICS)",
    reportSlug: "iec_62443",
    reportLabel: "IEC 62443 Industrial Cybersecurity",
  },
  {
    id: "cfw_nist_800_82_r3",
    name: "NIST SP 800-82 Rev. 3 (OT/ICS Security Guide)",
    longName: "NIST SP 800-82 R3 (OT Security)",
    reportSlug: "nist_800_82",
    reportLabel: "NIST SP 800-82 Rev. 3 OT Security",
  },
  {
    id: "cfw_nerc_cip",
    name: "NERC CIP (Critical Infrastructure Protection - Power Grid)",
    longName: "NERC CIP (Power Grid Critical Infra)",
    reportSlug: "nerc_cip",
    reportLabel: "NERC CIP Critical Infrastructure",
  },
  {
    id: "cfw_nis2",
    name: "EU NIS 2 Directive (Directive (EU) 2022/2555)",
    longName: "EU NIS 2 Directive (Directive 2022/2555)",
    reportSlug: "nis2",
    reportLabel: "EU NIS 2 Directive Audit Report",
  },
];

// Which of them this installation offers is a backend decision
// (`core.compliance_frameworks`), read from `/compliance/marketplace`. This
// constant is only the fallback for the first render and for a failed request:
// it fails *closed* to the two finished frameworks rather than open to all
// thirteen, because showing a framework the API will refuse is worse than
// showing one fewer for a moment.
const FALLBACK_ACTIVE_FRAMEWORK_IDS = ["cfw_iso27001_2022", "cfw_nist_csf_v2"];

// The Exceptions tab: the pending findings the workspace has already read,
// paged in the browser. Nothing here writes. CcurePagination has no first or
// last page control, which the tab has always offered, so those two buttons
// sit beside it.
function ExceptionsPanel({ exceptions, pagination, loading }) {
  const headingId = useId();
  const {
    page,
    setPage,
    pageSize,
    setPageSize,
    cardRef,
    totalPages,
    displayPage,
    paginatedItems,
  } = pagination;

  const columns = [
    {
      key: "control_id",
      header: "Control ID",
      isRowHeader: true,
      mono: true,
      cell: (exc) => exc.control_id,
    },
    {
      key: "asset_id",
      header: "Asset ID",
      mono: true,
      cell: (exc) => exc.asset_id || "Global",
    },
    {
      key: "reason",
      header: "Waiver Reason",
      cell: (exc) => exc.evidence?.note || exc.reason || "—",
    },
    {
      key: "status",
      header: "Status",
      cell: (exc) => <CcureBadge variant="info">{exc.status}</CcureBadge>,
    },
  ];

  return (
    <section ref={cardRef} className="cwx-panel" aria-labelledby={headingId}>
      <h2 id={headingId} className="cwx-panel__title">
        Exceptions
      </h2>

      <div className="cwx-panel__paging">
        <CcurePagination
          page={page}
          pageSize={pageSize}
          total={exceptions.length}
          onPageChange={setPage}
          onPageSizeChange={(size) => {
            setPageSize(size);
            setPage(1);
          }}
          pageSizeOptions={[10, 25, 50, 100]}
          label="Exceptions pagination"
          itemNoun="waivers"
          disabled={loading}
        />
        <div className="cwx-panel__jump" role="group" aria-label="Jump to page">
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

      <CcureTableStatus
        loading={loading}
        count={exceptions.length}
        noun="waivers"
      />
      <CcureTable
        caption="Pending exceptions and waivers"
        columns={columns}
        rows={paginatedItems}
        rowKey={(exc) => exc.id}
        loading={loading}
        emptyMessage="No pending exceptions or waivers recorded."
      />
    </section>
  );
}

// The dashboard's score colour follows the bands `getScoreClass` already
// decides; this only names them for the stylesheet.
const SCORE_TONE = {
  "radial-score--high": "high",
  "radial-score--medium": "medium",
  "radial-score--low": "low",
};

// NIST CSF 2.0 Functions keep a distinct badge each on the theme breakdown.
const NIST_FUNCTION_BADGE = {
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
function PagingControls({
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

/* The attestation dialog's evidence: its heading, the upload field the dialog
   passes in as children, and the attached files with their removal.

   Removal asks first. A file's Remove turns its row into a question — Delete
   file or Keep file — with focus on Keep file, so a stray Enter backs out
   rather than deleting. The question's buttons ignore a click that is part of
   a double-click, whose second click lands where Remove was; and Delete file is
   busy and disabled while its request is out, as is every other Remove. Keep
   file or Escape returns focus to the file's Remove. After a removal, focus
   goes to that Remove if the file is still listed (the API refused), otherwise
   to the list's heading.

   The question is asked in the row rather than in a second dialog: the shared
   dialog container closes on any Escape that reaches the document, so a nested
   confirmation would take the attestation form down with it. `onRemove` is the
   page's removal handler, unchanged — it sends the DELETE, re-reads the list
   and reports the outcome, and it never rejects. */
function AttestationEvidence({ files, onRemove, children }) {
  const headingId = useId();
  const promptId = useId();
  const [askingId, setAskingId] = useState(null);
  const [removingId, setRemovingId] = useState(null);
  const headingRef = useRef(null);
  const keepRef = useRef(null);
  const removeRefs = useRef(new Map());
  const inFlight = useRef(false);
  const focusAfter = useRef(null);

  useEffect(() => {
    if (askingId !== null) keepRef.current?.focus();
  }, [askingId]);

  useEffect(() => {
    const id = focusAfter.current;
    if (id === null || askingId !== null || removingId !== null) return;
    focusAfter.current = null;
    const remove = removeRefs.current.get(id);
    if (remove && files.some((f) => f.id === id)) remove.focus();
    else headingRef.current?.focus();
  }, [files, askingId, removingId]);

  const backOut = (file) => {
    focusAfter.current = file.id;
    setAskingId(null);
  };
  const onQuestionKeyDown = (event, file) => {
    if (event.key !== "Escape" || inFlight.current) return;
    // Answers the question only; the dialog stays open.
    event.stopPropagation();
    backOut(file);
  };
  const deleteFile = async (event, file) => {
    if (event.detail > 1 || inFlight.current) return;
    inFlight.current = true;
    setRemovingId(file.id);
    try {
      await onRemove(file);
    } finally {
      inFlight.current = false;
      focusAfter.current = file.id;
      setRemovingId(null);
      setAskingId(null);
    }
  };

  return (
    <div className="cwa-section">
      <h3
        id={headingId}
        ref={headingRef}
        tabIndex={-1}
        className="cwa-section__title"
      >
        Attached evidence
      </h3>
      {children}
      {files.length > 0 && (
        <ul className="cwa-evidence" aria-labelledby={headingId}>
          {files.map((f) => (
            <li key={f.id} className="cwa-evidence__item">
              <span className="cwa-evidence__file">
                <span aria-hidden="true">📎</span> {f.filename}{" "}
                <span className="cwa-evidence__size">
                  ({Math.round(f.size_bytes / 1024)} KB)
                </span>
              </span>
              {askingId === f.id ? (
                <div
                  role="group"
                  aria-labelledby={promptId}
                  className="cwa-evidence__question"
                >
                  <span id={promptId} className="cwa-evidence__prompt">
                    Delete {f.filename}? This cannot be undone.
                  </span>
                  <CcureButton
                    variant="danger"
                    size="sm"
                    loading={removingId === f.id}
                    onClick={(e) => deleteFile(e, f)}
                    onKeyDown={(e) => onQuestionKeyDown(e, f)}
                  >
                    Delete file
                  </CcureButton>
                  <CcureButton
                    ref={keepRef}
                    variant="secondary"
                    size="sm"
                    disabled={removingId === f.id}
                    onClick={(e) => {
                      if (e.detail <= 1) backOut(f);
                    }}
                    onKeyDown={(e) => onQuestionKeyDown(e, f)}
                  >
                    Keep file
                  </CcureButton>
                </div>
              ) : (
                <CcureButton
                  ref={(el) => {
                    if (el) removeRefs.current.set(f.id, el);
                    else removeRefs.current.delete(f.id);
                  }}
                  variant="ghost"
                  size="sm"
                  aria-label={`Remove ${f.filename}`}
                  disabled={removingId !== null}
                  onClick={() => setAskingId(f.id)}
                >
                  Remove
                </CcureButton>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function ComplianceWorkspace() {
  const { user } = useAuth();
  const roleName = (user?.role?.name || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_");
  const isComplianceAdmin =
    roleName === "superadmin" || roleName === "org_admin";
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();

  const [activeTab, setActiveTab] = useState("dashboard");
  // The tab list and the panel it controls share one id base; the page owns
  // which tab is chosen.
  const workspaceTabs = useCcureTabs(activeTab, {
    value: activeTab,
    onChange: setActiveTab,
  });
  // The framework whose uninstall is being confirmed, and whether its request
  // is out.
  const [uninstallTarget, setUninstallTarget] = useState(null);
  const [uninstallBusy, setUninstallBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState(null);
  const [marketplace, setMarketplace] = useState([]);
  // Which frameworks this installation offers. Owned by the backend so that
  // enabling one later is a server-side change and every selector in this file
  // follows automatically.
  const [activeFrameworkIds, setActiveFrameworkIds] = useState(
    FALLBACK_ACTIVE_FRAMEWORK_IDS,
  );
  const [policies, setPolicies] = useState([]);
  const [findings, setFindings] = useState([]);
  const [exceptions, setExceptions] = useState([]);
  const [error, setError] = useState(null);

  // Executive Compliance Reports Hub State
  const [reportFw, setReportFw] = useState("soa");
  const [reportFmt, setReportFmt] = useState("pdf");

  // Remediation & Credentials Manager States
  const [credentialsList, setCredentialsList] = useState([]);
  const [approvalsList, setApprovalsList] = useState([]);
  const [newCredName, setNewCredName] = useState("");
  const [newCredUsername, setNewCredUsername] = useState("");
  const [newCredAuthMethod, setNewCredAuthMethod] = useState("password");
  const [newCredPassword, setNewCredPassword] = useState("");
  const [newCredKeyContent, setNewCredKeyContent] = useState("");
  const [newCredPort, setNewCredPort] = useState(22);
  // A credential save or deletion in flight, and the credential whose deletion
  // is being confirmed.
  const [savingCredential, setSavingCredential] = useState(false);
  const [credentialToDelete, setCredentialToDelete] = useState(null);
  const [deletingCredential, setDeletingCredential] = useState(false);

  const [remediationCredSource, setRemediationCredSource] = useState("jit"); // jit | stored
  const [selectedCredId, setSelectedCredId] = useState("");
  const [jitUsername, setJitUsername] = useState("");
  const [jitPort, setJitPort] = useState(22);
  const [jitAuthMethod, setJitAuthMethod] = useState("password");
  const [jitPassword, setJitPassword] = useState("");
  const [jitKeyContent, setJitKeyContent] = useState("");
  const [emergencyBypass, setEmergencyBypass] = useState(false);
  // The Approvals Queue decision being confirmed — { req, kind } with kind
  // "cancel", "approve" or "reject" — and whether its request is out.
  const [queueDecision, setQueueDecision] = useState(null);
  const [queueDecisionBusy, setQueueDecisionBusy] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanPollCount, setScanPollCount] = useState(0); // Active framework filter & gap analysis states
  // Scan progress is read from the run itself rather than guessed from a
  // timer. The previous implementation stopped polling after six ticks
  // regardless of what the run was doing, so a failed run looked identical to
  // a slow one and its error was never shown.
  const [, setScanRunStatus] = useState(null);
  const [activeScanRunId, setActiveScanRunId] = useState(null);
  // Controls register
  const [controlsData, setControlsData] = useState(null);
  const [controlsStatusFilter, setControlsStatusFilter] = useState("all");
  const [controlsSearch, setControlsSearch] = useState("");
  const [controlEvidence, setControlEvidence] = useState([]);
  const [uploadingEvidence, setUploadingEvidence] = useState(false);
  const [selectedFrameworkId, setSelectedFrameworkId] = useState("all");
  const [saqProfileFilter, setSaqProfileFilter] = useState("all");
  const [cdeScopeFilter, setCdeScopeFilter] = useState(false);
  const [sdfScopeFilter, setSdfScopeFilter] = useState("all");
  const [privacyRoleFilter, setPrivacyRoleFilter] = useState("all");
  const [impactLevelFilter, setImpactLevelFilter] = useState("all");
  const [zeroTrustOnly, setZeroTrustOnly] = useState(false);
  const [purdueLevelFilter, setPurdueLevelFilter] = useState("all");
  const [componentTypeFilter, setComponentTypeFilter] = useState("all");
  const [slLevelFilter, setSlLevelFilter] = useState("all");
  const [besImpactLevelFilter, setBesImpactLevelFilter] = useState("all");
  const [standardNumberFilter, setStandardNumberFilter] = useState("all");
  const [nis2EntityTypeFilter, setNis2EntityTypeFilter] = useState("all");
  const [nis2SectorFilter, setNis2SectorFilter] = useState("all");
  const [nis2MemberStateFilter, setNis2MemberStateFilter] = useState("all");
  const [nis2AnnualTurnover, setNis2AnnualTurnover] = useState(50000000);
  const [regionalEntityFilter, setRegionalEntityFilter] = useState("WECC");
  const [gapAnalysis, setGapAnalysis] = useState(null);
  const [gapSourceFramework, setGapSourceFramework] =
    useState("cfw_iso27001_2022");
  const [gapTargetFramework, setGapTargetFramework] = useState("cfw_nis2");
  const [loadingGapAnalysis, setLoadingGapAnalysis] = useState(false);
  const [perFrameworkScores, setPerFrameworkScores] = useState([]);

  // The catalogue entries this installation actually offers, in the order the
  // backend lists them. Every framework selector, the cross-framework score
  // chart and the report menu are built from this, so a framework enabled
  // server-side appears everywhere at once and one that is parked disappears
  // everywhere at once.
  const activeFrameworks = useMemo(
    () =>
      activeFrameworkIds
        .map((id) => FRAMEWORK_CATALOGUE.find((fw) => fw.id === id))
        .filter(Boolean),
    [activeFrameworkIds],
  );

  // Fetched once on mount rather than with the marketplace tab: the framework
  // dropdown is on screen from the first render, on every tab.
  useEffect(() => {
    let cancelled = false;
    axiosInstance
      .get("/compliance/marketplace")
      .then((res) => {
        const ids = res.data?.active_framework_ids;
        if (!cancelled && Array.isArray(ids) && ids.length) {
          setActiveFrameworkIds(ids);
        }
      })
      .catch(() => {
        // Keep the fallback pair. Failing open to all thirteen would offer
        // frameworks the API now refuses with 403.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // A framework that is parked while it is selected — because the backend list
  // changed, or a stale tab — would otherwise keep querying a 403 endpoint.
  useEffect(() => {
    if (
      selectedFrameworkId &&
      selectedFrameworkId !== "all" &&
      !activeFrameworkIds.includes(selectedFrameworkId)
    ) {
      setSelectedFrameworkId("all");
    }
  }, [activeFrameworkIds, selectedFrameworkId]);

  // Same for the report menu: a stale `reportFw` would download a 403.
  useEffect(() => {
    const available = new Set(
      activeFrameworks.filter((fw) => fw.reportSlug).map((fw) => fw.reportSlug),
    );
    available.add("executive");
    if (!available.has(reportFw)) {
      setReportFw(activeFrameworks[0]?.reportSlug || "executive");
    }
  }, [activeFrameworks, reportFw]);

  // Reset scoping filters when switching frameworks
  useEffect(() => {
    setSaqProfileFilter("all");
    setCdeScopeFilter(false);
    setSdfScopeFilter("all");
    setPrivacyRoleFilter("all");
    setImpactLevelFilter("all");
    setZeroTrustOnly(false);
    setPurdueLevelFilter("all");
    setComponentTypeFilter("all");
    setSlLevelFilter("all");
    setBesImpactLevelFilter("all");
    setStandardNumberFilter("all");
    setNis2EntityTypeFilter("all");
    setNis2SectorFilter("all");
    setNis2MemberStateFilter("all");
    if (selectedFrameworkId && selectedFrameworkId !== "all") {
      setGapTargetFramework(selectedFrameworkId);
    }
  }, [selectedFrameworkId]);

  // Modals state
  const [modalOpen, setModalOpen] = useState(false);
  const [modalType, setModalType] = useState(""); // policy | attest | exception | remediate | log_viewer | gap_analysis
  const [selectedControl, setSelectedControl] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Form states
  const [newPolicyName, setNewPolicyName] = useState("");
  const [newPolicyPlatform, setNewPolicyPlatform] = useState("any");
  const [newPolicyRules, setNewPolicyRules] = useState([]);
  const [attestStatus, setAttestStatus] = useState("pass");
  const [attestNote, setAttestNote] = useState("");
  const [attestJustification, setAttestJustification] = useState("");
  const [attestNextReview, setAttestNextReview] = useState("");
  const [exceptionReason, setExceptionReason] = useState("");
  const [exceptionExpiry, setExceptionExpiry] = useState("");
  const [editRuleSeverity, setEditRuleSeverity] = useState("MEDIUM");
  const [editRuleExpected, setEditRuleExpected] = useState("");
  const [expandedPolicyId, setExpandedPolicyId] = useState(null);
  const [policyRules, setPolicyRules] = useState([]);
  const [loadingRules, setLoadingRules] = useState(false);
  const [filterAsset, setFilterAsset] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [filterIg, setFilterIg] = useState("all");
  const [filterSearch, setFilterSearch] = useState("");

  // Derived unique assets of findings for dropdown select
  const uniqueAssets = useMemo(
    () =>
      Array.from(
        new Map(
          findings
            .filter((f) => f.asset_id)
            .map((f) => [
              f.asset_id,
              { id: f.asset_id, ip: f.asset_ip, hostname: f.asset_hostname },
            ]),
        ).values(),
      ),
    [findings],
  );

  // Derived filtered findings list
  const filteredFindings = useMemo(
    () =>
      findings.filter((f) => {
        const matchesAsset =
          filterAsset === "all" || f.asset_id === filterAsset;
        const matchesStatus =
          filterStatus === "all" || f.status === filterStatus;
        const matchesSeverity =
          filterSeverity === "all" ||
          f.severity?.toUpperCase() === filterSeverity.toUpperCase();
        const matchesSearch =
          !filterSearch ||
          [
            f.control_id,
            f.control_title,
            f.rule_name,
            f.asset_ip,
            f.asset_hostname,
            f.status,
            f.severity,
            f.source,
          ].some(
            (v) =>
              typeof v === "string" &&
              v.toLowerCase().includes(filterSearch.toLowerCase()),
          ) ||
          (f.evidence &&
            JSON.stringify(f.evidence)
              .toLowerCase()
              .includes(filterSearch.toLowerCase()));
        const matchesIg =
          selectedFrameworkId !== "cfw_cis_v8_1" ||
          filterIg === "all" ||
          (f.control_tags &&
            Array.isArray(f.control_tags) &&
            f.control_tags.includes(filterIg));
        return (
          matchesAsset &&
          matchesStatus &&
          matchesSeverity &&
          matchesIg &&
          matchesSearch
        );
      }),
    [
      findings,
      filterAsset,
      filterStatus,
      filterSeverity,
      filterIg,
      filterSearch,
      selectedFrameworkId,
    ],
  );

  // Pagination hook instantiations
  const findingsPagination = useClientPagination(filteredFindings, 50);
  const policiesPagination = useClientPagination(policies, 25);
  const exceptionsPagination = useClientPagination(exceptions, 25);
  const credentialsPagination = useClientPagination(credentialsList, 25);
  const approvalsPagination = useClientPagination(approvalsList, 25);

  // The reset effects below depend on the `setPage` setters, not on the
  // pagination objects. `useClientPagination` returns a fresh object literal on
  // every render, so depending on the object would re-run each effect on every
  // render and call setPage(1) forever — the page would be impossible to leave.
  // The setters are `useState` setters and so keep a stable identity, which
  // makes these dependency arrays both complete and inert.
  const { setPage: setFindingsPage } = findingsPagination;
  const { setPage: setPoliciesPage } = policiesPagination;
  const { setPage: setExceptionsPage } = exceptionsPagination;
  const { setPage: setCredentialsPage } = credentialsPagination;
  const { setPage: setApprovalsPage } = approvalsPagination;

  // Reset findings page on search/filter changes
  useEffect(() => {
    setFindingsPage(1);
  }, [
    filterSearch,
    filterAsset,
    filterStatus,
    filterSeverity,
    filterIg,
    setFindingsPage,
  ]);

  // Reset pages on data updates
  useEffect(() => {
    setPoliciesPage(1);
  }, [policies, setPoliciesPage]);
  useEffect(() => {
    setExceptionsPage(1);
  }, [exceptions, setExceptionsPage]);
  useEffect(() => {
    setCredentialsPage(1);
  }, [credentialsList, setCredentialsPage]);
  useEffect(() => {
    setApprovalsPage(1);
  }, [approvalsList, setApprovalsPage]);

  // NOTE: an effect calling `fetchTabData(false)` on [activeTab] used to sit
  // here. The effect further down already lists `activeTab` first in its own
  // dependency array and calls `fetchTabData()`, whose `quiet` parameter
  // defaults to false — so the two were identical, and every tab switch issued
  // the whole tab's request set twice. Removed; the later effect is the one
  // that carries the framework and filter dependencies as well.

  // `fetchTabData` is declared below, reads roughly twenty pieces of filter
  // state, and is rebuilt on every render. The effects that call it must not
  // list it directly: their dependency arrays are evaluated during render,
  // before that `const` is initialised (a temporal dead zone ReferenceError),
  // and even hoisted into a useCallback its dependency set would include the
  // controls search box — so every keystroke would refetch the register, which
  // is exactly what the explicit Enter/`setTimeout` triggers exist to avoid.
  // Holding the newest one in a ref keeps each effect's trigger set unchanged
  // while guaranteeing it calls the current closure rather than a stale one.
  const fetchTabDataRef = useRef(null);

  // Poll the run itself. `scanPollCount` remains only as a safety valve for a
  // run the server never resolves — the authoritative signal is the run's own
  // status, so a failed scan now reports its reason instead of silently
  // ending the spinner.
  useEffect(() => {
    if (!isScanning || !activeScanRunId) return;

    let cancelled = false;
    const poll = async () => {
      try {
        const res = await axiosInstance.get(
          `/compliance/scans/${activeScanRunId}`,
        );
        if (cancelled) return;
        setScanRunStatus(res.data);
        if (res.data.status === "completed") {
          setIsScanning(false);
          setActiveScanRunId(null);
          pushToast("Compliance scan completed.", "success");
          fetchTabDataRef.current?.(true);
        } else if (res.data.status === "failed") {
          setIsScanning(false);
          setActiveScanRunId(null);
          pushToast(
            `Compliance scan failed: ${
              res.data.error_message || "no reason reported"
            }`,
            "error",
          );
        }
      } catch (e) {
        if (!cancelled) console.error("Failed to poll scan run", e);
      }
    };

    poll();
    const interval = setInterval(poll, 4000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [isScanning, activeScanRunId, pushToast]);

  // Safety valve: a run stuck in `queued` or `running` for ten minutes has
  // almost certainly lost its worker. Stop spinning and say so rather than
  // leaving the operator watching an indicator forever.
  useEffect(() => {
    if (isScanning && scanPollCount >= 150) {
      setIsScanning(false);
      setScanPollCount(0);
      setActiveScanRunId(null);
      pushToast(
        "The compliance scan has not reported progress for 10 minutes. Check that a worker is consuming the compliance queue.",
        "error",
      );
    }
  }, [scanPollCount, isScanning, pushToast]);

  useEffect(() => {
    let shouldPoll = false;
    if (activeTab === "findings") {
      shouldPoll =
        isScanning ||
        findings.some(
          (f) =>
            f.status === "pending_reverify" ||
            f.status === "queued" ||
            f.status === "running",
        );
    } else if (activeTab === "approvals") {
      shouldPoll = true;
    } else if (activeTab === "dashboard") {
      shouldPoll = isScanning;
    }

    if (!shouldPoll) return;

    const interval = setInterval(() => {
      if (isScanning) {
        setScanPollCount((prev) => prev + 1);
      }
      fetchTabDataRef.current?.(true);
    }, 5000);

    return () => clearInterval(interval);
  }, [activeTab, findings, approvalsList, isScanning]);

  useEffect(() => {
    fetchTabDataRef.current?.();
  }, [
    activeTab,
    selectedFrameworkId,
    saqProfileFilter,
    cdeScopeFilter,
    sdfScopeFilter,
    privacyRoleFilter,
    impactLevelFilter,
    zeroTrustOnly,
    purdueLevelFilter,
    componentTypeFilter,
    slLevelFilter,
    besImpactLevelFilter,
    standardNumberFilter,
  ]);

  const fetchGapAnalysis = async (
    sourceId = gapSourceFramework,
    targetId = gapTargetFramework,
  ) => {
    setLoadingGapAnalysis(true);
    try {
      const res = await axiosInstance.get(
        `/compliance/gap-analysis?source_framework_id=${sourceId}&target_framework_id=${targetId}`,
      );
      setGapAnalysis(res.data);
      setModalType("gap_analysis");
      setModalOpen(true);
    } catch (e) {
      pushToast(
        "Failed to run gap analysis: " +
          (e.response?.data?.detail || e.message),
        "error",
      );
    } finally {
      setLoadingGapAnalysis(false);
    }
  };

  const fetchTabData = async (quiet = false) => {
    if (!quiet) setLoading(true);
    setError(null);
    let params = [];
    if (selectedFrameworkId && selectedFrameworkId !== "all") {
      params.push(`framework_id=${selectedFrameworkId}`);
    }
    if (selectedFrameworkId === "cfw_pci_dss_v4") {
      if (saqProfileFilter && saqProfileFilter !== "all") {
        params.push(`saq_profile=${saqProfileFilter}`);
      }
      if (cdeScopeFilter) {
        params.push(`cde_scope_only=true`);
      }
    }
    if (selectedFrameworkId === "cfw_dpdp_2023") {
      if (sdfScopeFilter && sdfScopeFilter !== "all") {
        params.push(`sdf_scope=${sdfScopeFilter}`);
      }
    }
    if (selectedFrameworkId === "cfw_gdpr") {
      if (privacyRoleFilter && privacyRoleFilter !== "all") {
        params.push(`privacy_role=${privacyRoleFilter}`);
      }
    }
    if (selectedFrameworkId === "cfw_nist_800_53_r5") {
      if (impactLevelFilter && impactLevelFilter !== "all") {
        params.push(`impact_level=${impactLevelFilter}`);
      }
      if (zeroTrustOnly) {
        params.push(`zero_trust_only=true`);
      }
    }
    if (
      selectedFrameworkId === "cfw_iec_62443" ||
      selectedFrameworkId === "cfw_nist_800_82_r3" ||
      selectedFrameworkId === "cfw_nerc_cip"
    ) {
      if (purdueLevelFilter && purdueLevelFilter !== "all") {
        params.push(`purdue_level=${purdueLevelFilter}`);
      }
      if (componentTypeFilter && componentTypeFilter !== "all") {
        params.push(`component_type=${componentTypeFilter}`);
      }
      if (
        selectedFrameworkId === "cfw_iec_62443" &&
        slLevelFilter &&
        slLevelFilter !== "all"
      ) {
        params.push(`sl_level=${slLevelFilter}`);
      }
      if (selectedFrameworkId === "cfw_nerc_cip") {
        if (besImpactLevelFilter && besImpactLevelFilter !== "all") {
          params.push(`bes_impact_level=${besImpactLevelFilter}`);
        }
        if (standardNumberFilter && standardNumberFilter !== "all") {
          params.push(`standard_number=${standardNumberFilter}`);
        }
      }
    }
    if (selectedFrameworkId === "cfw_nis2") {
      if (nis2EntityTypeFilter && nis2EntityTypeFilter !== "all") {
        params.push(`nis2_entity_type=${nis2EntityTypeFilter}`);
      }
      if (nis2SectorFilter && nis2SectorFilter !== "all") {
        params.push(`nis2_sector=${nis2SectorFilter}`);
      }
      if (nis2MemberStateFilter && nis2MemberStateFilter !== "all") {
        params.push(`nis2_member_state=${nis2MemberStateFilter}`);
      }
    }
    const queryString = params.length > 0 ? `?${params.join("&")}` : "";

    try {
      if (activeTab === "dashboard") {
        const res = await axiosInstance.get(
          `/compliance/summary${queryString}`,
        );
        setSummary(res.data);

        // When All Frameworks is selected, also fetch per-framework scores for
        // the cross-framework comparison bar chart (industry-standard GRC view).
        if (!selectedFrameworkId || selectedFrameworkId === "all") {
          const FW_LIST = activeFrameworks;
          const fwResults = await Promise.allSettled(
            FW_LIST.map((fw) =>
              axiosInstance
                .get(`/compliance/summary?framework_id=${fw.id}`)
                .then((r) => ({
                  id: fw.id,
                  name: fw.name,
                  score: r.data.score_pct ?? 0,
                }))
                .catch(() => ({ id: fw.id, name: fw.name, score: null })),
            ),
          );
          setPerFrameworkScores(
            fwResults
              .filter((r) => r.status === "fulfilled" && r.value.score !== null)
              .map((r) => r.value),
          );
        } else {
          setPerFrameworkScores([]);
        }
      } else if (activeTab === "controls") {
        // The register needs a single framework; "all" has no control set.
        const fwId =
          selectedFrameworkId && selectedFrameworkId !== "all"
            ? selectedFrameworkId
            : "cfw_iso27001_2022";
        const cParams = [];
        if (controlsStatusFilter !== "all")
          cParams.push(`status=${controlsStatusFilter}`);
        if (controlsSearch.trim())
          cParams.push(`search=${encodeURIComponent(controlsSearch.trim())}`);
        const res = await axiosInstance.get(
          `/compliance/frameworks/${fwId}/controls${
            cParams.length ? `?${cParams.join("&")}` : ""
          }`,
        );
        setControlsData(res.data);
      } else if (activeTab === "marketplace") {
        const res = await axiosInstance.get("/compliance/marketplace");
        setMarketplace(res.data.data || []);
      } else if (activeTab === "policies") {
        const res = await axiosInstance.get(
          `/compliance/policies${queryString}`,
        );
        setPolicies(res.data.data || []);
      } else if (activeTab === "findings") {
        const res = await axiosInstance.get(
          `/compliance/findings?limit=10000${params.length > 0 ? `&${params.join("&")}` : ""}`,
        );
        setFindings(res.data.data || []);
      } else if (activeTab === "exceptions") {
        const res = await axiosInstance.get(
          `/compliance/findings?status=pending&limit=10000${params.length > 0 ? `&${params.join("&")}` : ""}`,
        );
        setExceptions(res.data.data || []);
      } else if (activeTab === "credentials") {
        const res = await axiosInstance.get("/compliance/credentials");
        setCredentialsList(res.data || []);
      } else if (activeTab === "approvals") {
        const res = await axiosInstance.get(
          "/compliance/remediations/requests",
        );
        setApprovalsList(res.data.data || []);
      }
    } catch (e) {
      console.error("Failed to load compliance data", e);
      if (!quiet)
        setError(
          e.response?.data?.detail ||
            e.message ||
            "Failed to load compliance data",
        );
    } finally {
      if (!quiet) setLoading(false);
    }
  };

  // Publish the current closure for the effects declared above.
  fetchTabDataRef.current = fetchTabData;

  const handleInstallFramework = async (id) => {
    try {
      await axiosInstance.post(`/compliance/marketplace/${id}/install`);
      pushToast("Framework installed successfully.", "success");
      fetchTabData(true);
    } catch (e) {
      pushToast(
        "Failed to install framework: " +
          (e.response?.data?.detail || e.response?.data?.message || e.message),
        "error",
      );
    }
  };

  const handleUninstallFramework = async (id) => {
    // Asked first by the Marketplace's uninstall dialog.
    try {
      await axiosInstance.post(`/compliance/marketplace/${id}/uninstall`);
      pushToast("Framework uninstalled successfully.", "success");
      fetchTabData(true);
    } catch (e) {
      pushToast(
        "Failed to uninstall framework: " +
          (e.response?.data?.detail || e.response?.data?.message || e.message),
        "error",
      );
    }
  };

  const handleCreatePolicy = async (e) => {
    e.preventDefault();
    try {
      await axiosInstance.post("/compliance/policies", {
        framework_id:
          selectedFrameworkId && selectedFrameworkId !== "all"
            ? selectedFrameworkId
            : "cfw_iso27001_2022",
        name: newPolicyName,
        target_platform: newPolicyPlatform,
        rule_ids: newPolicyRules
          .split(",")
          .map((r) => r.trim())
          .filter(Boolean),
      });
      setModalOpen(false);
      pushToast("Policy baseline created successfully.", "success");
      fetchTabData();
    } catch (e) {
      pushToast(
        "Failed to create policy: " +
          (e.response?.data?.detail || e.response?.data?.message || e.message),
        "error",
      );
    }
  };

  const handleSubmitAttestation = async (e) => {
    e.preventDefault();
    if (!selectedControl) return;

    // ISO/IEC 27001:2022 clause 6.1.3(d) requires a justification for every
    // exclusion. Caught here as well as server-side so the reviewer sees it
    // before losing the form.
    if (attestStatus === "not_applicable" && !attestJustification.trim()) {
      pushToast(
        "Excluding a control requires a justification — it is a mandatory part of the Statement of Applicability.",
        "error",
      );
      return;
    }

    try {
      await axiosInstance.post(
        `/compliance/controls/${selectedControl.id}/attest`,
        {
          status: attestStatus,
          note: attestNote,
          justification: attestJustification || null,
          next_review_at: attestNextReview
            ? new Date(attestNextReview).toISOString()
            : null,
          evidence_file_ids: controlEvidence.map((f) => f.id),
        },
      );
      setModalOpen(false);
      pushToast("Attestation recorded.", "success");
      fetchTabData();
    } catch (e) {
      pushToast(
        "Failed to submit attestation: " +
          (e.response?.data?.detail || e.response?.data?.message || e.message),
        "error",
      );
    }
  };

  const loadControlEvidence = async (controlId) => {
    try {
      const res = await axiosInstance.get(
        `/compliance/controls/${controlId}/evidence`,
      );
      setControlEvidence(res.data.data || []);
    } catch (e) {
      console.error("Failed to load control evidence", e);
      setControlEvidence([]);
    }
  };

  /* Kept in step with _ALLOWED_EVIDENCE_TYPES and _MAX_EVIDENCE_BYTES in
     routers/compliance.py. The server enforces both regardless — and now also
     checks the file's magic bytes, which the browser cannot — but without an
     `accept` the picker offered every file on disk and the only feedback was a
     400 after the whole upload had finished. */
  const EVIDENCE_ACCEPT =
    ".pdf,.png,.jpg,.jpeg,.gif,.txt,.csv,.doc,.docx,.xls,.xlsx";
  const MAX_EVIDENCE_BYTES = 25 * 1024 * 1024;

  const handleUploadEvidence = async (controlId, file) => {
    if (!file) return;

    if (file.size === 0) {
      pushToast(`${file.name} is empty.`, "error");
      return;
    }
    if (file.size > MAX_EVIDENCE_BYTES) {
      pushToast(
        `${file.name} is ${(file.size / (1024 * 1024)).toFixed(1)} MB, above the ` +
          `${MAX_EVIDENCE_BYTES / (1024 * 1024)} MB evidence limit.`,
        "error",
      );
      return;
    }

    setUploadingEvidence(true);
    const form = new FormData();
    form.append("file", file);
    try {
      await axiosInstance.post(
        `/compliance/controls/${controlId}/evidence`,
        form,
        { headers: { "Content-Type": "multipart/form-data" } },
      );
      pushToast(`Attached ${file.name}.`, "success");
      await loadControlEvidence(controlId);
    } catch (e) {
      pushToast(
        "Could not attach evidence: " + (e.response?.data?.detail || e.message),
        "error",
      );
    } finally {
      setUploadingEvidence(false);
    }
  };

  const handleDeleteEvidence = async (fileId, controlId) => {
    try {
      await axiosInstance.delete(`/compliance/evidence/${fileId}`);
      await loadControlEvidence(controlId);
      pushToast("Evidence removed.", "success");
    } catch (e) {
      pushToast(
        "Could not remove evidence: " + (e.response?.data?.detail || e.message),
        "error",
      );
    }
  };

  const openAttestModal = (control) => {
    setSelectedControl({
      id: control.control_id || control.id,
      control_number: control.control_number,
      title: control.title || control.control_title,
      description: control.description || control.control_description,
      evidence_checklist:
        control.evidence_checklist || control.control_evidence_checklist || [],
    });
    setAttestStatus(
      control.status === "not_applicable" ? "not_applicable" : "pass",
    );
    setAttestNote("");
    setAttestJustification(control.justification || "");
    setAttestNextReview("");
    setControlEvidence([]);
    loadControlEvidence(control.control_id || control.id);
    setModalType("attest");
    setModalOpen(true);
  };

  const handleSubmitException = async (e) => {
    e.preventDefault();
    if (!selectedFinding) return;
    try {
      await axiosInstance.post(
        `/compliance/findings/${selectedFinding.id}/exception`,
        {
          reason: exceptionReason,
          expires_at: new Date(exceptionExpiry).toISOString(),
        },
      );
      setModalOpen(false);
      pushToast("Exception waiver request submitted.", "success");
      fetchTabData();
    } catch (e) {
      pushToast(
        "Failed to submit exception waiver request: " +
          (e.response?.data?.detail || e.response?.data?.message || e.message),
        "error",
      );
    }
  };

  const handleOpenEditRule = (finding) => {
    setSelectedFinding(finding);
    setEditRuleSeverity(finding.severity || "MEDIUM");
    setEditRuleExpected(
      finding.check_definition?.expected !== undefined
        ? String(finding.check_definition.expected)
        : "",
    );
    setModalType("edit_rule");
    setModalOpen(true);
  };

  const handleSubmitEditRule = async (e) => {
    e.preventDefault();
    if (!selectedFinding || !selectedFinding.rule_id) return;
    try {
      const origDef = selectedFinding.check_definition || {};
      let expectedParsed = editRuleExpected;
      if (typeof origDef.expected === "number") {
        const parsed = parseInt(editRuleExpected, 10);
        if (!isNaN(parsed)) {
          expectedParsed = parsed;
        }
      }
      const checkDefUpdated = {
        ...origDef,
        expected: expectedParsed,
      };

      await axiosInstance.put(`/compliance/rules/${selectedFinding.rule_id}`, {
        check_definition: checkDefUpdated,
        severity: editRuleSeverity.toLowerCase(),
        severity_weight:
          editRuleSeverity.toUpperCase() === "CRITICAL"
            ? 10
            : editRuleSeverity.toUpperCase() === "HIGH"
              ? 7
              : editRuleSeverity.toUpperCase() === "MEDIUM"
                ? 5
                : editRuleSeverity.toUpperCase() === "LOW"
                  ? 2
                  : 0,
      });
      setModalOpen(false);
      pushToast(
        "Rule updated successfully! Click 'Run Compliance Scan' to apply changes and re-evaluate findings.",
        "success",
      );
      fetchTabData();
    } catch (e) {
      pushToast(
        "Failed to update compliance rule: " +
          (e.response?.data?.detail || e.response?.data?.message || e.message),
        "error",
      );
    }
  };

  const handleTriggerComplianceScan = async () => {
    setLoading(true);
    try {
      // Query fresh active policies directly from backend to avoid stale state
      const policyRes = await axiosInstance.get("/compliance/policies");
      const fetchedPolicies = policyRes.data.data || [];

      if (fetchedPolicies.length === 0) {
        pushToast(
          "Please create a policy baseline first under the 'Policies' tab before running a compliance scan.",
          "info",
        );
        setLoading(false);
        return;
      }

      let triggeredAny = false;
      let failedSome = false;
      let lastError = null;

      const targetPolicies =
        selectedFrameworkId && selectedFrameworkId !== "all"
          ? fetchedPolicies.filter(
              (p) => p.framework_id === selectedFrameworkId,
            )
          : fetchedPolicies;

      const policiesToRun =
        targetPolicies.length > 0 ? targetPolicies : fetchedPolicies;

      // Stagger requests sequentially to prevent DB concurrency locks/deadlocks in Celery workers
      let lastRunId = null;
      for (const policy of policiesToRun) {
        try {
          const runRes = await axiosInstance.post("/compliance/scans", {
            framework_id: policy.framework_id,
            policy_id: policy.id,
            asset_ids: [],
            asset_tags: [],
          });
          // Track the run so progress can be read from the server rather than
          // inferred from a fixed-length timer.
          lastRunId = runRes.data?.scan_run_id || lastRunId;
          triggeredAny = true;
        } catch (err) {
          failedSome = true;
          lastError = err;
          console.error(
            `Failed to trigger compliance scan for policy ${policy.name}`,
            err,
          );
        }
      }

      if (triggeredAny) {
        if (failedSome) {
          pushToast(
            "Compliance scans triggered with partial failures: " +
              (lastError.response?.data?.detail || lastError.message),
            "warning",
          );
        } else {
          pushToast(
            "Compliance scan triggered successfully for all active policies! Re-evaluating rules...",
            "success",
          );
        }
        setIsScanning(true);
        setScanPollCount(0);
        setActiveScanRunId(lastRunId);
        setScanRunStatus(null);
      } else {
        throw lastError || new Error("Failed to trigger scan for any policy.");
      }

      setTimeout(() => {
        fetchTabData();
        setLoading(false);
      }, 1500);
    } catch (e) {
      pushToast(
        "Failed to trigger compliance scan: " +
          (e.response?.data?.detail || e.response?.data?.message || e.message),
        "error",
      );
      setLoading(false);
    }
  };
  const handleTogglePolicy = async (policyId) => {
    if (expandedPolicyId === policyId) {
      setExpandedPolicyId(null);
      setPolicyRules([]);
    } else {
      setExpandedPolicyId(policyId);
      setLoadingRules(true);
      try {
        const res = await axiosInstance.get(
          `/compliance/policies/${policyId}/rules`,
        );
        setPolicyRules(res.data.data || []);
      } catch (e) {
        pushToast(
          "Failed to load policy rules: " +
            (e.response?.data?.detail ||
              e.response?.data?.message ||
              e.message),
          "error",
        );
      } finally {
        setLoadingRules(false);
      }
    }
  };

  useEffect(() => {
    if (modalOpen && (modalType === "remediate" || modalType === "rollback")) {
      axiosInstance
        .get("/compliance/credentials")
        .then((res) => setCredentialsList(res.data || []))
        .catch((err) =>
          console.error("Failed to load credentials for modal", err),
        );
    }
  }, [modalOpen, modalType]);

  const handleRemediate = async (id) => {
    try {
      const payload = {
        action: "apply_script",
        emergency_bypass: emergencyBypass,
      };

      if (remediationCredSource === "stored") {
        if (!selectedCredId) {
          pushToast("Please select a stored credential.", "error");
          return;
        }
        payload.credential_id = selectedCredId;
      } else {
        if (!jitUsername) {
          pushToast("JIT Username is required.", "error");
          return;
        }
        payload.jit_credentials = {
          username: jitUsername,
          port: parseInt(jitPort) || 22,
          auth_method: jitAuthMethod,
          password: jitAuthMethod === "password" ? jitPassword : null,
          key_content: jitAuthMethod === "key" ? jitKeyContent : null,
        };
      }

      const res = await axiosInstance.post(
        `/compliance/findings/${id}/remediate`,
        payload,
      );
      pushToast(res.data.message || "Remediation script processed.", "success");
      setJitUsername("");
      setJitPassword("");
      setJitKeyContent("");
      setEmergencyBypass(false);
      fetchTabData();
    } catch (e) {
      pushToast(
        "Remediation error: " +
          (e.response?.data?.detail || e.response?.data?.message || e.message),
        "error",
      );
    }
  };

  const handleRollback = async (requestId) => {
    try {
      const payload = {
        emergency_bypass: emergencyBypass,
      };

      if (remediationCredSource === "stored") {
        if (!selectedCredId) {
          pushToast("Please select a stored credential.", "error");
          return;
        }
        payload.credential_id = selectedCredId;
      } else {
        if (!jitUsername) {
          pushToast("JIT Username is required.", "error");
          return;
        }
        payload.jit_credentials = {
          username: jitUsername,
          port: parseInt(jitPort) || 22,
          auth_method: jitAuthMethod,
          password: jitAuthMethod === "password" ? jitPassword : null,
          key_content: jitAuthMethod === "key" ? jitKeyContent : null,
        };
      }

      const res = await axiosInstance.post(
        `/compliance/remediations/requests/${requestId}/rollback`,
        payload,
      );
      pushToast(res.data.message || "Rollback script processed.", "success");
      setJitUsername("");
      setJitPassword("");
      setJitKeyContent("");
      setEmergencyBypass(false);
      fetchTabData();
    } catch (e) {
      pushToast(
        "Rollback error: " +
          (e.response?.data?.detail || e.response?.data?.message || e.message),
        "error",
      );
    }
  };

  const handleCopyCommand = (text) => {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard
        .writeText(text)
        .then(() => pushToast("Command copied to clipboard!", "success"))
        .catch(() => fallbackCopy(text));
    } else {
      fallbackCopy(text);
    }
  };

  const fallbackCopy = (text) => {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.top = "0";
    textArea.style.left = "0";
    textArea.style.position = "fixed";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
      document.execCommand("copy");
      pushToast("Command copied to clipboard!", "success");
    } catch (err) {
      pushToast(
        "Failed to copy command. Please select the text and copy manually.",
        "error",
      );
    }
    document.body.removeChild(textArea);
  };

  const handleDownloadReport = async (endpoint, filename) => {
    try {
      setLoading(true);
      const res = await axiosInstance.get(endpoint, {
        responseType: "arraybuffer",
      });
      const mimeType =
        res.headers["content-type"] ||
        (filename.endsWith(".docx")
          ? "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
          : "application/pdf");
      const blob = new Blob([res.data], { type: mimeType });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", filename);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (e) {
      pushToast(
        "Failed to download report: " +
          (e.response?.data?.detail || e.response?.data?.message || e.message),
        "error",
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <AppLayout pageTitle="Policy Compliance Workspace">
      <div className="cwh-page">
        {loading && (
          <CcureProgress
            className="cwh-loading"
            label="Loading compliance data"
            showValue={false}
          />
        )}

        {/* Workspace Header */}
        <div className="cwh-header">
          <div className="cwh-heading">
            <h1 className="cwh-title">Policy Compliance</h1>
            <p className="cwh-subtitle">
              Standard catalogs, baseline verification scans, manual
              attestations, crosswalk gap analysis, and exception waivers.
            </p>
          </div>
          <div className="cwh-toolbar">
            <CcureSelect
              label="Framework"
              fieldClassName="cwh-filter"
              value={selectedFrameworkId}
              onChange={(e) => setSelectedFrameworkId(e.target.value)}
            >
              <option value="all">All Frameworks</option>
              {activeFrameworks.map((fw) => (
                <option key={`fw_sel_${fw.id}`} value={fw.id}>
                  {fw.name}
                </option>
              ))}
            </CcureSelect>
            {(selectedFrameworkId === "cfw_iec_62443" ||
              selectedFrameworkId === "cfw_nist_800_82_r3") && (
              <>
                <CcureSelect
                  label="Purdue Level"
                  fieldClassName="cwh-filter"
                  value={purdueLevelFilter}
                  onChange={(e) => setPurdueLevelFilter(e.target.value)}
                >
                  <option value="all">All Purdue Levels</option>
                  <option value="L0">Level 0 (Physical Process)</option>
                  <option value="L1">
                    Level 1 (Basic Control - PLCs/RTUs)
                  </option>
                  <option value="L2">
                    Level 2 (Area Control - HMIs/SCADA)
                  </option>
                  <option value="L3">
                    Level 3 (Site Operations/Historians)
                  </option>
                  <option value="L3.5">Level 3.5 (Industrial DMZ)</option>
                  {selectedFrameworkId === "cfw_nist_800_82_r3" && (
                    <>
                      <option value="L4">Level 4 (Enterprise Network)</option>
                      <option value="L5">
                        Level 5 (Enterprise Cloud / External)
                      </option>
                    </>
                  )}
                </CcureSelect>

                <CcureSelect
                  label="Component Type"
                  fieldClassName="cwh-filter"
                  value={componentTypeFilter}
                  onChange={(e) => setComponentTypeFilter(e.target.value)}
                >
                  <option value="all">All Component Types</option>
                  {selectedFrameworkId === "cfw_nist_800_82_r3" ? (
                    <>
                      <option value="PLC">
                        PLC (Programmable Logic Controller)
                      </option>
                      <option value="RTU">RTU (Remote Terminal Unit)</option>
                      <option value="SCADA">SCADA (Supervisory Control)</option>
                      <option value="DCS">
                        DCS (Distributed Control System)
                      </option>
                      <option value="SIS">
                        SIS (Safety Instrumented System)
                      </option>
                      <option value="HMI">HMI (Human-Machine Interface)</option>
                      <option value="HISTORIAN">
                        HISTORIAN (Process Historian)
                      </option>
                      <option value="IED">
                        IED (Intelligent Electronic Device)
                      </option>
                    </>
                  ) : (
                    <>
                      <option value="NDD">NDD (Network Device)</option>
                      <option value="EDR">EDR (Embedded Device)</option>
                      <option value="HDR">HDR (Host Device)</option>
                      <option value="SW">SW (Software Application)</option>
                    </>
                  )}
                </CcureSelect>

                {selectedFrameworkId === "cfw_iec_62443" && (
                  <CcureSelect
                    label="Target SL"
                    fieldClassName="cwh-filter"
                    value={slLevelFilter}
                    onChange={(e) => setSlLevelFilter(e.target.value)}
                  >
                    <option value="all">All Security Levels</option>
                    <option value="SL1">
                      SL-1 (Protection against casual violation)
                    </option>
                    <option value="SL2">
                      SL-2 (Protection against simple intentional violation)
                    </option>
                    <option value="SL3">
                      SL-3 (Protection against sophisticated violation)
                    </option>
                    <option value="SL4">
                      SL-4 (Protection against high motivation state actors)
                    </option>
                  </CcureSelect>
                )}
              </>
            )}
            {selectedFrameworkId === "cfw_nerc_cip" && (
              <>
                <CcureSelect
                  label="Regional Entity"
                  fieldClassName="cwh-filter"
                  value={regionalEntityFilter}
                  onChange={(e) => setRegionalEntityFilter(e.target.value)}
                >
                  <option value="WECC">
                    WECC (Western Electricity Coordinating Council)
                  </option>
                  <option value="SERC">SERC Reliability Corporation</option>
                  <option value="TEXAS_RE">
                    Texas RE (Texas Reliability Entity)
                  </option>
                  <option value="RELIABILITY_FIRST">
                    ReliabilityFirst (RF)
                  </option>
                  <option value="MRO">
                    MRO (Midwest Reliability Organization)
                  </option>
                  <option value="NPCC">
                    NPCC (Northeast Power Coordinating Council)
                  </option>
                </CcureSelect>

                <CcureSelect
                  label="BES Impact"
                  fieldClassName="cwh-filter"
                  value={besImpactLevelFilter}
                  onChange={(e) => setBesImpactLevelFilter(e.target.value)}
                >
                  <option value="all">All BES Impact Baselines</option>
                  <option value="High">High Impact BES Cyber Systems</option>
                  <option value="Medium">
                    Medium Impact BES Cyber Systems
                  </option>
                  <option value="Low">Low Impact BES Cyber Systems</option>
                </CcureSelect>

                <CcureSelect
                  label="Standard"
                  fieldClassName="cwh-filter"
                  value={standardNumberFilter}
                  onChange={(e) => setStandardNumberFilter(e.target.value)}
                >
                  <option value="all">
                    All Standards (CIP-002 to CIP-014)
                  </option>
                  <option value="CIP-002">
                    CIP-002 (Asset Categorization)
                  </option>
                  <option value="CIP-003">CIP-003 (Security Management)</option>
                  <option value="CIP-004">
                    CIP-004 (Personnel & Training)
                  </option>
                  <option value="CIP-005">
                    CIP-005 (Electronic Security Perimeters)
                  </option>
                  <option value="CIP-006">CIP-006 (Physical Security)</option>
                  <option value="CIP-007">
                    CIP-007 (System Security Management)
                  </option>
                  <option value="CIP-008">CIP-008 (Incident Reporting)</option>
                  <option value="CIP-009">CIP-009 (Recovery Plans)</option>
                  <option value="CIP-010">
                    CIP-010 (Configuration & Change Mgmt)
                  </option>
                  <option value="CIP-011">
                    CIP-011 (Information Protection)
                  </option>
                  <option value="CIP-012">
                    CIP-012 (Control Center Comms)
                  </option>
                  <option value="CIP-013">
                    CIP-013 (Supply Chain Risk Mgmt)
                  </option>
                  <option value="CIP-014">
                    CIP-014 (Physical Security Substation)
                  </option>
                </CcureSelect>
              </>
            )}
            {selectedFrameworkId === "cfw_nis2" && (
              <>
                <CcureSelect
                  label="Entity Scope"
                  fieldClassName="cwh-filter"
                  value={nis2EntityTypeFilter}
                  onChange={(e) => setNis2EntityTypeFilter(e.target.value)}
                >
                  <option value="all">All Entities</option>
                  <option value="essential">Essential Entity (Art. 3.1)</option>
                  <option value="important">Important Entity (Art. 3.2)</option>
                </CcureSelect>
                <CcureSelect
                  label="Sector"
                  fieldClassName="cwh-filter"
                  value={nis2SectorFilter}
                  onChange={(e) => setNis2SectorFilter(e.target.value)}
                >
                  <option value="all">
                    All 18 Critical Sectors (Annex I & II)
                  </option>
                  <option value="energy">
                    Energy (Electricity, Oil, Gas, Hydrogen, Heating)
                  </option>
                  <option value="transport">
                    Transport (Air, Rail, Water, Road)
                  </option>
                  <option value="banking">Banking & Credit Institutions</option>
                  <option value="financial_market_infra">
                    Financial Market Infrastructures
                  </option>
                  <option value="health">
                    Health & Healthcare (Hospitals, Pharma, Labs)
                  </option>
                  <option value="drinking_water">
                    Drinking Water Supply & Distribution
                  </option>
                  <option value="wastewater">
                    Wastewater Collection & Treatment
                  </option>
                  <option value="digital_infrastructure">
                    Digital Infrastructure (DNS, TLD, Cloud, DC, CDN)
                  </option>
                  <option value="ict">
                    ICT Service Management (B2B Managed Services & MSPs)
                  </option>
                  <option value="public_admin">
                    Public Administration (Central & Regional)
                  </option>
                  <option value="space">
                    Space (Operators of Ground-Based Infrastructure)
                  </option>
                  <option value="postal_courier">
                    Postal & Courier Services
                  </option>
                  <option value="waste_management">Waste Management</option>
                  <option value="chemicals">
                    Chemicals Production, Processing & Distribution
                  </option>
                  <option value="food">
                    Food Production, Processing & Wholesale Distribution
                  </option>
                  <option value="manufacturing">
                    Manufacturing (Medical, Electronics, Machinery)
                  </option>
                  <option value="digital_providers">
                    Digital Providers (Online Marketplaces, Search, Social)
                  </option>
                  <option value="research">Research Organisations</option>
                </CcureSelect>

                <CcureSelect
                  label="Member State"
                  fieldClassName="cwh-filter"
                  value={nis2MemberStateFilter}
                  onChange={(e) => setNis2MemberStateFilter(e.target.value)}
                >
                  <option value="all">
                    All EU (Generic / ENISA Coordinated)
                  </option>
                  <option value="DE">
                    Germany — BSI (Bundesamt für Sicherheit in der
                    Informationstechnik)
                  </option>
                  <option value="FR">
                    France — ANSSI (Agence nationale de la sécurité des SI)
                  </option>
                  <option value="IT">
                    Italy — ACN (Agenzia per la Cybersicurezza Nazionale)
                  </option>
                  <option value="NL">Netherlands — NCSC-NL</option>
                  <option value="BE">
                    Belgium — CCB (Centre for Cybersecurity Belgium)
                  </option>
                  <option value="ES">Spain — INCIBE / CCN-CERT</option>
                  <option value="SE">
                    Sweden — MSB (Myndigheten för samhällsskydd och beredskap)
                  </option>
                  <option value="PL">Poland — NASK / CERT Polska</option>
                  <option value="IE">Ireland — NCSC-IE</option>
                </CcureSelect>
              </>
            )}
            {selectedFrameworkId === "cfw_nist_800_53_r5" && (
              <>
                <CcureSelect
                  label="FedRAMP Baseline"
                  fieldClassName="cwh-filter"
                  value={impactLevelFilter}
                  onChange={(e) => setImpactLevelFilter(e.target.value)}
                >
                  <option value="all">All Impact Baselines</option>
                  <option value="LOW">FedRAMP LOW Impact Baseline</option>
                  <option value="MODERATE">
                    FedRAMP MODERATE Impact Baseline
                  </option>
                  <option value="HIGH">FedRAMP HIGH Impact Baseline</option>
                </CcureSelect>
                <label className="cwh-check">
                  <input
                    type="checkbox"
                    checked={zeroTrustOnly}
                    onChange={(e) => setZeroTrustOnly(e.target.checked)}
                  />
                  Zero Trust Only
                </label>
              </>
            )}
            {selectedFrameworkId === "cfw_dpdp_2023" && (
              <CcureSelect
                label="SDF Scope"
                fieldClassName="cwh-filter"
                value={sdfScopeFilter}
                onChange={(e) => setSdfScopeFilter(e.target.value)}
              >
                <option value="all">All Fiduciaries (General + SDF)</option>
                <option value="sdf_mandatory">
                  Significant Data Fiduciary (SDF Mandatory)
                </option>
                <option value="general_fiduciary">
                  General Data Fiduciary
                </option>
              </CcureSelect>
            )}
            {selectedFrameworkId === "cfw_gdpr" && (
              <CcureSelect
                label="Privacy Role"
                fieldClassName="cwh-filter"
                value={privacyRoleFilter}
                onChange={(e) => setPrivacyRoleFilter(e.target.value)}
              >
                <option value="all">All Roles (Controller & Processor)</option>
                <option value="controller">Data Controller</option>
                <option value="processor">Data Processor</option>
              </CcureSelect>
            )}
            {selectedFrameworkId === "cfw_pci_dss_v4" && (
              <>
                <CcureSelect
                  label="SAQ Profile"
                  fieldClassName="cwh-filter"
                  value={saqProfileFilter}
                  onChange={(e) => setSaqProfileFilter(e.target.value)}
                >
                  <option value="all">All SAQ Profiles (Full ~300)</option>
                  <option value="saq_a">
                    SAQ A (E-Commerce Outsourced ~31)
                  </option>
                  <option value="saq_a_ep">
                    SAQ A-EP (E-Commerce Direct ~190)
                  </option>
                  <option value="saq_b_ip">
                    SAQ B-IP (Standalone IP Terminals)
                  </option>
                  <option value="saq_c">
                    SAQ C (Payment Application Systems)
                  </option>
                  <option value="saq_d_merchant">
                    SAQ D Merchant (All Other Merchants)
                  </option>
                  <option value="saq_d_service_provider">
                    SAQ D Service Provider (Service Providers)
                  </option>
                </CcureSelect>
                <label className="cwh-check">
                  <input
                    type="checkbox"
                    checked={cdeScopeFilter}
                    onChange={(e) => setCdeScopeFilter(e.target.checked)}
                  />
                  CDE Scope Only
                </label>
              </>
            )}
            <CcureSelect
              label="Gap Source"
              fieldClassName="cwh-filter"
              value={gapSourceFramework}
              onChange={(e) => setGapSourceFramework(e.target.value)}
            >
              {activeFrameworks.map((fw) => (
                <option key={`tb_src_${fw.id}`} value={fw.id}>
                  {fw.longName}
                </option>
              ))}
            </CcureSelect>
            <div className="cwh-actions">
              <CcureButton
                variant="secondary"
                onClick={() =>
                  fetchGapAnalysis(
                    gapSourceFramework,
                    selectedFrameworkId === "all"
                      ? gapTargetFramework
                      : selectedFrameworkId,
                  )
                }
                loading={loadingGapAnalysis}
              >
                <span aria-hidden="true">📊</span>{" "}
                {loadingGapAnalysis ? "Calculating..." : "Gap Analysis"}
              </CcureButton>
              <CcureButton
                variant="primary"
                onClick={handleTriggerComplianceScan}
                disabled={loading}
              >
                <span aria-hidden="true">⚡</span> Run Compliance Scan
              </CcureButton>
              {activeTab === "policies" && (
                <CcureButton
                  variant="secondary"
                  onClick={() => {
                    setModalType("policy");
                    setModalOpen(true);
                  }}
                >
                  <span aria-hidden="true">+</span> Create Baseline Policy
                </CcureButton>
              )}
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <CcureTabs
          {...workspaceTabs.listProps}
          label="Compliance workspace sections"
          className="cwh-tabs"
          /* Choosing a tab reads its data, so the arrow keys move focus and
             Enter or Space chooses. */
          activateOnFocus={false}
          tabs={[
            { id: "dashboard", label: "Dashboard" },
            { id: "marketplace", label: "Marketplace" },
            { id: "policies", label: "Policies" },
            // The control register. Attestation used to be reachable only from
            // a findings row whose status happened to be manual_review, so a
            // control that had never been scanned could not be attested at all
            // — for ISO 27001 that put most of Annex A out of reach.
            { id: "controls", label: "Controls" },
            { id: "findings", label: "Findings" },
            { id: "exceptions", label: "Exceptions" },
            { id: "credentials", label: "Credentials Manager" },
            { id: "approvals", label: "Approvals Queue" },
          ]}
        />

        {/* Tab Content */}
        <CcureTabPanel
          {...workspaceTabs.panelProps(activeTab)}
          className="cwh-content"
        >
          {error && (
            <CcureAlert variant="danger" className="cwh-error">
              <strong>Connection or Database Error:</strong> {error}
            </CcureAlert>
          )}

          {activeTab === "dashboard" && summary && (
            <div className="cwv-dashboard">
              <div className="cwv-dashboard__scores">
                <CcureCard title="Overall Score">
                  <p
                    className={`cwv-score cwv-score--${SCORE_TONE[getScoreClass(summary.score_pct)]}`}
                  >
                    {summary.score_pct}%
                  </p>
                </CcureCard>
                <CcureCard title="Risk-Weighted Score">
                  <p
                    className={`cwv-score cwv-score--${SCORE_TONE[getScoreClass(summary.weighted_score_pct)]}`}
                  >
                    {summary.weighted_score_pct}%
                  </p>
                </CcureCard>
                <CcureCard
                  title={
                    !selectedFrameworkId || selectedFrameworkId === "all"
                      ? "All Frameworks"
                      : selectedFrameworkId === "cfw_nist_csf_v2"
                        ? "NIST CSF Controls"
                        : selectedFrameworkId === "cfw_cis_v8_1"
                          ? "CIS Safeguards"
                          : selectedFrameworkId === "cfw_soc2_type2"
                            ? "SOC 2 Criteria"
                            : selectedFrameworkId === "cfw_cert_in_2022"
                              ? "CERT-In Controls"
                              : selectedFrameworkId === "cfw_pci_dss_v4"
                                ? "PCI-DSS v4.0 Requirements"
                                : selectedFrameworkId === "cfw_dpdp_2023"
                                  ? "DPDP Act 2023 Controls"
                                  : selectedFrameworkId === "cfw_gdpr"
                                    ? "EU GDPR Controls"
                                    : selectedFrameworkId ===
                                        "cfw_nist_800_53_r5"
                                      ? "NIST SP 800-53 R5 Controls"
                                      : "ISO 27001 Controls"
                  }
                >
                  <dl className="cwv-kpis">
                    <div className="cwv-kpis__item">
                      <dt>Passed</dt>
                      <dd className="cwv-kpis__value cwv-kpis__value--success">
                        {summary.kpis?.passed || 0}
                      </dd>
                    </div>
                    <div className="cwv-kpis__item">
                      <dt>Failed</dt>
                      <dd className="cwv-kpis__value cwv-kpis__value--danger">
                        {summary.kpis?.failed || 0}
                      </dd>
                    </div>
                    <div className="cwv-kpis__item">
                      <dt>Active Waivers</dt>
                      <dd className="cwv-kpis__value cwv-kpis__value--info">
                        {summary.kpis?.exceptions || 0}
                      </dd>
                    </div>
                  </dl>
                </CcureCard>
              </div>

              {/* Executive Compliance Reports & SoA Hub */}
              <CcureCard
                title="Executive Compliance Reports & SoA Hub"
                subtitle="Generate audit-grade Statement of Applicability (SoA) and regulatory assessment reports in PDF & DOCX formats."
              >
                <div className="cwv-reports">
                  <CcureSelect
                    label="Report"
                    fieldClassName="cwv-reports__menu"
                    value={reportFw}
                    onChange={(e) => setReportFw(e.target.value)}
                  >
                    {activeFrameworks
                      .filter((fw) => fw.reportSlug)
                      .map((fw) => (
                        <option key={`rep_${fw.id}`} value={fw.reportSlug}>
                          {fw.reportLabel}
                        </option>
                      ))}
                    <option value="executive">
                      Multi-Framework Executive Briefing
                    </option>
                  </CcureSelect>

                  <div
                    className="cwv-segmented"
                    role="group"
                    aria-label="Report format"
                  >
                    <CcureButton
                      variant="secondary"
                      size="sm"
                      className="cwv-segmented__option"
                      aria-pressed={reportFmt === "pdf"}
                      onClick={() => setReportFmt("pdf")}
                    >
                      PDF
                    </CcureButton>
                    <CcureButton
                      variant="secondary"
                      size="sm"
                      className="cwv-segmented__option"
                      aria-pressed={reportFmt === "docx"}
                      onClick={() => setReportFmt("docx")}
                    >
                      Word (.docx)
                    </CcureButton>
                  </div>

                  <CcureButton
                    variant="primary"
                    disabled={loading}
                    onClick={() => {
                      let ep = `/compliance/reports/${reportFw}?fmt=${reportFmt}`;
                      let fname = `${reportFw}_report.${reportFmt}`;
                      if (reportFw === "soa") {
                        // A Statement of Applicability covers one standard.
                        // Without this the export emitted the controls of
                        // every installed framework under an ISO 27001 title.
                        const soaFw =
                          selectedFrameworkId && selectedFrameworkId !== "all"
                            ? selectedFrameworkId
                            : "cfw_iso27001_2022";
                        ep += `&framework_id=${soaFw}`;
                        fname = `soa_${soaFw}.${reportFmt}`;
                      }
                      if (reportFw === "pci_dss_v4") {
                        if (saqProfileFilter !== "all")
                          ep += `&saq_profile=${saqProfileFilter}`;
                        if (cdeScopeFilter) ep += "&cde_scope_only=true";
                      } else if (
                        reportFw === "dpdp_2023" &&
                        sdfScopeFilter !== "all"
                      ) {
                        ep += `&sdf_scope=${sdfScopeFilter}`;
                      } else if (
                        reportFw === "gdpr" &&
                        privacyRoleFilter !== "all"
                      ) {
                        ep += `&privacy_role=${privacyRoleFilter}`;
                      } else if (reportFw === "nist_800_53_r5") {
                        if (impactLevelFilter !== "all")
                          ep += `&impact_level=${impactLevelFilter}`;
                        if (zeroTrustOnly) ep += "&zero_trust_only=true";
                      } else if (reportFw === "iec_62443") {
                        if (purdueLevelFilter !== "all")
                          ep += `&purdue_level=${purdueLevelFilter}`;
                        if (componentTypeFilter !== "all")
                          ep += `&component_type=${componentTypeFilter}`;
                        if (slLevelFilter !== "all")
                          ep += `&sl_level=${slLevelFilter}`;
                      } else if (reportFw === "nist_800_82") {
                        if (purdueLevelFilter !== "all")
                          ep += `&purdue_level=${purdueLevelFilter}`;
                        if (componentTypeFilter !== "all")
                          ep += `&component_type=${componentTypeFilter}`;
                      } else if (reportFw === "nerc_cip") {
                        ep += `&regional_entity=${regionalEntityFilter}`;
                        if (besImpactLevelFilter !== "all")
                          ep += `&bes_impact_level=${besImpactLevelFilter}`;
                        if (standardNumberFilter !== "all")
                          ep += `&standard_number=${standardNumberFilter}`;
                        if (purdueLevelFilter !== "all")
                          ep += `&purdue_level=${purdueLevelFilter}`;
                        if (componentTypeFilter !== "all")
                          ep += `&component_type=${componentTypeFilter}`;
                      } else if (reportFw === "nis2") {
                        ep += `&nis2_entity_type=${nis2EntityTypeFilter}`;
                        if (nis2SectorFilter !== "all")
                          ep += `&nis2_sector=${nis2SectorFilter}`;
                      } else if (reportFw === "executive") {
                        ep = "/compliance/reports/executive";
                        fname = "executive_compliance_report.pdf";
                      }
                      handleDownloadReport(ep, fname);
                    }}
                  >
                    {loading ? (
                      "Generating..."
                    ) : (
                      <>
                        <span aria-hidden="true">📥</span> Download{" "}
                        {reportFmt.toUpperCase()} Report
                      </>
                    )}
                  </CcureButton>
                </div>

                <div
                  className="cwv-reports__quick"
                  role="group"
                  aria-label="Quick downloads"
                >
                  <span className="cwv-reports__quick-label" aria-hidden="true">
                    Quick Downloads:
                  </span>
                  <CcureButton
                    variant="ghost"
                    size="sm"
                    onClick={() =>
                      handleDownloadReport(
                        "/compliance/reports/soa?fmt=pdf",
                        "statement_of_applicability.pdf",
                      )
                    }
                  >
                    SoA PDF
                  </CcureButton>
                  <CcureButton
                    variant="ghost"
                    size="sm"
                    onClick={() =>
                      handleDownloadReport(
                        "/compliance/reports/soa?fmt=docx",
                        "statement_of_applicability.docx",
                      )
                    }
                  >
                    SoA Word
                  </CcureButton>
                  <CcureButton
                    variant="ghost"
                    size="sm"
                    onClick={() =>
                      handleDownloadReport(
                        "/compliance/reports/executive",
                        "executive_compliance_report.pdf",
                      )
                    }
                  >
                    Executive Brief (PDF)
                  </CcureButton>
                  <CcureButton
                    variant="ghost"
                    size="sm"
                    onClick={() =>
                      handleDownloadReport(
                        "/compliance/reports/nist_csf?fmt=pdf",
                        "nist_csf_v2_report.pdf",
                      )
                    }
                  >
                    NIST CSF PDF
                  </CcureButton>
                </div>
              </CcureCard>

              <CcureCard
                title={
                  !selectedFrameworkId || selectedFrameworkId === "all"
                    ? "Compliance Score by Framework"
                    : selectedFrameworkId === "cfw_nist_csf_v2"
                      ? "NIST CSF 2.0 Core Functions Breakdown"
                      : selectedFrameworkId === "cfw_cis_v8_1"
                        ? "CIS Controls v8.1 Safeguards Breakdown"
                        : selectedFrameworkId === "cfw_soc2_type2"
                          ? "SOC 2 Trust Services Criteria Breakdown"
                          : selectedFrameworkId === "cfw_cert_in_2022"
                            ? "CERT-In Directions & CCMP Themes Breakdown"
                            : selectedFrameworkId === "cfw_pci_dss_v4"
                              ? "PCI-DSS v4.0 12 Principal Requirements Breakdown"
                              : selectedFrameworkId === "cfw_dpdp_2023"
                                ? "DPDP Act 2023 6 Key Governance Principles Breakdown"
                                : selectedFrameworkId === "cfw_gdpr"
                                  ? "EU GDPR 7 Core Privacy Principles Breakdown"
                                  : selectedFrameworkId === "cfw_nist_800_53_r5"
                                    ? "NIST SP 800-53 R5 20 Control Families Breakdown"
                                    : selectedFrameworkId === "cfw_nis2"
                                      ? "EU NIS 2 Directive 10 Risk Management Domains (Art. 21.2)"
                                      : "ISO 27001 Themes Quadrant Breakdown"
                }
              >
                {/* ── All Frameworks: per-framework comparison chart ── */}
                {!selectedFrameworkId || selectedFrameworkId === "all" ? (
                  perFrameworkScores.length === 0 ? (
                    <p className="cwv-muted">
                      No enabled frameworks with scored controls yet. Install
                      and run a compliance scan to populate scores.
                    </p>
                  ) : (
                    <ul className="cwv-bars">
                      {perFrameworkScores.map((fw) => (
                        <li key={fw.id} className="cwv-bars__item">
                          <CcureProgress
                            label={fw.name}
                            value={fw.score}
                            showValue={false}
                          />
                          <span className="cwv-bars__value">{fw.score}%</span>
                        </li>
                      ))}
                    </ul>
                  )
                ) : (
                  /* ── Single Framework: per-theme breakdown ── */
                  <div className="cwv-breakdown">
                    {selectedFrameworkId === "cfw_nis2" && (
                      <CcureCard
                        headingLevel={3}
                        title={
                          <>
                            <span aria-hidden="true">💶</span> EU NIS 2
                            Regulatory Fine Risk Exposure Calculator (Article 32
                            & 34)
                          </>
                        }
                        actions={
                          <CcureBadge
                            variant={
                              nis2EntityTypeFilter === "important"
                                ? "warning"
                                : "info"
                            }
                          >
                            {nis2EntityTypeFilter === "important"
                              ? "Important Entity (Art. 3.2)"
                              : "Essential Entity (Art. 3.1)"}
                          </CcureBadge>
                        }
                      >
                        <div className="cwv-nis2">
                          <CcureInput
                            type="number"
                            label="Annual Global Turnover (EUR €)"
                            value={nis2AnnualTurnover}
                            onChange={(e) =>
                              setNis2AnnualTurnover(Number(e.target.value))
                            }
                          />
                          <div className="cwv-nis2__fact">
                            <p className="cwv-nis2__label">
                              Statutory Fine Ceiling:
                            </p>
                            <p className="cwv-nis2__ceiling">
                              €
                              {nis2EntityTypeFilter === "important"
                                ? Math.max(
                                    7000000,
                                    nis2AnnualTurnover * 0.014,
                                  ).toLocaleString()
                                : Math.max(
                                    10000000,
                                    nis2AnnualTurnover * 0.02,
                                  ).toLocaleString()}
                            </p>
                          </div>
                          <div className="cwv-nis2__fact">
                            <p className="cwv-nis2__label">
                              Executive Board Liability Exposure:
                            </p>
                            <p className="cwv-nis2__liability">
                              Article 20 Personal Liability & Operational Ban
                            </p>
                          </div>
                        </div>
                      </CcureCard>
                    )}

                    {selectedFrameworkId === "cfw_nis2" && (
                      <CcureCard
                        headingLevel={3}
                        title={
                          <>
                            <span aria-hidden="true">🚨</span> Article 23 CSIRT
                            Mandatory Incident Reporting SLA Readiness Tracker
                          </>
                        }
                        actions={
                          <CcureBadge variant="success">
                            Directive SLA Enforced
                          </CcureBadge>
                        }
                      >
                        <ul className="cwv-sla">
                          <li className="cwv-sla__item">
                            <p className="cwv-sla__deadline cwv-sla__deadline--danger">
                              <span aria-hidden="true">⚡</span> Early Warning
                              (≤ 24 Hours)
                            </p>
                            <p className="cwv-sla__text">
                              Submit initial CSIRT warning indicating whether
                              incident is suspect/unlawful or has cross-border
                              impact.
                            </p>
                          </li>
                          <li className="cwv-sla__item">
                            <p className="cwv-sla__deadline cwv-sla__deadline--warning">
                              <span aria-hidden="true">⏰</span> Incident
                              Notification (≤ 72 Hours)
                            </p>
                            <p className="cwv-sla__text">
                              Submit formal incident notification updating
                              initial assessment, severity metrics, and
                              technical IoC indicators.
                            </p>
                          </li>
                          <li className="cwv-sla__item">
                            <p className="cwv-sla__deadline cwv-sla__deadline--info">
                              <span aria-hidden="true">📋</span> Final Report (≤
                              1 Month)
                            </p>
                            <p className="cwv-sla__text">
                              Provide complete root-cause analysis, forensic
                              evidence, technical remediations applied, and
                              cross-border impact.
                            </p>
                          </li>
                        </ul>
                      </CcureCard>
                    )}
                    <ul className="cwv-bars">
                      {Object.entries(summary.quadrant_scores || {}).map(
                        ([key, val]) => (
                          <li key={key} className="cwv-bars__item">
                            <CcureProgress
                              label={
                                ["GV", "ID", "PR", "DE", "RS", "RC"].includes(
                                  key,
                                ) ? (
                                  <CcureBadge
                                    variant={NIST_FUNCTION_BADGE[key]}
                                    mono
                                  >
                                    {THEME_LABELS[key] || key}
                                  </CcureBadge>
                                ) : (
                                  THEME_LABELS[key] || key
                                )
                              }
                              value={val}
                              showValue={false}
                            />
                            <span className="cwv-bars__value">{val}%</span>
                          </li>
                        ),
                      )}
                    </ul>
                  </div>
                )}
              </CcureCard>
            </div>
          )}

          {activeTab === "marketplace" && (
            <section
              className="cww-marketplace"
              aria-labelledby="cww-marketplace-title"
            >
              <h2 id="cww-marketplace-title" className="cww-title">
                Framework Marketplace
              </h2>
              <div className="cww-marketplace__grid">
                {marketplace.map((fw) => (
                  <CcureCard
                    key={fw.framework_id}
                    headingLevel={3}
                    title={fw.name}
                    className="cww-framework"
                  >
                    <span className="cww-framework__icon" aria-hidden="true">
                      🔒
                    </span>
                    <p className="cww-framework__meta">
                      Code: {fw.code} | Version: {fw.version}
                    </p>
                    <p className="cww-framework__reqs">
                      Total Requirements: {fw.controls_count}
                    </p>
                    <div className="cww-framework__actions">
                      {fw.is_installed ? (
                        <>
                          <CcureBadge variant="success" dot>
                            Installed
                          </CcureBadge>
                          <CcureButton
                            variant="danger"
                            size="sm"
                            disabled={!isComplianceAdmin}
                            title={
                              !isComplianceAdmin
                                ? "Requires Org Admin or Superadmin permission"
                                : ""
                            }
                            aria-describedby={
                              !isComplianceAdmin
                                ? `cww-permission-${fw.framework_id}`
                                : undefined
                            }
                            aria-haspopup="dialog"
                            onClick={() =>
                              isComplianceAdmin && setUninstallTarget(fw)
                            }
                          >
                            Uninstall
                          </CcureButton>
                        </>
                      ) : (
                        <CcureButton
                          variant="primary"
                          size="sm"
                          disabled={!isComplianceAdmin}
                          title={
                            !isComplianceAdmin
                              ? "Requires Org Admin or Superadmin permission"
                              : ""
                          }
                          aria-describedby={
                            !isComplianceAdmin
                              ? `cww-permission-${fw.framework_id}`
                              : undefined
                          }
                          onClick={() =>
                            isComplianceAdmin &&
                            handleInstallFramework(fw.framework_id)
                          }
                        >
                          Install
                        </CcureButton>
                      )}
                    </div>
                    {!isComplianceAdmin && (
                      <p
                        id={`cww-permission-${fw.framework_id}`}
                        className="cww-framework__hint"
                      >
                        Requires Org Admin or Superadmin permission
                      </p>
                    )}
                  </CcureCard>
                ))}
              </div>
              {/* Uninstalling hides a framework's policies, findings, approvals
                  and dashboard averages, so it asks first: Cancel takes focus,
                  Escape backs out, and the question cannot be answered twice
                  while its request is out. */}
              <CcureConfirmDialog
                open={uninstallTarget !== null}
                title="Uninstall framework"
                subtitle={uninstallTarget?.name}
                warning="Are you sure you want to uninstall this compliance framework? This will hide its policies, findings, approvals, and dashboard averages."
                confirmLabel="Uninstall"
                cancelLabel="Cancel"
                tone="danger"
                busy={uninstallBusy}
                onCancel={() => setUninstallTarget(null)}
                onConfirm={async () => {
                  if (uninstallBusy || !uninstallTarget) return;
                  setUninstallBusy(true);
                  await handleUninstallFramework(uninstallTarget.framework_id);
                  setUninstallBusy(false);
                  setUninstallTarget(null);
                }}
              />
            </section>
          )}

          {activeTab === "policies" && (
            <section
              ref={policiesPagination.cardRef}
              className="cwv-policies cwv-view"
              aria-labelledby="cwv-policies-title"
            >
              <h2 id="cwv-policies-title" className="cwv-view__title">
                Policies
              </h2>
              <PagingControls
                pagination={policiesPagination}
                total={policies.length}
                loading={loading}
                label="Policies pagination"
                itemNoun="policies"
                sizes={[10, 25, 50, 100]}
              />
              <CcureTableStatus
                loading={loading && policies.length === 0}
                count={policies.length}
                noun="policies"
              />
              <CcureTable
                caption="Baseline policies"
                loading={loading && policies.length === 0}
                columns={[
                  { key: "name", header: "Baseline Name" },
                  { key: "platform", header: "Platform" },
                  { key: "version", header: "Version" },
                  { key: "rules", header: "Rules Count" },
                  { key: "status", header: "Status" },
                ]}
              >
                {policies.length === 0 && !loading && (
                  <tr>
                    <td colSpan={5} className="cwv-table-message">
                      No baseline policies defined. Click &quot;Create Baseline
                      Policy&quot; to define one.
                    </td>
                  </tr>
                )}
                {policiesPagination.paginatedItems.map((p) => (
                  <React.Fragment key={p.id}>
                    <tr>
                      <th scope="row" className="cwv-policy__name">
                        <CcureButton
                          variant="ghost"
                          size="sm"
                          className="cwv-disclosure"
                          aria-expanded={expandedPolicyId === p.id}
                          aria-controls={
                            expandedPolicyId === p.id
                              ? `cwv-policy-rules-${p.id}`
                              : undefined
                          }
                          onClick={() => handleTogglePolicy(p.id)}
                        >
                          <span
                            className="cwv-disclosure__chevron"
                            aria-hidden="true"
                          >
                            {expandedPolicyId === p.id ? "▼" : "▶"}
                          </span>
                          {p.name}
                        </CcureButton>
                      </th>
                      <td>
                        <CcureBadge>{p.target_platform}</CcureBadge>
                      </td>
                      <td className="cwv-mono">v{p.version_number}</td>
                      <td className="cwv-strong">{p.rules_count}</td>
                      <td>
                        <CcureBadge variant="success">{p.status}</CcureBadge>
                      </td>
                    </tr>
                    {expandedPolicyId === p.id && (
                      <tr>
                        <td
                          colSpan={5}
                          id={`cwv-policy-rules-${p.id}`}
                          className="cwv-policy__rules"
                        >
                          <h3 className="cwv-policy__rules-title">
                            <span aria-hidden="true">📋</span> Policy Rules &
                            Check Parameters
                          </h3>
                          {loadingRules ? (
                            <p className="cwv-muted" role="status">
                              Loading policy rules...
                            </p>
                          ) : policyRules.length === 0 ? (
                            <p className="cwv-muted">
                              No rules linked to this policy.
                            </p>
                          ) : (
                            <div className="cwv-policy__rules-scroll">
                              <CcureTable
                                caption={`Rules in ${p.name}`}
                                stickyHeader
                                rows={policyRules}
                                rowKey={(r) => r.id}
                                columns={[
                                  {
                                    key: "control",
                                    header: "Control ID",
                                    isRowHeader: true,
                                    mono: true,
                                    nowrap: true,
                                    cell: (r) =>
                                      (() => {
                                        // `String.replace` with a
                                        // string pattern swaps only the
                                        // first match, so a NIST CSF id
                                        // like PR_AA_05 rendered as
                                        // "PR.AA_05". The framework
                                        // prefix is stripped generically
                                        // and every separator replaced.
                                        const rawNum =
                                          r.control_number ||
                                          (r.control_id
                                            ? r.control_id
                                                .replace(
                                                  /^cct_[a-z0-9]+(?:_[a-z0-9]+)*?_(?=\d|[a-z]{2}_)/i,
                                                  "",
                                                )
                                                .replace(/_/g, ".")
                                            : "");
                                        if (
                                          rawNum.startsWith("A.") ||
                                          rawNum.startsWith("GV.") ||
                                          rawNum.startsWith("ID.") ||
                                          rawNum.startsWith("PR.") ||
                                          rawNum.startsWith("DE.") ||
                                          rawNum.startsWith("RS.") ||
                                          rawNum.startsWith("RC.")
                                        ) {
                                          return rawNum;
                                        }
                                        if (/^\d+\.\d+/.test(rawNum)) {
                                          return `A.${rawNum}`;
                                        }
                                        return rawNum || "N/A";
                                      })(),
                                  },
                                  {
                                    key: "title",
                                    header: "Rule & Control Title",
                                    cell: (r) => (
                                      <>
                                        <span className="cwv-cell__title">
                                          {r.control_title}
                                        </span>
                                        <span className="cwv-cell__detail">
                                          Rule Code:{" "}
                                          <span className="cwv-mono">
                                            {r.rule_name}
                                          </span>
                                        </span>
                                      </>
                                    ),
                                  },
                                  {
                                    key: "severity",
                                    header: "Severity",
                                    cell: (r) => (
                                      <CcureSeverityBadge
                                        severity={r.severity || "medium"}
                                      />
                                    ),
                                  },
                                  {
                                    key: "logic",
                                    header: "Checking Logic",
                                    cell: (r) =>
                                      r.evidence_source === "manual" ? (
                                        <CcureBadge>Manual Review</CcureBadge>
                                      ) : (
                                        <>
                                          <CcureBadge variant="primary">
                                            {r.evidence_source}
                                          </CcureBadge>
                                          {r.check_definition && (
                                            <code className="cwv-code">
                                              {r.check_definition.key}{" "}
                                              {r.check_definition.operator}{" "}
                                              {r.check_definition.expected}
                                            </code>
                                          )}
                                        </>
                                      ),
                                  },
                                  {
                                    key: "actions",
                                    header: "Actions",
                                    cell: (r) => (
                                      <CcureButton
                                        variant="ghost"
                                        size="sm"
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          handleOpenEditRule({
                                            rule_id: r.id,
                                            rule_name: r.rule_name,
                                            severity: r.severity,
                                            check_definition:
                                              r.check_definition,
                                            control_title: r.control_title,
                                            evidence: {},
                                          });
                                        }}
                                      >
                                        Configure
                                      </CcureButton>
                                    ),
                                  },
                                ]}
                              />
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </CcureTable>
            </section>
          )}

          {activeTab === "controls" && (
            <CcureCard
              title="Control Register"
              subtitle="Every control of the selected framework, with its current verdict and attestation state."
              className="cwv-controls"
            >
              <div className="cwv-filters cwv-controls__filters">
                <CcureInput
                  type="search"
                  label="Search controls"
                  placeholder="Search controls…"
                  value={controlsSearch}
                  onChange={(e) => setControlsSearch(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") fetchTabData();
                  }}
                />
                <CcureSelect
                  label="Status"
                  value={controlsStatusFilter}
                  onChange={(e) => {
                    setControlsStatusFilter(e.target.value);
                    setTimeout(fetchTabData, 0);
                  }}
                >
                  <option value="all">All statuses</option>
                  <option value="pass">Implemented</option>
                  <option value="fail">Not implemented</option>
                  <option value="manual_review">Awaiting review</option>
                  <option value="not_assessed">Not assessed</option>
                  <option value="not_applicable">Excluded</option>
                  <option value="exception">Exception</option>
                </CcureSelect>
              </div>

              {/* Readiness, not a single percentage. "62% compliant" cannot
                  distinguish a framework nobody has assessed from one that was
                  assessed and failed. */}
              {controlsData?.summary && (
                <dl className="cwv-tiles">
                  {[
                    ["Implemented", controlsData.summary.passed, "success"],
                    ["Not implemented", controlsData.summary.failed, "danger"],
                    [
                      "Awaiting review",
                      controlsData.summary.awaiting_review,
                      "warning",
                    ],
                    [
                      "Not assessed",
                      controlsData.summary.not_assessed,
                      "neutral",
                    ],
                    [
                      "Excluded",
                      controlsData.summary.not_applicable,
                      "neutral",
                    ],
                  ].map(([label, value, tone]) => (
                    <div key={label} className="cwv-tiles__item">
                      <dt className="cwv-tiles__label">{label}</dt>
                      <dd
                        className={`cwv-tiles__value cwv-tiles__value--${tone}`}
                      >
                        {value}
                      </dd>
                    </div>
                  ))}
                </dl>
              )}

              <CcureTableStatus
                loading={loading && (controlsData?.data || []).length === 0}
                count={(controlsData?.data || []).length}
                noun="controls"
              />
              <CcureTable
                caption="Control register"
                rows={controlsData?.data || []}
                rowKey={(c) => c.control_id}
                loading={loading && (controlsData?.data || []).length === 0}
                emptyMessage="No controls match the current filter."
                columns={[
                  {
                    key: "ref",
                    header: "Ref",
                    isRowHeader: true,
                    mono: true,
                    nowrap: true,
                    cell: (c) => c.control_number,
                  },
                  {
                    key: "control",
                    header: "Control",
                    cell: (c) => (
                      <>
                        <span className="cwv-cell__title">{c.title}</span>
                        {c.description && (
                          <span className="cwv-cell__detail cwv-cell__detail--measure">
                            {c.description}
                          </span>
                        )}
                      </>
                    ),
                  },
                  {
                    key: "theme",
                    header: "Theme",
                    cell: (c) => (
                      <>
                        {/* NIST CSF is Function ▸ Category ▸ Subcategory.
                            Printing the bare `theme` code showed "GV"
                            against all 31 Govern rows and named neither
                            level. The API derives both from the
                            Subcategory id and returns null for frameworks
                            that are not CSF, so this falls back cleanly. */}
                        <span className="cwv-cell__title">
                          {c.function || THEME_LABELS[c.theme] || c.theme}
                        </span>
                        {c.category && (
                          <span className="cwv-cell__detail">
                            {c.category} · {c.category_name}
                          </span>
                        )}
                      </>
                    ),
                  },
                  {
                    key: "mode",
                    header: "Mode",
                    cell: (c) => (
                      <span className="cwv-caps">{c.scannability}</span>
                    ),
                  },
                  {
                    key: "status",
                    header: "Status",
                    cell: (c) => (
                      <CcureBadge
                        variant={
                          c.status === "pass"
                            ? "success"
                            : c.status === "fail"
                              ? "danger"
                              : c.status === "not_applicable"
                                ? "neutral"
                                : "warning"
                        }
                      >
                        {c.status === "not_assessed"
                          ? "NOT ASSESSED"
                          : c.status.replace(/_/g, " ").toUpperCase()}
                      </CcureBadge>
                    ),
                  },
                  {
                    key: "evidence",
                    header: "Evidence",
                    nowrap: true,
                    cell: (c) =>
                      c.evidence_file_count > 0 ? (
                        <>
                          <span aria-hidden="true">📎</span>{" "}
                          {c.evidence_file_count}
                        </>
                      ) : (
                        "—"
                      ),
                  },
                  {
                    key: "reviewed",
                    header: "Reviewed",
                    nowrap: true,
                    cell: (c) =>
                      c.reviewed_at
                        ? new Date(c.reviewed_at).toLocaleDateString()
                        : "—",
                  },
                  {
                    key: "actions",
                    header: "Actions",
                    cell: (c) => (
                      <CcureButton
                        variant="primary"
                        size="sm"
                        onClick={() => openAttestModal(c)}
                      >
                        Attest
                      </CcureButton>
                    ),
                  },
                ]}
              />
            </CcureCard>
          )}

          {activeTab === "findings" && (
            <section
              ref={findingsPagination.cardRef}
              className="cwv-findings cwv-view"
              aria-labelledby="cwv-findings-title"
            >
              <h2 id="cwv-findings-title" className="cwv-view__title">
                Findings
              </h2>

              {/* Filter controls bar */}
              <div className="cwv-filters cwv-filters--bar">
                <CcureInput
                  label="Search findings"
                  placeholder="Search by Control, Rule..."
                  value={filterSearch}
                  onChange={(e) => setFilterSearch(e.target.value)}
                />
                <CcureSelect
                  label="Asset"
                  value={filterAsset}
                  onChange={(e) => setFilterAsset(e.target.value)}
                >
                  <option value="all">All Assets</option>
                  {uniqueAssets.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.hostname && a.hostname !== "Unknown"
                        ? `${a.hostname} (${a.ip})`
                        : a.ip || a.id}
                    </option>
                  ))}
                </CcureSelect>
                <CcureSelect
                  label="Status"
                  value={filterStatus}
                  onChange={(e) => setFilterStatus(e.target.value)}
                >
                  <option value="all">All Statuses</option>
                  <option value="pass">Pass</option>
                  <option value="fail">Fail</option>
                  <option value="manual_review">Manual Review</option>
                </CcureSelect>
                <CcureSelect
                  label="Severity"
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                >
                  <option value="all">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </CcureSelect>

                {selectedFrameworkId === "cfw_cis_v8_1" && (
                  <CcureSelect
                    label="Implementation group"
                    value={filterIg}
                    onChange={(e) => setFilterIg(e.target.value)}
                  >
                    <option value="all">All Groups (IG1-3)</option>
                    <option value="ig1">IG1 (Cyber Hygiene)</option>
                    <option value="ig2">IG2 (Enterprise)</option>
                    <option value="ig3">IG3 (Advanced)</option>
                  </CcureSelect>
                )}

                {(filterSearch ||
                  filterAsset !== "all" ||
                  filterStatus !== "all" ||
                  filterSeverity !== "all") && (
                  <CcureButton
                    variant="ghost"
                    size="sm"
                    className="cwv-filters__clear"
                    onClick={() => {
                      setFilterSearch("");
                      setFilterAsset("all");
                      setFilterStatus("all");
                      setFilterSeverity("all");
                      findingsPagination.setPage(1);
                    }}
                  >
                    Clear Filters
                  </CcureButton>
                )}
              </div>

              <PagingControls
                pagination={findingsPagination}
                total={filteredFindings.length}
                loading={loading}
                label="Findings pagination"
                itemNoun={
                  findings.length !== filteredFindings.length
                    ? `findings (filtered from ${findings.length} total)`
                    : "findings"
                }
                sizes={[25, 50, 100, 250]}
              />

              <CcureTableStatus
                loading={loading}
                count={filteredFindings.length}
                noun="findings"
              />
              <CcureTable
                caption="Compliance findings"
                rows={findingsPagination.paginatedItems}
                rowKey={(f) => f.id}
                loading={loading}
                loadingRows={5}
                emptyMessage="No matching compliance findings discovered."
                columns={[
                  {
                    key: "control",
                    header: "Control ID",
                    isRowHeader: true,
                    mono: true,
                    nowrap: true,
                    cell: (f) => f.control_id,
                  },
                  {
                    key: "title",
                    header: "Rule / Control Title",
                    cell: (f) => (
                      <>
                        <span className="cwv-cell__title">
                          {f.control_title}
                        </span>
                        {f.rule_name && (
                          <span className="cwv-cell__detail">
                            Rule Code:{" "}
                            <span className="cwv-mono">{f.rule_name}</span>
                          </span>
                        )}
                      </>
                    ),
                  },
                  {
                    key: "severity",
                    header: "Severity",
                    cell: (f) => (
                      <CcureSeverityBadge severity={f.severity || "medium"} />
                    ),
                  },
                  {
                    key: "asset",
                    header: "Asset Name / IP",
                    cell: (f) =>
                      f.asset_hostname && f.asset_hostname !== "Unknown" ? (
                        <>
                          <span className="cwv-asset">
                            <span className="cwv-cell__title">
                              {f.asset_hostname}
                            </span>
                            {f.asset_reboot_pending && (
                              <CcureBadge
                                variant="warning"
                                title="System reboot is required to apply configuration changes."
                              >
                                Reboot Required
                              </CcureBadge>
                            )}
                          </span>
                          <span className="cwv-cell__detail cwv-mono">
                            {f.asset_ip}
                          </span>
                        </>
                      ) : f.asset_ip ? (
                        <span className="cwv-asset">
                          <span className="cwv-mono">{f.asset_ip}</span>
                          {f.asset_reboot_pending && (
                            <CcureBadge
                              variant="warning"
                              title="System reboot is required to apply configuration changes."
                            >
                              Reboot Required
                            </CcureBadge>
                          )}
                        </span>
                      ) : (
                        "Global"
                      ),
                  },
                  {
                    key: "source",
                    header: "Scan Mode",
                    cell: (f) => <CcureBadge>{f.source}</CcureBadge>,
                  },
                  {
                    key: "status",
                    header: "Status",
                    cell: (f) => (
                      <>
                        <CcureBadge
                          variant={
                            f.status === "pass"
                              ? "success"
                              : f.status === "fail"
                                ? "danger"
                                : "info"
                          }
                        >
                          {f.status}
                        </CcureBadge>
                        {/* The engine already writes a plain-English
                            reason into the evidence payload whenever
                            a control could not be assessed. It was
                            never displayed, so `manual_review`
                            reached the operator with no indication of
                            what to do about it. */}
                        {f.status === "manual_review" && f.status_reason && (
                          <span className="cwv-cell__detail cwv-cell__detail--reason">
                            {f.status_reason}
                          </span>
                        )}
                      </>
                    ),
                  },
                  {
                    key: "actions",
                    header: "Actions",
                    cell: (f) => (
                      <span className="cwv-actions">
                        {f.status === "fail" && (
                          <>
                            <CcureButton
                              variant="primary"
                              size="sm"
                              onClick={() => {
                                setSelectedFinding(f);
                                setModalType("remediate");
                                setModalOpen(true);
                              }}
                            >
                              Remediate
                            </CcureButton>
                            <CcureButton
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setSelectedFinding(f);
                                setModalType("exception");
                                setModalOpen(true);
                              }}
                            >
                              Waiver
                            </CcureButton>
                          </>
                        )}
                        {f.status === "manual_review" && (
                          <CcureButton
                            variant="primary"
                            size="sm"
                            onClick={() => openAttestModal(f)}
                          >
                            Verify
                          </CcureButton>
                        )}
                        {f.rule_id && (
                          <CcureButton
                            variant="ghost"
                            size="sm"
                            onClick={() => handleOpenEditRule(f)}
                          >
                            Edit Rule
                          </CcureButton>
                        )}
                      </span>
                    ),
                  },
                ]}
              />
            </section>
          )}

          {activeTab === "exceptions" && (
            <ExceptionsPanel
              exceptions={exceptions}
              pagination={exceptionsPagination}
              loading={loading}
            />
          )}

          {activeTab === "credentials" && (
            <div className="cwc-layout">
              <div ref={credentialsPagination.cardRef} className="cwc-list">
                <CcureCard title="Saved Credentials" bodyFlush>
                  <div className="cwc-paging">
                    <PagingControls
                      pagination={credentialsPagination}
                      total={credentialsList.length}
                      loading={loading}
                      label="Credentials pagination"
                      itemNoun="credentials"
                      sizes={[10, 25, 50, 100]}
                    />
                  </div>
                  <CcureTableStatus
                    loading={loading}
                    count={credentialsList.length}
                    noun="credentials"
                  />
                  <CcureTable
                    caption="Saved credentials"
                    columns={[
                      {
                        key: "name",
                        header: "Nickname",
                        isRowHeader: true,
                        className: "cwc-name",
                        cell: (c) => c.name,
                      },
                      {
                        key: "username",
                        header: "Username",
                        cell: (c) => c.username,
                      },
                      {
                        key: "port",
                        header: "Port",
                        mono: true,
                        cell: (c) => c.port,
                      },
                      {
                        key: "auth_method",
                        header: "Auth Method",
                        nowrap: true,
                        cell: (c) => (
                          <CcureBadge
                            variant={
                              c.auth_method === "key" ? "primary" : "neutral"
                            }
                          >
                            {c.auth_method === "key" ? "SSH Key" : "Password"}
                          </CcureBadge>
                        ),
                      },
                      ...(isComplianceAdmin
                        ? [
                            {
                              key: "actions",
                              header: "Actions",
                              cell: (c) => (
                                <CcureButton
                                  variant="ghost"
                                  size="sm"
                                  className="cwc-delete"
                                  aria-label={`Delete ${c.name}`}
                                  aria-haspopup="dialog"
                                  onClick={() => setCredentialToDelete(c)}
                                >
                                  Delete
                                </CcureButton>
                              ),
                            },
                          ]
                        : []),
                    ]}
                    rows={credentialsPagination.paginatedItems}
                    rowKey={(c) => c.id}
                    loading={loading}
                    emptyMessage="No saved credentials registered."
                  />
                </CcureCard>
              </div>

              {isComplianceAdmin && (
                <CcureCard title="Register Credential" className="cwc-register">
                  <form
                    className="cwc-form"
                    onSubmit={async (e) => {
                      e.preventDefault();
                      if (savingCredential) return;
                      setSavingCredential(true);
                      try {
                        await axiosInstance.post("/compliance/credentials", {
                          name: newCredName,
                          username: newCredUsername,
                          auth_method: newCredAuthMethod,
                          password:
                            newCredAuthMethod === "password"
                              ? newCredPassword
                              : null,
                          key_content:
                            newCredAuthMethod === "key"
                              ? newCredKeyContent
                              : null,
                          port: parseInt(newCredPort) || 22,
                        });
                        pushToast("Credential saved successfully.", "success");
                        setNewCredName("");
                        setNewCredUsername("");
                        setNewCredPassword("");
                        setNewCredKeyContent("");
                        setNewCredPort(22);
                        fetchTabData();
                      } catch (err) {
                        pushToast(
                          "Failed to save credential: " +
                            (err.response?.data?.detail ||
                              err.response?.data?.message ||
                              err.message),
                          "error",
                        );
                      } finally {
                        setSavingCredential(false);
                      }
                    }}
                  >
                    <CcureInput
                      label="Name / Nickname"
                      value={newCredName}
                      onChange={(e) => setNewCredName(e.target.value)}
                      placeholder="e.g. Production Webservers"
                      required
                    />

                    <CcureInput
                      label="Username"
                      value={newCredUsername}
                      onChange={(e) => setNewCredUsername(e.target.value)}
                      placeholder="e.g. root"
                      required
                    />

                    <CcureInput
                      type="number"
                      label="Port"
                      value={newCredPort}
                      onChange={(e) => setNewCredPort(e.target.value)}
                      required
                    />

                    <CcureSelect
                      label="Authentication Method"
                      value={newCredAuthMethod}
                      onChange={(e) => setNewCredAuthMethod(e.target.value)}
                    >
                      <option value="password">Password</option>
                      <option value="key">Private SSH Key</option>
                    </CcureSelect>

                    {/* The secret is typed here and sent once, in the request
                        body. `new-password` stops the browser offering the
                        signed-in user's own password into a field that stores
                        someone else's, and keeps a revealed field out of form
                        history. */}
                    {newCredAuthMethod === "password" ? (
                      <CcurePasswordField
                        label="Password"
                        value={newCredPassword}
                        onChange={(e) => setNewCredPassword(e.target.value)}
                        placeholder="••••••••"
                        hint="Stored encrypted. The saved list never shows it."
                        autoComplete="new-password"
                        required
                      />
                    ) : (
                      <CcureField
                        id="cwc-key"
                        label="Private Key Content"
                        hint="Stored encrypted. The saved list never shows it."
                        required
                      >
                        <textarea
                          id="cwc-key"
                          className="cc-field__control cwc-key"
                          value={newCredKeyContent}
                          onChange={(e) => setNewCredKeyContent(e.target.value)}
                          placeholder="-----BEGIN OpenSSH PRIVATE KEY-----..."
                          aria-describedby="cwc-key-hint"
                          required
                        />
                      </CcureField>
                    )}

                    <CcureButton
                      type="submit"
                      variant="primary"
                      block
                      loading={savingCredential}
                      className="cwc-submit"
                    >
                      Save Target Credential
                    </CcureButton>
                  </form>
                </CcureCard>
              )}

              {/* Deleting asks in a design-system dialog rather than the
                  browser's confirm, which focuses OK: here Cancel takes focus,
                  Escape cancels, and the dialog is busy and cannot be dismissed
                  or confirmed again while the DELETE is out. */}
              <CcureConfirmDialog
                open={credentialToDelete !== null}
                title="Delete credential"
                subtitle="The stored password or key is removed with it. This cannot be undone."
                warning={
                  credentialToDelete
                    ? `Are you sure you want to delete ${credentialToDelete.name}?`
                    : null
                }
                confirmLabel="Delete credential"
                busy={deletingCredential}
                onCancel={() => setCredentialToDelete(null)}
                onConfirm={async () => {
                  if (deletingCredential || !credentialToDelete) return;
                  const c = credentialToDelete;
                  setDeletingCredential(true);
                  try {
                    await axiosInstance.delete(
                      `/compliance/credentials/${c.id}`,
                    );
                    pushToast("Credential deleted successfully.", "success");
                    fetchTabData();
                  } catch (e) {
                    pushToast(
                      "Delete failed: " +
                        (e.response?.data?.detail ||
                          e.response?.data?.message ||
                          e.message),
                      "error",
                    );
                  } finally {
                    setDeletingCredential(false);
                    setCredentialToDelete(null);
                  }
                }}
              />
            </div>
          )}

          {activeTab === "approvals" && (
            <section
              ref={approvalsPagination.cardRef}
              className="cwe-queue"
              aria-labelledby="cwe-queue-title"
            >
              <h2 id="cwe-queue-title" className="cwe-queue__title">
                Remediation Approvals Queue
              </h2>
              <PagingControls
                pagination={approvalsPagination}
                total={approvalsList.length}
                loading={loading}
                label="Approvals pagination"
                itemNoun="tickets"
                sizes={[10, 25, 50, 100]}
              />
              <CcureTableStatus
                loading={loading}
                count={approvalsList.length}
                noun="tickets"
              />
              <CcureTable
                caption="Remediation approval requests"
                columns={[
                  {
                    key: "id",
                    header: "Ticket ID",
                    isRowHeader: true,
                    mono: true,
                    className: "cwe-ticket",
                    cell: (req) => req.id,
                  },
                  {
                    key: "control",
                    header: "Control & Asset",
                    cell: (req) => (
                      <span className="cwe-cell">
                        <span className="cwe-cell__control">
                          {req.id.startsWith("crrq_rollback_") && (
                            <CcureBadge
                              variant="warning"
                              className="cwe-rollback"
                            >
                              Rollback
                            </CcureBadge>
                          )}
                          {req.control_id} - {req.control_title}
                        </span>
                        <span className="cwe-cell__detail">
                          Target Host:{" "}
                          <span className="cwe-mono">{req.asset_ip}</span>
                        </span>
                      </span>
                    ),
                  },
                  {
                    key: "fix_command",
                    header: "Fix Command",
                    cell: (req) => (
                      <code className="cwe-command">{req.fix_command}</code>
                    ),
                  },
                  {
                    key: "requested_by",
                    header: "Requested By",
                    cell: (req) => req.requested_by,
                  },
                  {
                    key: "status",
                    header: "Status",
                    nowrap: true,
                    // The status is the badge's word; the colour repeats it.
                    cell: (req) => (
                      <CcureBadge
                        className="cwe-status"
                        variant={
                          req.status === "pending_approval"
                            ? "warning"
                            : req.status === "executed"
                              ? "success"
                              : req.status === "approved"
                                ? "info"
                                : req.status === "failed"
                                  ? "danger"
                                  : "neutral"
                        }
                      >
                        {req.status.replace("_", " ")}
                      </CcureBadge>
                    ),
                  },
                  {
                    key: "actions",
                    header: "Actions",
                    cell: (req) => (
                      <span className="cwe-actions">
                        {req.status === "pending_approval" &&
                          (req.requested_by === user?.id ? (
                            <CcureButton
                              variant="ghost"
                              size="sm"
                              className="cwe-danger-text"
                              aria-haspopup="dialog"
                              aria-label={`${
                                req.id.startsWith("crrq_rollback_")
                                  ? "Cancel Rollback"
                                  : "Cancel Request"
                              } ${req.id}`}
                              onClick={() =>
                                setQueueDecision({ req, kind: "cancel" })
                              }
                            >
                              {req.id.startsWith("crrq_rollback_")
                                ? "Cancel Rollback"
                                : "Cancel Request"}
                            </CcureButton>
                          ) : isComplianceAdmin ? (
                            <>
                              <CcureButton
                                variant="primary"
                                size="sm"
                                aria-haspopup="dialog"
                                aria-label={`Approve ${req.id}`}
                                onClick={() =>
                                  setQueueDecision({ req, kind: "approve" })
                                }
                              >
                                Approve
                              </CcureButton>
                              <CcureButton
                                variant="ghost"
                                size="sm"
                                className="cwe-danger-text"
                                aria-haspopup="dialog"
                                aria-label={`Reject ${req.id}`}
                                onClick={() =>
                                  setQueueDecision({ req, kind: "reject" })
                                }
                              >
                                Reject
                              </CcureButton>
                            </>
                          ) : (
                            <span className="cwe-pending">
                              Pending approval
                            </span>
                          ))}
                        {(req.status === "executed" ||
                          req.status === "failed") &&
                          req.execution_log && (
                            <>
                              <CcureButton
                                variant="ghost"
                                size="sm"
                                aria-haspopup="dialog"
                                aria-label={`View Logs for ${req.id}`}
                                onClick={() => {
                                  setSelectedFinding({
                                    control_id: req.control_id,
                                    control_title: req.control_title,
                                    asset_ip: req.asset_ip,
                                    execution_log: req.execution_log,
                                  });
                                  setModalType("log_viewer");
                                  setModalOpen(true);
                                }}
                              >
                                View Logs
                              </CcureButton>
                              {req.status === "executed" &&
                                !req.id.startsWith("crrq_rollback_") &&
                                (() => {
                                  const hasActiveRollback = approvalsList.some(
                                    (r) =>
                                      r.finding_id === req.finding_id &&
                                      r.id.startsWith("crrq_rollback_") &&
                                      (r.status === "pending_approval" ||
                                        r.status === "approved"),
                                  );
                                  if (!hasActiveRollback) {
                                    return (
                                      <CcureButton
                                        variant="ghost"
                                        size="sm"
                                        className="cwe-danger-text"
                                        aria-haspopup="dialog"
                                        aria-label={`Rollback ${req.id}`}
                                        onClick={() => {
                                          setSelectedFinding({
                                            id: req.id,
                                            control_id: req.control_id,
                                            control_title: req.control_title,
                                            asset_ip: req.asset_ip,
                                            fix_command: req.fix_command,
                                            recommendation_text:
                                              "Reverse the security control and reopen the port on the target machine.",
                                          });
                                          setModalType("rollback");
                                          setModalOpen(true);
                                        }}
                                      >
                                        Rollback
                                      </CcureButton>
                                    );
                                  }
                                  return null;
                                })()}
                            </>
                          )}
                      </span>
                    ),
                  },
                ]}
                rows={approvalsPagination.paginatedItems}
                rowKey={(req) => req.id}
                loading={loading}
                emptyMessage="No approval tickets in this status."
              />

              {/* Cancelling, approving and rejecting each ask first. Approving
                  queues a script to run on a customer host with the
                  credentials the request was made with, and rejecting or
                  cancelling clears those credentials, so none of them is a
                  single click: Go back takes focus, Escape goes back, and the
                  question is busy and cannot be answered twice while its
                  request is out. */}
              <CcureConfirmDialog
                open={queueDecision !== null}
                title={
                  queueDecision
                    ? `${
                        queueDecision.kind === "cancel"
                          ? "Cancel"
                          : queueDecision.kind === "approve"
                            ? "Approve"
                            : "Reject"
                      } ${
                        queueDecision.req.id.startsWith("crrq_rollback_")
                          ? "rollback"
                          : "remediation"
                      } request`
                    : ""
                }
                subtitle={
                  queueDecision
                    ? `${queueDecision.req.id} — ${queueDecision.req.control_id} on ${queueDecision.req.asset_ip}`
                    : undefined
                }
                warning={
                  !queueDecision
                    ? null
                    : queueDecision.kind === "cancel"
                      ? `Are you sure you want to cancel this ${
                          queueDecision.req.id.startsWith("crrq_rollback_")
                            ? "rollback"
                            : "remediation"
                        } request?`
                      : queueDecision.kind === "approve"
                        ? `Approving queues this ${
                            queueDecision.req.id.startsWith("crrq_rollback_")
                              ? "rollback"
                              : "remediation"
                          } to run on ${queueDecision.req.asset_ip} with the credentials it was requested with.`
                        : `Rejecting closes this ${
                            queueDecision.req.id.startsWith("crrq_rollback_")
                              ? "rollback"
                              : "remediation"
                          } request and clears the credentials held with it; it will not run.`
                }
                confirmLabel={
                  !queueDecision
                    ? "Confirm"
                    : queueDecision.kind === "cancel"
                      ? queueDecision.req.id.startsWith("crrq_rollback_")
                        ? "Cancel Rollback"
                        : "Cancel Request"
                      : queueDecision.kind === "approve"
                        ? "Approve"
                        : "Reject"
                }
                cancelLabel="Go back"
                tone={queueDecision?.kind === "approve" ? "info" : "danger"}
                busy={queueDecisionBusy}
                onCancel={() => setQueueDecision(null)}
                onConfirm={async () => {
                  if (queueDecisionBusy || !queueDecision) return;
                  const { req, kind } = queueDecision;
                  setQueueDecisionBusy(true);
                  if (kind === "cancel") {
                    const label = req.id.startsWith("crrq_rollback_")
                      ? "rollback"
                      : "remediation";
                    try {
                      await axiosInstance.post(
                        `/compliance/remediations/requests/${req.id}/cancel`,
                      );
                      pushToast(
                        `${label.charAt(0).toUpperCase() + label.slice(1)} request cancelled successfully.`,
                        "success",
                      );
                      fetchTabData();
                    } catch (e) {
                      pushToast(
                        "Cancellation failed: " +
                          (e.response?.data?.detail ||
                            e.response?.data?.message ||
                            e.message),
                        "error",
                      );
                    }
                  } else if (kind === "approve") {
                    try {
                      await axiosInstance.post(
                        `/compliance/remediations/requests/${req.id}/approve`,
                        { status: "approved" },
                      );
                      const label = req.id.startsWith("crrq_rollback_")
                        ? "Rollback"
                        : "Remediation request";
                      pushToast(`${label} approved and queued.`, "success");
                      fetchTabData();
                    } catch (e) {
                      pushToast(
                        "Approval failed: " +
                          (e.response?.data?.detail ||
                            e.response?.data?.message ||
                            e.message),
                        "error",
                      );
                    }
                  } else {
                    try {
                      await axiosInstance.post(
                        `/compliance/remediations/requests/${req.id}/approve`,
                        { status: "rejected" },
                      );
                      const label = req.id.startsWith("crrq_rollback_")
                        ? "Rollback"
                        : "Remediation request";
                      pushToast(`${label} rejected.`, "success");
                      fetchTabData();
                    } catch (e) {
                      pushToast(
                        "Rejection failed: " +
                          (e.response?.data?.detail ||
                            e.response?.data?.message ||
                            e.message),
                        "error",
                      );
                    }
                  }
                  setQueueDecisionBusy(false);
                  setQueueDecision(null);
                }}
              />
            </section>
          )}
        </CcureTabPanel>
      </div>

      {/* Dynamic Popups Modals */}
      <CcureModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        closeLabel="Close"
        title={
          {
            policy: "Create Policy Baseline",
            attest: "Control Manual Attestation",
            exception: "Request Exception Waiver",
            edit_rule: "Configure Rule Parameters",
            // Named for the person reading them rather than by their type.
            remediate: "Remediate Finding",
            rollback: "Roll Back Remediation",
            log_viewer: "Execution Log",
            gap_analysis: "Gap Analysis",
          }[modalType]
        }
        aria-label="Compliance dialog"
        size={
          modalType === "policy" ||
          modalType === "attest" ||
          modalType === "exception" ||
          modalType === "edit_rule"
            ? "md"
            : "lg"
        }
        className={
          modalType === "policy" ||
          modalType === "attest" ||
          modalType === "exception" ||
          modalType === "edit_rule"
            ? ""
            : "cwh-modal--wide"
        }
      >
        {modalType === "policy" && (
          <form onSubmit={handleCreatePolicy} className="cww-form">
            <CcureInput
              label="Policy Name"
              value={newPolicyName}
              onChange={(e) => setNewPolicyName(e.target.value)}
              required
            />
            <CcureSelect
              label="Target Platform"
              value={newPolicyPlatform}
              onChange={(e) => setNewPolicyPlatform(e.target.value)}
            >
              <option value="any">Any</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
            </CcureSelect>
            <CcureInput
              label="Rule IDs"
              hint="Comma separated."
              value={newPolicyRules}
              onChange={(e) => setNewPolicyRules(e.target.value)}
              placeholder="crl_net_tls_001_v1, crl_auth_mfa_001_v1"
              required
            />
            <CcureButton
              type="submit"
              variant="primary"
              block
              className="cww-form__submit"
            >
              Publish Baseline
            </CcureButton>
          </form>
        )}

        {modalType === "attest" && (
          <form onSubmit={handleSubmitAttestation} className="cww-form">
            {selectedControl?.control_number && (
              <div className="cwa-control">
                <p className="cwa-control__title">
                  {selectedControl.control_number} — {selectedControl.title}
                </p>
                {selectedControl.description && (
                  <p className="cwa-control__description">
                    {selectedControl.description}
                  </p>
                )}
              </div>
            )}

            <CcureSelect
              label="Applicability & Status"
              value={attestStatus}
              onChange={(e) => setAttestStatus(e.target.value)}
            >
              <option value="pass">Applicable — implemented</option>
              <option value="fail">Applicable — not implemented</option>
              {/* Declaring a control inapplicable, with justification, is the
                  central act of an ISO 27001 Statement of Applicability. The
                  API has always accepted it; this menu only offered pass and
                  fail, so the decision had no route through the product. */}
              <option value="not_applicable">
                Not applicable — excluded from scope
              </option>
            </CcureSelect>

            <CcureField
              id="cwa-justification"
              label={
                attestStatus === "not_applicable"
                  ? "Justification for exclusion"
                  : "Justification for inclusion"
              }
              required={attestStatus === "not_applicable"}
              hint={
                attestStatus === "not_applicable"
                  ? "ISO/IEC 27001:2022 clause 6.1.3(d) requires every exclusion to carry a documented justification."
                  : undefined
              }
            >
              <textarea
                id="cwa-justification"
                className="cc-field__control cww-form__textarea"
                value={attestJustification}
                onChange={(e) => setAttestJustification(e.target.value)}
                required={attestStatus === "not_applicable"}
                aria-describedby={
                  attestStatus === "not_applicable"
                    ? "cwa-justification-hint"
                    : undefined
                }
                placeholder={
                  attestStatus === "not_applicable"
                    ? "Why this control does not apply to the organization's ISMS scope."
                    : "Why this control is applicable — defaults to the control objective if left blank."
                }
              />
            </CcureField>

            {selectedControl?.evidence_checklist &&
              selectedControl.evidence_checklist.length > 0 && (
                <div className="cwa-section">
                  <h3 id="cwa-checklist-title" className="cwa-section__title">
                    Audit evidence expected for this control
                  </h3>
                  <ul
                    className="cwa-checklist"
                    aria-labelledby="cwa-checklist-title"
                  >
                    {selectedControl.evidence_checklist.map((item, idx) => (
                      <li key={idx}>{item}</li>
                    ))}
                  </ul>
                </div>
              )}

            {/* Real evidence attachment. `evidence_file_ids` has been on the
                finding model since the first migration with no upload path
                behind it, and the checklist above used to be pre-ticked
                checkboxes that were never read or submitted. */}
            <AttestationEvidence
              files={controlEvidence}
              onRemove={(f) => handleDeleteEvidence(f.id, selectedControl.id)}
            >
              <CcureField
                id="cwa-evidence-file"
                label="Add evidence file"
                hint={`Accepted: ${EVIDENCE_ACCEPT.replace(/\./g, "")
                  .toUpperCase()
                  .split(",")
                  .join(
                    ", ",
                  )}. Up to ${MAX_EVIDENCE_BYTES / (1024 * 1024)} MB.`}
              >
                <input
                  id="cwa-evidence-file"
                  type="file"
                  className="cwa-file"
                  accept={EVIDENCE_ACCEPT}
                  disabled={uploadingEvidence}
                  aria-describedby="cwa-evidence-file-hint"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) handleUploadEvidence(selectedControl.id, f);
                    e.target.value = "";
                  }}
                />
              </CcureField>
              {uploadingEvidence && <CcureLoader inline label="Uploading…" />}
            </AttestationEvidence>

            <CcureInput
              type="date"
              label="Next review date"
              value={attestNextReview}
              onChange={(e) => setAttestNextReview(e.target.value)}
            />

            <CcureField id="cwa-note" label="Reviewer note" required>
              <textarea
                id="cwa-note"
                className="cc-field__control cww-form__textarea"
                value={attestNote}
                onChange={(e) => setAttestNote(e.target.value)}
                required
              />
            </CcureField>
            <CcureButton
              type="submit"
              variant="primary"
              block
              className="cww-form__submit"
            >
              Save Attestation
            </CcureButton>
          </form>
        )}

        {modalType === "exception" && (
          <form onSubmit={handleSubmitException} className="cww-form">
            <CcureField
              id="cww-waiver-reason"
              label="Reason for Exception Waiver"
              required
            >
              <textarea
                id="cww-waiver-reason"
                className="cc-field__control cww-form__textarea"
                value={exceptionReason}
                onChange={(e) => setExceptionReason(e.target.value)}
                required
              />
            </CcureField>
            <CcureInput
              type="date"
              label="Expiry Date"
              value={exceptionExpiry}
              onChange={(e) => setExceptionExpiry(e.target.value)}
              required
            />
            <CcureButton
              type="submit"
              variant="primary"
              block
              className="cww-form__submit"
            >
              Request Waiver
            </CcureButton>
          </form>
        )}

        {modalType === "edit_rule" && selectedFinding && (
          <form onSubmit={handleSubmitEditRule} className="cww-form">
            <div className="cww-form__intro">
              <h3 className="cww-form__heading">
                Editing Rule:{" "}
                <span className="cww-mono">{selectedFinding.rule_name}</span>
              </h3>
              <p className="cww-form__context">
                Control: {selectedFinding.control_title}
              </p>
            </div>

            <CcureSelect
              label="Severity Level"
              value={editRuleSeverity}
              onChange={(e) => setEditRuleSeverity(e.target.value)}
            >
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </CcureSelect>

            <CcureInput
              label="Expected Rule Value"
              value={editRuleExpected}
              onChange={(e) => setEditRuleExpected(e.target.value)}
              hint={
                <>
                  Current evidence value is:{" "}
                  <code className="cww-code">
                    {JSON.stringify(selectedFinding.evidence)}
                  </code>
                </>
              }
              required
            />

            <CcureButton
              type="submit"
              variant="primary"
              block
              className="cww-form__submit"
            >
              Save Rule Configuration
            </CcureButton>
          </form>
        )}

        {modalType === "gap_analysis" && gapAnalysis && (
          <div className="cwg-gap">
            {/* Choosing a framework sends nothing: the pair is read only when
                Recalculate Gap is pressed, and the result below stays on
                screen until the new one arrives. */}
            <div className="cwg-pickers">
              <CcureSelect
                label="Source Baseline"
                fieldClassName="cwg-pickers__field"
                value={gapSourceFramework}
                onChange={(e) => setGapSourceFramework(e.target.value)}
              >
                {activeFrameworks.map((fw) => (
                  <option key={`modal_src_${fw.id}`} value={fw.id}>
                    {fw.longName}
                  </option>
                ))}
              </CcureSelect>

              <span className="cwg-pickers__arrow" aria-hidden="true">
                ➔
              </span>

              <CcureSelect
                label="Target Mandate"
                fieldClassName="cwg-pickers__field"
                value={gapTargetFramework}
                onChange={(e) => setGapTargetFramework(e.target.value)}
              >
                {activeFrameworks.map((fw) => (
                  <option key={`modal_tgt_${fw.id}`} value={fw.id}>
                    {fw.longName}
                  </option>
                ))}
              </CcureSelect>

              <CcureButton
                variant="primary"
                className="cwg-pickers__action"
                onClick={() =>
                  fetchGapAnalysis(gapSourceFramework, gapTargetFramework)
                }
                loading={loadingGapAnalysis}
              >
                <span aria-hidden="true">🔄</span>{" "}
                {loadingGapAnalysis ? "Calculating..." : "Recalculate Gap"}
              </CcureButton>
            </div>

            <div className="cwg-summary">
              <div className="cwg-summary__head">
                <div className="cwg-summary__intro">
                  {/* The arrow is drawn, and "to" is what is read. */}
                  <h3 className="cwg-summary__title">
                    {gapAnalysis.source_framework?.code}{" "}
                    <span aria-hidden="true">➔</span>
                    <span className="cc-sr-only">to</span>{" "}
                    {gapAnalysis.target_framework?.code}
                  </h3>
                  <p className="cwg-summary__context">
                    Estimated baseline compliance posture for{" "}
                    {gapAnalysis.target_framework?.name} based on existing{" "}
                    {gapAnalysis.source_framework?.name} scan findings.
                  </p>
                </div>
                <p className="cwg-score">
                  <span className="cwg-score__label">Estimated score</span>
                  <span className="cwg-score__value">
                    {gapAnalysis.summary?.estimated_score_pct}%
                  </span>
                </p>
              </div>
              {/* Pass and fail are named by their terms; the colour repeats
                  them. */}
              <dl className="cwg-stats">
                <div className="cwg-stat">
                  <dt>Target Controls</dt>
                  <dd>{gapAnalysis.summary?.total_target_controls}</dd>
                </div>
                <div className="cwg-stat">
                  <dt>Crosswalk Mapped</dt>
                  <dd>{gapAnalysis.summary?.mapped_controls}</dd>
                </div>
                <div className="cwg-stat">
                  <dt>Estimated Pass</dt>
                  <dd className="cwg-stat__pass">
                    {gapAnalysis.summary?.estimated_pass}
                  </dd>
                </div>
                <div className="cwg-stat">
                  <dt>Estimated Fail</dt>
                  <dd className="cwg-stat__fail">
                    {gapAnalysis.summary?.estimated_fail}
                  </dd>
                </div>
              </dl>
            </div>

            {/* Scrolls when the target framework is long, so a keyboard user
                can reach and scroll it. */}
            <div
              className="cwg-results"
              role="region"
              aria-label="Estimated status by control"
              tabIndex={0}
            >
              <CcureTable
                caption={`${gapAnalysis.target_framework?.code || "Target"} controls estimated from ${gapAnalysis.source_framework?.code || "source"} findings`}
                columns={[
                  {
                    key: "control_number",
                    header: `${gapAnalysis.target_framework?.code || "Target"} Control`,
                    isRowHeader: true,
                    mono: true,
                    nowrap: true,
                    cell: (c) => c.control_number,
                  },
                  {
                    key: "title",
                    header: "Title",
                    cell: (c) => c.title,
                  },
                  {
                    key: "crosswalk",
                    header: `Mapped ${gapAnalysis.source_framework?.code || "Source"} Controls`,
                    cell: (c) => (
                      <span className="cwg-refs">
                        {(c.crosswalk || []).map((iso) => (
                          <CcureBadge key={iso} mono>
                            {iso}
                          </CcureBadge>
                        ))}
                      </span>
                    ),
                  },
                  {
                    key: "estimated_status",
                    header: "Estimated Status",
                    nowrap: true,
                    // The status is the badge's word; the colour repeats it.
                    cell: (c) => (
                      <CcureBadge
                        variant={
                          c.estimated_status === "pass"
                            ? "success"
                            : c.estimated_status === "fail"
                              ? "danger"
                              : "info"
                        }
                      >
                        {c.estimated_status}
                      </CcureBadge>
                    ),
                  },
                ]}
                rows={gapAnalysis.controls || []}
                rowKey={(c) => c.control_id}
                emptyMessage="No target controls to compare."
              />
            </div>
          </div>
        )}
        {(modalType === "remediate" || modalType === "rollback") &&
          selectedFinding && (
            <div className="cwe-guide">
              <div className="cwe-guide__intro">
                <h3 className="cwe-guide__heading">
                  {modalType === "rollback"
                    ? "Rollback Security Rule"
                    : "Remediation Guide"}
                  :{" "}
                  <span className="cwe-mono">{selectedFinding.control_id}</span>
                </h3>
                <p className="cwe-guide__context">
                  Control Name: {selectedFinding.control_title}
                </p>
              </div>

              <div className="cwe-target">
                <p className="cwe-label">Target Machine / IP</p>
                <p className="cwe-target__value">
                  {selectedFinding.asset_hostname &&
                  selectedFinding.asset_hostname !== "Unknown"
                    ? `${selectedFinding.asset_hostname} (${selectedFinding.asset_ip})`
                    : selectedFinding.asset_ip}
                </p>
              </div>

              <div className="cwe-section">
                <h4 className="cwe-label">
                  {modalType === "rollback"
                    ? "Warning Description"
                    : "How to Resolve This Finding"}
                </h4>
                {/* A rollback's warning is an alert in words, not only an
                    orange rule beside a paragraph. */}
                {modalType === "rollback" ? (
                  <CcureAlert variant="warning" live={false}>
                    This action will execute a script to reverse the security
                    control and reopen the port on the target machine.
                  </CcureAlert>
                ) : (
                  <p className="cwe-guide__advice">
                    {selectedFinding.recommendation_text ||
                      "No recommendation text registered."}
                  </p>
                )}
              </div>

              {selectedFinding.fix_command && (
                <div className="cwe-section">
                  <div className="cwe-section__bar">
                    <h4 id="cwe-script-title" className="cwe-label">
                      Automated Repair Script
                    </h4>
                    <CcureButton
                      variant="ghost"
                      size="sm"
                      aria-label="Copy repair script"
                      onClick={() =>
                        handleCopyCommand(selectedFinding.fix_command)
                      }
                    >
                      Copy
                    </CcureButton>
                  </div>
                  {/* Scrollable, so a keyboard user can reach and scroll it. */}
                  <pre
                    className="cwe-console"
                    role="region"
                    aria-labelledby="cwe-script-title"
                    tabIndex={0}
                  >
                    {selectedFinding.fix_command}
                  </pre>
                </div>
              )}

              <fieldset className="cwe-credentials">
                <legend className="cwe-credentials__legend">
                  Execution Credentials
                </legend>
                <div className="cwe-choices">
                  <label className="cwe-choice">
                    <input
                      type="radio"
                      name="cwe-credential-source"
                      checked={remediationCredSource === "jit"}
                      onChange={() => setRemediationCredSource("jit")}
                    />
                    One-time JIT Credentials
                  </label>
                  <label className="cwe-choice">
                    <input
                      type="radio"
                      name="cwe-credential-source"
                      checked={remediationCredSource === "stored"}
                      onChange={() => setRemediationCredSource("stored")}
                    />
                    Use Stored Credential
                  </label>
                </div>

                {/* A stored credential is chosen by its name and account and
                    sent as its id; its secret never reaches the page. */}
                {remediationCredSource === "stored" ? (
                  <CcureSelect
                    label="Select Saved Credential"
                    value={selectedCredId}
                    onChange={(e) => setSelectedCredId(e.target.value)}
                  >
                    <option value="">-- Choose Credential --</option>
                    {credentialsList.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.name} ({c.username})
                      </option>
                    ))}
                  </CcureSelect>
                ) : (
                  <div className="cwe-jit">
                    <CcureInput
                      label="SSH Username"
                      value={jitUsername}
                      onChange={(e) => setJitUsername(e.target.value)}
                      placeholder="e.g. root"
                    />
                    <CcureInput
                      type="number"
                      label="SSH Port"
                      value={jitPort}
                      onChange={(e) => setJitPort(e.target.value)}
                      placeholder="22"
                    />
                    <CcureSelect
                      label="Auth Method"
                      fieldClassName="cwe-jit__wide"
                      value={jitAuthMethod}
                      onChange={(e) => setJitAuthMethod(e.target.value)}
                    >
                      <option value="password">Password</option>
                      <option value="key">Private SSH Key</option>
                    </CcureSelect>
                    {/* `new-password`: the browser must not offer the signed-in
                        user's own password into a field that sends someone
                        else's, nor keep a revealed value in form history. */}
                    {jitAuthMethod === "password" ? (
                      <CcurePasswordField
                        className="cwe-jit__wide"
                        label="Password"
                        value={jitPassword}
                        onChange={(e) => setJitPassword(e.target.value)}
                        placeholder="••••••••"
                        hint="Encrypted with this request; not added to saved credentials."
                        autoComplete="new-password"
                      />
                    ) : (
                      <CcureField
                        id="cwe-jit-key"
                        className="cwe-jit__wide"
                        label="Private Key Content"
                        hint="Encrypted with this request; not added to saved credentials."
                      >
                        <textarea
                          id="cwe-jit-key"
                          className="cc-field__control cwe-key"
                          value={jitKeyContent}
                          onChange={(e) => setJitKeyContent(e.target.value)}
                          placeholder="-----BEGIN OpenSSH PRIVATE KEY-----..."
                          aria-describedby="cwe-jit-key-hint"
                        />
                      </CcureField>
                    )}
                  </div>
                )}
              </fieldset>

              {isComplianceAdmin && (
                <div className="cwe-bypass">
                  <label className="cwe-choice cwe-choice--strong">
                    <input
                      type="checkbox"
                      checked={emergencyBypass}
                      onChange={(e) => setEmergencyBypass(e.target.checked)}
                      aria-describedby="cwe-bypass-note"
                    />
                    <span aria-hidden="true">⚡</span> Emergency Bypass (Direct
                    Execution - Skip Approvals Queue)
                  </label>
                  <p id="cwe-bypass-note" className="cwe-bypass__note">
                    Note: Emergency bypass will log a critical priority incident
                    alert to the IP audit logs.
                  </p>
                </div>
              )}

              {/* Dispatch is a danger action for a rollback and whenever the
                  bypass would run the script at once rather than queue it. */}
              <div className="cwe-guide__actions">
                {selectedFinding.fix_command ? (
                  <CcureButton
                    variant={
                      modalType === "rollback" || emergencyBypass
                        ? "danger"
                        : "primary"
                    }
                    onClick={() => {
                      if (modalType === "rollback") {
                        handleRollback(selectedFinding.id);
                      } else {
                        handleRemediate(selectedFinding.id);
                      }
                      setModalOpen(false);
                    }}
                  >
                    <span aria-hidden="true">🚀</span>{" "}
                    {modalType === "rollback"
                      ? "Dispatch Rollback Request"
                      : "Dispatch Fix Request"}
                  </CcureButton>
                ) : (
                  <CcureButton variant="secondary" disabled>
                    <span aria-hidden="true">⚙️</span>{" "}
                    {modalType === "rollback"
                      ? "No Automated Rollback Available"
                      : "No Automated Fix Available"}
                  </CcureButton>
                )}
                <CcureButton
                  variant="ghost"
                  onClick={() => setModalOpen(false)}
                >
                  Close Guide
                </CcureButton>
              </div>
            </div>
          )}

        {modalType === "log_viewer" && selectedFinding && (
          <div className="cwe-guide">
            <div className="cwe-guide__intro">
              <h3 className="cwe-guide__heading">
                Execution Log:{" "}
                <span className="cwe-mono">{selectedFinding.control_id}</span>
              </h3>
              <p className="cwe-guide__context">
                Target IP: {selectedFinding.asset_ip}
              </p>
            </div>
            <div className="cwe-section">
              <h4 id="cwe-log-title" className="cwe-label">
                Console Output
              </h4>
              <pre
                className="cwe-console cwe-console--tall"
                role="region"
                aria-labelledby="cwe-log-title"
                tabIndex={0}
              >
                {selectedFinding.execution_log || "No console output recorded."}
              </pre>
            </div>
            <div className="cwe-guide__actions">
              <CcureButton variant="ghost" onClick={() => setModalOpen(false)}>
                Close Logs
              </CcureButton>
            </div>
          </div>
        )}
      </CcureModal>
      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </AppLayout>
  );
}
