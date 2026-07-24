/**
 * src/pages/ComplianceWorkspace.jsx
 * Compliance baselines, controls, rules, exceptions, and scoring dashboards.
 */

import React, { useState, useEffect, useMemo, useRef } from "react";
import axiosInstance from "../api/axiosInstance";
import AppLayout from "../components/layout/AppLayout";
import Modal from "../components/layout/Modal";
import { useAuth } from "../context/AuthContext";
import { useToasts, ToastContainer } from "../components/common/Toast";
import "../styles/dashboard.css";
import "../styles/compliance.css";
import "../styles/scan.css";

function Skeleton({ h = 14, w = "100%", style }) {
  return (
    <div
      className="db-skeleton"
      style={{ height: h, width: w, borderRadius: 4, ...style }}
    />
  );
}

function PaginationBar({
  currentPage,
  pageSize,
  totalItems,
  totalPages,
  onPageChange,
  onPageSizeChange,
  loading,
  itemLabel = "items",
  sizerOptions = [10, 25, 50, 100],
  customSummary,
}) {
  const displayPage = Math.min(currentPage, totalPages);
  const startRange = totalItems === 0 ? 0 : (displayPage - 1) * pageSize + 1;
  const endRange = Math.min(displayPage * pageSize, totalItems);

  return (
    <div className="cw-pagination">
      <span className="cw-pagination-summary">
        {customSummary ||
          (totalItems === 0
            ? `No ${itemLabel} found`
            : `Showing ${startRange}–${endRange} of ${totalItems} ${itemLabel}`)}
      </span>

      <div className="cw-pagination-controls">
        <button
          className="cw-pagination-btn"
          disabled={loading || displayPage === 1}
          onClick={() => onPageChange(1)}
        >
          «
        </button>
        <button
          className="cw-pagination-btn"
          disabled={loading || displayPage === 1}
          onClick={() => onPageChange((p) => p - 1)}
        >
          Prev
        </button>
        <span className="cw-pagination-page-indicator">
          Page {displayPage} of {totalPages}
        </span>
        <button
          className="cw-pagination-btn"
          disabled={loading || displayPage === totalPages}
          onClick={() => onPageChange((p) => p + 1)}
        >
          Next
        </button>
        <button
          className="cw-pagination-btn"
          disabled={loading || displayPage === totalPages}
          onClick={() => onPageChange(totalPages)}
        >
          »
        </button>
      </div>

      <div className="cw-pagination-sizer">
        <span>Show</span>
        <select
          className="cw-pagination-select"
          value={pageSize}
          onChange={(e) => {
            onPageSizeChange(Number(e.target.value));
            onPageChange(1);
          }}
        >
          {sizerOptions.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
        <span>per page</span>
      </div>
    </div>
  );
}

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

const GAP_FRAMEWORK_OPTIONS = [
  { id: "cfw_iso27001_2022", name: "ISO 27001:2022 (Information Security)" },
  { id: "cfw_nist_csf_v2", name: "NIST CSF 2.0 (Cybersecurity Framework)" },
  { id: "cfw_soc2_type2", name: "SOC 2 Type II (Trust Services)" },
  { id: "cfw_cis_v8_1", name: "CIS Controls v8.1 (Critical Controls)" },
  { id: "cfw_cert_in_2022", name: "CERT-In 2022 (Cyber Incident Directives)" },
  { id: "cfw_pci_dss_v4", name: "PCI-DSS v4.0 (Payment Card Security)" },
  { id: "cfw_dpdp_2023", name: "DPDP Act 2023 (Data Protection)" },
  { id: "cfw_gdpr", name: "EU GDPR (General Data Protection)" },
  { id: "cfw_nist_800_53_r5", name: "NIST SP 800-53 R5 (Federal & Defense)" },
  { id: "cfw_iec_62443", name: "IEC 62443 (Industrial & OT/ICS)" },
  { id: "cfw_nist_800_82_r3", name: "NIST SP 800-82 R3 (OT Security)" },
  { id: "cfw_nerc_cip", name: "NERC CIP (Power Grid Critical Infra)" },
  { id: "cfw_nis2", name: "EU NIS 2 Directive (Directive 2022/2555)" },
];

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
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState(null);
  const [marketplace, setMarketplace] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [findings, setFindings] = useState([]);
  const [exceptions, setExceptions] = useState([]);
  const [error, setError] = useState(null);

  // Remediation & Credentials Manager States
  const [credentialsList, setCredentialsList] = useState([]);
  const [approvalsList, setApprovalsList] = useState([]);
  const [newCredName, setNewCredName] = useState("");
  const [newCredUsername, setNewCredUsername] = useState("");
  const [newCredAuthMethod, setNewCredAuthMethod] = useState("password");
  const [newCredPassword, setNewCredPassword] = useState("");
  const [newCredKeyContent, setNewCredKeyContent] = useState("");
  const [newCredPort, setNewCredPort] = useState(22);

  const [remediationCredSource, setRemediationCredSource] = useState("jit"); // jit | stored
  const [selectedCredId, setSelectedCredId] = useState("");
  const [jitUsername, setJitUsername] = useState("");
  const [jitPort, setJitPort] = useState(22);
  const [jitAuthMethod, setJitAuthMethod] = useState("password");
  const [jitPassword, setJitPassword] = useState("");
  const [jitKeyContent, setJitKeyContent] = useState("");
  const [emergencyBypass, setEmergencyBypass] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanPollCount, setScanPollCount] = useState(0); // Active framework filter & gap analysis states
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

  // Reset findings page on search/filter changes
  useEffect(() => {
    findingsPagination.setPage(1);
  }, [filterSearch, filterAsset, filterStatus, filterSeverity, filterIg]);

  // Reset pages on data updates
  useEffect(() => {
    policiesPagination.setPage(1);
  }, [policies]);
  useEffect(() => {
    exceptionsPagination.setPage(1);
  }, [exceptions]);
  useEffect(() => {
    credentialsPagination.setPage(1);
  }, [credentialsList]);
  useEffect(() => {
    approvalsPagination.setPage(1);
  }, [approvalsList]);

  useEffect(() => {
    fetchTabData(false);
  }, [activeTab]);

  useEffect(() => {
    if (isScanning && scanPollCount >= 6) {
      setIsScanning(false);
      setScanPollCount(0);
    }
  }, [scanPollCount, isScanning]);

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
      fetchTabData(true);
    }, 5000);

    return () => clearInterval(interval);
  }, [activeTab, findings, approvalsList, isScanning]);

  useEffect(() => {
    fetchTabData();
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
          const FW_LIST = [
            { id: "cfw_iso27001_2022", name: "ISO 27001:2022" },
            { id: "cfw_nist_csf_v2", name: "NIST CSF 2.0" },
            { id: "cfw_soc2_type2", name: "SOC 2 Type II" },
            { id: "cfw_cis_v8_1", name: "CIS Controls v8.1" },
            { id: "cfw_cert_in_2022", name: "CERT-In 2022" },
            { id: "cfw_pci_dss_v4", name: "PCI-DSS v4.0" },
            { id: "cfw_dpdp_2023", name: "DPDP Act 2023" },
            { id: "cfw_gdpr", name: "EU GDPR" },
            { id: "cfw_nist_800_53_r5", name: "NIST SP 800-53 R5" },
            { id: "cfw_iec_62443", name: "IEC 62443 (OT/ICS)" },
            { id: "cfw_nist_800_82_r3", name: "NIST SP 800-82 R3 (OT)" },
            { id: "cfw_nerc_cip", name: "NERC CIP (Power Grid)" },
            { id: "cfw_nis2", name: "EU NIS 2 Directive" },
          ];
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
    if (
      !window.confirm(
        "Are you sure you want to uninstall this compliance framework? This will hide its policies, findings, approvals, and dashboard averages.",
      )
    )
      return;
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
    try {
      await axiosInstance.post(
        `/compliance/controls/${selectedControl.id}/attest`,
        {
          status: attestStatus,
          note: attestNote,
        },
      );
      setModalOpen(false);
      pushToast("Attestation submitted successfully.", "success");
      fetchTabData();
    } catch (e) {
      pushToast(
        "Failed to submit attestation: " +
          (e.response?.data?.detail || e.response?.data?.message || e.message),
        "error",
      );
    }
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
      for (const policy of policiesToRun) {
        try {
          await axiosInstance.post("/compliance/scans", {
            framework_id: policy.framework_id,
            policy_id: policy.id,
            asset_ids: [],
            asset_tags: [],
          });
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
      const res = await axiosInstance.get(endpoint, { responseType: "blob" });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", filename);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
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
      <div className="db-page">
        {loading && <div className="loading-bar" />}

        {/* Workspace Header */}
        <div className="db-page-header">
          <div>
            <div className="db-page-title">Policy Compliance</div>
            <div className="db-page-subtitle">
              Standard catalogs, baseline verification scans, manual
              attestations, crosswalk gap analysis, and exception waivers.
            </div>
          </div>
          <div
            className="db-header-actions"
            style={{ display: "flex", gap: "10px", alignItems: "center" }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span
                style={{
                  fontSize: "0.85rem",
                  fontWeight: 600,
                  color: "var(--text-muted)",
                }}
              >
                Framework:
              </span>
              <select
                className="cw-pagination-select"
                value={selectedFrameworkId}
                onChange={(e) => setSelectedFrameworkId(e.target.value)}
                style={{
                  padding: "6px 12px",
                  borderRadius: "6px",
                  fontSize: "0.85rem",
                  background: "var(--bg-white)",
                  border: "1px solid var(--border)",
                  fontWeight: 600,
                }}
              >
                <option value="all">All Frameworks</option>
                <option value="cfw_iso27001_2022">ISO/IEC 27001:2022</option>
                <option value="cfw_nist_csf_v2">NIST CSF v2.0</option>
                <option value="cfw_cis_v8_1">CIS Controls v8.1</option>
                <option value="cfw_soc2_type2">
                  SOC 2 Type II (Trust Services Criteria)
                </option>
                <option value="cfw_cert_in_2022">
                  CERT-In Directions 2022 & CCMP
                </option>
                <option value="cfw_pci_dss_v4">
                  PCI-DSS v4.0 (Cardholder Data Security)
                </option>
                <option value="cfw_dpdp_2023">
                  DPDP Act 2023 (Digital Personal Data Protection)
                </option>
                <option value="cfw_gdpr">
                  GDPR (EU General Data Protection Regulation)
                </option>
                <option value="cfw_nist_800_53_r5">
                  NIST SP 800-53 Rev. 5 (U.S. Federal & Defense)
                </option>
                <option value="cfw_iec_62443">
                  IEC 62443 (Industrial Communication Networks & OT/ICS)
                </option>
                <option value="cfw_nist_800_82_r3">
                  NIST SP 800-82 Rev. 3 (OT/ICS Security Guide)
                </option>
                <option value="cfw_nerc_cip">
                  NERC CIP (Critical Infrastructure Protection - Power Grid)
                </option>
                <option value="cfw_nis2">
                  EU NIS 2 Directive (Directive (EU) 2022/2555)
                </option>
              </select>
            </div>
            {(selectedFrameworkId === "cfw_iec_62443" ||
              selectedFrameworkId === "cfw_nist_800_82_r3") && (
              <>
                <div
                  style={{ display: "flex", alignItems: "center", gap: "6px" }}
                >
                  <span
                    style={{
                      fontSize: "0.85rem",
                      fontWeight: 600,
                      color: "var(--text-muted)",
                    }}
                  >
                    Purdue Level:
                  </span>
                  <select
                    className="cw-pagination-select"
                    value={purdueLevelFilter}
                    onChange={(e) => setPurdueLevelFilter(e.target.value)}
                    style={{
                      padding: "6px 10px",
                      borderRadius: "6px",
                      fontSize: "0.85rem",
                      background: "var(--bg-white)",
                      border: "1px solid var(--border)",
                      fontWeight: 600,
                    }}
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
                  </select>
                </div>

                <div
                  style={{ display: "flex", alignItems: "center", gap: "6px" }}
                >
                  <span
                    style={{
                      fontSize: "0.85rem",
                      fontWeight: 600,
                      color: "var(--text-muted)",
                    }}
                  >
                    Component Type:
                  </span>
                  <select
                    className="cw-pagination-select"
                    value={componentTypeFilter}
                    onChange={(e) => setComponentTypeFilter(e.target.value)}
                    style={{
                      padding: "6px 10px",
                      borderRadius: "6px",
                      fontSize: "0.85rem",
                      background: "var(--bg-white)",
                      border: "1px solid var(--border)",
                      fontWeight: 600,
                    }}
                  >
                    <option value="all">All Component Types</option>
                    {selectedFrameworkId === "cfw_nist_800_82_r3" ? (
                      <>
                        <option value="PLC">
                          PLC (Programmable Logic Controller)
                        </option>
                        <option value="RTU">RTU (Remote Terminal Unit)</option>
                        <option value="SCADA">
                          SCADA (Supervisory Control)
                        </option>
                        <option value="DCS">
                          DCS (Distributed Control System)
                        </option>
                        <option value="SIS">
                          SIS (Safety Instrumented System)
                        </option>
                        <option value="HMI">
                          HMI (Human-Machine Interface)
                        </option>
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
                  </select>
                </div>

                {selectedFrameworkId === "cfw_iec_62443" && (
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                    }}
                  >
                    <span
                      style={{
                        fontSize: "0.85rem",
                        fontWeight: 600,
                        color: "var(--text-muted)",
                      }}
                    >
                      Target SL:
                    </span>
                    <select
                      className="cw-pagination-select"
                      value={slLevelFilter}
                      onChange={(e) => setSlLevelFilter(e.target.value)}
                      style={{
                        padding: "6px 10px",
                        borderRadius: "6px",
                        fontSize: "0.85rem",
                        background: "var(--bg-white)",
                        border: "1px solid var(--border)",
                        fontWeight: 600,
                      }}
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
                    </select>
                  </div>
                )}
              </>
            )}
            {selectedFrameworkId === "cfw_nerc_cip" && (
              <>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                  }}
                >
                  <span
                    style={{
                      fontSize: "0.85rem",
                      fontWeight: 600,
                      color: "var(--text-muted)",
                    }}
                  >
                    Regional Entity:
                  </span>
                  <select
                    className="cw-pagination-select"
                    value={regionalEntityFilter}
                    onChange={(e) => setRegionalEntityFilter(e.target.value)}
                    style={{
                      padding: "6px 10px",
                      borderRadius: "6px",
                      fontSize: "0.85rem",
                      background: "var(--bg-white)",
                      border: "1px solid var(--border)",
                      fontWeight: 600,
                    }}
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
                  </select>
                </div>

                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                  }}
                >
                  <span
                    style={{
                      fontSize: "0.85rem",
                      fontWeight: 600,
                      color: "var(--text-muted)",
                    }}
                  >
                    BES Impact:
                  </span>
                  <select
                    className="cw-pagination-select"
                    value={besImpactLevelFilter}
                    onChange={(e) => setBesImpactLevelFilter(e.target.value)}
                    style={{
                      padding: "6px 10px",
                      borderRadius: "6px",
                      fontSize: "0.85rem",
                      background: "var(--bg-white)",
                      border: "1px solid var(--border)",
                      fontWeight: 600,
                    }}
                  >
                    <option value="all">All BES Impact Baselines</option>
                    <option value="High">High Impact BES Cyber Systems</option>
                    <option value="Medium">
                      Medium Impact BES Cyber Systems
                    </option>
                    <option value="Low">Low Impact BES Cyber Systems</option>
                  </select>
                </div>

                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                  }}
                >
                  <span
                    style={{
                      fontSize: "0.85rem",
                      fontWeight: 600,
                      color: "var(--text-muted)",
                    }}
                  >
                    Standard:
                  </span>
                  <select
                    className="cw-pagination-select"
                    value={standardNumberFilter}
                    onChange={(e) => setStandardNumberFilter(e.target.value)}
                    style={{
                      padding: "6px 10px",
                      borderRadius: "6px",
                      fontSize: "0.85rem",
                      background: "var(--bg-white)",
                      border: "1px solid var(--border)",
                      fontWeight: 600,
                    }}
                  >
                    <option value="all">
                      All Standards (CIP-002 to CIP-014)
                    </option>
                    <option value="CIP-002">
                      CIP-002 (Asset Categorization)
                    </option>
                    <option value="CIP-003">
                      CIP-003 (Security Management)
                    </option>
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
                    <option value="CIP-008">
                      CIP-008 (Incident Reporting)
                    </option>
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
                  </select>
                </div>
              </>
            )}
            {selectedFrameworkId === "cfw_nis2" && (
              <>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                  }}
                >
                  <span
                    style={{
                      fontSize: "0.85rem",
                      fontWeight: 600,
                      color: "var(--text-muted)",
                    }}
                  >
                    Entity Scope:
                  </span>
                  <select
                    className="cw-pagination-select"
                    value={nis2EntityTypeFilter}
                    onChange={(e) => setNis2EntityTypeFilter(e.target.value)}
                    style={{
                      padding: "6px 10px",
                      borderRadius: "6px",
                      fontSize: "0.85rem",
                      background: "var(--bg-white)",
                      border: "1px solid var(--border)",
                      fontWeight: 600,
                    }}
                  >
                    <option value="all">All Entities</option>
                    <option value="essential">
                      Essential Entity (Art. 3.1)
                    </option>
                    <option value="important">
                      Important Entity (Art. 3.2)
                    </option>
                  </select>
                </div>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                  }}
                >
                  <span
                    style={{
                      fontSize: "0.85rem",
                      fontWeight: 600,
                      color: "var(--text-muted)",
                    }}
                  >
                    Sector:
                  </span>
                  <select
                    className="cw-pagination-select"
                    value={nis2SectorFilter}
                    onChange={(e) => setNis2SectorFilter(e.target.value)}
                    style={{
                      padding: "6px 10px",
                      borderRadius: "6px",
                      fontSize: "0.85rem",
                      background: "var(--bg-white)",
                      border: "1px solid var(--border)",
                      fontWeight: 600,
                    }}
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
                    <option value="banking">
                      Banking & Credit Institutions
                    </option>
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
                  </select>
                </div>

                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                  }}
                >
                  <span
                    style={{
                      fontSize: "0.85rem",
                      fontWeight: 600,
                      color: "var(--text-muted)",
                    }}
                  >
                    Member State:
                  </span>
                  <select
                    className="cw-pagination-select"
                    value={nis2MemberStateFilter}
                    onChange={(e) => setNis2MemberStateFilter(e.target.value)}
                    style={{
                      padding: "6px 10px",
                      borderRadius: "6px",
                      fontSize: "0.85rem",
                      background: "var(--bg-white)",
                      border: "1px solid var(--border)",
                      fontWeight: 600,
                    }}
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
                  </select>
                </div>
              </>
            )}
            {selectedFrameworkId === "cfw_nist_800_53_r5" && (
              <>
                <div
                  style={{ display: "flex", alignItems: "center", gap: "6px" }}
                >
                  <span
                    style={{
                      fontSize: "0.85rem",
                      fontWeight: 600,
                      color: "var(--text-muted)",
                    }}
                  >
                    FedRAMP Baseline:
                  </span>
                  <select
                    className="cw-pagination-select"
                    value={impactLevelFilter}
                    onChange={(e) => setImpactLevelFilter(e.target.value)}
                    style={{
                      padding: "6px 10px",
                      borderRadius: "6px",
                      fontSize: "0.85rem",
                      background: "var(--bg-white)",
                      border: "1px solid var(--border)",
                      fontWeight: 600,
                    }}
                  >
                    <option value="all">All Impact Baselines</option>
                    <option value="LOW">FedRAMP LOW Impact Baseline</option>
                    <option value="MODERATE">
                      FedRAMP MODERATE Impact Baseline
                    </option>
                    <option value="HIGH">FedRAMP HIGH Impact Baseline</option>
                  </select>
                </div>
                <label
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                    fontSize: "0.85rem",
                    fontWeight: 600,
                    cursor: "pointer",
                  }}
                >
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
              <div
                style={{ display: "flex", alignItems: "center", gap: "6px" }}
              >
                <span
                  style={{
                    fontSize: "0.85rem",
                    fontWeight: 600,
                    color: "var(--text-muted)",
                  }}
                >
                  SDF Scope:
                </span>
                <select
                  className="cw-pagination-select"
                  value={sdfScopeFilter}
                  onChange={(e) => setSdfScopeFilter(e.target.value)}
                  style={{
                    padding: "6px 10px",
                    borderRadius: "6px",
                    fontSize: "0.85rem",
                    background: "var(--bg-white)",
                    border: "1px solid var(--border)",
                    fontWeight: 600,
                  }}
                >
                  <option value="all">All Fiduciaries (General + SDF)</option>
                  <option value="sdf_mandatory">
                    Significant Data Fiduciary (SDF Mandatory)
                  </option>
                  <option value="general_fiduciary">
                    General Data Fiduciary
                  </option>
                </select>
              </div>
            )}
            {selectedFrameworkId === "cfw_gdpr" && (
              <div
                style={{ display: "flex", alignItems: "center", gap: "6px" }}
              >
                <span
                  style={{
                    fontSize: "0.85rem",
                    fontWeight: 600,
                    color: "var(--text-muted)",
                  }}
                >
                  Privacy Role:
                </span>
                <select
                  className="cw-pagination-select"
                  value={privacyRoleFilter}
                  onChange={(e) => setPrivacyRoleFilter(e.target.value)}
                  style={{
                    padding: "6px 10px",
                    borderRadius: "6px",
                    fontSize: "0.85rem",
                    background: "var(--bg-white)",
                    border: "1px solid var(--border)",
                    fontWeight: 600,
                  }}
                >
                  <option value="all">
                    All Roles (Controller & Processor)
                  </option>
                  <option value="controller">Data Controller</option>
                  <option value="processor">Data Processor</option>
                </select>
              </div>
            )}
            {selectedFrameworkId === "cfw_pci_dss_v4" && (
              <>
                <div
                  style={{ display: "flex", alignItems: "center", gap: "6px" }}
                >
                  <span
                    style={{
                      fontSize: "0.85rem",
                      fontWeight: 600,
                      color: "var(--text-muted)",
                    }}
                  >
                    SAQ Profile:
                  </span>
                  <select
                    className="cw-pagination-select"
                    value={saqProfileFilter}
                    onChange={(e) => setSaqProfileFilter(e.target.value)}
                    style={{
                      padding: "6px 10px",
                      borderRadius: "6px",
                      fontSize: "0.85rem",
                      background: "var(--bg-white)",
                      border: "1px solid var(--border)",
                      fontWeight: 600,
                    }}
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
                  </select>
                </div>
                <label
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                    fontSize: "0.85rem",
                    fontWeight: 600,
                    cursor: "pointer",
                  }}
                >
                  <input
                    type="checkbox"
                    checked={cdeScopeFilter}
                    onChange={(e) => setCdeScopeFilter(e.target.checked)}
                  />
                  CDE Scope Only
                </label>
              </>
            )}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              <span
                style={{
                  fontSize: "0.85rem",
                  fontWeight: 600,
                  color: "var(--text-muted)",
                }}
              >
                Gap Source:
              </span>
              <select
                className="cw-pagination-select"
                value={gapSourceFramework}
                onChange={(e) => setGapSourceFramework(e.target.value)}
                style={{
                  padding: "6px 10px",
                  borderRadius: "6px",
                  fontSize: "0.85rem",
                  background: "var(--bg-white)",
                  border: "1px solid var(--border)",
                  fontWeight: 600,
                }}
              >
                {GAP_FRAMEWORK_OPTIONS.map((fw) => (
                  <option key={`tb_src_${fw.id}`} value={fw.id}>
                    {fw.name}
                  </option>
                ))}
              </select>
            </div>
            <button
              className="db-btn db-btn--ghost"
              onClick={() =>
                fetchGapAnalysis(
                  gapSourceFramework,
                  selectedFrameworkId === "all"
                    ? gapTargetFramework
                    : selectedFrameworkId,
                )
              }
              disabled={loadingGapAnalysis}
              style={{ display: "flex", alignItems: "center", gap: "6px" }}
            >
              <span>
                📊 {loadingGapAnalysis ? "Calculating..." : "Gap Analysis"}
              </span>
            </button>
            <button
              className="db-btn db-btn--primary"
              onClick={handleTriggerComplianceScan}
              disabled={loading}
              style={{ display: "flex", alignItems: "center", gap: "6px" }}
            >
              <span>⚡ Run Compliance Scan</span>
            </button>
            {activeTab === "policies" && (
              <button
                className="db-btn db-btn--ghost"
                onClick={() => {
                  setModalType("policy");
                  setModalOpen(true);
                }}
              >
                + Create Baseline Policy
              </button>
            )}
          </div>
        </div>

        {/* Navigation Tabs */}
        <div
          style={{
            padding: "0 28px",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            gap: 24,
            background: "var(--bg-white)",
            marginBottom: "2rem",
          }}
        >
          {[
            { id: "dashboard", label: "Dashboard" },
            { id: "marketplace", label: "Marketplace" },
            { id: "policies", label: "Policies" },
            { id: "findings", label: "Findings" },
            { id: "exceptions", label: "Exceptions" },
            { id: "credentials", label: "Credentials Manager" },
            { id: "approvals", label: "Approvals Queue" },
          ].map((tab) => {
            const active = activeTab === tab.id;
            return (
              <div
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  padding: "16px 4px",
                  fontSize: "0.85rem",
                  fontWeight: active ? 700 : 500,
                  color: active ? "var(--accent)" : "var(--text-muted)",
                  borderBottom: `2px solid ${active ? "var(--accent)" : "transparent"}`,
                  cursor: "pointer",
                  transition: "all 0.2s",
                }}
              >
                {tab.label}
              </div>
            );
          })}
        </div>

        {/* Tab Content */}
        <div style={{ padding: "0 28px" }}>
          {error && (
            <div
              className="db-alert db-alert--critical"
              style={{ marginBottom: "2rem" }}
            >
              <span className="db-alert-icon">⚠️</span>
              <div className="db-alert-body">
                <strong>Connection or Database Error:</strong> {error}
              </div>
            </div>
          )}

          {activeTab === "dashboard" && summary && (
            <div className="dashboard-view">
              <div className="metrics-grid">
                <div className="metric-card">
                  <h3>Overall Score</h3>
                  <div
                    className={`radial-score ${getScoreClass(summary.score_pct)}`}
                  >
                    {summary.score_pct}%
                  </div>
                </div>
                <div className="metric-card">
                  <h3>Risk-Weighted Score</h3>
                  <div
                    className={`radial-score ${getScoreClass(summary.weighted_score_pct)}`}
                  >
                    {summary.weighted_score_pct}%
                  </div>
                </div>
                <div className="metric-card">
                  <h3>
                    {!selectedFrameworkId || selectedFrameworkId === "all"
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
                                      : "ISO 27001 Controls"}
                  </h3>

                  <div className="kpis-list">
                    <div>
                      Passed:{" "}
                      <span style={{ color: "var(--ok)" }}>
                        {summary.kpis?.passed || 0}
                      </span>
                    </div>
                    <div>
                      Failed:{" "}
                      <span className="danger">
                        {summary.kpis?.failed || 0}
                      </span>
                    </div>
                    <div>
                      Active Waivers:{" "}
                      <span className="info">
                        {summary.kpis?.exceptions || 0}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              <div
                className="db-card"
                style={{
                  marginBottom: "2rem",
                  padding: "1.5rem",
                  display: "flex",
                  gap: "1rem",
                  flexWrap: "wrap",
                  background: "var(--bg-white)",
                }}
              >
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      "/compliance/reports/soa?fmt=pdf",
                      "statement_of_applicability.pdf",
                    )
                  }
                >
                  Download SoA PDF (ISO)
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      "/compliance/reports/soa?fmt=docx",
                      "statement_of_applicability.docx",
                    )
                  }
                >
                  Download SoA Word (ISO)
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      "/compliance/reports/nist_csf?fmt=pdf",
                      "nist_csf_v2_report.pdf",
                    )
                  }
                >
                  Download NIST CSF PDF
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      "/compliance/reports/nist_csf?fmt=docx",
                      "nist_csf_v2_report.docx",
                    )
                  }
                >
                  Download NIST CSF Word
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      "/compliance/reports/cis_v8_1?fmt=pdf",
                      "cis_v8_1_executive_report.pdf",
                    )
                  }
                >
                  Download CIS Controls PDF
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      "/compliance/reports/cis_v8_1?fmt=docx",
                      "cis_v8_1_executive_report.docx",
                    )
                  }
                >
                  Download CIS Controls Word
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      "/compliance/reports/soc2_type2?fmt=pdf",
                      "soc2_type2_executive_report.pdf",
                    )
                  }
                >
                  Download SOC 2 PDF
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      "/compliance/reports/soc2_type2?fmt=docx",
                      "soc2_type2_executive_report.docx",
                    )
                  }
                >
                  Download SOC 2 Word
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      "/compliance/reports/cert_in_2022?fmt=pdf",
                      "cert_in_2022_executive_report.pdf",
                    )
                  }
                >
                  Download CERT-In PDF
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      "/compliance/reports/cert_in_2022?fmt=docx",
                      "cert_in_2022_executive_report.docx",
                    )
                  }
                >
                  Download CERT-In Word
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/pci_dss_v4?fmt=pdf${saqProfileFilter !== "all" ? `&saq_profile=${saqProfileFilter}` : ""}${cdeScopeFilter ? "&cde_scope_only=true" : ""}`,
                      "pci_dss_v4_compliance_report.pdf",
                    )
                  }
                >
                  Download PCI-DSS PDF
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/pci_dss_v4?fmt=docx${saqProfileFilter !== "all" ? `&saq_profile=${saqProfileFilter}` : ""}${cdeScopeFilter ? "&cde_scope_only=true" : ""}`,
                      "pci_dss_v4_compliance_report.docx",
                    )
                  }
                >
                  Download PCI-DSS Word
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/dpdp_2023?fmt=pdf${sdfScopeFilter !== "all" ? `&sdf_scope=${sdfScopeFilter}` : ""}`,
                      "dpdp_2023_compliance_report.pdf",
                    )
                  }
                >
                  Download DPDP PDF
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/dpdp_2023?fmt=docx${sdfScopeFilter !== "all" ? `&sdf_scope=${sdfScopeFilter}` : ""}`,
                      "dpdp_2023_compliance_report.docx",
                    )
                  }
                >
                  Download DPDP Word
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/gdpr?fmt=pdf${privacyRoleFilter !== "all" ? `&privacy_role=${privacyRoleFilter}` : ""}`,
                      "gdpr_compliance_report.pdf",
                    )
                  }
                >
                  Download GDPR PDF
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/gdpr?fmt=docx${privacyRoleFilter !== "all" ? `&privacy_role=${privacyRoleFilter}` : ""}`,
                      "gdpr_compliance_report.docx",
                    )
                  }
                >
                  Download GDPR Word
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/nist_800_53_r5?fmt=pdf${impactLevelFilter !== "all" ? `&impact_level=${impactLevelFilter}` : ""}${zeroTrustOnly ? "&zero_trust_only=true" : ""}`,
                      "nist_800_53_r5_compliance_report.pdf",
                    )
                  }
                >
                  Download NIST 800-53 PDF
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/nist_800_53_r5?fmt=docx${impactLevelFilter !== "all" ? `&impact_level=${impactLevelFilter}` : ""}${zeroTrustOnly ? "&zero_trust_only=true" : ""}`,
                      "nist_800_53_r5_compliance_report.docx",
                    )
                  }
                >
                  Download NIST 800-53 Word
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/iec_62443?fmt=pdf${purdueLevelFilter !== "all" ? `&purdue_level=${purdueLevelFilter}` : ""}${componentTypeFilter !== "all" ? `&component_type=${componentTypeFilter}` : ""}${slLevelFilter !== "all" ? `&sl_level=${slLevelFilter}` : ""}`,
                      "iec_62443_compliance_report.pdf",
                    )
                  }
                >
                  Download IEC 62443 PDF
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/iec_62443?fmt=docx${purdueLevelFilter !== "all" ? `&purdue_level=${purdueLevelFilter}` : ""}${componentTypeFilter !== "all" ? `&component_type=${componentTypeFilter}` : ""}${slLevelFilter !== "all" ? `&sl_level=${slLevelFilter}` : ""}`,
                      "iec_62443_compliance_report.docx",
                    )
                  }
                >
                  Download IEC 62443 Word
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/nist_800_82?fmt=pdf${purdueLevelFilter !== "all" ? `&purdue_level=${purdueLevelFilter}` : ""}${componentTypeFilter !== "all" ? `&component_type=${componentTypeFilter}` : ""}`,
                      "nist_800_82_r3_compliance_report.pdf",
                    )
                  }
                >
                  Download NIST 800-82 PDF
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/nist_800_82?fmt=docx${purdueLevelFilter !== "all" ? `&purdue_level=${purdueLevelFilter}` : ""}${componentTypeFilter !== "all" ? `&component_type=${componentTypeFilter}` : ""}`,
                      "nist_800_82_r3_compliance_report.docx",
                    )
                  }
                >
                  Download NIST 800-82 Word
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/nerc_cip?fmt=pdf&regional_entity=${regionalEntityFilter}${besImpactLevelFilter !== "all" ? `&bes_impact_level=${besImpactLevelFilter}` : ""}${standardNumberFilter !== "all" ? `&standard_number=${standardNumberFilter}` : ""}${purdueLevelFilter !== "all" ? `&purdue_level=${purdueLevelFilter}` : ""}${componentTypeFilter !== "all" ? `&component_type=${componentTypeFilter}` : ""}`,
                      "nerc_cip_compliance_report.pdf",
                    )
                  }
                >
                  Download NERC CIP PDF
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/nerc_cip?fmt=docx&regional_entity=${regionalEntityFilter}${besImpactLevelFilter !== "all" ? `&bes_impact_level=${besImpactLevelFilter}` : ""}${standardNumberFilter !== "all" ? `&standard_number=${standardNumberFilter}` : ""}${purdueLevelFilter !== "all" ? `&purdue_level=${purdueLevelFilter}` : ""}${componentTypeFilter !== "all" ? `&component_type=${componentTypeFilter}` : ""}`,
                      "nerc_cip_compliance_report.docx",
                    )
                  }
                >
                  Download NERC CIP Word
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/nis2?fmt=pdf&nis2_entity_type=${nis2EntityTypeFilter}${nis2SectorFilter !== "all" ? `&nis2_sector=${nis2SectorFilter}` : ""}`,
                      "nis2_compliance_report.pdf",
                    )
                  }
                >
                  Download NIS 2 PDF
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      `/compliance/reports/nis2?fmt=docx&nis2_entity_type=${nis2EntityTypeFilter}${nis2SectorFilter !== "all" ? `&nis2_sector=${nis2SectorFilter}` : ""}`,
                      "nis2_compliance_report.docx",
                    )
                  }
                >
                  Download NIS 2 Word
                </button>
                <button
                  className="db-btn db-btn--ghost"
                  onClick={() =>
                    handleDownloadReport(
                      "/compliance/reports/executive",
                      "executive_compliance_report.pdf",
                    )
                  }
                >
                  Download Executive Brief
                </button>
              </div>

              <div className="quadrant-scores">
                {/* ── All Frameworks: per-framework comparison chart ── */}
                {!selectedFrameworkId || selectedFrameworkId === "all" ? (
                  <>
                    <h3>Compliance Score by Framework</h3>
                    <div className="quadrant-grid">
                      {perFrameworkScores.length === 0 ? (
                        <p
                          style={{
                            color: "var(--text-muted)",
                            fontSize: "0.85rem",
                          }}
                        >
                          No enabled frameworks with scored controls yet.
                          Install and run a compliance scan to populate scores.
                        </p>
                      ) : (
                        perFrameworkScores.map((fw) => (
                          <div key={fw.id} className="quad-item">
                            <span className="quad-label">{fw.name}</span>
                            <div className="progress-container">
                              <div
                                className="comp-progress-fill"
                                style={{ width: `${fw.score}%` }}
                              />
                            </div>
                            <span className="quad-value">{fw.score}%</span>
                          </div>
                        ))
                      )}
                    </div>
                  </>
                ) : (
                  /* ── Single Framework: per-theme breakdown ── */
                  <>
                    <h3>
                      {selectedFrameworkId === "cfw_nist_csf_v2"
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
                                    : selectedFrameworkId ===
                                        "cfw_nist_800_53_r5"
                                      ? "NIST SP 800-53 R5 20 Control Families Breakdown"
                                      : selectedFrameworkId === "cfw_nis2"
                                        ? "EU NIS 2 Directive 10 Risk Management Domains (Art. 21.2)"
                                        : "ISO 27001 Themes Quadrant Breakdown"}
                    </h3>

                    {selectedFrameworkId === "cfw_nis2" && (
                      <div
                        style={{
                          background: "var(--bg-card)",
                          border: "1px solid var(--border)",
                          borderRadius: "8px",
                          padding: "16px",
                          marginBottom: "20px",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            marginBottom: "10px",
                          }}
                        >
                          <h4
                            style={{
                              margin: 0,
                              color: "var(--text-main)",
                              fontSize: "0.95rem",
                            }}
                          >
                            💶 EU NIS 2 Regulatory Fine Risk Exposure Calculator
                            (Article 32 & 34)
                          </h4>
                          <span
                            style={{
                              background:
                                nis2EntityTypeFilter === "important"
                                  ? "#f59e0b"
                                  : "#2563eb",
                              color: "#fff",
                              fontSize: "0.75rem",
                              fontWeight: 700,
                              padding: "3px 8px",
                              borderRadius: "4px",
                            }}
                          >
                            {nis2EntityTypeFilter === "important"
                              ? "Important Entity (Art. 3.2)"
                              : "Essential Entity (Art. 3.1)"}
                          </span>
                        </div>
                        <div
                          style={{
                            display: "grid",
                            gridTemplateColumns: "1fr 1fr 1fr",
                            gap: "16px",
                            alignItems: "center",
                          }}
                        >
                          <div>
                            <label
                              style={{
                                fontSize: "0.8rem",
                                color: "var(--text-muted)",
                                display: "block",
                                marginBottom: "4px",
                              }}
                            >
                              Annual Global Turnover (EUR €):
                            </label>
                            <input
                              type="number"
                              className="cw-pagination-select"
                              value={nis2AnnualTurnover}
                              onChange={(e) =>
                                setNis2AnnualTurnover(Number(e.target.value))
                              }
                              style={{
                                width: "100%",
                                padding: "6px 10px",
                                borderRadius: "6px",
                                fontSize: "0.85rem",
                                fontWeight: 600,
                              }}
                            />
                          </div>
                          <div>
                            <div
                              style={{
                                fontSize: "0.8rem",
                                color: "var(--text-muted)",
                                marginBottom: "4px",
                              }}
                            >
                              Statutory Fine Ceiling:
                            </div>
                            <div
                              style={{
                                fontSize: "1.1rem",
                                fontWeight: 700,
                                color: "var(--danger)",
                              }}
                            >
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
                            </div>
                          </div>
                          <div>
                            <div
                              style={{
                                fontSize: "0.8rem",
                                color: "var(--text-muted)",
                                marginBottom: "4px",
                              }}
                            >
                              Executive Board Liability Exposure:
                            </div>
                            <div
                              style={{
                                fontSize: "0.85rem",
                                fontWeight: 600,
                                color: "var(--warning)",
                              }}
                            >
                              Article 20 Personal Liability & Operational Ban
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {selectedFrameworkId === "cfw_nis2" && (
                      <div
                        style={{
                          background: "#f8fafc",
                          border: "1px solid #cbd5e1",
                          borderRadius: "8px",
                          padding: "16px",
                          marginBottom: "20px",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            marginBottom: "10px",
                          }}
                        >
                          <h4
                            style={{
                              margin: 0,
                              color: "#1e293b",
                              fontSize: "0.95rem",
                            }}
                          >
                            🚨 Article 23 CSIRT Mandatory Incident Reporting SLA
                            Readiness Tracker
                          </h4>
                          <span
                            style={{
                              background: "#059669",
                              color: "#fff",
                              fontSize: "0.75rem",
                              fontWeight: 700,
                              padding: "3px 8px",
                              borderRadius: "4px",
                            }}
                          >
                            Directive SLA Enforced
                          </span>
                        </div>

                        <div
                          style={{
                            display: "grid",
                            gridTemplateColumns: "1fr 1fr 1fr",
                            gap: "12px",
                          }}
                        >
                          <div
                            style={{
                              background: "#ffffff",
                              padding: "12px",
                              borderRadius: "6px",
                              border: "1px solid #e2e8f0",
                            }}
                          >
                            <div
                              style={{
                                fontSize: "0.78rem",
                                fontWeight: 700,
                                color: "#e11d48",
                                marginBottom: "4px",
                              }}
                            >
                              ⚡ Early Warning (≤ 24 Hours)
                            </div>
                            <p
                              style={{
                                margin: 0,
                                fontSize: "0.78rem",
                                color: "#475569",
                              }}
                            >
                              Submit initial CSIRT warning indicating whether
                              incident is suspect/unlawful or has cross-border
                              impact.
                            </p>
                          </div>

                          <div
                            style={{
                              background: "#ffffff",
                              padding: "12px",
                              borderRadius: "6px",
                              border: "1px solid #e2e8f0",
                            }}
                          >
                            <div
                              style={{
                                fontSize: "0.78rem",
                                fontWeight: 700,
                                color: "#d97706",
                                marginBottom: "4px",
                              }}
                            >
                              ⏰ Incident Notification (≤ 72 Hours)
                            </div>
                            <p
                              style={{
                                margin: 0,
                                fontSize: "0.78rem",
                                color: "#475569",
                              }}
                            >
                              Submit formal incident notification updating
                              initial assessment, severity metrics, and
                              technical IoC indicators.
                            </p>
                          </div>

                          <div
                            style={{
                              background: "#ffffff",
                              padding: "12px",
                              borderRadius: "6px",
                              border: "1px solid #e2e8f0",
                            }}
                          >
                            <div
                              style={{
                                fontSize: "0.78rem",
                                fontWeight: 700,
                                color: "#2563eb",
                                marginBottom: "4px",
                              }}
                            >
                              📋 Final Report (≤ 1 Month)
                            </div>
                            <p
                              style={{
                                margin: 0,
                                fontSize: "0.78rem",
                                color: "#475569",
                              }}
                            >
                              Provide complete root-cause analysis, forensic
                              evidence, technical remediations applied, and
                              cross-border impact.
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                    <div className="quadrant-grid">
                      {Object.entries(summary.quadrant_scores || {}).map(
                        ([key, val]) => (
                          <div key={key} className="quad-item">
                            <span
                              className={
                                ["GV", "ID", "PR", "DE", "RS", "RC"].includes(
                                  key,
                                )
                                  ? `nist-badge nist-badge--${key}`
                                  : "quad-label"
                              }
                            >
                              {THEME_LABELS[key] || key}
                            </span>
                            <div className="progress-container">
                              <div
                                className="comp-progress-fill"
                                style={{ width: `${val}%` }}
                              />
                            </div>
                            <span className="quad-value">{val}%</span>
                          </div>
                        ),
                      )}
                    </div>
                  </>
                )}
              </div>
            </div>
          )}

          {activeTab === "marketplace" && (
            <div className="marketplace-view grid-3">
              {marketplace.map((fw) => (
                <div key={fw.framework_id} className="framework-card">
                  <div className="framework-card-header">
                    <div className="fw-icon">🔒</div>
                    <h3>{fw.name}</h3>
                    <p className="fw-meta">
                      Code: {fw.code} | Version: {fw.version}
                    </p>
                    <p className="fw-reqs">
                      Total Requirements: {fw.controls_count}
                    </p>
                  </div>
                  <div className="framework-card-actions">
                    {fw.is_installed ? (
                      <>
                        <div className="framework-installed-badge">
                          ✓ Installed
                        </div>
                        <button
                          className="db-btn db-btn--danger fw-action-btn"
                          onClick={() =>
                            handleUninstallFramework(fw.framework_id)
                          }
                        >
                          Uninstall
                        </button>
                      </>
                    ) : (
                      <>
                        <div className="framework-status-placeholder" />
                        <button
                          className="db-btn db-btn--primary fw-action-btn"
                          onClick={() =>
                            handleInstallFramework(fw.framework_id)
                          }
                        >
                          Install
                        </button>
                      </>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {activeTab === "policies" && (
            <div
              ref={policiesPagination.cardRef}
              className="db-card"
              style={{ padding: 0 }}
            >
              <PaginationBar
                currentPage={policiesPagination.page}
                pageSize={policiesPagination.pageSize}
                totalItems={policies.length}
                totalPages={policiesPagination.totalPages}
                onPageChange={policiesPagination.setPage}
                onPageSizeChange={policiesPagination.setPageSize}
                loading={loading}
                itemLabel="policies"
                sizerOptions={[10, 25, 50, 100]}
              />
              <div className="db-table-wrap">
                <table className="db-table">
                  <thead>
                    <tr>
                      <th>Baseline Name</th>
                      <th>Platform</th>
                      <th>Version</th>
                      <th>Rules Count</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {policies.length === 0 && (
                      <tr>
                        <td
                          colSpan={5}
                          style={{ textAlign: "center", padding: "24px" }}
                        >
                          No baseline policies defined. Click "Create Baseline
                          Policy" to define one.
                        </td>
                      </tr>
                    )}
                    {policiesPagination.paginatedItems.map((p) => (
                      <React.Fragment key={p.id}>
                        <tr
                          onClick={() => handleTogglePolicy(p.id)}
                          style={{
                            cursor: "pointer",
                            transition: "background 0.2s",
                          }}
                          onMouseEnter={(e) =>
                            (e.currentTarget.style.background =
                              "rgba(0,0,0,0.02)")
                          }
                          onMouseLeave={(e) =>
                            (e.currentTarget.style.background = "none")
                          }
                        >
                          <td style={{ fontWeight: 600 }}>
                            <span
                              style={{
                                marginRight: 8,
                                display: "inline-block",
                                width: 12,
                              }}
                            >
                              {expandedPolicyId === p.id ? "▼" : "▶"}
                            </span>
                            {p.name}
                          </td>
                          <td>
                            <span className="db-tag">{p.target_platform}</span>
                          </td>
                          <td className="mono">v{p.version_number}</td>
                          <td style={{ fontWeight: 600 }}>{p.rules_count}</td>
                          <td>
                            <span className="db-status db-status--complete">
                              {p.status}
                            </span>
                          </td>
                        </tr>
                        {expandedPolicyId === p.id && (
                          <tr>
                            <td
                              colSpan={5}
                              style={{
                                background: "rgba(0,0,0,0.02)",
                                padding: "20px 24px",
                              }}
                            >
                              <h4
                                style={{
                                  margin: "0 0 12px 0",
                                  fontSize: "0.85rem",
                                  display: "flex",
                                  alignItems: "center",
                                  gap: 8,
                                }}
                              >
                                <span style={{ color: "var(--accent)" }}>
                                  📋
                                </span>{" "}
                                Policy Rules & Check Parameters
                              </h4>
                              {loadingRules ? (
                                <div
                                  style={{
                                    padding: 12,
                                    color: "var(--text-muted)",
                                    fontSize: "0.8rem",
                                  }}
                                >
                                  Loading policy rules...
                                </div>
                              ) : policyRules.length === 0 ? (
                                <div
                                  style={{
                                    padding: 12,
                                    color: "var(--text-muted)",
                                    fontSize: "0.8rem",
                                  }}
                                >
                                  No rules linked to this policy.
                                </div>
                              ) : (
                                <div
                                  className="db-table-wrap"
                                  style={{
                                    border: "1px solid var(--border)",
                                    borderRadius: 6,
                                    maxHeight: "400px",
                                    overflowY: "auto",
                                    background: "#fff",
                                  }}
                                >
                                  <table
                                    className="db-table"
                                    style={{ margin: 0 }}
                                  >
                                    <thead>
                                      <tr>
                                        <th
                                          style={{
                                            background: "#f8f9fa",
                                            position: "sticky",
                                            top: 0,
                                            zIndex: 1,
                                          }}
                                        >
                                          Control ID
                                        </th>
                                        <th
                                          style={{
                                            background: "#f8f9fa",
                                            position: "sticky",
                                            top: 0,
                                            zIndex: 1,
                                          }}
                                        >
                                          Rule & Control Title
                                        </th>
                                        <th
                                          style={{
                                            background: "#f8f9fa",
                                            position: "sticky",
                                            top: 0,
                                            zIndex: 1,
                                          }}
                                        >
                                          Severity
                                        </th>
                                        <th
                                          style={{
                                            background: "#f8f9fa",
                                            position: "sticky",
                                            top: 0,
                                            zIndex: 1,
                                          }}
                                        >
                                          Checking Logic
                                        </th>
                                        <th
                                          style={{
                                            background: "#f8f9fa",
                                            position: "sticky",
                                            top: 0,
                                            zIndex: 1,
                                          }}
                                        >
                                          Actions
                                        </th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {policyRules.map((r) => {
                                        const sevClass =
                                          r.severity === "CRITICAL"
                                            ? "db-sev-badge--critical"
                                            : r.severity === "HIGH"
                                              ? "db-sev-badge--high"
                                              : r.severity === "MEDIUM"
                                                ? "db-sev-badge--medium"
                                                : r.severity === "LOW"
                                                  ? "db-sev-badge--low"
                                                  : "db-sev-badge--info";
                                        return (
                                          <tr key={r.id}>
                                            <td
                                              className="mono"
                                              style={{
                                                fontSize: "0.72rem",
                                                fontWeight: 600,
                                              }}
                                            >
                                              {(() => {
                                                const rawNum =
                                                  r.control_number ||
                                                  (r.control_id
                                                    ? r.control_id
                                                        .replace(
                                                          "cct_iso27001_2022_",
                                                          "",
                                                        )
                                                        .replace(
                                                          "cct_nist_csf_v2_",
                                                          "",
                                                        )
                                                        .replace("_", ".")
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
                                              })()}
                                            </td>
                                            <td>
                                              <div
                                                style={{
                                                  fontWeight: 600,
                                                  fontSize: "0.76rem",
                                                }}
                                              >
                                                {r.control_title}
                                              </div>
                                              <div
                                                style={{
                                                  fontSize: "0.68rem",
                                                  color: "var(--text-muted)",
                                                }}
                                              >
                                                Rule Code:{" "}
                                                <span className="mono">
                                                  {r.rule_name}
                                                </span>
                                              </div>
                                            </td>
                                            <td>
                                              <span
                                                className={`db-sev-badge ${sevClass}`}
                                                style={{
                                                  textTransform: "capitalize",
                                                }}
                                              >
                                                {r.severity
                                                  ? r.severity.toLowerCase()
                                                  : "medium"}
                                              </span>
                                            </td>
                                            <td style={{ fontSize: "0.72rem" }}>
                                              {r.evidence_source ===
                                              "manual" ? (
                                                <span className="db-tag">
                                                  Manual Review
                                                </span>
                                              ) : (
                                                <div>
                                                  <span className="db-tag db-tag--primary">
                                                    {r.evidence_source}
                                                  </span>
                                                  {r.check_definition && (
                                                    <code
                                                      className="mono"
                                                      style={{
                                                        display: "block",
                                                        fontSize: "0.65rem",
                                                        marginTop: 4,
                                                        color: "var(--accent)",
                                                      }}
                                                    >
                                                      {r.check_definition.key}{" "}
                                                      {
                                                        r.check_definition
                                                          .operator
                                                      }{" "}
                                                      {
                                                        r.check_definition
                                                          .expected
                                                      }
                                                    </code>
                                                  )}
                                                </div>
                                              )}
                                            </td>
                                            <td>
                                              <button
                                                className="db-btn db-btn--ghost"
                                                style={{
                                                  padding: "4px 8px",
                                                  fontSize: "0.68rem",
                                                }}
                                                onClick={(e) => {
                                                  e.stopPropagation();
                                                  handleOpenEditRule({
                                                    rule_id: r.id,
                                                    rule_name: r.rule_name,
                                                    severity: r.severity,
                                                    check_definition:
                                                      r.check_definition,
                                                    control_title:
                                                      r.control_title,
                                                    evidence: {},
                                                  });
                                                }}
                                              >
                                                Configure
                                              </button>
                                            </td>
                                          </tr>
                                        );
                                      })}
                                    </tbody>
                                  </table>
                                </div>
                              )}
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === "findings" &&
            (() => {
              return (
                <div
                  ref={findingsPagination.cardRef}
                  className="db-card"
                  style={{ padding: 0 }}
                >
                  {/* Filter controls bar */}
                  <div
                    style={{
                      display: "flex",
                      gap: "12px",
                      padding: "16px 24px",
                      background: "rgba(0,0,0,0.02)",
                      borderBottom: "1px solid var(--border)",
                      borderTopLeftRadius: 8,
                      borderTopRightRadius: 8,
                      flexWrap: "wrap",
                      alignItems: "center",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: "4px",
                      }}
                    >
                      <label
                        style={{
                          fontSize: "0.7rem",
                          color: "var(--text-muted)",
                          fontWeight: 600,
                        }}
                      >
                        SEARCH FINDINGS
                      </label>
                      <input
                        type="text"
                        placeholder="Search by Control, Rule..."
                        className="db-input"
                        value={filterSearch}
                        onChange={(e) => setFilterSearch(e.target.value)}
                        style={{
                          minWidth: "220px",
                          padding: "6px 12px",
                          fontSize: "0.8rem",
                          border: "1px solid var(--border)",
                          borderRadius: "4px",
                        }}
                      />
                    </div>

                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: "4px",
                      }}
                    >
                      <label
                        style={{
                          fontSize: "0.7rem",
                          color: "var(--text-muted)",
                          fontWeight: 600,
                        }}
                      >
                        FILTER BY ASSET
                      </label>
                      <select
                        className="db-select"
                        value={filterAsset}
                        onChange={(e) => setFilterAsset(e.target.value)}
                        style={{
                          minWidth: "180px",
                          padding: "6px 12px",
                          fontSize: "0.8rem",
                          border: "1px solid var(--border)",
                          borderRadius: "4px",
                          background: "#fff",
                        }}
                      >
                        <option value="all">All Assets</option>
                        {uniqueAssets.map((a) => (
                          <option key={a.id} value={a.id}>
                            {a.hostname && a.hostname !== "Unknown"
                              ? `${a.hostname} (${a.ip})`
                              : a.ip || a.id}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: "4px",
                      }}
                    >
                      <label
                        style={{
                          fontSize: "0.7rem",
                          color: "var(--text-muted)",
                          fontWeight: 600,
                        }}
                      >
                        STATUS
                      </label>
                      <select
                        className="db-select"
                        value={filterStatus}
                        onChange={(e) => setFilterStatus(e.target.value)}
                        style={{
                          minWidth: "120px",
                          padding: "6px 12px",
                          fontSize: "0.8rem",
                          border: "1px solid var(--border)",
                          borderRadius: "4px",
                          background: "#fff",
                        }}
                      >
                        <option value="all">All Statuses</option>
                        <option value="pass">Pass</option>
                        <option value="fail">Fail</option>
                        <option value="manual_review">Manual Review</option>
                      </select>
                    </div>

                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: "4px",
                      }}
                    >
                      <label
                        style={{
                          fontSize: "0.7rem",
                          color: "var(--text-muted)",
                          fontWeight: 600,
                        }}
                      >
                        SEVERITY
                      </label>
                      <select
                        className="db-select"
                        value={filterSeverity}
                        onChange={(e) => setFilterSeverity(e.target.value)}
                        style={{
                          minWidth: "120px",
                          padding: "6px 12px",
                          fontSize: "0.8rem",
                          border: "1px solid var(--border)",
                          borderRadius: "4px",
                          background: "#fff",
                        }}
                      >
                        <option value="all">All Severities</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                      </select>
                    </div>

                    {selectedFrameworkId === "cfw_cis_v8_1" && (
                      <div
                        style={{
                          display: "flex",
                          flexDirection: "column",
                          gap: "4px",
                        }}
                      >
                        <label
                          style={{
                            fontSize: "0.7rem",
                            color: "var(--text-muted)",
                            fontWeight: 600,
                          }}
                        >
                          IMPLEMENTATION GROUP
                        </label>
                        <select
                          className="db-select"
                          value={filterIg}
                          onChange={(e) => setFilterIg(e.target.value)}
                          style={{
                            minWidth: "160px",
                            padding: "6px 12px",
                            fontSize: "0.8rem",
                            border: "1px solid var(--border)",
                            borderRadius: "4px",
                            background: "#fff",
                          }}
                        >
                          <option value="all">All Groups (IG1-3)</option>
                          <option value="ig1">IG1 (Cyber Hygiene)</option>
                          <option value="ig2">IG2 (Enterprise)</option>
                          <option value="ig3">IG3 (Advanced)</option>
                        </select>
                      </div>
                    )}

                    {(filterSearch ||
                      filterAsset !== "all" ||
                      filterStatus !== "all" ||
                      filterSeverity !== "all") && (
                      <button
                        className="db-btn db-btn--ghost"
                        onClick={() => {
                          setFilterSearch("");
                          setFilterAsset("all");
                          setFilterStatus("all");
                          setFilterSeverity("all");
                          findingsPagination.setPage(1);
                        }}
                        style={{
                          padding: "6px 12px",
                          fontSize: "0.8rem",
                          marginTop: "16px",
                        }}
                      >
                        Clear Filters
                      </button>
                    )}
                  </div>

                  <PaginationBar
                    currentPage={findingsPagination.page}
                    pageSize={findingsPagination.pageSize}
                    totalItems={filteredFindings.length}
                    totalPages={findingsPagination.totalPages}
                    onPageChange={findingsPagination.setPage}
                    onPageSizeChange={findingsPagination.setPageSize}
                    loading={loading}
                    sizerOptions={[25, 50, 100, 250]}
                    customSummary={
                      filteredFindings.length === 0
                        ? "No findings match your filters"
                        : `Showing ${(findingsPagination.displayPage - 1) * findingsPagination.pageSize + 1}–${Math.min(findingsPagination.displayPage * findingsPagination.pageSize, filteredFindings.length)} of ${filteredFindings.length} findings${
                            findings.length !== filteredFindings.length
                              ? ` (filtered from ${findings.length} total)`
                              : ""
                          }`
                    }
                  />

                  <div
                    className="db-table-wrap"
                    style={{ borderTopLeftRadius: 0, borderTopRightRadius: 0 }}
                  >
                    <table className="db-table">
                      <thead>
                        <tr>
                          <th>Control ID</th>
                          <th>Rule / Control Title</th>
                          <th>Severity</th>
                          <th>Asset Name / IP</th>
                          <th>Scan Mode</th>
                          <th>Status</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {loading ? (
                          [1, 2, 3, 4, 5].map((i) => (
                            <tr key={i}>
                              <td>
                                <Skeleton h={16} w={120} />
                              </td>
                              <td>
                                <Skeleton
                                  h={16}
                                  w={200}
                                  style={{ marginBottom: 4 }}
                                />
                                <Skeleton h={10} w={100} />
                              </td>
                              <td>
                                <Skeleton h={20} w={60} />
                              </td>
                              <td>
                                <Skeleton h={14} w={100} />
                              </td>
                              <td>
                                <Skeleton h={18} w={80} />
                              </td>
                              <td>
                                <Skeleton h={20} w={70} />
                              </td>
                              <td>
                                <Skeleton h={24} w={150} />
                              </td>
                            </tr>
                          ))
                        ) : filteredFindings.length === 0 ? (
                          <tr>
                            <td
                              colSpan={7}
                              style={{ textAlign: "center", padding: "24px" }}
                            >
                              No matching compliance findings discovered.
                            </td>
                          </tr>
                        ) : (
                          findingsPagination.paginatedItems.map((f) => {
                            const sevClass =
                              f.severity === "CRITICAL"
                                ? "db-sev-badge--critical"
                                : f.severity === "HIGH"
                                  ? "db-sev-badge--high"
                                  : f.severity === "MEDIUM"
                                    ? "db-sev-badge--medium"
                                    : f.severity === "LOW"
                                      ? "db-sev-badge--low"
                                      : "db-sev-badge--info";
                            return (
                              <tr key={f.id}>
                                <td
                                  className="mono"
                                  style={{ fontWeight: 600 }}
                                >
                                  {f.control_id}
                                </td>
                                <td>
                                  <div style={{ fontWeight: 600 }}>
                                    {f.control_title}
                                  </div>
                                  {f.rule_name && (
                                    <div
                                      style={{
                                        fontSize: "0.68rem",
                                        color: "var(--text-muted)",
                                      }}
                                    >
                                      Rule Code:{" "}
                                      <span className="mono">
                                        {f.rule_name}
                                      </span>
                                    </div>
                                  )}
                                </td>
                                <td>
                                  <span
                                    className={`db-sev-badge ${sevClass}`}
                                    style={{ textTransform: "capitalize" }}
                                  >
                                    {f.severity
                                      ? f.severity.toLowerCase()
                                      : "medium"}
                                  </span>
                                </td>
                                <td style={{ fontSize: "0.72rem" }}>
                                  {f.asset_hostname &&
                                  f.asset_hostname !== "Unknown" ? (
                                    <div>
                                      <div
                                        style={{
                                          display: "flex",
                                          alignItems: "center",
                                          gap: "6px",
                                        }}
                                      >
                                        <span style={{ fontWeight: 600 }}>
                                          {f.asset_hostname}
                                        </span>
                                        {f.asset_reboot_pending && (
                                          <span
                                            className="db-status"
                                            style={{
                                              background:
                                                "rgba(234,179,8,0.12)",
                                              color: "#fcd34d",
                                              fontSize: "0.58rem",
                                              padding: "1px 5px",
                                              borderRadius: "3px",
                                              lineHeight: "1",
                                            }}
                                            title="System reboot is required to apply configuration changes."
                                          >
                                            Reboot Required
                                          </span>
                                        )}
                                      </div>
                                      <div
                                        style={{
                                          color: "var(--text-muted)",
                                          fontSize: "0.68rem",
                                        }}
                                        className="mono"
                                      >
                                        {f.asset_ip}
                                      </div>
                                    </div>
                                  ) : f.asset_ip ? (
                                    <div
                                      style={{
                                        display: "flex",
                                        alignItems: "center",
                                        gap: "6px",
                                      }}
                                    >
                                      <span className="mono">{f.asset_ip}</span>
                                      {f.asset_reboot_pending && (
                                        <span
                                          className="db-status"
                                          style={{
                                            background: "rgba(234,179,8,0.12)",
                                            color: "#fcd34d",
                                            fontSize: "0.58rem",
                                            padding: "1px 5px",
                                            borderRadius: "3px",
                                            lineHeight: "1",
                                          }}
                                          title="System reboot is required to apply configuration changes."
                                        >
                                          Reboot Required
                                        </span>
                                      )}
                                    </div>
                                  ) : (
                                    "Global"
                                  )}
                                </td>
                                <td>
                                  <span className="db-tag">{f.source}</span>
                                </td>
                                <td>
                                  <span
                                    className={`db-status ${
                                      f.status === "pass"
                                        ? "db-status--complete"
                                        : f.status === "fail"
                                          ? "db-status--failed"
                                          : "db-status--queued"
                                    }`}
                                  >
                                    {f.status}
                                  </span>
                                </td>
                                <td className="actions-cell">
                                  {f.status === "fail" && (
                                    <>
                                      <button
                                        className="db-btn db-btn--primary"
                                        style={{
                                          padding: "4px 8px",
                                          fontSize: "0.72rem",
                                        }}
                                        onClick={() => {
                                          setSelectedFinding(f);
                                          setModalType("remediate");
                                          setModalOpen(true);
                                        }}
                                      >
                                        Remediate
                                      </button>
                                      <button
                                        className="db-btn db-btn--ghost"
                                        style={{
                                          padding: "4px 8px",
                                          fontSize: "0.72rem",
                                        }}
                                        onClick={() => {
                                          setSelectedFinding(f);
                                          setModalType("exception");
                                          setModalOpen(true);
                                        }}
                                      >
                                        Waiver
                                      </button>
                                    </>
                                  )}
                                  {f.status === "manual_review" && (
                                    <button
                                      className="db-btn db-btn--primary"
                                      style={{
                                        padding: "4px 8px",
                                        fontSize: "0.72rem",
                                      }}
                                      onClick={() => {
                                        setSelectedControl({
                                          id: f.control_id,
                                          evidence_checklist:
                                            f.control_evidence_checklist || [],
                                        });
                                        setModalType("attest");
                                        setModalOpen(true);
                                      }}
                                    >
                                      Verify
                                    </button>
                                  )}
                                  {f.rule_id && (
                                    <button
                                      className="db-btn db-btn--ghost"
                                      style={{
                                        padding: "4px 8px",
                                        fontSize: "0.72rem",
                                      }}
                                      onClick={() => handleOpenEditRule(f)}
                                    >
                                      Edit Rule
                                    </button>
                                  )}
                                </td>
                              </tr>
                            );
                          })
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              );
            })()}

          {activeTab === "exceptions" && (
            <div
              ref={exceptionsPagination.cardRef}
              className="db-card"
              style={{ padding: 0 }}
            >
              <PaginationBar
                currentPage={exceptionsPagination.page}
                pageSize={exceptionsPagination.pageSize}
                totalItems={exceptions.length}
                totalPages={exceptionsPagination.totalPages}
                onPageChange={exceptionsPagination.setPage}
                onPageSizeChange={exceptionsPagination.setPageSize}
                loading={loading}
                itemLabel="waivers"
                sizerOptions={[10, 25, 50, 100]}
              />
              <div className="db-table-wrap">
                <table className="db-table">
                  <thead>
                    <tr>
                      <th>Control ID</th>
                      <th>Asset ID</th>
                      <th>Waiver Reason</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {exceptions.length === 0 && (
                      <tr>
                        <td
                          colSpan={4}
                          style={{ textAlign: "center", padding: "24px" }}
                        >
                          No pending exceptions or waivers recorded.
                        </td>
                      </tr>
                    )}
                    {exceptionsPagination.paginatedItems.map((exc) => (
                      <tr key={exc.id}>
                        <td className="mono" style={{ fontWeight: 600 }}>
                          {exc.control_id}
                        </td>
                        <td className="mono">{exc.asset_id || "Global"}</td>
                        <td>{exc.evidence?.note || exc.reason || "—"}</td>
                        <td>
                          <span className="db-status db-status--queued">
                            {exc.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === "credentials" && (
            <div
              style={{ display: "flex", gap: "24px", alignItems: "flex-start" }}
            >
              <div
                ref={credentialsPagination.cardRef}
                className="db-card"
                style={{ flex: 1, padding: 0 }}
              >
                <div
                  style={{
                    padding: "16px 24px",
                    borderBottom: "1px solid var(--border)",
                    fontWeight: 600,
                  }}
                >
                  Saved Credentials
                </div>
                <PaginationBar
                  currentPage={credentialsPagination.page}
                  pageSize={credentialsPagination.pageSize}
                  totalItems={credentialsList.length}
                  totalPages={credentialsPagination.totalPages}
                  onPageChange={credentialsPagination.setPage}
                  onPageSizeChange={credentialsPagination.setPageSize}
                  loading={loading}
                  itemLabel="credentials"
                  sizerOptions={[10, 25, 50, 100]}
                />
                <div className="db-table-wrap">
                  <table className="db-table">
                    <thead>
                      <tr>
                        <th>Nickname</th>
                        <th>Username</th>
                        <th>Port</th>
                        <th>Auth Method</th>
                        {isComplianceAdmin && <th>Actions</th>}
                      </tr>
                    </thead>
                    <tbody>
                      {credentialsList.length === 0 && (
                        <tr>
                          <td
                            colSpan={isComplianceAdmin ? 5 : 4}
                            style={{ textAlign: "center", padding: "24px" }}
                          >
                            No saved credentials registered.
                          </td>
                        </tr>
                      )}
                      {credentialsPagination.paginatedItems.map((c) => (
                        <tr key={c.id}>
                          <td style={{ fontWeight: 600 }}>{c.name}</td>
                          <td>{c.username}</td>
                          <td className="mono">{c.port}</td>
                          <td>
                            <span
                              className={`db-tag ${c.auth_method === "key" ? "db-tag--primary" : ""}`}
                            >
                              {c.auth_method === "key" ? "SSH Key" : "Password"}
                            </span>
                          </td>
                          {isComplianceAdmin && (
                            <td>
                              <button
                                className="db-btn db-btn--ghost"
                                style={{
                                  padding: "4px 8px",
                                  fontSize: "0.68rem",
                                  color: "var(--critical)",
                                }}
                                onClick={async () => {
                                  if (
                                    window.confirm(
                                      `Are you sure you want to delete ${c.name}?`,
                                    )
                                  ) {
                                    try {
                                      await axiosInstance.delete(
                                        `/compliance/credentials/${c.id}`,
                                      );
                                      pushToast(
                                        "Credential deleted successfully.",
                                        "success",
                                      );
                                      fetchTabData();
                                    } catch (e) {
                                      pushToast(
                                        "Delete failed: " +
                                          (e.response?.data?.detail ||
                                            e.response?.data?.message ||
                                            e.message),
                                        "error",
                                      );
                                    }
                                  }
                                }}
                              >
                                Delete
                              </button>
                            </td>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {isComplianceAdmin && (
                <div className="db-card" style={{ width: "350px" }}>
                  <div style={{ fontWeight: 600, marginBottom: "16px" }}>
                    Register Credential
                  </div>
                  <form
                    className="compliance-form"
                    onSubmit={async (e) => {
                      e.preventDefault();
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
                      }
                    }}
                  >
                    <label>Name / Nickname</label>
                    <input
                      type="text"
                      value={newCredName}
                      onChange={(e) => setNewCredName(e.target.value)}
                      placeholder="e.g. Production Webservers"
                      required
                    />

                    <label>Username</label>
                    <input
                      type="text"
                      value={newCredUsername}
                      onChange={(e) => setNewCredUsername(e.target.value)}
                      placeholder="e.g. root"
                      required
                    />

                    <label>Port</label>
                    <input
                      type="number"
                      value={newCredPort}
                      onChange={(e) => setNewCredPort(e.target.value)}
                      required
                    />

                    <label>Authentication Method</label>
                    <select
                      value={newCredAuthMethod}
                      onChange={(e) => setNewCredAuthMethod(e.target.value)}
                    >
                      <option value="password">Password</option>
                      <option value="key">Private SSH Key</option>
                    </select>

                    {newCredAuthMethod === "password" ? (
                      <>
                        <label>Password</label>
                        <input
                          type="password"
                          value={newCredPassword}
                          onChange={(e) => setNewCredPassword(e.target.value)}
                          placeholder="••••••••"
                          required
                        />
                      </>
                    ) : (
                      <>
                        <label>Private Key Content</label>
                        <textarea
                          value={newCredKeyContent}
                          onChange={(e) => setNewCredKeyContent(e.target.value)}
                          placeholder="-----BEGIN OpenSSH PRIVATE KEY-----..."
                          style={{
                            fontFamily: "monospace",
                            fontSize: "0.72rem",
                            height: "100px",
                          }}
                          required
                        />
                      </>
                    )}

                    <button
                      type="submit"
                      className="db-btn db-btn--primary"
                      style={{ marginTop: "1rem", width: "100%" }}
                    >
                      Save Target Credential
                    </button>
                  </form>
                </div>
              )}
            </div>
          )}

          {activeTab === "approvals" && (
            <div
              ref={approvalsPagination.cardRef}
              className="db-card"
              style={{ padding: 0 }}
            >
              <div
                style={{
                  padding: "16px 24px",
                  borderBottom: "1px solid var(--border)",
                  fontWeight: 600,
                }}
              >
                Remediation Approvals Queue
              </div>
              <PaginationBar
                currentPage={approvalsPagination.page}
                pageSize={approvalsPagination.pageSize}
                totalItems={approvalsList.length}
                totalPages={approvalsPagination.totalPages}
                onPageChange={approvalsPagination.setPage}
                onPageSizeChange={approvalsPagination.setPageSize}
                loading={loading}
                itemLabel="tickets"
                sizerOptions={[10, 25, 50, 100]}
              />
              <div className="db-table-wrap">
                <table className="db-table">
                  <thead>
                    <tr>
                      <th>Ticket ID</th>
                      <th>Control & Asset</th>
                      <th>Fix Command</th>
                      <th>Requested By</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {approvalsList.length === 0 && (
                      <tr>
                        <td
                          colSpan={6}
                          style={{ textAlign: "center", padding: "24px" }}
                        >
                          No approval tickets in this status.
                        </td>
                      </tr>
                    )}
                    {approvalsPagination.paginatedItems.map((req) => (
                      <tr key={req.id}>
                        <td className="mono" style={{ fontSize: "0.72rem" }}>
                          {req.id}
                        </td>
                        <td>
                          <div style={{ fontWeight: 600, fontSize: "0.78rem" }}>
                            {req.id.startsWith("crrq_rollback_") && (
                              <span
                                style={{
                                  background: "rgba(245, 124, 0, 0.1)",
                                  color: "#f57c00",
                                  padding: "2px 6px",
                                  borderRadius: "4px",
                                  fontSize: "0.65rem",
                                  marginRight: "8px",
                                  fontWeight: 700,
                                  textTransform: "uppercase",
                                }}
                              >
                                Rollback
                              </span>
                            )}
                            {req.control_id} - {req.control_title}
                          </div>
                          <div
                            style={{
                              fontSize: "0.68rem",
                              color: "var(--text-muted)",
                            }}
                          >
                            Target Host:{" "}
                            <span className="mono">{req.asset_ip}</span>
                          </div>
                        </td>
                        <td
                          className="mono"
                          style={{
                            fontSize: "0.68rem",
                            maxWidth: "250px",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          <code>{req.fix_command}</code>
                        </td>
                        <td style={{ fontSize: "0.75rem" }}>
                          {req.requested_by}
                        </td>
                        <td>
                          <span
                            className={`db-status ${
                              req.status === "pending_approval"
                                ? "db-status--queued"
                                : req.status === "approved" ||
                                    req.status === "executed"
                                  ? "db-status--active"
                                  : "db-status--suspended"
                            }`}
                            style={{ textTransform: "capitalize" }}
                          >
                            {req.status.replace("_", " ")}
                          </span>
                        </td>
                        <td>
                          {req.status === "pending_approval" && (
                            <div style={{ display: "flex", gap: "8px" }}>
                              {req.requested_by === user?.id ? (
                                <button
                                  className="db-btn db-btn--ghost"
                                  style={{
                                    padding: "4px 8px",
                                    fontSize: "0.68rem",
                                    color: "var(--critical)",
                                  }}
                                  onClick={async () => {
                                    const label = req.id.startsWith(
                                      "crrq_rollback_",
                                    )
                                      ? "rollback"
                                      : "remediation";
                                    if (
                                      window.confirm(
                                        `Are you sure you want to cancel this ${label} request?`,
                                      )
                                    ) {
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
                                    }
                                  }}
                                >
                                  {req.id.startsWith("crrq_rollback_")
                                    ? "Cancel Rollback"
                                    : "Cancel Request"}
                                </button>
                              ) : isComplianceAdmin ? (
                                <>
                                  <button
                                    className="db-btn db-btn--primary"
                                    style={{
                                      padding: "4px 8px",
                                      fontSize: "0.68rem",
                                    }}
                                    onClick={async () => {
                                      try {
                                        await axiosInstance.post(
                                          `/compliance/remediations/requests/${req.id}/approve`,
                                          { status: "approved" },
                                        );
                                        const label = req.id.startsWith(
                                          "crrq_rollback_",
                                        )
                                          ? "Rollback"
                                          : "Remediation request";
                                        pushToast(
                                          `${label} approved and queued.`,
                                          "success",
                                        );
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
                                    }}
                                  >
                                    Approve
                                  </button>
                                  <button
                                    className="db-btn db-btn--ghost"
                                    style={{
                                      padding: "4px 8px",
                                      fontSize: "0.68rem",
                                      color: "var(--critical)",
                                    }}
                                    onClick={async () => {
                                      try {
                                        await axiosInstance.post(
                                          `/compliance/remediations/requests/${req.id}/approve`,
                                          { status: "rejected" },
                                        );
                                        const label = req.id.startsWith(
                                          "crrq_rollback_",
                                        )
                                          ? "Rollback"
                                          : "Remediation request";
                                        pushToast(
                                          `${label} rejected.`,
                                          "success",
                                        );
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
                                    }}
                                  >
                                    Reject
                                  </button>
                                </>
                              ) : (
                                <span
                                  style={{
                                    fontSize: "0.75rem",
                                    color: "var(--text-muted)",
                                    fontStyle: "italic",
                                  }}
                                >
                                  Pending approval
                                </span>
                              )}
                            </div>
                          )}
                          {(req.status === "executed" ||
                            req.status === "failed") &&
                            req.execution_log && (
                              <div
                                style={{
                                  display: "flex",
                                  gap: "8px",
                                  alignItems: "center",
                                }}
                              >
                                <button
                                  className="db-btn db-btn--ghost"
                                  style={{
                                    padding: "4px 8px",
                                    fontSize: "0.68rem",
                                  }}
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
                                </button>
                                {req.status === "executed" &&
                                  !req.id.startsWith("crrq_rollback_") &&
                                  (() => {
                                    const hasActiveRollback =
                                      approvalsList.some(
                                        (r) =>
                                          r.finding_id === req.finding_id &&
                                          r.id.startsWith("crrq_rollback_") &&
                                          (r.status === "pending_approval" ||
                                            r.status === "approved"),
                                      );
                                    if (!hasActiveRollback) {
                                      return (
                                        <button
                                          className="db-btn db-btn--ghost"
                                          style={{
                                            padding: "4px 8px",
                                            fontSize: "0.68rem",
                                            color: "#f57c00",
                                          }}
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
                                        </button>
                                      );
                                    }
                                    return null;
                                  })()}
                              </div>
                            )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Dynamic Popups Modals */}
      <Modal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        title={
          modalType === "policy"
            ? "Create Policy Baseline"
            : modalType === "attest"
              ? "Control Manual Attestation"
              : modalType === "exception"
                ? "Request Exception Waiver"
                : modalType === "edit_rule"
                  ? "Configure Rule Parameters"
                  : modalType.toUpperCase()
        }
        size={
          modalType === "policy" ||
          modalType === "attest" ||
          modalType === "exception" ||
          modalType === "edit_rule"
            ? "medium"
            : "large"
        }
      >
        {modalType === "policy" && (
          <form onSubmit={handleCreatePolicy} className="compliance-form">
            <label>Policy Name</label>
            <input
              type="text"
              value={newPolicyName}
              onChange={(e) => setNewPolicyName(e.target.value)}
              required
            />
            <label>Target Platform</label>
            <select
              value={newPolicyPlatform}
              onChange={(e) => setNewPolicyPlatform(e.target.value)}
            >
              <option value="any">Any</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
            </select>
            <label>Rules IDs (comma separated)</label>
            <input
              type="text"
              value={newPolicyRules}
              onChange={(e) => setNewPolicyRules(e.target.value)}
              placeholder="crl_net_tls_001_v1, crl_auth_mfa_001_v1"
              required
            />
            <button
              type="submit"
              className="db-btn db-btn--primary"
              style={{ marginTop: "1rem" }}
            >
              Publish Baseline
            </button>
          </form>
        )}

        {modalType === "attest" && (
          <form onSubmit={handleSubmitAttestation} className="compliance-form">
            <label>Select Status</label>
            <select
              value={attestStatus}
              onChange={(e) => setAttestStatus(e.target.value)}
            >
              <option value="pass">Pass</option>
              <option value="fail">Fail</option>
            </select>

            {selectedControl?.evidence_checklist &&
              selectedControl.evidence_checklist.length > 0 && (
                <div style={{ marginTop: "1rem", marginBottom: "1rem" }}>
                  <label
                    style={{
                      fontWeight: 600,
                      display: "block",
                      marginBottom: "6px",
                    }}
                  >
                    Required Audit Evidence Checklist:
                  </label>
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: "6px",
                      background: "rgba(0,0,0,0.03)",
                      padding: "10px",
                      borderRadius: "6px",
                    }}
                  >
                    {selectedControl.evidence_checklist.map((item, idx) => (
                      <label
                        key={idx}
                        style={{
                          fontSize: "0.8rem",
                          display: "flex",
                          alignItems: "center",
                          gap: "8px",
                          cursor: "pointer",
                        }}
                      >
                        <input type="checkbox" defaultChecked />
                        <span>{item}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}

            <label>Attestation Note</label>
            <textarea
              value={attestNote}
              onChange={(e) => setAttestNote(e.target.value)}
              required
            />
            <button
              type="submit"
              className="db-btn db-btn--primary"
              style={{ marginTop: "1rem" }}
            >
              Save Attestation
            </button>
          </form>
        )}

        {modalType === "exception" && (
          <form onSubmit={handleSubmitException} className="compliance-form">
            <label>Reason for Exception Waiver</label>
            <textarea
              value={exceptionReason}
              onChange={(e) => setExceptionReason(e.target.value)}
              required
            />
            <label>Expiry Date</label>
            <input
              type="date"
              value={exceptionExpiry}
              onChange={(e) => setExceptionExpiry(e.target.value)}
              required
            />
            <button
              type="submit"
              className="db-btn db-btn--primary"
              style={{ marginTop: "1rem" }}
            >
              Request Waiver
            </button>
          </form>
        )}

        {modalType === "edit_rule" && selectedFinding && (
          <form onSubmit={handleSubmitEditRule} className="compliance-form">
            <h3 style={{ margin: 0, fontSize: "0.95rem" }}>
              Editing Rule:{" "}
              <span className="mono">{selectedFinding.rule_name}</span>
            </h3>
            <p
              style={{
                margin: "0.25rem 0 1rem",
                fontSize: "0.8rem",
                color: "var(--text-muted)",
              }}
            >
              Control: {selectedFinding.control_title}
            </p>

            <label>Severity Level</label>
            <select
              value={editRuleSeverity}
              onChange={(e) => setEditRuleSeverity(e.target.value)}
            >
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </select>

            <label>Expected Rule Value</label>
            <input
              type="text"
              value={editRuleExpected}
              onChange={(e) => setEditRuleExpected(e.target.value)}
              required
            />
            <p
              style={{
                margin: "0.25rem 0",
                fontSize: "0.72rem",
                color: "var(--text-muted)",
              }}
            >
              Current evidence value is:{" "}
              <code
                className="mono"
                style={{
                  background: "rgba(0,0,0,0.05)",
                  padding: "2px 4px",
                  borderRadius: 3,
                }}
              >
                {JSON.stringify(selectedFinding.evidence)}
              </code>
            </p>

            <button
              type="submit"
              className="db-btn db-btn--primary"
              style={{ marginTop: "1rem" }}
            >
              Save Rule Configuration
            </button>
          </form>
        )}

        {modalType === "gap_analysis" && gapAnalysis && (
          <div
            style={{ display: "flex", flexDirection: "column", gap: "16px" }}
          >
            {/* Interactive Any-to-Any Framework Selector Bar */}
            <div
              style={{
                background: "#f1f5f9",
                padding: "12px 16px",
                borderRadius: "8px",
                border: "1px solid #cbd5e1",
                display: "flex",
                flexWrap: "wrap",
                alignItems: "center",
                justifyContent: "space-between",
                gap: "12px",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "12px",
                  flexWrap: "wrap",
                }}
              >
                <div
                  style={{ display: "flex", alignItems: "center", gap: "6px" }}
                >
                  <label
                    style={{
                      fontSize: "0.8rem",
                      fontWeight: 700,
                      color: "#334155",
                    }}
                  >
                    Source Baseline:
                  </label>
                  <select
                    value={gapSourceFramework}
                    onChange={(e) => setGapSourceFramework(e.target.value)}
                    style={{
                      padding: "5px 8px",
                      borderRadius: "6px",
                      border: "1px solid #cbd5e1",
                      fontSize: "0.82rem",
                      fontWeight: 600,
                      background: "#ffffff",
                    }}
                  >
                    {GAP_FRAMEWORK_OPTIONS.map((fw) => (
                      <option key={`modal_src_${fw.id}`} value={fw.id}>
                        {fw.name}
                      </option>
                    ))}
                  </select>
                </div>

                <span style={{ fontWeight: 800, color: "#64748b" }}>➔</span>

                <div
                  style={{ display: "flex", alignItems: "center", gap: "6px" }}
                >
                  <label
                    style={{
                      fontSize: "0.8rem",
                      fontWeight: 700,
                      color: "#334155",
                    }}
                  >
                    Target Mandate:
                  </label>
                  <select
                    value={gapTargetFramework}
                    onChange={(e) => setGapTargetFramework(e.target.value)}
                    style={{
                      padding: "5px 8px",
                      borderRadius: "6px",
                      border: "1px solid #cbd5e1",
                      fontSize: "0.82rem",
                      fontWeight: 600,
                      background: "#ffffff",
                    }}
                  >
                    {GAP_FRAMEWORK_OPTIONS.map((fw) => (
                      <option key={`modal_tgt_${fw.id}`} value={fw.id}>
                        {fw.name}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <button
                className="db-btn db-btn--primary"
                onClick={() =>
                  fetchGapAnalysis(gapSourceFramework, gapTargetFramework)
                }
                disabled={loadingGapAnalysis}
                style={{
                  padding: "6px 14px",
                  fontSize: "0.82rem",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                }}
              >
                <span>🔄</span>{" "}
                {loadingGapAnalysis ? "Calculating..." : "Recalculate Gap"}
              </button>
            </div>
            <div
              style={{
                background: "#f8fafc",
                padding: "16px",
                borderRadius: "8px",
                border: "1px solid #e2e8f0",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                }}
              >
                <div>
                  <h3 style={{ margin: 0, fontSize: "1.05rem" }}>
                    {gapAnalysis.source_framework?.code} ➔{" "}
                    {gapAnalysis.target_framework?.code}
                  </h3>
                  <p
                    style={{
                      margin: "4px 0 0",
                      fontSize: "0.8rem",
                      color: "var(--text-muted)",
                    }}
                  >
                    Estimated baseline compliance posture for{" "}
                    {gapAnalysis.target_framework?.name} based on existing{" "}
                    {gapAnalysis.source_framework?.name} scan findings.
                  </p>
                </div>
                <div
                  style={{
                    fontSize: "2rem",
                    fontWeight: 800,
                    color: "var(--accent)",
                  }}
                >
                  {gapAnalysis.summary?.estimated_score_pct}%
                </div>
              </div>
              <div
                style={{
                  display: "flex",
                  gap: "16px",
                  marginTop: "12px",
                  fontSize: "0.8rem",
                }}
              >
                <div>
                  Target Controls:{" "}
                  <strong>{gapAnalysis.summary?.total_target_controls}</strong>
                </div>
                <div>
                  Crosswalk Mapped:{" "}
                  <strong>{gapAnalysis.summary?.mapped_controls}</strong>
                </div>
                <div>
                  Estimated Pass:{" "}
                  <strong style={{ color: "var(--ok)" }}>
                    {gapAnalysis.summary?.estimated_pass}
                  </strong>
                </div>
                <div>
                  Estimated Fail:{" "}
                  <strong style={{ color: "var(--danger)" }}>
                    {gapAnalysis.summary?.estimated_fail}
                  </strong>
                </div>
              </div>
            </div>

            <div style={{ maxHeight: "350px", overflowY: "auto" }}>
              <table className="db-table" style={{ fontSize: "0.78rem" }}>
                <thead>
                  <tr>
                    <th>
                      {gapAnalysis.target_framework?.code || "Target"} Control
                    </th>
                    <th>Title</th>
                    <th>
                      Mapped {gapAnalysis.source_framework?.code || "Source"}{" "}
                      Controls
                    </th>
                    <th>Estimated Status</th>
                  </tr>
                </thead>
                <tbody>
                  {(gapAnalysis.controls || []).map((c) => (
                    <tr key={c.control_id}>
                      <td className="mono" style={{ fontWeight: 600 }}>
                        {c.control_number}
                      </td>
                      <td>{c.title}</td>
                      <td>
                        {(c.crosswalk || []).map((iso) => (
                          <span
                            key={iso}
                            className="crosswalk-tag"
                            style={{ marginRight: 4 }}
                          >
                            {iso}
                          </span>
                        ))}
                      </td>
                      <td>
                        <span
                          className={`db-sev-badge ${
                            c.estimated_status === "pass"
                              ? "db-sev-badge--low"
                              : c.estimated_status === "fail"
                                ? "db-sev-badge--critical"
                                : "db-sev-badge--info"
                          }`}
                        >
                          {c.estimated_status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {(modalType === "remediate" || modalType === "rollback") &&
          selectedFinding && (
            <div
              className="compliance-form"
              style={{ display: "flex", flexDirection: "column", gap: "12px" }}
            >
              <div>
                <h3 style={{ margin: 0, fontSize: "0.95rem" }}>
                  {modalType === "rollback"
                    ? "Rollback Security Rule"
                    : "Remediation Guide"}
                  : <span className="mono">{selectedFinding.control_id}</span>
                </h3>
                <p
                  style={{
                    margin: "0.25rem 0 1rem",
                    fontSize: "0.8rem",
                    color: "var(--text-muted)",
                  }}
                >
                  Control Name: {selectedFinding.control_title}
                </p>
              </div>

              <div
                style={{
                  padding: "12px",
                  background: "rgba(0,0,0,0.02)",
                  borderRadius: "6px",
                  border: "1px solid var(--border)",
                }}
              >
                <div
                  style={{
                    fontSize: "0.72rem",
                    color: "var(--text-muted)",
                    textTransform: "uppercase",
                    fontWeight: 600,
                  }}
                >
                  Target Machine / IP
                </div>
                <div
                  style={{
                    fontWeight: 600,
                    fontSize: "0.8rem",
                    marginTop: "2px",
                  }}
                >
                  {selectedFinding.asset_hostname &&
                  selectedFinding.asset_hostname !== "Unknown"
                    ? `${selectedFinding.asset_hostname} (${selectedFinding.asset_ip})`
                    : selectedFinding.asset_ip}
                </div>
              </div>

              <div>
                <label
                  style={{
                    fontSize: "0.72rem",
                    color: "var(--text-muted)",
                    fontWeight: 600,
                    display: "block",
                    marginBottom: "6px",
                    textTransform: "uppercase",
                  }}
                >
                  {modalType === "rollback"
                    ? "Warning Description"
                    : "How to Resolve This Finding"}
                </label>
                <div
                  style={{
                    fontSize: "0.8rem",
                    lineHeight: 1.5,
                    background: "var(--bg-light)",
                    padding: "12px",
                    borderRadius: "4px",
                    borderLeft: `3px solid ${modalType === "rollback" ? "#f57c00" : "var(--accent)"}`,
                    color: "var(--text)",
                  }}
                >
                  {modalType === "rollback"
                    ? "This action will execute a script to reverse the security control and reopen the port on the target machine."
                    : selectedFinding.recommendation_text ||
                      "No recommendation text registered."}
                </div>
              </div>

              {selectedFinding.fix_command && (
                <div>
                  <label
                    style={{
                      fontSize: "0.72rem",
                      color: "var(--text-muted)",
                      fontWeight: 600,
                      display: "block",
                      marginBottom: "6px",
                      textTransform: "uppercase",
                    }}
                  >
                    Automated Repair Script
                  </label>
                  <div style={{ position: "relative" }}>
                    <pre
                      className="mono"
                      style={{
                        background: "#272822",
                        color: "#f8f8f2",
                        padding: "12px",
                        borderRadius: "4px",
                        fontSize: "0.72rem",
                        overflowX: "auto",
                        margin: 0,
                        maxHeight: "150px",
                      }}
                    >
                      {selectedFinding.fix_command}
                    </pre>
                    <button
                      type="button"
                      className="db-btn db-btn--ghost"
                      style={{
                        position: "absolute",
                        right: "6px",
                        top: "6px",
                        padding: "2px 6px",
                        fontSize: "0.6rem",
                        background: "rgba(255,255,255,0.15)",
                        color: "#fff",
                        border: "none",
                        cursor: "pointer",
                      }}
                      onClick={() =>
                        handleCopyCommand(selectedFinding.fix_command)
                      }
                    >
                      Copy
                    </button>
                  </div>
                </div>
              )}

              <div
                style={{
                  borderTop: "1px solid var(--border)",
                  paddingTop: "12px",
                  marginTop: "8px",
                }}
              >
                <label
                  style={{
                    fontWeight: 600,
                    display: "block",
                    marginBottom: "8px",
                    fontSize: "0.8rem",
                  }}
                >
                  Execution Credentials
                </label>
                <div
                  style={{ display: "flex", gap: "16px", marginBottom: "12px" }}
                >
                  <label
                    style={{
                      fontSize: "0.78rem",
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                      cursor: "pointer",
                    }}
                  >
                    <input
                      type="radio"
                      checked={remediationCredSource === "jit"}
                      onChange={() => setRemediationCredSource("jit")}
                    />
                    One-time JIT Credentials
                  </label>
                  <label
                    style={{
                      fontSize: "0.78rem",
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                      cursor: "pointer",
                    }}
                  >
                    <input
                      type="radio"
                      checked={remediationCredSource === "stored"}
                      onChange={() => setRemediationCredSource("stored")}
                    />
                    Use Stored Credential
                  </label>
                </div>

                {remediationCredSource === "stored" ? (
                  <div>
                    <label
                      style={{
                        fontSize: "0.72rem",
                        color: "var(--text-muted)",
                        display: "block",
                        marginBottom: "4px",
                      }}
                    >
                      Select Saved Credential
                    </label>
                    <select
                      value={selectedCredId}
                      onChange={(e) => setSelectedCredId(e.target.value)}
                      style={{
                        width: "100%",
                        padding: "8px",
                        borderRadius: "4px",
                        border: "1px solid var(--border)",
                      }}
                    >
                      <option value="">-- Choose Credential --</option>
                      {credentialsList.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.name} ({c.username})
                        </option>
                      ))}
                    </select>
                  </div>
                ) : (
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "1fr 1fr",
                      gap: "10px",
                    }}
                  >
                    <div>
                      <label
                        style={{
                          fontSize: "0.72rem",
                          color: "var(--text-muted)",
                          display: "block",
                          marginBottom: "4px",
                        }}
                      >
                        SSH Username
                      </label>
                      <input
                        type="text"
                        value={jitUsername}
                        onChange={(e) => setJitUsername(e.target.value)}
                        placeholder="e.g. root"
                      />
                    </div>
                    <div>
                      <label
                        style={{
                          fontSize: "0.72rem",
                          color: "var(--text-muted)",
                          display: "block",
                          marginBottom: "4px",
                        }}
                      >
                        SSH Port
                      </label>
                      <input
                        type="number"
                        value={jitPort}
                        onChange={(e) => setJitPort(e.target.value)}
                        placeholder="22"
                      />
                    </div>
                    <div style={{ gridColumn: "span 2" }}>
                      <label
                        style={{
                          fontSize: "0.72rem",
                          color: "var(--text-muted)",
                          display: "block",
                          marginBottom: "4px",
                        }}
                      >
                        Auth Method
                      </label>
                      <select
                        value={jitAuthMethod}
                        onChange={(e) => setJitAuthMethod(e.target.value)}
                        style={{
                          width: "100%",
                          padding: "8px",
                          borderRadius: "4px",
                          border: "1px solid var(--border)",
                          marginBottom: "8px",
                        }}
                      >
                        <option value="password">Password</option>
                        <option value="key">Private SSH Key</option>
                      </select>
                    </div>
                    {jitAuthMethod === "password" ? (
                      <div style={{ gridColumn: "span 2" }}>
                        <label
                          style={{
                            fontSize: "0.72rem",
                            color: "var(--text-muted)",
                            display: "block",
                            marginBottom: "4px",
                          }}
                        >
                          Password
                        </label>
                        <input
                          type="password"
                          value={jitPassword}
                          onChange={(e) => setJitPassword(e.target.value)}
                          placeholder="••••••••"
                        />
                      </div>
                    ) : (
                      <div style={{ gridColumn: "span 2" }}>
                        <label
                          style={{
                            fontSize: "0.72rem",
                            color: "var(--text-muted)",
                            display: "block",
                            marginBottom: "4px",
                          }}
                        >
                          Private Key Content
                        </label>
                        <textarea
                          value={jitKeyContent}
                          onChange={(e) => setJitKeyContent(e.target.value)}
                          placeholder="-----BEGIN OpenSSH PRIVATE KEY-----..."
                          style={{
                            fontFamily: "monospace",
                            fontSize: "0.72rem",
                            height: "80px",
                            width: "100%",
                            boxSizing: "border-box",
                          }}
                        />
                      </div>
                    )}
                  </div>
                )}
              </div>

              {isComplianceAdmin && (
                <div
                  style={{
                    marginTop: "8px",
                    borderTop: "1px solid var(--border)",
                    paddingTop: "12px",
                  }}
                >
                  <label
                    style={{
                      fontSize: "0.78rem",
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                      cursor: "pointer",
                      fontWeight: 600,
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={emergencyBypass}
                      onChange={(e) => setEmergencyBypass(e.target.checked)}
                    />
                    ⚡ Emergency Bypass (Direct Execution - Skip Approvals
                    Queue)
                  </label>
                  <p
                    style={{
                      margin: "0.25rem 0 0 20px",
                      fontSize: "0.68rem",
                      color: "var(--text-muted)",
                    }}
                  >
                    Note: Emergency bypass will log a critical priority incident
                    alert to the IP audit logs.
                  </p>
                </div>
              )}

              <div
                style={{
                  display: "flex",
                  gap: "10px",
                  marginTop: "20px",
                  justifyContent: "flex-end",
                }}
              >
                {selectedFinding.fix_command ? (
                  <button
                    type="button"
                    className="db-btn db-btn--primary"
                    onClick={() => {
                      if (modalType === "rollback") {
                        handleRollback(selectedFinding.id);
                      } else {
                        handleRemediate(selectedFinding.id);
                      }
                      setModalOpen(false);
                    }}
                    style={{
                      background:
                        modalType === "rollback" ? "#f57c00" : undefined,
                      borderColor:
                        modalType === "rollback" ? "#f57c00" : undefined,
                    }}
                  >
                    {modalType === "rollback"
                      ? "🚀 Dispatch Rollback Request"
                      : "🚀 Dispatch Fix Request"}
                  </button>
                ) : (
                  <button
                    type="button"
                    className="db-btn db-btn--ghost"
                    style={{ cursor: "not-allowed", opacity: 0.6 }}
                    disabled
                  >
                    {modalType === "rollback"
                      ? "⚙️ No Automated Rollback Available"
                      : "⚙️ No Automated Fix Available"}
                  </button>
                )}
                <button
                  type="button"
                  className="db-btn db-btn--ghost"
                  onClick={() => setModalOpen(false)}
                >
                  Close Guide
                </button>
              </div>
            </div>
          )}

        {modalType === "log_viewer" && selectedFinding && (
          <div
            className="compliance-form"
            style={{ display: "flex", flexDirection: "column", gap: "12px" }}
          >
            <div>
              <h3 style={{ margin: 0, fontSize: "0.95rem" }}>
                Execution Log:{" "}
                <span className="mono">{selectedFinding.control_id}</span>
              </h3>
              <p
                style={{
                  margin: "0.25rem 0 1rem",
                  fontSize: "0.8rem",
                  color: "var(--text-muted)",
                }}
              >
                Target IP: {selectedFinding.asset_ip}
              </p>
            </div>
            <div>
              <label
                style={{
                  fontSize: "0.72rem",
                  color: "var(--text-muted)",
                  fontWeight: 600,
                  display: "block",
                  marginBottom: "6px",
                  textTransform: "uppercase",
                }}
              >
                Console Output
              </label>
              <pre
                className="mono"
                style={{
                  background: "#272822",
                  color: "#f8f8f2",
                  padding: "12px",
                  borderRadius: "4px",
                  fontSize: "0.72rem",
                  overflowX: "auto",
                  margin: 0,
                  maxHeight: "300px",
                }}
              >
                {selectedFinding.execution_log || "No console output recorded."}
              </pre>
            </div>
            <div
              style={{
                display: "flex",
                justifyContent: "flex-end",
                marginTop: "12px",
              }}
            >
              <button
                type="button"
                className="db-btn db-btn--ghost"
                onClick={() => setModalOpen(false)}
              >
                Close Logs
              </button>
            </div>
          </div>
        )}
      </Modal>
      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </AppLayout>
  );
}
