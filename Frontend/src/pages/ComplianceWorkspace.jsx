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
  const [scanPollCount, setScanPollCount] = useState(0);

  // Modals state
  const [modalOpen, setModalOpen] = useState(false);
  const [modalType, setModalType] = useState(""); // policy | attest | exception | remediate | log_viewer
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
        return (
          matchesAsset && matchesStatus && matchesSeverity && matchesSearch
        );
      }),
    [findings, filterAsset, filterStatus, filterSeverity, filterSearch],
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
  }, [filterSearch, filterAsset, filterStatus, filterSeverity]);

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

  const fetchTabData = async (quiet = false) => {
    if (!quiet) setLoading(true);
    setError(null);
    try {
      if (activeTab === "dashboard") {
        const res = await axiosInstance.get("/compliance/dashboard/summary");
        setSummary(res.data);
      } else if (activeTab === "marketplace") {
        const res = await axiosInstance.get("/compliance/marketplace");
        setMarketplace(res.data.data || []);
      } else if (activeTab === "policies") {
        const res = await axiosInstance.get("/compliance/policies");
        setPolicies(res.data.data || []);
      } else if (activeTab === "findings") {
        const res = await axiosInstance.get("/compliance/findings?limit=10000");
        setFindings(res.data.data || []);
      } else if (activeTab === "exceptions") {
        const res = await axiosInstance.get(
          "/compliance/findings?status=pending&limit=10000",
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
        framework_id: "cfw_iso27001_2022",
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

      // Stagger requests sequentially to prevent DB concurrency locks/deadlocks in Celery workers
      for (const policy of fetchedPolicies) {
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
              attestations, and exception waivers.
            </div>
          </div>
          <div
            className="db-header-actions"
            style={{ display: "flex", gap: "10px" }}
          >
            <button
              className="db-btn db-btn--primary"
              onClick={handleTriggerComplianceScan}
              disabled={loading}
              style={{ display: "flex", alignItems: "center", gap: "6px" }}
            >
              <span>⚡</span> Run Compliance Scan
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
                <div
                  style={{
                    fontSize: "0.8rem",
                    color: "var(--text-muted)",
                    marginTop: "0.5rem",
                  }}
                >
                  Please make sure you have applied the database migrations and
                  seeded the controls catalog:
                  <br />
                  <code
                    style={{
                      background: "rgba(0,0,0,0.05)",
                      padding: "0.2rem 0.5rem",
                      borderRadius: "0.25rem",
                      display: "inline-block",
                      marginTop: "0.5rem",
                      fontFamily: "var(--mono)",
                      color: "var(--text)",
                    }}
                  >
                    .\.venv\Scripts\python -m alembic upgrade head
                  </code>
                  <br />
                  <code
                    style={{
                      background: "rgba(0,0,0,0.05)",
                      padding: "0.2rem 0.5rem",
                      borderRadius: "0.25rem",
                      display: "inline-block",
                      marginTop: "0.25rem",
                      fontFamily: "var(--mono)",
                      color: "var(--text)",
                    }}
                  >
                    .\.venv\Scripts\python -m scripts.seed_compliance
                  </code>
                </div>
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
                  <h3>ISO 27001 Controls</h3>
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
                  Download SoA PDF
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
                  Download SoA Word
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
                  Download Executive Report
                </button>
              </div>

              <div className="quadrant-scores">
                <h3>ISO Themes Quadrant Breakdown</h3>
                <div className="quadrant-grid">
                  {Object.entries(summary.quadrant_scores || {}).map(
                    ([key, val]) => (
                      <div key={key} className="quad-item">
                        <span className="quad-label">{key}</span>
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
                                              {r.control_id
                                                ? r.control_id.split(
                                                    "iso27001_2022_",
                                                  )[1]
                                                : "N/A"}
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
                                              {r.evidence_source !==
                                                "manual" && (
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
                                              )}
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
