/**
 * The compliance workspace's calls to `/compliance`.
 *
 * The workspace made these calls itself (34 sites), through the shared axios instance
 * (F1 of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md). They are moved
 * here unchanged: each function sends the method, path, query, body and
 * config the page sent, built the same way, so the requests on the wire are
 * the ones they were. Recurring scans have their own module,
 * `complianceSchedules.js`.
 *
 * Stored credentials are not compliance's: the workspace reads and writes them
 * through `credentials.js`, the credential store's own API (F3).
 */

import api from "@shell/api/axiosInstance";

// ── Reads ─────────────────────────────────────────────────────────────────

/** A compliance scan run, polled while it runs. */
export const getComplianceScanRun = (runId) =>
  api.get(`/compliance/scans/${runId}`);

/** Coverage of one framework by another. */
export const getComplianceGapAnalysis = (sourceId, targetId) =>
  api.get(
    `/compliance/gap-analysis?source_framework_id=${sourceId}&target_framework_id=${targetId}`,
  );

/** The dashboard summary; `queryString` is "" or begins with "?". */
export const getComplianceSummary = (queryString) =>
  api.get(`/compliance/summary${queryString}`);

/** A framework's control register; `params` are "key=value" pairs. */
export const listFrameworkControls = (frameworkId, params) =>
  api.get(
    `/compliance/frameworks/${frameworkId}/controls${
      params.length ? `?${params.join("&")}` : ""
    }`,
  );

/** The framework marketplace. */
export const listComplianceMarketplace = () =>
  api.get("/compliance/marketplace");

/** Policy baselines; `queryString` is "" or begins with "?". */
export const listCompliancePolicies = (queryString = "") =>
  api.get(`/compliance/policies${queryString}`);

/** A policy baseline's rules. */
export const listCompliancePolicyRules = (policyId) =>
  api.get(`/compliance/policies/${policyId}/rules`);

/** Findings, up to 10,000; `params` are "key=value" pairs. */
export const listComplianceFindings = (params) =>
  api.get(
    `/compliance/findings?limit=10000${params.length > 0 ? `&${params.join("&")}` : ""}`,
  );

/** Findings with a pending exception, up to 10,000. */
export const listPendingExceptionFindings = (params) =>
  api.get(
    `/compliance/findings?status=pending&limit=10000${params.length > 0 ? `&${params.join("&")}` : ""}`,
  );

/** The maker-checker remediation queue. */
export const listRemediationRequests = () =>
  api.get("/compliance/remediations/requests");

/** A control's evidence files. */
export const listControlEvidence = (controlId) =>
  api.get(`/compliance/controls/${controlId}/evidence`);

/** A report document, as bytes; `endpoint` is the report's path and query. */
export const downloadComplianceReport = (endpoint) =>
  api.get(endpoint, {
    responseType: "arraybuffer",
  });

// ── Writes ────────────────────────────────────────────────────────────────

/** Install a framework from the marketplace. */
export const installComplianceFramework = (id) =>
  api.post(`/compliance/marketplace/${id}/install`);

/** Uninstall a framework. */
export const uninstallComplianceFramework = (id) =>
  api.post(`/compliance/marketplace/${id}/uninstall`);

/** Create a policy baseline. */
export const createCompliancePolicy = (body) =>
  api.post("/compliance/policies", body);

/** Change a rule's check definition and severity. */
export const updateComplianceRule = (ruleId, body) =>
  api.put(`/compliance/rules/${ruleId}`, body);

/** Start a compliance scan. */
export const triggerComplianceScan = (body) =>
  api.post("/compliance/scans", body);

/** A person's verdict on a control. */
export const attestComplianceControl = (controlId, body) =>
  api.post(`/compliance/controls/${controlId}/attest`, body);

/** Upload an evidence file; `form` is the multipart body. */
export const uploadControlEvidence = (controlId, form) =>
  api.post(`/compliance/controls/${controlId}/evidence`, form, {
    headers: { "Content-Type": "multipart/form-data" },
  });

/** Delete an evidence file. */
export const deleteComplianceEvidence = (fileId) =>
  api.delete(`/compliance/evidence/${fileId}`);

/** Request an exception waiver for a finding. */
export const requestComplianceException = (findingId, body) =>
  api.post(`/compliance/findings/${findingId}/exception`, body);

/** Approve or reject an exception waiver. */
export const decideComplianceException = (exceptionId, status) =>
  api.patch(`/compliance/exceptions/${encodeURIComponent(exceptionId)}`, {
    status,
  });

/** Apply a finding's automated fix, directly or through the queue. */
export const applyComplianceRemediation = (findingId, payload) =>
  api.post(`/compliance/findings/${findingId}/remediate`, payload);

/** Roll an executed remediation back. */
export const rollbackRemediationRequest = (requestId, payload) =>
  api.post(`/compliance/remediations/requests/${requestId}/rollback`, payload);

/** Cancel a remediation request. */
export const cancelRemediationRequest = (requestId) =>
  api.post(`/compliance/remediations/requests/${requestId}/cancel`);

/** Approve or reject a remediation request. */
export const decideRemediationRequest = (requestId, status) =>
  api.post(`/compliance/remediations/requests/${requestId}/approve`, {
    status,
  });
