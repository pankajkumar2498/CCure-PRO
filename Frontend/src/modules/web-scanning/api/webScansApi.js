import axiosInstance from "../../../api/axiosInstance";

const apiBase = () => {
  const baseURL = axiosInstance.defaults.baseURL || "";
  return baseURL.endsWith("/") ? baseURL.slice(0, -1) : baseURL;
};

const wsBase = () => {
  const base = apiBase();
  if (!base) {
    return window.location.origin.replace(/^http/i, "ws");
  }
  if (base.startsWith("http")) {
    return base.replace(/^http/i, "ws");
  }
  return `${window.location.origin}${base}`.replace(/^http/i, "ws");
};

const cookieStringToMap = (cookieString = "") =>
  String(cookieString)
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((acc, part) => {
      const separator = part.indexOf("=");
      if (separator <= 0) return acc;
      const name = part.slice(0, separator).trim();
      const value = part.slice(separator + 1).trim();
      if (name) acc[name] = value;
      return acc;
    }, {});

const normalizeAuthConfig = (authConfig = {}) => {
  const type = authConfig.type || "none";

  if (type === "bearer") {
    return {
      type: "bearer_token",
      token: authConfig.token || "",
    };
  }

  if (type === "cookie") {
    return {
      type: "cookie",
      cookies: cookieStringToMap(authConfig.token),
    };
  }

  if (type === "basic") {
    return {
      type: "custom_header",
      headers: {
        Authorization: `Basic ${btoa(`${authConfig.username || ""}:${authConfig.password || ""}`)}`,
      },
    };
  }

  return { type: "none" };
};

const normalizeStartPayload = (data = {}) => ({
  target_url: data.target_url,
  scan_name: data.scan_name,
  authorization_confirmed: data.authorization_confirmed,
  scan_scope: {
    include_subdomains: Boolean(data.options?.include_subdomains),
    exclude_paths: data.scan_scope?.exclude_paths || [],
    max_depth: Number(data.options?.depth || data.scan_scope?.max_depth || 3),
  },
  auth: normalizeAuthConfig(data.auth_config || data.auth),
  options: {
    enable_sqli: data.options?.enable_sqli ?? true,
    enable_xss: data.options?.enable_xss ?? true,
    nuclei_severity: data.options?.nuclei_severity || [
      "medium",
      "high",
      "critical",
    ],
    rate_limit: Number(
      data.options?.concurrency || data.options?.rate_limit || 10,
    ),
  },
});

export const webScansApi = {
  // Scans
  startScan: (data) =>
    axiosInstance.post("/web-scans", normalizeStartPayload(data), {
      headers: data?._idempotencyKey
        ? { "Idempotency-Key": data._idempotencyKey }
        : undefined,
    }),
  getScans: (params) => axiosInstance.get("/web-scans", { params }),
  getScan: (id) => axiosInstance.get(`/web-scans/${id}`),
  getProgressTicket: () => axiosInstance.post("/auth/ticket", {}),
  getProgressSocketUrl: (id, ticket) =>
    `${wsBase()}/web-scans/${encodeURIComponent(id)}/progress?ticket=${encodeURIComponent(ticket)}`,
  cancelScan: (id) => axiosInstance.post(`/web-scans/${id}/cancel`),
  deleteScan: (id) => axiosInstance.delete(`/web-scans/${id}`),
  downloadReport: (id) =>
    axiosInstance.get(`/web-scans/${id}/report`, { responseType: "blob" }),

  // Findings
  getFindings: (id, params) =>
    axiosInstance.get(`/web-scans/${id}/findings`, { params }),
  updateFindingStatus: (id, findingId, statusData) =>
    axiosInstance.patch(`/web-scans/${id}/findings/${findingId}`, statusData),
  // Proof screenshot (Codex item 10). Fetched as a blob so the request carries
  // the auth header an <img src> could not; the caller makes an object URL.
  getFindingScreenshot: (id, findingId) =>
    axiosInstance.get(`/web-scans/${id}/findings/${findingId}/screenshot`, {
      responseType: "blob",
    }),

  // Assets
  getAssets: (id, params) =>
    axiosInstance.get(`/web-scans/${id}/assets`, { params }),

  // Attack surface (Codex items 1, 2): first-class parameters, forms and API
  // operations discovered by the scan, with per-parameter coverage.
  getParameters: (id, params) =>
    axiosInstance.get(`/web-scans/${id}/parameters`, { params }),
  getForms: (id, params) =>
    axiosInstance.get(`/web-scans/${id}/forms`, { params }),
  getApiOperations: (id, params) =>
    axiosInstance.get(`/web-scans/${id}/api-operations`, { params }),
};

export const webDashboardApi = {
  getSummary: (params) =>
    axiosInstance.get("/dashboard/web-scan-summary", { params }),
  getOwaspScorecard: (params) =>
    axiosInstance.get("/dashboard/web-owasp-scorecard", { params }),
  getTrends: (params) =>
    axiosInstance.get("/dashboard/web-scan-trends", { params }),
  // Org-wide drill-downs behind the dashboard counts (severity / OWASP / trend
  // date → findings; the endpoints card → discovered endpoints).
  getAllFindings: (params) =>
    axiosInstance.get("/dashboard/web-findings", { params }),
  getAllEndpoints: (params) =>
    axiosInstance.get("/dashboard/web-endpoints", { params }),
};
