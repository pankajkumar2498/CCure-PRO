/**
 * src/api/dashboard.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Dashboard analytics API calls.
 * All endpoints are RBAC-gated on the backend; these are thin wrappers
 * around the authenticated axiosInstance (JWT + cookie refresh built-in).
 */
import api from "./axiosInstance";

const params = (extra = {}) => ({ params: extra });

// ── 1. Summary Cards ──────────────────────────────────────────────────────────
export const getDashboardSummary = (orgId) =>
  api.get("/dashboard/summary", params(orgId ? { org_id: orgId } : {}));

// ── 2. Risk Breakdown ─────────────────────────────────────────────────────────
export const getRiskBreakdown = (orgId) =>
  api.get("/dashboard/risk-breakdown", params(orgId ? { org_id: orgId } : {}));

// ── 3. Vuln Trends (line chart) ───────────────────────────────────────────────
export const getVulnTrends = (days = 30, orgId) =>
  api.get(
    "/dashboard/vuln-trends",
    params({ days, ...(orgId ? { org_id: orgId } : {}) }),
  );

// ── 4. Top Assets ─────────────────────────────────────────────────────────────
export const getTopAssets = (limit = 10, orgId) =>
  api.get(
    "/dashboard/top-assets",
    params({ limit, ...(orgId ? { org_id: orgId } : {}) }),
  );

// ── 5. Top CVEs ───────────────────────────────────────────────────────────────
export const getTopCVEs = (limit = 10, severity, orgId) =>
  api.get(
    "/dashboard/top-cves",
    params({
      limit,
      ...(severity ? { severity } : {}),
      ...(orgId ? { org_id: orgId } : {}),
    }),
  );

// ── 6. Service Exposure ───────────────────────────────────────────────────────
export const getServicesExposure = (orgId) =>
  api.get(
    "/dashboard/services-exposure",
    params(orgId ? { org_id: orgId } : {}),
  );

// ── 7. TLS Health ─────────────────────────────────────────────────────────────
export const getTLSHealth = (orgId) =>
  api.get("/dashboard/tls-health", params(orgId ? { org_id: orgId } : {}));

// ── 8. HTTP Headers ───────────────────────────────────────────────────────────
export const getHTTPHeaders = (orgId) =>
  api.get("/dashboard/http-headers", params(orgId ? { org_id: orgId } : {}));

// ── 9. Compliance ─────────────────────────────────────────────────────────────
export const getCompliance = (orgId) =>
  api.get("/dashboard/compliance", params(orgId ? { org_id: orgId } : {}));

// ── 10. Asset Breakdown ───────────────────────────────────────────────────────
export const getAssetBreakdown = (orgId) =>
  api.get("/dashboard/asset-breakdown", params(orgId ? { org_id: orgId } : {}));

// ── 11. Scan Activity ─────────────────────────────────────────────────────────
export const getScanActivity = (limit = 8, orgId) =>
  api.get(
    "/dashboard/scan-activity",
    params({ limit, ...(orgId ? { org_id: orgId } : {}) }),
  );

// ── 12. Insights ──────────────────────────────────────────────────────────────
export const getInsights = (orgId) =>
  api.get("/dashboard/insights", params(orgId ? { org_id: orgId } : {}));
