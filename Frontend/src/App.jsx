/**
 * src/App.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * NOTE: BrowserRouter + AuthProvider are already in main.jsx — do NOT re-wrap.
 * This file only defines Routes.
 *
 * Route changes from original:
 *   /           → CCure Home, the platform's Product Hub (Phase 12.2)
 *   /audit-dashboard → SecurityDashboard, Audit's canonical dashboard address
 *   /dashboard  → redirect to /audit-dashboard (old links and bookmarks)
 *   /:entry     → a product's entry page from the registry (Policy Pro, Rank, IR)
 *   /scan       → Dashboard.jsx (scan template picker, moved from /)
 *   /assets     → AssetRegistry
 *   /assets/:id → AssetDetail
 *   /vulnerabilities → VulnerabilityBrowser
 *   /remediation → Remediation
 *
 * All original pages kept exactly. Missing pages (ScanDetail, NotFound,
 * NotificationsPage) are replaced with the pages that actually exist.
 */

import { lazy, Suspense } from "react";
import { Routes, Route, Navigate, useLocation } from "react-router-dom";
import PrivateRoute from "@shell/auth/PrivateRoute";
import { AccessFallbackProvider } from "@shell/auth/accessFallback";
import { AUDIT_ACCESS_FALLBACKS } from "@audit/config/accessFallbacks";
import { ScanProvider } from "@audit/context/ScanContext";

// ── New dashboard pages ───────────────────────────────────────────────────────
import SecurityDashboard from "@audit/pages/SecurityDashboard";
import AssetRegistry from "@audit/pages/AssetRegistry";
import AssetDetail from "@audit/pages/AssetDetail";
import VulnerabilityBrowser from "@audit/pages/VulnerabilityBrowser";
import ComplianceWorkspace from "@audit/pages/ComplianceWorkspace";

// ── Existing pages (all verified to exist on disk) ────────────────────────────
import Login from "./pages/Login";
import Register from "./pages/Register";
import VerifyEmail from "./pages/VerifyEmail";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import Dashboard from "@audit/pages/Dashboard"; // scan launcher → /scan
import ScanHistory from "@audit/pages/ScanHistory";
import ScanSchedules from "@audit/pages/scan/ScanSchedules";
import ConfigurationChecks from "@audit/pages/scan/ConfigurationChecks";
import ConfigurationRuleValidator from "@audit/pages/scan/ConfigurationRuleValidator";
import ScanCredentials from "@audit/pages/scan/ScanCredentials";
import ArchivedScans from "@audit/pages/ArchivedScans";
import RecycleBin from "@audit/pages/RecycleBin";
import SecurityReports from "@audit/pages/SecurityReports";

// Scan sub-pages
import NewScan from "@audit/pages/scan/NewScan";
import Phase1Results from "@audit/pages/scan/Phase1Results";
import Phase2Results from "@audit/pages/scan/Phase2Results";
import Phase3Results from "@audit/pages/scan/Phase3Results";
import CredentialedScan from "@audit/pages/scan/CredentialedScan";
import CredentialedResults from "@audit/pages/scan/CredentialedResults";
import ScanComparison from "@audit/pages/scan/ScanComparison";
import ScanPolicies from "@audit/pages/scan/ScanPolicies";
import Remediation from "@audit/pages/Remediation";
import NetworkMap from "@audit/pages/scan/NetworkMap";

import WebScanningRoutes from "@audit/web-scanning/WebScanningRoutes";

// ── Platform shell (Phase 12): CCure Home and the product entry pages ────────
import CcureHome from "@shell/pages/CcureHome";
import ModuleEntryPage from "@shell/pages/ModuleEntryPage";

// ── Design-system showcase, development builds only ─────────────────────────
// `import.meta.env.DEV` is a literal `false` in a production build, so Rollup
// drops both the route and — because this is the only reference — the module
// behind it. Verified rather than assumed: a guardrail test asserts the
// showcase's marker string is absent from dist/.
//
// It renders no application data and calls no API, so it is safe to leave
// reachable in development without an auth gate. It exists to exercise the
// primitives in both themes; it is not, and must not become, a product page.
const Ux4gShowcase = import.meta.env.DEV
  ? lazy(() => import("@audit/pages/DesignSystemShowcase"))
  : null;

// Admin pages
import AuditLogs from "@shell/admin/pages/AuditLogs";
import EmailDomainRules from "@shell/admin/pages/EmailDomainRules";
import UserManagement from "@shell/admin/pages/UserManagement";
import OrganizationManagement from "@shell/admin/pages/OrganizationManagement";
import RoleManagement from "@shell/admin/pages/RoleManagement";
import DeletedUsers from "@shell/admin/pages/DeletedUsers";
import AMTIntegration from "@audit/pages/admin/AMTIntegration";

// Imported after every page, where both modules are already loaded, so the
// stylesheet order in the bundle is unchanged.
import { ProductFrameProvider } from "@shell/layout/ProductFrame";
import AppLayout from "@audit/components/layout/AppLayout";

// /dashboard → /audit-dashboard, keeping the query string, fragment and router
// state, so a link carrying any of them lands exactly where it pointed.
function AuditDashboardRedirect() {
  const { search, hash, state } = useLocation();
  return (
    <Navigate
      to={{ pathname: "/audit-dashboard", search, hash }}
      state={state}
      replace
    />
  );
}

// Audit's providers around the routes: its scan state; the pages a refused
// route falls back to — the shell's guard holds the rule, Audit names the
// pages (Phase 12.3); and the frame the platform's shared screens (users,
// organisations, roles, email domains, audit logs) render in — Audit's layout,
// so they stay inside the navigation a person reached them from.
function AuditProviders({ children }) {
  return (
    <ScanProvider>
      <AccessFallbackProvider candidates={AUDIT_ACCESS_FALLBACKS}>
        <ProductFrameProvider frame={AppLayout}>
          {children}
        </ProductFrameProvider>
      </AccessFallbackProvider>
    </ScanProvider>
  );
}

export default function App() {
  return (
    <AuditProviders>
      <Routes>
        {/* ── Public ── */}
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        {/* Target of the emailed verification link. Public by necessity: the
            whole point is that the visitor cannot authenticate yet. */}
        <Route path="/verify-email" element={<VerifyEmail />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />

        {/* Development-only, see the declaration above. Absent from every
            production build. */}
        {Ux4gShowcase ? (
          <Route
            path="/design-system"
            element={
              <Suspense fallback={null}>
                <Ux4gShowcase />
              </Suspense>
            }
          />
        ) : null}

        {/* ── Protected ── */}
        <Route element={<PrivateRoute />}>
          {/* CCure Home — the Product Hub, read from the platform registry */}
          <Route path="/" element={<CcureHome />} />

          {/* Audit's Security Dashboard. /dashboard was its address until
              Phase 12 and stays a redirect, so bookmarks, report links and
              anything outside the repository still land (D12-7). */}
          <Route path="/audit-dashboard" element={<SecurityDashboard />} />
          <Route path="/dashboard" element={<AuditDashboardRedirect />} />

          {/* A product's entry page — /policy-dashboard, /rank-dashboard,
              /ir-dashboard — looked up in the registry. Every static route
              outranks it; an address that is no product's entry falls through
              to / exactly as the catch-all below does. */}
          <Route path="/:entry" element={<ModuleEntryPage />} />

          {/* Original scan launcher (moved from / to /scan) */}
          <Route path="/scan" element={<Dashboard />} />

          {/* Asset Registry */}
          <Route path="/assets" element={<AssetRegistry />} />
          <Route path="/assets/:id" element={<AssetDetail />} />

          {/* Vulnerability Browser */}
          <Route path="/vulnerabilities" element={<VulnerabilityBrowser />} />

          {/* Scan history + lifecycle */}
          <Route path="/monitor" element={<ScanHistory mode="monitor" />} />
          <Route path="/history" element={<ScanHistory mode="history" />} />
          <Route path="/scan-schedules" element={<ScanSchedules />} />
          <Route path="/scan-credentials" element={<ScanCredentials />} />
          <Route path="/scan-policies" element={<ScanPolicies />} />
          <Route path="/remediation" element={<Remediation />} />
          <Route
            path="/configuration-checks"
            element={<ConfigurationChecks />}
          />
          {/* Its own route rather than a panel on the catalogue: that page's
              contract is no POST of any kind, pinned by a test that drives
              every control on it. */}
          <Route
            path="/configuration-checks/validate"
            element={<ConfigurationRuleValidator />}
          />
          <Route
            path="/scan-history"
            element={<Navigate to="/history" replace />}
          />
          <Route path="/archived" element={<ArchivedScans />} />
          <Route
            path="/archived-scans"
            element={<Navigate to="/archived" replace />}
          />
          <Route path="/recycle-bin" element={<RecycleBin />} />

          {/* Scan sub-pages (existing + legacy compatibility routes) */}
          <Route path="/scan/new" element={<NewScan />} />
          <Route path="/scan/active/:scanId" element={<NewScan />} />
          <Route path="/scan/host-discovery" element={<Phase1Results />} />
          <Route path="/scan/asset-discovery" element={<Phase2Results />} />
          <Route path="/scan/vulnerability-audit" element={<Phase3Results />} />
          <Route
            path="/scan/advanced-scan"
            element={<Navigate to="/scan/vulnerability-audit" replace />}
          />
          {/* One route, scan chosen by query string, so a comparison can be
              linked to and shared. */}
          <Route path="/scan/comparison" element={<ScanComparison />} />
          <Route path="/scan/credentialed" element={<CredentialedScan />} />
          <Route
            path="/scan/credentialed/results"
            element={<CredentialedResults />}
          />
          <Route path="/scan/:scanId/phase1" element={<Phase1Results />} />
          <Route path="/scan/:scanId/phase2" element={<Phase2Results />} />
          <Route path="/scan/:scanId/phase3" element={<Phase3Results />} />
          <Route
            path="/scan/:scanId/credentialed"
            element={<CredentialedScan />}
          />
          <Route
            path="/scan/:scanId/credentialed-results"
            element={<CredentialedResults />}
          />

          {/* Network Topology Map */}
          <Route path="/scan/topology-map" element={<NetworkMap />} />
          <Route path="/scan/:scanId/topology-map" element={<NetworkMap />} />
          <Route path="/topology" element={<NetworkMap />} />

          {/* Web Application Scanning */}
          <Route path="/web-scans/*" element={<WebScanningRoutes />} />

          {/* Reports */}
          <Route path="/reports" element={<SecurityReports />} />
          <Route path="/compliance" element={<ComplianceWorkspace />} />

          {/* Admin — RBAC-gated */}
          <Route
            element={
              <PrivateRoute
                requiredPermission={{ resource: "audit", action: "read" }}
              />
            }
          >
            <Route path="/admin/audit-logs" element={<AuditLogs />} />
          </Route>
          <Route
            element={
              <PrivateRoute
                requiredPermission={{ resource: "assets", action: "update" }}
              />
            }
          >
            <Route path="/admin/amt" element={<AMTIntegration />} />
          </Route>
          <Route
            element={
              <PrivateRoute
                requiredPermission={{ resource: "users", action: "read" }}
              />
            }
          >
            <Route path="/admin/users" element={<UserManagement />} />
            <Route path="/admin/users/deleted" element={<DeletedUsers />} />
          </Route>
          {/* Superadmin only, matching require_role("superadmin") on the
              router. These rules are platform-wide: an org_admin denying a
              domain would be blocking another tenant's customers. */}
          <Route element={<PrivateRoute superadminOnly />}>
            <Route path="/admin/email-domains" element={<EmailDomainRules />} />
          </Route>
          <Route
            element={
              <PrivateRoute
                requiredPermission={{
                  resource: "organizations",
                  action: "read",
                }}
              />
            }
          >
            <Route
              path="/admin/organizations"
              element={<OrganizationManagement />}
            />
          </Route>
          <Route
            element={
              <PrivateRoute
                requiredPermission={{ resource: "roles", action: "read" }}
              />
            }
          >
            <Route path="/admin/roles" element={<RoleManagement />} />
          </Route>

          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </AuditProviders>
  );
}
