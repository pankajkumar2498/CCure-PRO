/**
 * src/App.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * NOTE: BrowserRouter + AuthProvider are already in main.jsx — do NOT re-wrap.
 * This file only defines Routes.
 *
 * Route changes from original:
 *   /           → SecurityDashboard (new SOC overview)
 *   /dashboard  → SecurityDashboard
 *   /scan       → Dashboard.jsx (scan template picker, moved from /)
 *   /assets     → AssetRegistry
 *   /assets/:id → AssetDetail
 *   /vulnerabilities → VulnerabilityBrowser
 *
 * All original pages kept exactly. Missing pages (ScanDetail, NotFound,
 * NotificationsPage) are replaced with the pages that actually exist.
 */

import { lazy, Suspense } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import PrivateRoute from "./components/auth/PrivateRoute";
import { ScanProvider } from "./context/ScanContext";

// ── New dashboard pages ───────────────────────────────────────────────────────
import SecurityDashboard from "./pages/SecurityDashboard";
import AssetRegistry from "./pages/AssetRegistry";
import AssetDetail from "./pages/AssetDetail";
import VulnerabilityBrowser from "./pages/VulnerabilityBrowser";
import ComplianceWorkspace from "./pages/ComplianceWorkspace";

// ── Existing pages (all verified to exist on disk) ────────────────────────────
import Login from "./pages/Login";
import Register from "./pages/Register";
import VerifyEmail from "./pages/VerifyEmail";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import Dashboard from "./pages/Dashboard"; // scan launcher → /scan
import ScanHistory from "./pages/ScanHistory";
import ScanSchedules from "./pages/scan/ScanSchedules";
import ConfigurationChecks from "./pages/scan/ConfigurationChecks";
import ScanCredentials from "./pages/scan/ScanCredentials";
import ArchivedScans from "./pages/ArchivedScans";
import RecycleBin from "./pages/RecycleBin";
import SecurityReports from "./pages/SecurityReports";

// Scan sub-pages
import NewScan from "./pages/scan/NewScan";
import Phase1Results from "./pages/scan/Phase1Results";
import Phase2Results from "./pages/scan/Phase2Results";
import Phase3Results from "./pages/scan/Phase3Results";
import CredentialedScan from "./pages/scan/CredentialedScan";
import CredentialedResults from "./pages/scan/CredentialedResults";
import ScanComparison from "./pages/scan/ScanComparison";
import NetworkMap from "./pages/scan/NetworkMap";

import WebScanningRoutes from "./modules/web-scanning/WebScanningRoutes";

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
  ? lazy(() => import("./pages/DesignSystemShowcase"))
  : null;

// Admin pages
import AuditLogs from "./pages/admin/AuditLogs";
import EmailDomainRules from "./pages/admin/EmailDomainRules";
import UserManagement from "./pages/admin/UserManagement";
import OrganizationManagement from "./pages/admin/OrganizationManagement";
import RoleManagement from "./pages/admin/RoleManagement";
import DeletedUsers from "./pages/admin/DeletedUsers";
import AMTIntegration from "./pages/admin/AMTIntegration";

export default function App() {
  return (
    <ScanProvider>
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
          {/* SOC Security Dashboard — new home */}
          <Route path="/" element={<SecurityDashboard />} />
          <Route path="/dashboard" element={<SecurityDashboard />} />

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
          <Route
            path="/configuration-checks"
            element={<ConfigurationChecks />}
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
    </ScanProvider>
  );
}
