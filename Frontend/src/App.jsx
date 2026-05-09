/**
 * src/App.jsx
 *
 * Advanced Scan pipeline: Host Discovery → Asset Discovery → Vulnerability & Risk Audit (3 phases).
 * Phase 4 (Risk Report) is embedded inside Phase 3 on the backend — no separate frontend phase needed.
 */
import { Routes, Route, Navigate } from "react-router-dom";
import { ScanProvider }            from "./context/ScanContext";
import PrivateRoute                from "./components/PrivateRoute";

import Login             from "./pages/Login";
import Register          from "./pages/Register";
import Dashboard         from "./pages/Dashboard";
import ScanHistory       from "./pages/ScanHistory";
import ArchivedScans     from "./pages/ArchivedScans";
import RecycleBin        from "./pages/RecycleBin";
import SecurityReports    from "./pages/SecurityReports";
import UserManagement     from "./pages/admin/UserManagement";
import DeletedUsers       from "./pages/admin/DeletedUsers";
import RoleManagement     from "./pages/admin/RoleManagement";
import OrganizationManagement from "./pages/admin/OrganizationManagement";
import AuditLogs          from "./pages/admin/AuditLogs";
import NewScan           from "./pages/scan/NewScan";
import Phase1Results     from "./pages/scan/Phase1Results";
import Phase2Results     from "./pages/scan/Phase2Results";
import Phase3Results     from "./pages/scan/Phase3Results";
import CredentialedScan  from "./pages/scan/CredentialedScan";
import CredentialedResults from "./pages/scan/CredentialedResults";

export default function App() {
  return (
    <ScanProvider>
      <Routes>
        <Route path="/login"    element={<Login />} />
        <Route path="/register" element={<Register />} />

        <Route path="/"        element={<Navigate to="/dashboard" replace />} />
        <Route path="/archived" element={<Navigate to="/archived-scans" replace />} />

        <Route path="/dashboard"     element={<PrivateRoute requiredPermission={{resource: "scans", action: "execute"}}><Dashboard /></PrivateRoute>} />
        <Route path="/scan"          element={<PrivateRoute requiredPermission={{resource: "scans", action: "execute"}}><NewScan /></PrivateRoute>} />
        <Route path="/scan/host-discovery"   element={<PrivateRoute requiredPermission={{resource: "scans", action: "read"}}><Phase1Results /></PrivateRoute>} />
        <Route path="/scan/asset-discovery"   element={<PrivateRoute requiredPermission={{resource: "scans", action: "read"}}><Phase2Results /></PrivateRoute>} />
        <Route path="/scan/advanced-scan"   element={<PrivateRoute requiredPermission={{resource: "scans", action: "read"}}><Phase3Results /></PrivateRoute>} />
        <Route path="/scan/credentialed"         element={<PrivateRoute requiredPermission={{resource: "scans", action: "execute"}}><CredentialedScan /></PrivateRoute>} />
        <Route path="/scan/credentialed/results" element={<PrivateRoute requiredPermission={{resource: "scans", action: "read"}}><CredentialedResults /></PrivateRoute>} />
        <Route path="/history"       element={<PrivateRoute requiredPermission={{resource: "scans", action: "read"}}><ScanHistory /></PrivateRoute>} />
        <Route path="/archived-scans" element={<PrivateRoute requiredPermission={{resource: "scans", action: "read"}}><ArchivedScans /></PrivateRoute>} />
        <Route path="/recycle-bin"   element={<PrivateRoute requiredPermission={{resource: "scans", action: "read"}}><RecycleBin /></PrivateRoute>} />
        <Route path="/reports"       element={<PrivateRoute requiredPermission={{resource: "reports", action: "read"}}><SecurityReports /></PrivateRoute>} />

        {/* Admin Module */}
        <Route path="/admin/users"   element={<PrivateRoute requiredPermission={{resource: "users", action: "read"}}><UserManagement /></PrivateRoute>} />
        <Route path="/admin/deleted-users" element={<PrivateRoute requiredPermission={{resource: "users", action: "delete"}}><DeletedUsers /></PrivateRoute>} />
        <Route path="/admin/roles"   element={<PrivateRoute requiredPermission={{resource: "roles", action: "read"}}><RoleManagement /></PrivateRoute>} />
        <Route path="/admin/organizations" element={<PrivateRoute superadminOnly><OrganizationManagement /></PrivateRoute>} />
        <Route path="/admin/audit-logs" element={<PrivateRoute requiredPermission={{resource: "audit", action: "read"}}><AuditLogs /></PrivateRoute>} />

        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </ScanProvider>
  );
}
