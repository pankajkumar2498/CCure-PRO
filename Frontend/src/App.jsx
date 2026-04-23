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

        <Route path="/dashboard"     element={<PrivateRoute><Dashboard /></PrivateRoute>} />
        <Route path="/scan"          element={<PrivateRoute><NewScan /></PrivateRoute>} />
        <Route path="/scan/host-discovery"   element={<PrivateRoute><Phase1Results /></PrivateRoute>} />
        <Route path="/scan/asset-discovery"   element={<PrivateRoute><Phase2Results /></PrivateRoute>} />
        <Route path="/scan/advanced-scan"   element={<PrivateRoute><Phase3Results /></PrivateRoute>} />
        <Route path="/scan/credentialed"         element={<PrivateRoute><CredentialedScan /></PrivateRoute>} />
        <Route path="/scan/credentialed/results" element={<PrivateRoute><CredentialedResults /></PrivateRoute>} />
        <Route path="/history"       element={<PrivateRoute><ScanHistory /></PrivateRoute>} />
        <Route path="/archived-scans" element={<PrivateRoute><ArchivedScans /></PrivateRoute>} />
        <Route path="/recycle-bin"   element={<PrivateRoute><RecycleBin /></PrivateRoute>} />
        <Route path="/reports"       element={<PrivateRoute><SecurityReports /></PrivateRoute>} />

        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </ScanProvider>
  );
}
