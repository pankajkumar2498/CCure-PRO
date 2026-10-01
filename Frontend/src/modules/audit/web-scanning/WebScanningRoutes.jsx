import { Routes, Route, Navigate } from "react-router-dom";
import WebDashboard from "./pages/WebDashboard";
import ScanList from "./pages/ScanList";
import NewWebScan from "./pages/NewWebScan";
import ScanDetail from "./pages/ScanDetail";
import FindingsExplorer from "./pages/FindingsExplorer";
import AssetInventory from "./pages/AssetInventory";
import AttackSurface from "./pages/AttackSurface";
import AllFindings from "./pages/AllFindings";
import AllEndpoints from "./pages/AllEndpoints";

import PanelErrorBoundary from "@audit/components/common/PanelErrorBoundary";
import "./styles/web-scanning.css";

export default function WebScanningRoutes() {
  return (
    <PanelErrorBoundary>
      <Routes>
        <Route path="dashboard" element={<WebDashboard />} />
        <Route path="list" element={<ScanList />} />
        <Route path="new" element={<NewWebScan />} />
        {/* Org-wide drill-downs — static paths, declared before :id so a scan
            id can never shadow them. */}
        <Route path="all-findings" element={<AllFindings />} />
        <Route path="all-endpoints" element={<AllEndpoints />} />
        <Route path=":id" element={<ScanDetail />} />
        <Route path=":id/findings" element={<FindingsExplorer />} />
        <Route path=":id/assets" element={<AssetInventory />} />
        <Route path=":id/attack-surface" element={<AttackSurface />} />
        <Route
          path="*"
          element={<Navigate to="/web-scans/dashboard" replace />}
        />
      </Routes>
    </PanelErrorBoundary>
  );
}
