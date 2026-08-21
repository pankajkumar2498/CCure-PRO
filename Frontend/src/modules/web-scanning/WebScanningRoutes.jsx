import { Routes, Route, Navigate } from "react-router-dom";
import WebDashboard from "./pages/WebDashboard";
import ScanList from "./pages/ScanList";
import NewWebScan from "./pages/NewWebScan";
import ScanDetail from "./pages/ScanDetail";
import FindingsExplorer from "./pages/FindingsExplorer";
import AssetInventory from "./pages/AssetInventory";

import PanelErrorBoundary from "../../components/common/PanelErrorBoundary";
import "./styles/web-scanning.css";

export default function WebScanningRoutes() {
  return (
    <PanelErrorBoundary>
      <Routes>
        <Route path="dashboard" element={<WebDashboard />} />
        <Route path="list" element={<ScanList />} />
        <Route path="new" element={<NewWebScan />} />
        <Route path=":id" element={<ScanDetail />} />
        <Route path=":id/findings" element={<FindingsExplorer />} />
        <Route path=":id/assets" element={<AssetInventory />} />
        <Route path="*" element={<Navigate to="dashboard" replace />} />
      </Routes>
    </PanelErrorBoundary>
  );
}
