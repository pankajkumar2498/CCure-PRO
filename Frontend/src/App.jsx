/**
 * src/App.jsx — Phase 3 routes (5 real pages)
 */
import { Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider }   from "./context/AuthContext";
import { ScanProvider }   from "./context/ScanContext";
import PrivateRoute       from "./components/PrivateRoute";

import Login          from "./pages/Login";
import Register       from "./pages/Register";
import NewScan        from "./pages/scan/NewScan";
import Phase1Results  from "./pages/scan/Phase1Results";
import Phase2Results  from "./pages/scan/Phase2Results";
import Phase3Results  from "./pages/scan/Phase3Results";
import ScanHistory    from "./pages/ScanHistory";

export default function App() {
  return (
    <AuthProvider>
      <ScanProvider>
        <Routes>
          {/* Public */}
          <Route path="/login"    element={<Login />} />
          <Route path="/register" element={<Register />} />

          {/* Protected scan wizard */}
          <Route path="/scan"         element={<PrivateRoute><NewScan /></PrivateRoute>} />
          <Route path="/scan/phase1"  element={<PrivateRoute><Phase1Results /></PrivateRoute>} />
          <Route path="/scan/phase2"  element={<PrivateRoute><Phase2Results /></PrivateRoute>} />
          <Route path="/scan/phase3"  element={<PrivateRoute><Phase3Results /></PrivateRoute>} />

          {/* History */}
          <Route path="/history"  element={<PrivateRoute><ScanHistory /></PrivateRoute>} />

          {/* Default */}
          <Route path="*" element={<Navigate to="/scan" replace />} />
        </Routes>
      </ScanProvider>
    </AuthProvider>
  );
}
