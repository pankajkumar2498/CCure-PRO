/**
 * src/components/PrivateRoute.jsx
 *
 * Wrap any route that requires authentication.
 *
 * Usage in App.jsx:
 *   <Route path="/scan" element={<PrivateRoute><NewScan /></PrivateRoute>} />
 *
 * - Shows a fullscreen spinner while the auth state is still loading.
 * - Redirects to /login (saving the intended path) if not authenticated.
 */

import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function PrivateRoute({ children }) {
  const { user, loading } = useAuth();
  const location          = useLocation();

  if (loading) {
    return (
      <div style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "#050a0e",
      }}>
        <div className="spinner" />
      </div>
    );
  }

  if (!user) {
    // Save the attempted URL so we can redirect after login
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}
