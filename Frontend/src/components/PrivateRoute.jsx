/**
 * src/components/PrivateRoute.jsx
 * Wraps protected routes. Shows spinner while auth state loads,
 * then redirects to /login if user is not authenticated.
 */
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function PrivateRoute({ children, requiredPermission }) {
  const { user, loading, authState, authMessage } = useAuth();
  const location          = useLocation();

  if (loading) {
    return (
      <div style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "#1a2332",
      }}>
        <div className="spinner" />
      </div>
    );
  }

  if (!user) {
    return (
      <Navigate
        to="/login"
        state={{ from: location, reason: authState, message: authMessage }}
        replace
      />
    );
  }

  if (requiredPermission) {
    const { resource, action } = requiredPermission;
    const hasPermission = user.role?.permissions?.some(
      (p) => p.resource === resource && (p.action === action || p.action === "manage")
    );

    if (!hasPermission) {
      return <Navigate to="/dashboard" replace />;
    }
  }

  return children;
}
