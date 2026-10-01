/**
 * src/components/auth/PrivateRoute.jsx
 * Wraps protected routes. Shows spinner while auth state loads,
 * then redirects to /login if user is not authenticated.
 */
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import {
  canPermission,
  canAny,
  canAll,
  isSuperAdmin,
} from "../../auth/permissions";

const fallbackPathFor = (user, currentPath) => {
  const candidates = [
    {
      path: "/audit-dashboard",
      permission: { resource: "scans", action: "execute" },
    },
    { path: "/history", permission: { resource: "scans", action: "read" } },
    { path: "/reports", permission: { resource: "reports", action: "read" } },
    { path: "/admin/users", permission: { resource: "users", action: "read" } },
    {
      path: "/admin/audit-logs",
      permission: { resource: "audit", action: "read" },
    },
  ];

  return (
    candidates.find(
      (candidate) =>
        candidate.path !== currentPath &&
        canPermission(user, candidate.permission),
    )?.path || "/login"
  );
};

export default function PrivateRoute({
  children,
  requiredPermission,
  requiredAny,
  requiredAll,
  superadminOnly = false,
}) {
  const { user, loading, authState, authMessage } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#1a2332",
        }}
      >
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

  const authorized =
    (!superadminOnly || isSuperAdmin(user)) &&
    (!requiredPermission || canPermission(user, requiredPermission)) &&
    (!requiredAny || canAny(user, requiredAny)) &&
    (!requiredAll || canAll(user, requiredAll));

  if (!authorized) {
    return <Navigate to={fallbackPathFor(user, location.pathname)} replace />;
  }

  return children || <Outlet />;
}
