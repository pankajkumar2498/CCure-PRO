/**
 * src/shell/auth/PrivateRoute.jsx
 * Wraps protected routes. Shows spinner while auth state loads,
 * then redirects to /login if user is not authenticated.
 */
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "./AuthContext";
import { canPermission, canAny, canAll, isSuperAdmin } from "./permissions";
import { useAccessFallbacks } from "./accessFallback";

// The first candidate the user may open, other than the page just refused;
// otherwise sign-in. Candidates come from the product (accessFallback.jsx).
const fallbackPathFor = (user, currentPath, candidates) =>
  candidates.find(
    (candidate) =>
      candidate.path !== currentPath &&
      canPermission(user, candidate.permission),
  )?.path || "/login";

export default function PrivateRoute({
  children,
  requiredPermission,
  requiredAny,
  requiredAll,
  superadminOnly = false,
}) {
  const { user, loading, authState, authMessage } = useAuth();
  const location = useLocation();
  const fallbacks = useAccessFallbacks();

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
    return (
      <Navigate
        to={fallbackPathFor(user, location.pathname, fallbacks)}
        replace
      />
    );
  }

  return children || <Outlet />;
}
