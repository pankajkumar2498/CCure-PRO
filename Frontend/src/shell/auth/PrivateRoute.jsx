/**
 * src/shell/auth/PrivateRoute.jsx
 * Wraps protected routes. Shows spinner while auth state loads,
 * then redirects to /login if user is not authenticated. A signed-in user who
 * is refused is redirected to the product's first permitted page, or shown
 * `deniedElement` when the route supplies one (platform routes do).
 */
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "./AuthContext";
import { canPermission, canAny, canAll } from "./permissions";
import { useAccessFallbacks } from "./accessFallback";
import IncompatibleBackend from "./IncompatibleBackend";

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
  // What a refused user sees instead of being redirected. A platform route
  // passes the platform's own denied page, so the refusal stays in the Platform
  // Shell; without it the guard sends the user to the product's first
  // permitted page (accessFallback.jsx), as it always has.
  deniedElement,
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

  if (authState === "incompatible") {
    return <IncompatibleBackend message={authMessage} />;
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
    (!requiredPermission || canPermission(user, requiredPermission)) &&
    (!requiredAny || canAny(user, requiredAny)) &&
    (!requiredAll || canAll(user, requiredAll));

  if (!authorized) {
    if (deniedElement) return deniedElement;
    return (
      <Navigate
        to={fallbackPathFor(user, location.pathname, fallbacks)}
        replace
      />
    );
  }

  return children || <Outlet />;
}
