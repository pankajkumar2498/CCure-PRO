/**
 * src/shell/auth/IncompatibleBackend.jsx
 * Shown when the backend does not answer with the authorization contract this
 * build requires. There is no older-backend fallback: the UI says so instead of
 * guessing what the account may do.
 */
import { CcureAlert } from "../../design-system";
import AuthLayout from "./components/AuthLayout";
import AuthErrorBoundary from "./components/AuthErrorBoundary";

export default function IncompatibleBackend({ message }) {
  return (
    <AuthErrorBoundary>
      <AuthLayout pageType="unavailable" title="Account access unavailable">
        <h1 className="auth-title">Account access unavailable</h1>
        <p className="auth-sub">
          CCure PRO cannot complete sign-in with this backend. Contact your
          administrator.
        </p>
        <CcureAlert variant="danger">{message}</CcureAlert>
      </AuthLayout>
    </AuthErrorBoundary>
  );
}
