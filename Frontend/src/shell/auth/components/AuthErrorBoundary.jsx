import { Component } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { CcureAlert, CcureButton } from "../../../design-system";
import AuthLayout from "./AuthLayout";

/** Rendering failures only; Authentication requests and decisions stay in pages. */
export class AuthenticationRenderBoundary extends Component {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    if (!this.state.failed) return this.props.children;

    return (
      <AuthLayout
        pageType="unavailable"
        title="Authentication page unavailable"
      >
        <h1 className="auth-title">Authentication page unavailable</h1>
        <p className="auth-sub">
          Return to sign in to try again. If this continues, contact your
          administrator.
        </p>
        <CcureAlert variant="danger" className="auth-message">
          This authentication page could not be displayed.
        </CcureAlert>
        {/* A fresh document also recovers a failure on /login itself. No
            verification/reset token or error stack is copied into the link. */}
        <CcureButton as="a" href="/login" block size="lg">
          Return to sign in
        </CcureButton>
      </AuthLayout>
    );
  }
}

export default function AuthErrorBoundary({ children }) {
  const location = useLocation();
  return (
    <AuthenticationRenderBoundary key={location.pathname}>
      {children || <Outlet />}
    </AuthenticationRenderBoundary>
  );
}
