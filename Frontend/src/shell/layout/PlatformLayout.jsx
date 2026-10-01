/**
 * src/shell/layout/PlatformLayout.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * The platform's own page frame: CCure branding, the signed-in user and
 * sign-out. Used by CCure Home and the module entry pages. It is deliberately
 * not Audit's AppLayout — the platform pages belong to no product, and showing
 * Audit's sidebar on them would make CCure Home read as an Audit screen.
 */
import { Link } from "react-router-dom";
import { CcureButton } from "../../design-system";
import { useAuth } from "../auth/AuthContext";
import "./platform-layout.css";

export default function PlatformLayout({ children }) {
  const { user, logout } = useAuth();
  const who = user?.username || user?.email || "";

  return (
    <div className="pl-frame">
      <header className="pl-header">
        <Link to="/" className="pl-brand" aria-label="CCure Home">
          <span className="pl-brand__name">CCure</span>
          <span className="pl-brand__sub">Home</span>
        </Link>
        <div className="pl-header__actions">
          {who ? (
            <span className="pl-user" title={who}>
              {who}
            </span>
          ) : null}
          <CcureButton variant="ghost" size="sm" onClick={() => logout()}>
            Sign out
          </CcureButton>
        </div>
      </header>
      <main className="pl-main" id="main-content">
        {children}
      </main>
    </div>
  );
}
