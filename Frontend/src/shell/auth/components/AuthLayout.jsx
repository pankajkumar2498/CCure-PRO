import { useEffect } from "react";
import { CcureCard } from "../../../design-system";
import AuthHeroPanel from "./AuthHeroPanel";
import { ShieldLogoIcon } from "./AuthIcons";
import "../styles/auth.css";

/** Authentication composition only; shared UX4G adapters own every control. */
export default function AuthLayout({ pageType = "login", title, children }) {
  useEffect(() => {
    const previousTitle = document.title;
    document.title = `${title} | CCure`;
    return () => {
      document.title = previousTitle;
    };
  }, [title]);

  return (
    <main className="auth-split-wrapper auth-layout">
      <header className="auth-platform-header">
        <div className="auth-platform-brand">
          <ShieldLogoIcon size={34} />
          <span className="auth-brand-name">CCure</span>
        </div>
        <p className="auth-platform-description">
          Enterprise Security / Vulnerability Management Platform
        </p>
      </header>

      <div className="auth-workspace">
        <AuthHeroPanel pageType={pageType} />
        <div className="auth-form-panel">
          <CcureCard as="div" className="auth-card">
            {children}
          </CcureCard>
        </div>
      </div>

      <footer className="auth-platform-footer">
        <span>CCure · Account access</span>
        <span>For access assistance, contact your administrator.</span>
      </footer>
    </main>
  );
}
