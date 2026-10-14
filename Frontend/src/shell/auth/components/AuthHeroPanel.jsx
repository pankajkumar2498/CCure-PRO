/**
 * src/shell/auth/components/AuthHeroPanel.jsx
 * Platform identity and task context beside the authentication form.
 * No measured status, certification, or product-specific branding belongs here.
 */
import { CcureBadge } from "../../../design-system";

const HERO_CONTENT = {
  login: {
    badge: "Account access",
    heading: "Your CCure PRO workspace",
    subheadline:
      "Use your CCure PRO account to continue to your organization's security workspace.",
  },
  register: {
    badge: "Account registration",
    heading: "Access starts with your account",
    subheadline:
      "Create your account and verify your email. An administrator reviews new accounts before sign-in is enabled.",
  },
  forgot: {
    badge: "Account recovery",
    heading: "Restore access to CCure PRO",
    subheadline: "Reset your password with a link sent to your email address.",
  },
  reset: {
    badge: "Password reset",
    heading: "Restore access to CCure PRO",
    subheadline:
      "Choose a new password to restore access to your CCure PRO account.",
  },
  mfa: {
    badge: "Identity verification",
    heading: "Complete your sign-in",
    subheadline:
      "Enter a code from your authenticator, a recovery code, or request a code by email.",
  },
  verify: {
    badge: "Email verification",
    heading: "Confirm your email address",
    subheadline:
      "Email verification is one step in account registration. Administrator approval is required before you can sign in.",
  },
  unavailable: {
    badge: "Account access",
    heading: "Access needs attention",
    subheadline:
      "Contact your administrator with the message shown to resolve this access issue.",
  },
};

export default function AuthHeroPanel({ pageType = "login" }) {
  const content = HERO_CONTENT[pageType] || HERO_CONTENT.login;

  return (
    <aside
      className="auth-hero-panel cc-theme-dark"
      aria-label="About CCure PRO"
    >
      <div className="auth-hero-content">
        <p className="auth-hero-eyebrow">CCure PRO Platform</p>
        <h2 className="auth-hero-headline">
          Enterprise security &amp; vulnerability management
        </h2>
        <div className="auth-hero-context">
          <CcureBadge variant="neutral" className="auth-hero-badge">
            {content.badge}
          </CcureBadge>
          <p className="auth-hero-context-title">{content.heading}</p>
          <p className="auth-hero-subheadline">{content.subheadline}</p>
        </div>
      </div>
    </aside>
  );
}
