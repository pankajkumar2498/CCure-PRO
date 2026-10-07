/**
 * src/shell/auth/components/AuthHeroPanel.jsx
 * The panel beside every sign-in screen. A platform screen: it names the platform
 * ("CCure") and no product, and it states no capability, figure or status it
 * cannot back — the earlier panel carried invented usage figures and a hardcoded
 * status badge, none of which was measured from anything (UI semantic integrity: an absent answer is not a
 * reassuring one). Product wording is the owner's (D12-9); none is written here.
 */
import { CcureBadge } from "../../../design-system";
import { ShieldLogoIcon } from "./AuthIcons";

const HERO_CONTENT = {
  login: {
    badge: "SECURE SIGN-IN",
    headline: "Sign in to CCure",
    subheadline: "Use your CCure account to continue.",
  },
  register: {
    badge: "ACCOUNT REQUEST",
    headline: "Request a CCure account",
    subheadline: "Register your organization to get started.",
  },
  forgot: {
    badge: "SECURE RECOVERY",
    headline: "Recover your account",
    subheadline: "Reset your password with a link sent to your email address.",
  },
  reset: {
    badge: "ACCESS RESTORATION",
    headline: "Set a new password",
    subheadline:
      "Choose a new password to restore access to your CCure account.",
  },
};

export default function AuthHeroPanel({ pageType = "login" }) {
  const content = HERO_CONTENT[pageType] || HERO_CONTENT.login;

  return (
    <div className="auth-hero-panel">
      <div className="auth-hero-content">
        {/* Brand Header */}
        <div className="auth-hero-brand">
          <ShieldLogoIcon size={36} />
          <span className="auth-hero-brand-title">CCure</span>
        </div>

        {/* Dynamic Context Section */}
        <div className="auth-hero-context">
          <CcureBadge variant="info" className="auth-hero-badge">
            {content.badge}
          </CcureBadge>
          {/* h2, not h1. Every auth page renders its own <h1> in the card —
              the page's actual name — and this panel is decorative marketing
              copy beside it. Two level-1 headings gave each of the five auth
              pages two competing document titles, which is what a screen
              reader announces when the user asks what page they are on.
              The class carries every visual property and theme.css zeroes UA
              margins globally, so the change is visually inert. */}
          <h2 className="auth-hero-headline">{content.headline}</h2>
          <p className="auth-hero-subheadline">{content.subheadline}</p>
        </div>
      </div>
    </div>
  );
}
