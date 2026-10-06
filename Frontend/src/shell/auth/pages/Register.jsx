/**
 * src/pages/Register.jsx
 * Dark-themed registration form matching CAST design.
 *
 * API: POST /auth/register → 202 { detail, status: "pending_verification" }
 *
 * Registration returns no tokens and does not sign the user in. The account is
 * created unverified, inactive and unapproved, and needs both a confirmed
 * mailbox and an administrator approval before it can log in. On success this
 * page shows a "check your email" panel rather than navigating to /dashboard.
 *
 * The whole route is also feature-gated: when a deployment has
 * ALLOW_SELF_REGISTRATION off (the default) every self-service endpoint returns
 * 404, and the page says so instead of presenting a form that cannot succeed.
 *
 * ── Unchanged by the Checkpoint 3C migration ────────────────────────────────
 * Every handler, request, guard, validation rule and message below is what it
 * was before; the migration changed presentation only. Three properties are
 * worth naming because they look cosmetic and are not:
 *
 *   * there is still no live "this email is already registered" check, and
 *     there must never be one — see the note beside the checkEmail effect;
 *   * the email is lower-cased and trimmed, and the password is never
 *     trimmed;
 *   * the resend failure is swallowed, because the endpoint answers
 *     identically for every address.
 */
import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "@shell/auth/AuthContext";
import AuthHeroPanel from "../components/AuthHeroPanel";
import AuthTrustFooter from "../components/AuthTrustFooter";
import { ShieldLogoIcon } from "../components/AuthIcons";
import {
  CcureAlert,
  CcureButton,
  CcureInput,
  CcureCheckbox,
  CcureModal,
  CcurePasswordField,
  gradePassword,
  CcureCard,
} from "../../../design-system";
import {
  checkEmail,
  checkUsername,
  isSelfRegistrationEnabled,
  resendVerification,
} from "@shell/api/auth";
import { useDebounce } from "@shell/hooks/useDebounce";
import "../styles/auth.css";

function validate(fullName, username, email, password, confirm, agreeToTerms) {
  if (!fullName || !fullName.trim()) return "Full name is required.";
  if (fullName.trim().length > 255)
    return "Full name cannot exceed 255 characters.";
  if (username.trim().length < 3)
    return "Username must be at least 3 characters.";
  if (username.includes("@")) return "Username cannot contain '@' symbol.";
  if (!/\S+@\S+\.\S+/.test(email)) return "Enter a valid email address.";
  if (password.length < 12) return "Password must be at least 12 characters.";
  if (!/[A-Z]/.test(password))
    return "Password must contain at least one uppercase letter.";
  if (!/[0-9]/.test(password))
    return "Password must contain at least one digit.";
  if (!/[^a-zA-Z0-9]/.test(password))
    return "Password must contain at least one special character.";
  if (password !== confirm) return "Passwords do not match.";
  if (!agreeToTerms)
    return "You must agree to the Terms of Service and Privacy Policy.";
  return null;
}

/* Re-exported from the design system so the two pages that grade a password
   cannot drift into two different scales. The named export is kept because
   it was public before the migration. */
export const strengthOf = gradePassword;

export default function Register() {
  const { register } = useAuth();

  const [fullName, setFullName] = useState("");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [agreeToTerms, setAgreeToTerms] = useState(false);

  const [showTermsModal, setShowTermsModal] = useState(false);
  const [showPrivacyModal, setShowPrivacyModal] = useState(false);

  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const [usernameTaken, setUsernameTaken] = useState(false);
  const [usernameChecked, setUsernameChecked] = useState(false);

  // Set once registration succeeds; swaps the form for the "check your email"
  // panel. Registration no longer produces a session, so there is nothing to
  // navigate to.
  const [submitted, setSubmitted] = useState(false);
  const [resendState, setResendState] = useState("");

  // null = still probing, true/false = known. Rendering the form before this
  // resolves would flash a signup form at users of a deployment that does not
  // allow signup.
  const [selfRegAllowed, setSelfRegAllowed] = useState(null);

  useEffect(() => {
    let cancelled = false;
    isSelfRegistrationEnabled().then((allowed) => {
      if (!cancelled) setSelfRegAllowed(allowed);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const debouncedUsername = useDebounce(username, 500);

  useEffect(() => {
    if (debouncedUsername.length >= 3 && !debouncedUsername.includes("@")) {
      checkUsername(debouncedUsername)
        .then((res) => {
          setUsernameTaken(!res.available);
          setUsernameChecked(true);
        })
        .catch(() => {
          setUsernameChecked(false);
        });
    } else {
      setUsernameTaken(false);
      setUsernameChecked(false);
    }
  }, [debouncedUsername]);

  // The live "this email is already registered" check is gone deliberately.
  //
  // /auth/check-email does not answer that question and never will: answering
  // truthfully made it an unauthenticated oracle for testing whether any given
  // address held an account, one request at a time. A collision is still
  // enforced server-side — it surfaces as the same generic 202 as every other
  // outcome, so the attacker learns nothing and the legitimate user is told by
  // email.
  //
  // It does now answer about the *domain*, which is a different kind of fact:
  // "this is a disposable mail service" is true for every caller and reveals
  // nothing about any account. Surfacing it here saves someone from filling in
  // the whole form only to be refused at submit.
  const debouncedEmail = useDebounce(email, 600);
  const [domainWarning, setDomainWarning] = useState("");

  useEffect(() => {
    const candidate = debouncedEmail.trim().toLowerCase();
    if (!/\S+@\S+\.\S+/.test(candidate)) {
      setDomainWarning("");
      return;
    }
    let cancelled = false;
    checkEmail(candidate)
      .then((res) => {
        if (cancelled) return;
        setDomainWarning(res?.available === false ? res.detail || "" : "");
      })
      .catch(() => {
        // Advisory only. A failed probe must not stop anyone signing up; the
        // authoritative check runs at submit.
        if (!cancelled) setDomainWarning("");
      });
    return () => {
      cancelled = true;
    };
  }, [debouncedEmail]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const normalizedEmail = email.trim().toLowerCase();
    const ve = validate(
      fullName,
      username,
      normalizedEmail,
      password,
      confirm,
      agreeToTerms,
    );
    if (ve) {
      setError(ve);
      return;
    }
    setError("");
    setLoading(true);
    try {
      await register({
        username: username.trim(),
        email: normalizedEmail,
        password,
        full_name: fullName.trim() || undefined,
        agree_to_terms: agreeToTerms,
      });
      // No tokens come back and the account cannot log in yet, so there is
      // nowhere to navigate. Show the pending panel instead.
      setSubmitted(true);
    } catch (err) {
      // 404 means the deployment has self-registration disabled.
      if (err.response?.status === 404) {
        setSelfRegAllowed(false);
        return;
      }
      let errMsg = "Registration failed. Please try again.";
      if (err.response?.data?.details) {
        errMsg = err.response.data.details
          .map((d) => (d.msg || d.type || "").replace(/^Value error,\s*/i, ""))
          .filter(Boolean)
          .join(", ");
      } else if (err.response?.data?.message) {
        errMsg = err.response.data.message;
      } else if (err.response?.data?.detail) {
        const detail = err.response.data.detail;
        if (Array.isArray(detail)) {
          errMsg = detail
            .map((d) => (d.msg || "").replace(/^Value error,\s*/i, ""))
            .filter(Boolean)
            .join(", ");
        } else if (typeof detail === "string") {
          errMsg = detail.replace(/^Value error,\s*/i, "");
        }
      }
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    setResendState("sending");
    try {
      await resendVerification(email.trim().toLowerCase());
      setResendState("sent");
    } catch {
      // The endpoint answers identically for every address, so there is no
      // failure state worth distinguishing for the user.
      setResendState("sent");
    }
  };

  const brandHeader = (
    <div className="auth-brand">
      <ShieldLogoIcon size={24} />
      <div className="auth-brand-text">
        <span className="auth-brand-name">CCure</span>
      </div>
    </div>
  );

  /* Shared auth surfaces follow the application theme and design-system tokens. */
  const shell = (body) => (
    <main className="auth-split-wrapper">
      <AuthHeroPanel pageType="register" />
      <div className="auth-form-panel">
        <CcureCard as="div" className="auth-card">
          {brandHeader}
          {body}
          <AuthTrustFooter />
        </CcureCard>
      </div>
    </main>
  );

  // ── Self-registration disabled for this deployment ───────────────────────
  if (selfRegAllowed === false) {
    return shell(
      <div className="auth-prose">
        <h1 className="auth-title">Accounts are created by an administrator</h1>
        <p className="auth-sub">
          Self-service sign-up is turned off on this installation, so accounts
          are provisioned deliberately rather than opened on request.
        </p>
        <p className="auth-sub">
          Ask your CCure administrator to create an account for you. If you
          already have one, sign in below.
        </p>
        <CcureButton as={Link} to="/login" block size="lg">
          Back to sign in
        </CcureButton>
      </div>,
    );
  }

  // ── Registered, awaiting mailbox confirmation ────────────────────────────
  if (submitted) {
    return shell(
      <div className="auth-prose">
        <h1 className="auth-title">Check your email</h1>
        <p className="auth-sub">
          If that address can be registered, we have sent a verification link to{" "}
          <strong>{email.trim().toLowerCase()}</strong>. The link is valid for
          24 hours and can be used once.
        </p>
        {/* `role="status"` deliberately overrides the assertive role
            CcureAlert gives `warning`: this is a caveat attached to a success
            the user is already reading, not an interruption. The pre-migration
            markup was explicitly polite and that was right. It also previously
            hardcoded #b45309 on an amber tint, which measured 3.02:1 over the
            dark card — the most important sentence on the page was the least
            readable thing on it. */}
        <CcureAlert variant="warning" role="status">
          Confirming your email does not by itself grant access. An
          administrator reviews and approves new accounts before sign-in is
          enabled, and you will be notified once that happens.
        </CcureAlert>
        <CcureButton
          type="button"
          block
          size="lg"
          onClick={handleResend}
          loading={resendState === "sending"}
          disabled={resendState === "sent"}
        >
          {resendState === "sent"
            ? "Verification email re-sent"
            : resendState === "sending"
              ? "Sending…"
              : "Resend verification email"}
        </CcureButton>
        <p className="auth-sub">
          <CcureButton
            as={Link}
            variant="ghost"
            size="sm"
            to="/login"
            className="auth-link"
          >
            Back to sign in
          </CcureButton>
        </p>
      </div>,
    );
  }

  /* Username feedback. Previously four sibling <span>s beside the field, none
     of them associated with it; now one message routed through CcureInput's
     error/hint wiring so it is announced with the field it describes. Error
     supersedes hint, which is the component's own rule. */
  const usernameError = username.includes("@")
    ? "Username cannot contain '@' symbol"
    : usernameTaken
      ? "This username is already taken."
      : undefined;
  const usernameHint =
    username && !username.includes("@") && username.length < 3
      ? "Min. 3 characters"
      : usernameChecked &&
          !usernameTaken &&
          username.length >= 3 &&
          !username.includes("@")
        ? "Username available"
        : undefined;

  const policyFooter = (close) => (
    <CcureButton
      type="button"
      onClick={() => {
        setAgreeToTerms(true);
        close();
      }}
    >
      Accept &amp; Close
    </CcureButton>
  );

  return (
    <>
      {shell(
        <>
          <h1 className="auth-title">Create account</h1>
          <p className="auth-sub">Register your organization to get started</p>

          {error && (
            <CcureAlert variant="danger" className="auth-message">
              {error}
            </CcureAlert>
          )}

          <form onSubmit={handleSubmit} className="auth-form auth-stack">
            <CcureInput
              id="fullName"
              name="fullName"
              label="Full Name"
              type="text"
              autoComplete="name"
              maxLength={255}
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="e.g. John Doe"
              required
            />

            <CcureInput
              id="username"
              name="username"
              label="Username"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="username"
              required
              error={usernameError}
              hint={usernameHint}
            />

            <CcureInput
              id="email"
              name="email"
              label="Email"
              type="email"
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="name@company.com"
              required
              /* Still no "already registered" hint, by design — see the note
                 beside the checkEmail effect above. The domain verdict is a
                 different fact and safe to show. */
              error={domainWarning || undefined}
              hint="We will send a verification link to this address."
            />

            <CcurePasswordField
              id="password"
              name="password"
              label="Password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
              showStrength
            />

            <CcurePasswordField
              id="confirm"
              name="confirm"
              label="Confirm password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="••••••••"
              required
              error={
                confirm && confirm !== password
                  ? "Passwords don't match"
                  : undefined
              }
              hint={
                confirm && confirm === password && password
                  ? "Passwords match"
                  : undefined
              }
            />

            {/* Terms of Service & Privacy Policy Checkbox */}
            <div className="auth-checkbox-row auth-consent-row">
              <CcureCheckbox
                checked={agreeToTerms}
                onChange={(e) => setAgreeToTerms(e.target.checked)}
                required
                aria-describedby="registration-policies"
              >
                I agree to the Terms of Service and Privacy Policy
              </CcureCheckbox>
              <div id="registration-policies" className="auth-policy-actions">
                <CcureButton
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowTermsModal(true)}
                >
                  Terms of Service
                </CcureButton>{" "}
                and{" "}
                <CcureButton
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowPrivacyModal(true)}
                >
                  Privacy Policy
                </CcureButton>
              </div>
            </div>

            <CcureButton type="submit" loading={loading} block size="lg">
              {loading ? "Creating account..." : "Create Account →"}
            </CcureButton>
          </form>

          <p className="auth-switch">
            Already have access?{" "}
            <CcureButton
              as={Link}
              variant="ghost"
              size="sm"
              to="/login"
              className="auth-link"
            >
              Sign in
            </CcureButton>
          </p>
        </>,
      )}

      {/* Both policy dialogs were previously raw fixed-position <div>s: no
          role, no accessible name, no focus trap, no Escape, and a dismiss
          control named only by the glyph "×". CcureModal supplies all five. */}
      <CcureModal
        open={showTermsModal}
        onClose={() => setShowTermsModal(false)}
        title="Terms of Service — CCure Audit PRO"
        footer={policyFooter(() => setShowTermsModal(false))}
      >
        <div
          className="auth-policy-body"
          role="region"
          aria-label="Terms and conditions text"
          tabIndex={0}
        >
          <p>
            Welcome to CCure Audit PRO. By creating an account and using our
            network security platform, you agree to comply with the following
            terms:
          </p>
          <h4>1. Authorized Use</h4>
          <p>
            You agree to only perform security assessments and vulnerability
            scans on networks, hosts, and domain infrastructure that you own or
            have explicit written authorization to audit.
          </p>
          <h4>2. Account Security</h4>
          <p>
            You are responsible for maintaining the confidentiality of your
            credentials and multi-factor authentication tokens. Any action
            initiated under your credentials is your responsibility.
          </p>
          <h4>3. Compliance &amp; Audit Logs</h4>
          <p>
            All activities performed on this platform are recorded in
            tamper-resistant immutable audit logs for enterprise compliance and
            SIEM auditing.
          </p>
        </div>
      </CcureModal>

      <CcureModal
        open={showPrivacyModal}
        onClose={() => setShowPrivacyModal(false)}
        title="Privacy Policy — CCure Audit PRO"
        footer={policyFooter(() => setShowPrivacyModal(false))}
      >
        <div
          className="auth-policy-body"
          role="region"
          aria-label="Privacy policy text"
          tabIndex={0}
        >
          <p>
            Your privacy and data security are our top priorities. Here is how
            we handle your personal and enterprise telemetry data:
          </p>
          <h4>1. Data Collection</h4>
          <p>
            We collect your username, email address, optional full name, and
            authentication logs to provide secure tenant isolation and audit
            trails.
          </p>
          <h4>2. Scan Result Encryption</h4>
          <p>
            All network scan assets, vulnerability reports, and credential
            credentials are stored with strict multi-tenant isolation and
            database encryption.
          </p>
          <h4>3. No Data Sharing</h4>
          <p>
            We never sell or share your telemetry or scan findings with third
            parties.
          </p>
        </div>
      </CcureModal>
    </>
  );
}
