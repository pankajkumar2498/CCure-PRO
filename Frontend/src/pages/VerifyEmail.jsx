/**
 * src/pages/VerifyEmail.jsx
 * Landing page for the link in the verification email.
 *
 * API: POST /auth/verify-email { token } → 200 { detail, status }
 *
 * The token arrives as a query parameter because that is what an email client
 * can click, but it is submitted in a POST body rather than being sent as part
 * of a GET the browser might replay, log, or leak through a Referer header.
 *
 * Verification is not a login. It confirms control of the mailbox and nothing
 * more; the account still needs an administrator's approval before it can sign
 * in, and this page says so rather than implying access has been granted.
 *
 * ── Unchanged by the Checkpoint 3C migration ────────────────────────────────
 * Every state, request, guard and message below is what it was before; the
 * migration changed presentation only. Two behaviours are worth naming because
 * they look like details and are not:
 *
 *   * `attempted` still guards the single-use token against StrictMode's
 *     double mount — the row is deleted in the same transaction that flips
 *     is_verified, so a second call would spend a token the first had already
 *     consumed and report a valid link as invalid;
 *   * the resend failure is still swallowed. The endpoint answers identically
 *     whether or not the address exists, so a distinct failure state here
 *     would rebuild the account-existence oracle the uniform response exists
 *     to prevent.
 */
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import AuthHeroPanel from "../components/auth/AuthHeroPanel";
import AuthTrustFooter from "../components/auth/AuthTrustFooter";
import { ShieldLogoIcon } from "../components/auth/AuthIcons";
import { CcureAlert, CcureButton, CcureInput } from "../design-system";
import { verifyEmail, resendVerification } from "@shell/api/auth";
import "../styles/auth.css";

export default function VerifyEmail() {
  const [params] = useSearchParams();
  const token = params.get("token") || "";

  // "working" | "verified" | "pending_approval" | "invalid" | "missing"
  const [state, setState] = useState(token ? "working" : "missing");
  const [message, setMessage] = useState("");

  const [resendEmail, setResendEmail] = useState("");
  const [resendState, setResendState] = useState("");

  // Tokens are single-use: the row is deleted in the same transaction that
  // flips is_verified. React 18's StrictMode mounts effects twice in
  // development, so without this guard the second call would consume a token
  // the first had already spent and the page would report a valid link as
  // invalid.
  const attempted = useRef(false);

  useEffect(() => {
    if (!token || attempted.current) return;
    attempted.current = true;

    verifyEmail(token)
      .then((data) => {
        setMessage(data?.detail || "");
        setState(data?.status === "verified" ? "verified" : "pending_approval");
      })
      .catch((err) => {
        setMessage(
          err?.response?.data?.detail ||
            err?.response?.data?.message ||
            "This verification link is invalid or has expired.",
        );
        setState("invalid");
      });
  }, [token]);

  const handleResend = async () => {
    if (!/\S+@\S+\.\S+/.test(resendEmail)) {
      setResendState("bad-email");
      return;
    }
    setResendState("sending");
    try {
      await resendVerification(resendEmail);
    } catch {
      // Deliberately ignored: the endpoint answers identically whether or not
      // the address exists, so there is no distinct failure to surface.
    }
    setResendState("sent");
  };

  const shell = (title, body) => (
    <div className="auth-split-wrapper">
      <AuthHeroPanel pageType="register" />
      {/* `cc-theme-dark` scopes the CCure semantic tokens to their dark values.
          The auth surface is a fixed dark panel that ignores `data-theme`. */}
      <div className="auth-form-panel">
        <div className="auth-card cc-theme-dark">
          <div className="auth-brand">
            <ShieldLogoIcon size={24} />
            <div className="auth-brand-text">
              <span className="auth-brand-name">CCure Audit</span>
              <span className="auth-brand-badge">PRO</span>
            </div>
          </div>
          <h1 className="auth-title">{title}</h1>
          {body}
          <AuthTrustFooter />
        </div>
      </div>
    </div>
  );

  if (state === "working") {
    return shell(
      "Verifying your email…",
      // role="status" so a user who cannot see the panel is told the page is
      // waiting on the network rather than left with silence. Previously this
      // was a plain paragraph and announced nothing at all.
      <p className="auth-sub" role="status">
        One moment while we confirm your link.
      </p>,
    );
  }

  if (state === "verified") {
    return shell(
      "Email verified",
      <div className="auth-prose">
        <p className="auth-sub">{message || "You can now sign in."}</p>
        <CcureButton as={Link} to="/login" block size="lg">
          Continue to sign in
        </CcureButton>
      </div>,
    );
  }

  if (state === "pending_approval") {
    return shell(
      "Email verified",
      <div className="auth-prose">
        <p className="auth-sub">
          {message ||
            "Your account is awaiting administrator approval; you will be able to sign in once it is approved."}
        </p>
        {/* This previously reused `.auth-error` with three inline overrides,
            and the text colour it set — #b45309 on an amber tint over the dark
            card — measured 3.02:1. The most important sentence on the page was
            the least readable thing on it; the token layer resolves it against
            the scoped-dark palette instead.

            `role="status"` is set deliberately, overriding the assertive role
            CcureAlert gives `warning`. This is a caveat attached to a success,
            not an error: the user has just landed on the page and the message
            is already the first thing on it, so announcing it assertively
            interrupts a reader who is being told the very same thing anyway.
            The pre-migration markup was explicitly `role="status"` and that
            was right. */}
        <CcureAlert variant="warning" role="status">
          Confirming your email proves you control this mailbox. It does not
          grant access on its own — an administrator approves new accounts
          before sign-in is enabled.
        </CcureAlert>
        <p className="auth-sub">
          <Link to="/login" className="auth-link">
            Back to sign in
          </Link>
        </p>
      </div>,
    );
  }

  // "invalid" and "missing" share a panel: a link that never had a token and a
  // link whose token expired or was already used are the same dead end, and
  // distinguishing them would leak which tokens exist.
  return shell(
    "This link is no longer valid",
    <div className="auth-prose">
      <p className="auth-sub">
        {message ||
          "Verification links expire after 24 hours and can be used only once."}
      </p>

      <CcureInput
        id="resend-email"
        name="resend-email"
        label="Enter your email to receive a new link"
        type="email"
        autoComplete="email"
        value={resendEmail}
        onChange={(e) => setResendEmail(e.target.value)}
        placeholder="name@company.com"
        error={
          resendState === "bad-email"
            ? "Enter a valid email address."
            : undefined
        }
      />

      <CcureButton
        type="button"
        block
        size="lg"
        onClick={handleResend}
        loading={resendState === "sending"}
        disabled={resendState === "sent"}
      >
        {resendState === "sent"
          ? "Check your inbox"
          : resendState === "sending"
            ? "Sending…"
            : "Send a new verification link"}
      </CcureButton>

      {resendState === "sent" && (
        <p className="auth-sub" role="status">
          If that address has an account awaiting verification, a new link is on
          its way.
        </p>
      )}

      <p className="auth-sub">
        <Link to="/login" className="auth-link">
          Back to sign in
        </Link>
      </p>
    </div>,
  );
}
