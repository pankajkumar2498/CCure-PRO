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
 */
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import AuthHeroPanel from "../components/auth/AuthHeroPanel";
import AuthTrustFooter from "../components/auth/AuthTrustFooter";
import { ShieldLogoIcon } from "../components/auth/AuthIcons";
import { verifyEmail, resendVerification } from "../api/auth";

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
      <div className="auth-form-panel">
        <div className="auth-card">
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
      <p className="auth-sub">One moment while we confirm your link.</p>,
    );
  }

  if (state === "verified") {
    return shell(
      "Email verified",
      <>
        <p className="auth-sub">{message || "You can now sign in."}</p>
        <Link
          to="/login"
          className="auth-btn"
          style={{ textDecoration: "none" }}
        >
          Continue to sign in
        </Link>
      </>,
    );
  }

  if (state === "pending_approval") {
    return shell(
      "Email verified",
      <>
        <p className="auth-sub">
          {message ||
            "Your account is awaiting administrator approval; you will be able to sign in once it is approved."}
        </p>
        <div
          className="auth-error"
          role="status"
          style={{
            background: "rgba(245,158,11,0.12)",
            borderColor: "#f59e0b",
            color: "#b45309",
          }}
        >
          <span>ℹ</span> Confirming your email proves you control this mailbox.
          It does not grant access on its own — an administrator approves new
          accounts before sign-in is enabled.
        </div>
        <p className="auth-sub" style={{ marginTop: 16 }}>
          <Link to="/login">Back to sign in</Link>
        </p>
      </>,
    );
  }

  // "invalid" and "missing" share a panel: a link that never had a token and a
  // link whose token expired or was already used are the same dead end, and
  // distinguishing them would leak which tokens exist.
  return shell(
    "This link is no longer valid",
    <>
      <p className="auth-sub">
        {message ||
          "Verification links expire after 24 hours and can be used only once."}
      </p>
      <div className="field">
        <label htmlFor="resend-email">
          Enter your email to receive a new link
        </label>
        <input
          id="resend-email"
          type="email"
          autoComplete="email"
          value={resendEmail}
          onChange={(e) => setResendEmail(e.target.value)}
          placeholder="name@company.com"
        />
        {resendState === "bad-email" && (
          <span className="field-hint field-hint--error">
            Enter a valid email address.
          </span>
        )}
      </div>
      <button
        type="button"
        className="auth-btn"
        onClick={handleResend}
        disabled={resendState === "sending" || resendState === "sent"}
      >
        {resendState === "sent"
          ? "Check your inbox"
          : resendState === "sending"
            ? "Sending…"
            : "Send a new verification link"}
      </button>
      {resendState === "sent" && (
        <p className="auth-sub" style={{ marginTop: 12 }}>
          If that address has an account awaiting verification, a new link is on
          its way.
        </p>
      )}
      <p className="auth-sub" style={{ marginTop: 16 }}>
        <Link to="/login">Back to sign in</Link>
      </p>
    </>,
  );
}
