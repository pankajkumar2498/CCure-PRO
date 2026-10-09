/**
 * src/pages/Login.jsx
 * CCure account sign-in and MFA challenge.
 * API: POST /auth/login -> { access_token, user }
 *
 * ── Security contract, unchanged by the Checkpoint 3C migration ─────────────
 * Every handler, piece of state, storage key, endpoint and navigation below is
 * byte-for-byte what it was before. The migration changed presentation only.
 * Specifically preserved:
 *
 *   * the identifier is trimmed and the password is never trimmed — trimming a
 *     password silently authenticates with a credential the user did not type;
 *   * an `mfa_required` response shows the challenge and does not navigate, and
 *     the `mfa_token` is held in state only: never rendered, never persisted;
 *   * "remember me" writes the identifier and only the identifier, and clearing
 *     it also clears the legacy `ccure_remembered_email` key;
 *   * the post-login destination comes from router state, or from
 *     `postLoginRedirect` when and only when the visit was an expiry, and that
 *     key is removed on success so a stale destination cannot be replayed;
 *   * the self-registration probe is the backend's decision, not this page's —
 *     `null` renders neither branch rather than flashing a link.
 *
 * src/__tests__/pages/Login.test.jsx asserts all of the above and was written
 * against the pre-migration page.
 */
import { useMemo, useState, useRef, useEffect } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "@shell/auth/AuthContext";
import AuthLayout from "../components/AuthLayout";
import {
  CcureAlert,
  CcureButton,
  CcureInput,
  CcureCheckbox,
  CcurePasswordField,
} from "../../../design-system";
import {
  verifyMfa as verifyMfaApi,
  sendEmailOtp as sendEmailOtpApi,
  isSelfRegistrationEnabled,
} from "@shell/api/auth";
import "../styles/auth.css";

export default function Login() {
  const { login, refreshUser, authMessage } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  // Whether this deployment allows self-service signup. The backend is the only
  // authority: with ALLOW_SELF_REGISTRATION off, /auth/register and the
  // availability probes all return 404, so a "Register here" link would send
  // the user to a page that can only tell them they cannot register.
  //
  // null while the probe is in flight, so nothing is rendered in that gap
  // rather than flashing a link that is about to disappear.
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
  const fromLocation = location.state?.from;
  const savedRedirect =
    location.state?.reason === "expired"
      ? sessionStorage.getItem("postLoginRedirect")
      : "";
  // With no page to return to, sign-in lands on CCure Home (Phase 12); a deep
  // link through sign-in, or the page a session expired on, still wins.
  const from = fromLocation
    ? `${fromLocation.pathname || "/"}${fromLocation.search || ""}${fromLocation.hash || ""}`
    : savedRedirect || "/";

  const [rememberMe, setRememberMe] = useState(() => {
    return localStorage.getItem("ccure_remember_me") === "true";
  });

  const [emailOrUsername, setEmailOrUsername] = useState(() => {
    return (
      localStorage.getItem("ccure_remembered_identity") ||
      localStorage.getItem("ccure_remembered_email") ||
      ""
    );
  });

  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // MFA Challenge State
  const [showMfa, setShowMfa] = useState(false);
  const [mfaToken, setMfaToken] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [emailSent, setEmailSent] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);

  const resendIntervalRef = useRef(null);

  const noticeMessage = useMemo(() => {
    return location.state?.message || authMessage || "";
  }, [location.state, authMessage]);

  const clearResendInterval = () => {
    if (resendIntervalRef.current) {
      clearInterval(resendIntervalRef.current);
      resendIntervalRef.current = null;
    }
  };

  useEffect(() => {
    return () => clearResendInterval();
  }, []);

  const startCooldown = () => {
    clearResendInterval();
    setResendCooldown(60);
    resendIntervalRef.current = setInterval(() => {
      setResendCooldown((prev) => {
        if (prev <= 1) {
          clearResendInterval();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    const cleanedIdentifier = emailOrUsername.trim();

    // Remember Me persistence
    if (rememberMe) {
      localStorage.setItem("ccure_remember_me", "true");
      localStorage.setItem("ccure_remembered_identity", cleanedIdentifier);
    } else {
      localStorage.removeItem("ccure_remember_me");
      localStorage.removeItem("ccure_remembered_identity");
      localStorage.removeItem("ccure_remembered_email");
    }

    try {
      const res = await login({
        email_or_username: cleanedIdentifier,
        password,
      });
      if (res?.status === "mfa_required") {
        setMfaToken(res.mfa_token);
        setShowMfa(true);
      } else {
        sessionStorage.removeItem("postLoginRedirect");
        navigate(from, { replace: true });
      }
    } catch (err) {
      let errMsg = "Login failed. Check your credentials.";
      if (err.response?.data?.message) {
        errMsg = err.response.data.message;
      } else if (err.response?.data?.detail) {
        const detail = err.response.data.detail;
        errMsg = Array.isArray(detail)
          ? detail.map((d) => d.msg).join(", ")
          : detail;
      }
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  };

  const handleMfaSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      await verifyMfaApi(mfaToken, mfaCode.trim());
      await refreshUser();
      sessionStorage.removeItem("postLoginRedirect");
      navigate(from, { replace: true });
    } catch (err) {
      let errMsg = "Verification failed.";
      if (err.response?.data?.detail) {
        const detail = err.response.data.detail;
        errMsg = Array.isArray(detail)
          ? detail.map((d) => d.msg).join(", ")
          : detail;
      }
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  };

  const handleSendEmailOtp = async () => {
    if (resendCooldown > 0) return;
    setError("");
    setEmailSent(false);

    try {
      startCooldown();
      await sendEmailOtpApi(mfaToken);
      setEmailSent(true);
    } catch (err) {
      let errMsg = "Failed to send email verification code.";
      if (err.response?.data?.detail) {
        const detail = err.response.data.detail;
        errMsg = Array.isArray(detail)
          ? detail.map((d) => d.msg).join(", ")
          : detail;
      }
      setError(errMsg);
      clearResendInterval();
      setResendCooldown(0);
    }
  };

  const handleBackToLogin = () => {
    setShowMfa(false);
    setMfaToken("");
    setMfaCode("");
    setEmailSent(false);
    clearResendInterval();
    setResendCooldown(0);
    setError("");
  };

  return (
    <AuthLayout
      pageType={showMfa ? "mfa" : "login"}
      title={showMfa ? "Verify your identity" : "Sign in"}
    >
      {showMfa ? (
        <>
          <h1 className="auth-title">Verification Code</h1>
          <p className="auth-sub">
            Use your authenticator, recovery code, or email code.
          </p>

          {error && (
            <CcureAlert variant="danger" className="auth-message">
              {error}
            </CcureAlert>
          )}

          {emailSent && (
            <CcureAlert variant="success" className="auth-message">
              Verification code sent to your email.
            </CcureAlert>
          )}

          <form onSubmit={handleMfaSubmit} className="auth-form auth-stack">
            <CcureInput
              key="mfa-code"
              id="mfaCode"
              name="mfaCode"
              label="Verification Code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value)}
              placeholder="Enter code"
              required
              autoFocus
              maxLength={12}
            />

            <div className="auth-inline-action">
              <CcureButton
                type="button"
                variant="ghost"
                size="sm"
                onClick={handleSendEmailOtp}
                disabled={resendCooldown > 0}
              >
                {resendCooldown > 0
                  ? `Resend code in ${resendCooldown}s`
                  : "Send code to email"}
              </CcureButton>
            </div>

            <CcureButton type="submit" loading={loading} block size="lg">
              {loading ? "Verifying..." : "Verify Code →"}
            </CcureButton>
          </form>

          <p className="auth-switch">
            <CcureButton
              type="button"
              variant="ghost"
              size="sm"
              onClick={handleBackToLogin}
            >
              ← Back to credentials
            </CcureButton>
          </p>
        </>
      ) : (
        <>
          <h1 className="auth-title">Sign in</h1>
          <p className="auth-sub">Use your account credentials to continue.</p>

          {error && (
            <CcureAlert variant="danger" className="auth-message">
              {error}
            </CcureAlert>
          )}

          {!error && noticeMessage && (
            <CcureAlert variant="info" className="auth-message">
              {noticeMessage}
            </CcureAlert>
          )}

          <form onSubmit={handleSubmit} className="auth-form auth-stack">
            <CcureInput
              id="emailOrUsername"
              name="emailOrUsername"
              label="Email or Username"
              // type="text", not "email": the endpoint resolves
              // or_(email_matches, username_matches), and type="email"
              // would make the browser reject a username before the
              // request was ever made.
              type="text"
              autoComplete="username"
              value={emailOrUsername}
              onChange={(e) => setEmailOrUsername(e.target.value)}
              placeholder="name@company.com or username"
              required
            />

            <CcurePasswordField
              visibilityToggleTabIndex={0}
              id="password"
              name="password"
              label="Password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
            />

            {/* Remember Me & Forgot Password Row */}
            <div className="auth-checkbox-row">
              <CcureCheckbox
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
              >
                Remember me
              </CcureCheckbox>
              <CcureButton
                as={Link}
                variant="ghost"
                size="sm"
                to="/forgot-password"
                className="auth-link"
              >
                Forgot password?
              </CcureButton>
            </div>

            <CcureButton type="submit" loading={loading} block size="lg">
              {loading ? "Signing in..." : "Sign In →"}
            </CcureButton>
          </form>

          {selfRegAllowed === true && (
            <p className="auth-switch">
              No account?{" "}
              <CcureButton
                as={Link}
                variant="ghost"
                size="sm"
                to="/register"
                className="auth-link"
              >
                Register here
              </CcureButton>
            </p>
          )}
          {selfRegAllowed === false && (
            <p className="auth-switch">
              Accounts are created by your administrator. Contact them to
              request access.
            </p>
          )}
        </>
      )}
    </AuthLayout>
  );
}
