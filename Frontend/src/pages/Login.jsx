/**
 * src/pages/Login.jsx
 * Dark-themed auth page consistent with the dashboard brand.
 * API: POST /auth/login -> { access_token, user }
 */
import { useMemo, useState, useRef, useEffect } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import AuthHeroPanel from "../components/auth/AuthHeroPanel";
import AuthTrustFooter from "../components/auth/AuthTrustFooter";
import {
  ShieldLogoIcon,
  EyeIcon,
  EyeOffIcon,
} from "../components/auth/AuthIcons";
import {
  verifyMfa as verifyMfaApi,
  sendEmailOtp as sendEmailOtpApi,
} from "../api/auth";

export default function Login() {
  const { login, refreshUser, authMessage } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const fromLocation = location.state?.from;
  const savedRedirect =
    location.state?.reason === "expired"
      ? sessionStorage.getItem("postLoginRedirect")
      : "";
  const from = fromLocation
    ? `${fromLocation.pathname || "/dashboard"}${fromLocation.search || ""}${fromLocation.hash || ""}`
    : savedRedirect || "/dashboard";

  const [rememberMe, setRememberMe] = useState(() => {
    return localStorage.getItem("ccure_remember_me") === "true";
  });

  const [email, setEmail] = useState(() => {
    return localStorage.getItem("ccure_remembered_email") || "";
  });

  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [capsLockOn, setCapsLockOn] = useState(false);
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

  const handleKeyDown = (e) => {
    if (e.getModifierState) {
      setCapsLockOn(e.getModifierState("CapsLock"));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    const normalizedEmail = email.trim().toLowerCase();

    // Remember Me persistence
    if (rememberMe) {
      localStorage.setItem("ccure_remember_me", "true");
      localStorage.setItem("ccure_remembered_email", normalizedEmail);
    } else {
      localStorage.removeItem("ccure_remember_me");
      localStorage.removeItem("ccure_remembered_email");
    }

    try {
      const res = await login({ email: normalizedEmail, password });
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
    <div className="auth-split-wrapper">
      {/* Left Enterprise Showcase Panel */}
      <AuthHeroPanel pageType="login" />

      {/* Right Form Panel */}
      <div className="auth-form-panel">
        <div className="auth-card">
          {/* Mobile Brand Header */}
          <div className="auth-brand">
            <ShieldLogoIcon size={24} />
            <div className="auth-brand-text">
              <span className="auth-brand-name">CCure Audit</span>
              <span className="auth-brand-badge">PRO</span>
            </div>
          </div>

          {showMfa ? (
            <>
              <h1 className="auth-title">Verification Code</h1>
              <p className="auth-sub">Enter your security verification code</p>

              {error && (
                <div className="auth-error" role="alert">
                  <span>⚠</span> {error}
                </div>
              )}

              {emailSent && (
                <div className="auth-success" role="status">
                  ✓ Verification code sent to your email!
                </div>
              )}

              <form onSubmit={handleMfaSubmit} className="auth-form">
                <div className="field">
                  <label htmlFor="mfaCode">Verification Code</label>
                  <input
                    id="mfaCode"
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
                </div>

                <div style={{ margin: "4px 0 12px 0", textAlign: "center" }}>
                  <button
                    type="button"
                    onClick={handleSendEmailOtp}
                    disabled={resendCooldown > 0}
                    className="auth-link"
                    style={{
                      background: "none",
                      border: "none",
                      fontSize: "0.8rem",
                      cursor: resendCooldown > 0 ? "not-allowed" : "pointer",
                      opacity: resendCooldown > 0 ? 0.6 : 1,
                    }}
                  >
                    {resendCooldown > 0
                      ? `Resend code in ${resendCooldown}s`
                      : "Send code to email"}
                  </button>
                </div>

                <button type="submit" className="auth-btn" disabled={loading}>
                  {loading ? (
                    <>
                      <span className="btn-spinner" /> Verifying...
                    </>
                  ) : (
                    "Verify Code →"
                  )}
                </button>
              </form>

              <p className="auth-switch">
                <button
                  type="button"
                  onClick={handleBackToLogin}
                  className="auth-link"
                  style={{
                    background: "none",
                    border: "none",
                    cursor: "pointer",
                    fontSize: "0.84rem",
                  }}
                >
                  ← Back to credentials login
                </button>
              </p>
            </>
          ) : (
            <>
              <h1 className="auth-title">Sign in</h1>
              <p className="auth-sub">
                Enter your credentials to access your workspace
              </p>

              {error && (
                <div className="auth-error" role="alert">
                  <span>⚠</span> {error}
                </div>
              )}

              {!error && noticeMessage && (
                <div className="auth-info" role="status">
                  ℹ {noticeMessage}
                </div>
              )}

              <form onSubmit={handleSubmit} className="auth-form">
                <div className="field">
                  <label htmlFor="email">Email</label>
                  <input
                    id="email"
                    type="email"
                    autoComplete="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="name@company.com"
                    required
                  />
                </div>

                <div className="field">
                  <label htmlFor="password">Password</label>
                  <div className="password-input-wrapper">
                    <input
                      id="password"
                      type={showPassword ? "text" : "password"}
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      onKeyDown={handleKeyDown}
                      onKeyUp={handleKeyDown}
                      placeholder="••••••••"
                      required
                    />
                    <button
                      type="button"
                      tabIndex="-1"
                      aria-label="Toggle password visibility"
                      className="password-toggle-btn"
                      onClick={() => setShowPassword((prev) => !prev)}
                    >
                      {showPassword ? <EyeOffIcon /> : <EyeIcon />}
                    </button>
                  </div>
                  {capsLockOn && (
                    <div className="caps-lock-warning">⚠️ Caps Lock is ON</div>
                  )}
                </div>

                {/* Remember Me & Forgot Password Row */}
                <div className="auth-checkbox-row">
                  <label className="auth-checkbox-label">
                    <input
                      type="checkbox"
                      checked={rememberMe}
                      onChange={(e) => setRememberMe(e.target.checked)}
                    />
                    <span>Remember me</span>
                  </label>
                  <Link
                    to="/forgot-password"
                    className="auth-link"
                    style={{ fontSize: "0.78rem" }}
                  >
                    Forgot password?
                  </Link>
                </div>

                <button
                  type="submit"
                  className="auth-btn"
                  disabled={loading}
                  style={{ marginTop: "16px" }}
                >
                  {loading ? (
                    <>
                      <span className="btn-spinner" /> Signing in...
                    </>
                  ) : (
                    "Sign In →"
                  )}
                </button>
              </form>

              <p className="auth-switch">
                No account?{" "}
                <Link to="/register" className="auth-link">
                  Register here
                </Link>
              </p>
            </>
          )}

          {/* Reusable Enterprise Security Trust Footer */}
          <AuthTrustFooter />
        </div>
      </div>
    </div>
  );
}
