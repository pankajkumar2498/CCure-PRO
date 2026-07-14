/**
 * src/pages/Login.jsx
 * Dark-themed auth page consistent with the dashboard brand.
 * API: POST /auth/login -> { access_token, user }
 */
import { useMemo, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
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

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // MFA Challenge State
  const [showMfa, setShowMfa] = useState(false);
  const [mfaToken, setMfaToken] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [emailSent, setEmailSent] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);

  const noticeMessage = useMemo(() => {
    return location.state?.message || authMessage || "";
  }, [location.state, authMessage]);

  const startCooldown = () => {
    setResendCooldown(60);
    const interval = setInterval(() => {
      setResendCooldown((prev) => {
        if (prev <= 1) {
          clearInterval(interval);
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

    try {
      const res = await login({ email: email.trim().toLowerCase(), password });
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
      // Start cooldown immediately to block duplicates
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
      setResendCooldown(0); // reset on failure
    }
  };

  const handleBackToLogin = () => {
    setShowMfa(false);
    setMfaToken("");
    setMfaCode("");
    setEmailSent(false);
    setResendCooldown(0);
    setError("");
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-brand">
          <span className="auth-brand-gem">*</span>
          <div className="auth-brand-text">
            <span className="auth-brand-name">CCure Audit</span>
            <span className="auth-brand-badge">PRO</span>
          </div>
        </div>

        {showMfa ? (
          <>
            <h1 className="auth-title">Verification Code</h1>
            <p className="auth-sub">
              Enter the code from your authenticator app, email OTP, or a backup
              code.
            </p>

            {error && (
              <div className="auth-error" role="alert">
                <span>!</span> {error}
              </div>
            )}

            {emailSent && (
              <div
                role="status"
                style={{
                  marginBottom: 16,
                  padding: "12px 14px",
                  borderRadius: 10,
                  border: "1px solid rgba(16, 185, 129, 0.35)",
                  background: "rgba(16, 185, 129, 0.12)",
                  color: "#a7f3d0",
                  fontSize: 14,
                }}
              >
                Verification code sent to your email!
              </div>
            )}

            <form
              onSubmit={handleMfaSubmit}
              className="auth-form form-horizontal"
            >
              <div className="field">
                <label htmlFor="mfaCode">Verification Code</label>
                <input
                  id="mfaCode"
                  type="text"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  placeholder="Enter code"
                  required
                  autoFocus
                  maxLength={12}
                />
              </div>

              <div style={{ margin: "6px 0 20px 0", textAlign: "center" }}>
                <button
                  type="button"
                  onClick={handleSendEmailOtp}
                  disabled={resendCooldown > 0}
                  style={{
                    background: "none",
                    border: "none",
                    color: resendCooldown > 0 ? "#6b7280" : "#818cf8",
                    cursor: resendCooldown > 0 ? "not-allowed" : "pointer",
                    fontSize: "12px",
                    padding: 0,
                    textDecoration: resendCooldown > 0 ? "none" : "underline",
                    fontWeight: 500,
                  }}
                >
                  {resendCooldown > 0
                    ? `Resend code to email in ${resendCooldown}s`
                    : "Send verification code to email"}
                </button>
              </div>

              <button type="submit" className="auth-btn" disabled={loading}>
                {loading ? <span className="btn-spinner" /> : "Verify ->"}
              </button>
            </form>

            <p className="auth-switch">
              <button
                type="button"
                onClick={handleBackToLogin}
                style={{
                  background: "none",
                  border: "none",
                  color: "#9ca3af",
                  cursor: "pointer",
                  textDecoration: "underline",
                  fontSize: "13px",
                  marginTop: "8px",
                }}
              >
                Back to credentials login
              </button>
            </p>
          </>
        ) : (
          <>
            <h1 className="auth-title">Sign in</h1>
            <p className="auth-sub">Network intelligence platform</p>

            {error && (
              <div className="auth-error" role="alert">
                <span>!</span> {error}
              </div>
            )}

            {!error && noticeMessage && (
              <div
                role="status"
                style={{
                  marginBottom: 16,
                  padding: "12px 14px",
                  borderRadius: 10,
                  border: "1px solid rgba(59, 130, 246, 0.35)",
                  background: "rgba(59, 130, 246, 0.12)",
                  color: "#bfdbfe",
                  fontSize: 14,
                }}
              >
                {noticeMessage}
              </div>
            )}

            <form onSubmit={handleSubmit} className="auth-form form-horizontal">
              <div className="field">
                <label htmlFor="email">Email</label>
                <input
                  id="email"
                  type="email"
                  autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="username@ccure.com"
                  required
                />
              </div>

              <div className="field">
                <label htmlFor="password">Password</label>
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "6px",
                  }}
                >
                  <input
                    id="password"
                    type="password"
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="........"
                    required
                  />
                  <div style={{ textAlign: "right" }}>
                    <Link
                      to="/forgot-password"
                      style={{
                        fontSize: "12px",
                        color: "#818cf8",
                        textDecoration: "none",
                        fontWeight: 500,
                      }}
                    >
                      Forgot password?
                    </Link>
                  </div>
                </div>
              </div>

              <button type="submit" className="auth-btn" disabled={loading}>
                {loading ? <span className="btn-spinner" /> : "Login ->"}
              </button>
            </form>

            <p className="auth-switch">
              No account? <Link to="/register">Register here</Link>
            </p>
          </>
        )}
      </div>
    </div>
  );
}
