/**
 * src/pages/ForgotPassword.jsx
 * Dark-themed password recovery request page.
 */
import { useState } from "react";
import { Link } from "react-router-dom";
import { forgotPassword } from "../api/auth";
import AuthHeroPanel from "../components/auth/AuthHeroPanel";
import AuthTrustFooter from "../components/auth/AuthTrustFooter";
import { ShieldLogoIcon } from "../components/auth/AuthIcons";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [success, setSuccess] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");
    setLoading(true);

    try {
      const res = await forgotPassword(email);
      setSuccess(
        res.detail ||
          "If this email is registered, you will receive a reset link shortly.",
      );
    } catch (err) {
      let errMsg = "An error occurred. Please try again.";
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

  return (
    <div className="auth-split-wrapper">
      {/* Left Enterprise Showcase Panel */}
      <AuthHeroPanel pageType="forgot" />

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

          <h1 className="auth-title">Reset password</h1>
          <p className="auth-sub">
            Enter your email to receive an encrypted reset link
          </p>

          {error && (
            <div className="auth-error" role="alert">
              <span>⚠</span> {error}
            </div>
          )}

          {success ? (
            <div className="auth-success" role="status">
              ✓ {success}
            </div>
          ) : (
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

              <button type="submit" className="auth-btn" disabled={loading}>
                {loading ? (
                  <>
                    <span className="btn-spinner" /> Sending recovery link...
                  </>
                ) : (
                  "Send recovery link →"
                )}
              </button>
            </form>
          )}

          <p className="auth-switch">
            Remember your password?{" "}
            <Link to="/login" className="auth-link">
              Sign in
            </Link>
          </p>

          {/* Reusable Enterprise Security Trust Footer */}
          <AuthTrustFooter />
        </div>
      </div>
    </div>
  );
}
