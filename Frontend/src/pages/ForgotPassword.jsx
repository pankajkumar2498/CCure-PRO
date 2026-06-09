/**
 * src/pages/ForgotPassword.jsx
 * Dark-themed password recovery request page.
 */
import { useState } from "react";
import { Link } from "react-router-dom";
import { forgotPassword } from "../api/auth";

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
      setSuccess(res.detail || "If this email is registered, you will receive a reset link shortly.");
    } catch (err) {
      let errMsg = "An error occurred. Please try again.";
      if (err.response?.data?.message) {
        errMsg = err.response.data.message;
      } else if (err.response?.data?.detail) {
        const detail = err.response.data.detail;
        errMsg = Array.isArray(detail) ? detail.map(d => d.msg).join(", ") : detail;
      }
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        {/* Brand */}
        <div className="auth-brand">
          <span className="auth-brand-gem">◈</span>
          <div className="auth-brand-text">
            <span className="auth-brand-name">CCure Audit</span>
            <span className="auth-brand-badge">PRO</span>
          </div>
        </div>

        <h1 className="auth-title">Reset password</h1>
        <p className="auth-sub">Enter your email to receive a recovery link</p>

        {error && (
          <div className="auth-error" role="alert">
            <span>⚠</span> {error}
          </div>
        )}

        {success ? (
          <div
            role="status"
            style={{
              marginTop: 16,
              marginBottom: 16,
              padding: "16px",
              borderRadius: 10,
              border: "1px solid rgba(16, 185, 129, 0.35)",
              background: "rgba(16, 185, 129, 0.12)",
              color: "#a7f3d0",
              fontSize: 14,
              lineHeight: 1.5
            }}
          >
            ✓ {success}
          </div>
        ) : (
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

            <button type="submit" className="auth-btn" disabled={loading}>
              {loading ? <span className="btn-spinner" /> : "Send recovery link →"}
            </button>
          </form>
        )}

        <p className="auth-switch">
          Remember your password? <Link to="/login">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
