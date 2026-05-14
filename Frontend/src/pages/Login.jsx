/**
 * src/pages/Login.jsx
 * Dark-themed auth page consistent with the dashboard brand.
 * API: POST /auth/login -> { access_token, user }
 */
import { useMemo, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function Login() {
  const { login, authMessage } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const from = location.state?.from?.pathname || "/dashboard";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const noticeMessage = useMemo(() => {
    return location.state?.message || authMessage || "";
  }, [location.state, authMessage]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      await login({ email: email.trim().toLowerCase(), password });
      navigate(from, { replace: true });
    } catch (err) {
      let errMsg = "Login failed. Check your credentials.";
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
        <div className="auth-brand">
          <span className="auth-brand-gem">*</span>
          <div className="auth-brand-text">
            <span className="auth-brand-name">CCure Audit</span>
            <span className="auth-brand-badge">PRO</span>
          </div>
        </div>

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
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="........"
              required
            />
          </div>

          <button type="submit" className="auth-btn" disabled={loading}>
            {loading ? <span className="btn-spinner" /> : "Login ->"}
          </button>
        </form>

        <p className="auth-switch">
          No account? <Link to="/register">Register here</Link>
        </p>
      </div>
    </div>
  );
}
