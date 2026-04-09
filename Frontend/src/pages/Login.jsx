/**
 * src/pages/Login.jsx
 */

import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function Login() {
  const { login }                       = useAuth();
  const location                        = useLocation();
  const from                            = location.state?.from?.pathname || "/scan";

  const [email, setEmail]               = useState("");
  const [password, setPassword]         = useState("");
  const [error, setError]               = useState("");
  const [loading, setLoading]           = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(email, password, from);
    } catch (err) {
      setError(err.response?.data?.detail || "Login failed. Check your credentials.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      {/* ── Animated grid background ───────────────────────────────────── */}
      <div className="grid-bg" aria-hidden />

      <div className="auth-card">
        {/* Logo / wordmark */}
        <div className="auth-brand">
          <span className="brand-icon">◈</span>
          <span className="brand-name">CCURE AUDIT</span>
          <span className="brand-badge">PRO</span>
        </div>

        <h1 className="auth-title">Sign in</h1>
        <p className="auth-sub">Network intelligence platform</p>

        {error && (
          <div className="auth-error" role="alert">
            <span className="error-icon">⚠</span> {error}
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
              placeholder="operator@ccure.com"
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
              placeholder="••••••••"
              required
            />
          </div>

          <button type="submit" className="auth-btn" disabled={loading}>
            {loading ? <span className="btn-spinner" /> : "Login"}
          </button>
        </form>

        <p className="auth-switch">
          No account?{" "}
          <Link to="/register">Register</Link>
        </p>
      </div>
    </div>
  );
}
