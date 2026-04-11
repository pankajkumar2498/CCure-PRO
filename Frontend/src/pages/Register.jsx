/**
 * src/pages/Register.jsx
 * Dark-themed registration form matching CAST design.
 * API: POST /auth/register → { access_token, refresh_token, user }
 */
import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

function validate(username, email, password, confirm) {
  if (username.trim().length < 3) return "Username must be at least 3 characters.";
  if (!/\S+@\S+\.\S+/.test(email)) return "Enter a valid email address.";
  if (password.length < 6)         return "Password must be at least 6 characters.";
  if (password !== confirm)        return "Passwords do not match.";
  return null;
}

function strengthOf(pw) {
  if (!pw)           return { label: "",       level: 0 };
  if (pw.length < 6) return { label: "Weak",   level: 1 };
  if (pw.length < 10)return { label: "Fair",   level: 2 };
  if (/[^a-zA-Z0-9]/.test(pw)) return { label: "Strong", level: 4 };
  return { label: "Good", level: 3 };
}

export default function Register() {
  const { register } = useAuth();

  const [username, setUsername] = useState("");
  const [email,    setEmail]    = useState("");
  const [password, setPassword] = useState("");
  const [confirm,  setConfirm]  = useState("");
  const [error,    setError]    = useState("");
  const [loading,  setLoading]  = useState(false);

  const strength = strengthOf(password);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const ve = validate(username, email, password, confirm);
    if (ve) { setError(ve); return; }
    setError(""); setLoading(true);
    try {
      await register(username, email, password);
    } catch (err) {
      setError(err.response?.data?.detail || "Registration failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card auth-card--wide">
        {/* Brand */}
        <div className="auth-brand">
          <span className="auth-brand-gem">◈</span>
          <div className="auth-brand-text">
            <span className="auth-brand-name">CCure Audit</span>
            <span className="auth-brand-badge">PRO</span>
          </div>
        </div>

        <h1 className="auth-title">Create account</h1>
        <p className="auth-sub">Join the network intelligence platform</p>

        {error && (
          <div className="auth-error" role="alert"><span>⚠</span> {error}</div>
        )}

        <form onSubmit={handleSubmit} className="auth-form">
          <div className="field">
            <label htmlFor="username">Username</label>
            <input
              id="username" type="text" autoComplete="username"
              value={username} onChange={e => setUsername(e.target.value)}
              placeholder="operator_name" required
            />
            {username && username.length < 3 && (
              <span className="field-hint field-hint--warn">Min. 3 characters</span>
            )}
          </div>

          <div className="field">
            <label htmlFor="email">Email</label>
            <input
              id="email" type="email" autoComplete="email"
              value={email} onChange={e => setEmail(e.target.value)}
              placeholder="operator@domain.com" required
            />
          </div>

          <div className="field">
            <label htmlFor="password">Password</label>
            <input
              id="password" type="password" autoComplete="new-password"
              value={password} onChange={e => setPassword(e.target.value)}
              placeholder="••••••••" required
            />
            {password && (
              <div className="strength-bar">
                {[1,2,3,4].map(n => (
                  <span key={n} className={`strength-seg ${n <= strength.level ? `strength-${strength.level}` : ""}`} />
                ))}
                <span className="strength-label">{strength.label}</span>
              </div>
            )}
          </div>

          <div className="field">
            <label htmlFor="confirm">Confirm password</label>
            <input
              id="confirm" type="password" autoComplete="new-password"
              value={confirm} onChange={e => setConfirm(e.target.value)}
              placeholder="••••••••" required
            />
            {confirm && confirm !== password && (
              <span className="field-hint field-hint--warn">Passwords don't match</span>
            )}
            {confirm && confirm === password && password && (
              <span className="field-hint field-hint--ok">✓ Passwords match</span>
            )}
          </div>

          <button type="submit" className="auth-btn" disabled={loading}>
            {loading ? <span className="btn-spinner" /> : "Create account →"}
          </button>
        </form>

        <p className="auth-switch">
          Already have access? <Link to="/login">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
