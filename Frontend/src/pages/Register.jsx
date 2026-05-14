/**
 * src/pages/Register.jsx
 * Dark-themed registration form matching CAST design.
 * API: POST /auth/register → { access_token, refresh_token, user }
 */
import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { checkUsername, checkEmail } from "../api/auth";
import { useDebounce } from "../hooks/useDebounce";

function validate(username, email, password, confirm) {
  if (username.trim().length < 3) return "Username must be at least 3 characters.";
  if (!/\S+@\S+\.\S+/.test(email)) return "Enter a valid email address.";
  if (password.length < 12) return "Password must be at least 12 characters.";
  if (password !== confirm) return "Passwords do not match.";
  return null;
}

function strengthOf(pw) {
  if (!pw) return { label: "", level: 0 };
  if (pw.length < 12) return { label: "Weak", level: 1 };
  if (pw.length < 14) return { label: "Fair", level: 2 };
  if (/[^a-zA-Z0-9]/.test(pw)) return { label: "Strong", level: 4 };
  return { label: "Good", level: 3 };
}

export default function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const [usernameTaken, setUsernameTaken] = useState(false);
  const [emailTaken, setEmailTaken] = useState(false);

  const debouncedUsername = useDebounce(username, 500);
  const debouncedEmail = useDebounce(email, 500);

  useEffect(() => {
    if (debouncedUsername.length >= 3) {
      checkUsername(debouncedUsername).then(res => setUsernameTaken(!res.available)).catch(() => { });
    } else {
      setUsernameTaken(false);
    }
  }, [debouncedUsername]);

  useEffect(() => {
    if (/\S+@\S+\.\S+/.test(debouncedEmail)) {
      checkEmail(debouncedEmail).then(res => setEmailTaken(!res.available)).catch(() => { });
    } else {
      setEmailTaken(false);
    }
  }, [debouncedEmail]);

  const strength = strengthOf(password);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const normalizedEmail = email.trim().toLowerCase();
    const ve = validate(username, normalizedEmail, password, confirm);
    if (ve) { setError(ve); return; }
    setError(""); setLoading(true);
    try {
      await register({ username, email: normalizedEmail, password });
      navigate("/dashboard", { replace: true });
    } catch (err) {
      let errMsg = "Registration failed. Please try again.";
      if (err.response?.data?.details) {
        errMsg = err.response.data.details.map(d => d.msg || d.type).join(", ");
      } else if (err.response?.data?.message) {
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

        <form onSubmit={handleSubmit} className="auth-form form-horizontal">
          <div className="field">
            <label htmlFor="username">Username</label>
            <input
              id="username" type="text" autoComplete="username"
              value={username} onChange={e => setUsername(e.target.value)}
              placeholder="username" required
            />
            {username && username.length < 3 && (
              <span className="field-hint field-hint--warn">Min. 3 characters</span>
            )}
            {usernameTaken && (
              <span className="field-hint field-hint--error" style={{ color: "var(--danger)" }}>This username is already taken.</span>
            )}
          </div>

          <div className="field">
            <label htmlFor="email">Email</label>
            <input
              id="email" type="email" autoComplete="email"
              value={email} onChange={e => setEmail(e.target.value)}
              placeholder="username@ccure.com" required
            />
            {emailTaken && (
              <span className="field-hint field-hint--error" style={{ color: "var(--danger)" }}>This email is already registered.</span>
            )}
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
                {[1, 2, 3, 4].map(n => (
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

