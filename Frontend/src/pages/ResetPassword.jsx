/**
 * src/pages/ResetPassword.jsx
 * Dark-themed reset password page with complexity validation.
 */
import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { resetPassword } from "../api/auth";

function strengthOf(pw) {
  if (!pw) return { label: "", level: 0 };
  if (pw.length < 12) return { label: "Weak", level: 1 };
  if (pw.length < 14) return { label: "Fair", level: 2 };
  if (/[^a-zA-Z0-9]/.test(pw)) return { label: "Strong", level: 4 };
  return { label: "Good", level: 3 };
}

function validate(password, confirm) {
  if (password.length < 12) return "Password must be at least 12 characters.";
  if (!/[A-Z]/.test(password))
    return "Password must contain at least one uppercase letter.";
  if (!/[0-9]/.test(password))
    return "Password must contain at least one digit.";
  if (!/[^a-zA-Z0-9]/.test(password))
    return "Password must contain at least one special character.";
  if (password !== confirm) return "Passwords do not match.";
  return null;
}

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");
  const navigate = useNavigate();

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [success, setSuccess] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const strength = strengthOf(password);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!token) {
      setError(
        "Reset token is missing from the link. Please request a new one.",
      );
      return;
    }

    const validationError = validate(password, confirm);
    if (validationError) {
      setError(validationError);
      return;
    }

    setError("");
    setSuccess("");
    setLoading(true);

    try {
      await resetPassword(token, password);
      setSuccess("Your password has been successfully reset.");
      setTimeout(() => {
        navigate("/login");
      }, 3000);
    } catch (err) {
      let errMsg =
        "Failed to reset password. The link might be expired or invalid.";
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

        <h1 className="auth-title">Set new password</h1>
        <p className="auth-sub">Enter your new secure password below</p>

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
              lineHeight: 1.5,
            }}
          >
            ✓ {success} Redirecting to login in a moment...
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="auth-form form-horizontal">
            <div className="field">
              <label htmlFor="password">New Password</label>
              <input
                id="password"
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
              />
              {password && (
                <div className="strength-bar" style={{ marginTop: 8 }}>
                  {[1, 2, 3, 4].map((n) => (
                    <span
                      key={n}
                      className={`strength-seg ${n <= strength.level ? `strength-${strength.level}` : ""}`}
                    />
                  ))}
                  <span className="strength-label">{strength.label}</span>
                </div>
              )}
            </div>

            <div className="field">
              <label htmlFor="confirm">Confirm Password</label>
              <input
                id="confirm"
                type="password"
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                placeholder="••••••••"
                required
              />
              {confirm && confirm !== password && (
                <span className="field-hint field-hint--warn">
                  Passwords don't match
                </span>
              )}
              {confirm && confirm === password && password && (
                <span className="field-hint field-hint--ok">
                  ✓ Passwords match
                </span>
              )}
            </div>

            <button type="submit" className="auth-btn" disabled={loading}>
              {loading ? <span className="btn-spinner" /> : "Save password →"}
            </button>
          </form>
        )}

        <p className="auth-switch">
          Back to <Link to="/login">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
