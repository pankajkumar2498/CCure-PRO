/**
 * src/pages/ResetPassword.jsx
 * Dark-themed reset password page with complexity validation.
 */
import { useState, useEffect } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { resetPassword } from "../api/auth";
import AuthHeroPanel from "../components/auth/AuthHeroPanel";
import AuthTrustFooter from "../components/auth/AuthTrustFooter";
import {
  ShieldLogoIcon,
  EyeIcon,
  EyeOffIcon,
} from "../components/auth/AuthIcons";

function strengthOf(pw) {
  if (!pw) return { label: "", level: 0 };
  let level = 0;
  if (pw.length >= 12) level++;
  if (/[A-Z]/.test(pw)) level++;
  if (/[0-9]/.test(pw)) level++;
  if (/[^a-zA-Z0-9]/.test(pw)) level++;

  const labels = ["", "Weak", "Fair", "Good", "Strong"];
  return { label: labels[level], level };
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
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [capsLockPw, setCapsLockPw] = useState(false);
  const [capsLockConfirm, setCapsLockConfirm] = useState(false);

  const [success, setSuccess] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!token) {
      setError(
        "Reset token is missing or invalid. Please request a new recovery link.",
      );
    }
  }, [token]);

  const strength = strengthOf(password);

  const handlePwKey = (e) => {
    if (e.getModifierState) setCapsLockPw(e.getModifierState("CapsLock"));
  };

  const handleConfirmKey = (e) => {
    if (e.getModifierState) setCapsLockConfirm(e.getModifierState("CapsLock"));
  };

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
      setSuccess(
        "Your password has been successfully reset. Redirecting to login...",
      );
      setTimeout(() => {
        navigate("/login");
      }, 2500);
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
    <div className="auth-split-wrapper">
      {/* Left Enterprise Showcase Panel */}
      <AuthHeroPanel pageType="reset" />

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

          <h1 className="auth-title">Set new password</h1>
          <p className="auth-sub">
            Set a high-entropy password for your account
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
          ) : !token ? (
            <div style={{ textAlign: "center", marginTop: 20 }}>
              <Link
                to="/forgot-password"
                className="auth-btn"
                style={{ textDecoration: "none" }}
              >
                Request new reset link →
              </Link>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="auth-form">
              <div className="field">
                <label htmlFor="password">New Password</label>
                <div className="password-input-wrapper">
                  <input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    autoComplete="new-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    onKeyDown={handlePwKey}
                    onKeyUp={handlePwKey}
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
                {capsLockPw && (
                  <div className="caps-lock-warning">⚠️ Caps Lock is ON</div>
                )}
                {password && (
                  <>
                    <div className="strength-bar" style={{ marginTop: 8 }}>
                      {[1, 2, 3, 4].map((n) => (
                        <span
                          key={n}
                          className={`strength-seg ${n <= strength.level ? `strength-${strength.level}` : ""}`}
                        />
                      ))}
                      <span className="strength-label">{strength.label}</span>
                    </div>
                    <div
                      className="field-hint"
                      style={{
                        marginTop: "6px",
                        fontSize: "0.78rem",
                        display: "flex",
                        gap: "10px",
                        flexWrap: "wrap",
                      }}
                    >
                      <span
                        style={{
                          color: password.length >= 12 ? "#34d399" : "#64748b",
                        }}
                      >
                        {password.length >= 12 ? "✓" : "•"} 12+ chars
                      </span>
                      <span
                        style={{
                          color: /[A-Z]/.test(password) ? "#34d399" : "#64748b",
                        }}
                      >
                        {/[A-Z]/.test(password) ? "✓" : "•"} Uppercase
                      </span>
                      <span
                        style={{
                          color: /[0-9]/.test(password) ? "#34d399" : "#64748b",
                        }}
                      >
                        {/[0-9]/.test(password) ? "✓" : "•"} Number
                      </span>
                      <span
                        style={{
                          color: /[^a-zA-Z0-9]/.test(password)
                            ? "#34d399"
                            : "#64748b",
                        }}
                      >
                        {/[^a-zA-Z0-9]/.test(password) ? "✓" : "•"} Special char
                      </span>
                    </div>
                  </>
                )}
              </div>

              <div className="field">
                <label htmlFor="confirm">Confirm Password</label>
                <div className="password-input-wrapper">
                  <input
                    id="confirm"
                    type={showConfirm ? "text" : "password"}
                    autoComplete="new-password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    onKeyDown={handleConfirmKey}
                    onKeyUp={handleConfirmKey}
                    placeholder="••••••••"
                    required
                  />
                  <button
                    type="button"
                    tabIndex="-1"
                    aria-label="Toggle confirm password visibility"
                    className="password-toggle-btn"
                    onClick={() => setShowConfirm((prev) => !prev)}
                  >
                    {showConfirm ? <EyeOffIcon /> : <EyeIcon />}
                  </button>
                </div>
                {capsLockConfirm && (
                  <div className="caps-lock-warning">⚠️ Caps Lock is ON</div>
                )}
                {confirm && confirm !== password && (
                  <span className="field-hint field-hint--warn">
                    Passwords don&apos;t match
                  </span>
                )}
                {confirm && confirm === password && password && (
                  <span className="field-hint field-hint--ok">
                    ✓ Passwords match
                  </span>
                )}
              </div>

              <button type="submit" className="auth-btn" disabled={loading}>
                {loading ? (
                  <>
                    <span className="btn-spinner" /> Saving password...
                  </>
                ) : (
                  "Save password →"
                )}
              </button>
            </form>
          )}

          <p className="auth-switch">
            Back to{" "}
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
