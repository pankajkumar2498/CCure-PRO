/**
 * src/pages/Register.jsx
 * Dark-themed registration form matching CAST design.
 * API: POST /auth/register → { access_token, refresh_token, user }
 */
import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import AuthHeroPanel from "../components/auth/AuthHeroPanel";
import AuthTrustFooter from "../components/auth/AuthTrustFooter";
import {
  ShieldLogoIcon,
  EyeIcon,
  EyeOffIcon,
} from "../components/auth/AuthIcons";
import { checkUsername, checkEmail } from "../api/auth";
import { useDebounce } from "../hooks/useDebounce";

function validate(username, email, password, confirm) {
  if (username.trim().length < 3)
    return "Username must be at least 3 characters.";
  if (!/\S+@\S+\.\S+/.test(email)) return "Enter a valid email address.";
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

export function strengthOf(pw) {
  if (!pw) return { label: "", level: 0 };
  let level = 0;
  if (pw.length >= 12) level++;
  if (/[A-Z]/.test(pw)) level++;
  if (/[0-9]/.test(pw)) level++;
  if (/[^a-zA-Z0-9]/.test(pw)) level++;

  const labels = ["", "Weak", "Fair", "Good", "Strong"];
  return { label: labels[level], level };
}

export default function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [capsLockPw, setCapsLockPw] = useState(false);
  const [capsLockConfirm, setCapsLockConfirm] = useState(false);

  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const [usernameTaken, setUsernameTaken] = useState(false);
  const [usernameChecked, setUsernameChecked] = useState(false);
  const [emailTaken, setEmailTaken] = useState(false);
  const [emailChecked, setEmailChecked] = useState(false);

  const debouncedUsername = useDebounce(username, 500);
  const debouncedEmail = useDebounce(email, 500);

  useEffect(() => {
    if (debouncedUsername.length >= 3) {
      checkUsername(debouncedUsername)
        .then((res) => {
          setUsernameTaken(!res.available);
          setUsernameChecked(true);
        })
        .catch(() => {
          setUsernameChecked(false);
        });
    } else {
      setUsernameTaken(false);
      setUsernameChecked(false);
    }
  }, [debouncedUsername]);

  useEffect(() => {
    if (/\S+@\S+\.\S+/.test(debouncedEmail)) {
      checkEmail(debouncedEmail)
        .then((res) => {
          setEmailTaken(!res.available);
          setEmailChecked(true);
        })
        .catch(() => {
          setEmailChecked(false);
        });
    } else {
      setEmailTaken(false);
      setEmailChecked(false);
    }
  }, [debouncedEmail]);

  const strength = strengthOf(password);

  const handlePwKey = (e) => {
    if (e.getModifierState) setCapsLockPw(e.getModifierState("CapsLock"));
  };

  const handleConfirmKey = (e) => {
    if (e.getModifierState) setCapsLockConfirm(e.getModifierState("CapsLock"));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const normalizedEmail = email.trim().toLowerCase();
    const ve = validate(username, normalizedEmail, password, confirm);
    if (ve) {
      setError(ve);
      return;
    }
    setError("");
    setLoading(true);
    try {
      await register({ username, email: normalizedEmail, password });
      navigate("/dashboard", { replace: true });
    } catch (err) {
      let errMsg = "Registration failed. Please try again.";
      if (err.response?.data?.details) {
        errMsg = err.response.data.details
          .map((d) => (d.msg || d.type || "").replace(/^Value error,\s*/i, ""))
          .filter(Boolean)
          .join(", ");
      } else if (err.response?.data?.message) {
        errMsg = err.response.data.message;
      } else if (err.response?.data?.detail) {
        const detail = err.response.data.detail;
        if (Array.isArray(detail)) {
          errMsg = detail
            .map((d) => (d.msg || "").replace(/^Value error,\s*/i, ""))
            .filter(Boolean)
            .join(", ");
        } else if (typeof detail === "string") {
          errMsg = detail.replace(/^Value error,\s*/i, "");
        }
      }
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-split-wrapper">
      {/* Left Enterprise Showcase Panel */}
      <AuthHeroPanel pageType="register" />

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

          <h1 className="auth-title">Create account</h1>
          <p className="auth-sub">
            Register your organization to start auditing
          </p>

          {error && (
            <div className="auth-error" role="alert">
              <span>⚠</span> {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="auth-form">
            <div className="field">
              <label htmlFor="username">Username</label>
              <input
                id="username"
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="username"
                required
              />
              {username && username.length < 3 && (
                <span className="field-hint field-hint--warn">
                  Min. 3 characters
                </span>
              )}
              {usernameTaken && (
                <span className="field-hint field-hint--error">
                  This username is already taken.
                </span>
              )}
              {usernameChecked && !usernameTaken && username.length >= 3 && (
                <span className="field-hint field-hint--ok">
                  ✓ Username available
                </span>
              )}
            </div>

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
              {emailTaken && (
                <span className="field-hint field-hint--error">
                  This email is already registered.
                </span>
              )}
              {emailChecked && !emailTaken && (
                <span className="field-hint field-hint--ok">
                  ✓ Email available
                </span>
              )}
            </div>

            <div className="field">
              <label htmlFor="password">Password</label>
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
                  <div className="strength-bar">
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
              <label htmlFor="confirm">Confirm password</label>
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
              {loading ? (
                <>
                  <span className="btn-spinner" /> Creating account...
                </>
              ) : (
                "Create Account →"
              )}
            </button>
          </form>

          <p className="auth-switch">
            Already have access?{" "}
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
