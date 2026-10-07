/**
 * src/pages/ResetPassword.jsx
 * Dark-themed reset password page with complexity validation.
 *
 * ── Security contract, unchanged by the Checkpoint 3C migration ─────────────
 * The reset token arrives as a query parameter because that is what an email
 * client can click, and it reaches the API in a POST body and nowhere else: it
 * is never rendered, never persisted, and never carried into an outgoing link.
 *
 * CLAUDE.md records two properties of `/auth/reset-password` this page must not
 * undermine: completing a reset retires *every* outstanding token for the
 * account, and all three failure branches answer identically because a distinct
 * message would be an oracle over which links exist. The page therefore adds no
 * wording of its own that separates "expired" from "already used" from "no such
 * token" — it renders whatever single message the backend sends, and falls back
 * to one generic string.
 *
 * The complexity rules below are the client-side mirror of the server's. They
 * are unchanged; `gradePassword` in the design system computes the same four
 * levels from the same four predicates, and `validate` still owns the refusal
 * messages, so a rule can never be enforced in one place and not the other.
 *
 * src/__tests__/pages/ResetPassword.test.jsx asserts all of this and was
 * written against the pre-migration page.
 */
import { useState, useEffect } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { resetPassword } from "@shell/api/auth";
import AuthHeroPanel from "../components/AuthHeroPanel";
import { ShieldLogoIcon } from "../components/AuthIcons";
import {
  CcureAlert,
  CcureButton,
  CcurePasswordField,
  CcureCard,
} from "../../../design-system";
import "../styles/auth.css";

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

  useEffect(() => {
    if (!token) {
      setError(
        "Reset token is missing or invalid. Please request a new recovery link.",
      );
    }
  }, [token]);

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

  // The live match/mismatch feedback is a field-level error rather than loose
  // text beside the input, so CcurePasswordField wires it through
  // aria-describedby and aria-invalid. Previously it was a bare <span> that a
  // screen reader never associated with the field it described.
  const confirmMismatch = confirm && confirm !== password;

  return (
    <main className="auth-split-wrapper">
      {/* Left Enterprise Showcase Panel */}
      <AuthHeroPanel pageType="reset" />

      {/* Shared auth surfaces follow the application theme. */}
      <div className="auth-form-panel">
        <CcureCard as="div" className="auth-card">
          {/* Mobile Brand Header */}
          <div className="auth-brand">
            <ShieldLogoIcon size={24} />
            <div className="auth-brand-text">
              <span className="auth-brand-name">CCure</span>
            </div>
          </div>

          <h1 className="auth-title">Set new password</h1>
          <p className="auth-sub">
            Set a high-entropy password for your account
          </p>

          {error && (
            <CcureAlert variant="danger" className="auth-message">
              {error}
            </CcureAlert>
          )}

          {success ? (
            <CcureAlert variant="success" className="auth-message">
              {success}
            </CcureAlert>
          ) : !token ? (
            <div className="auth-inline-action">
              <CcureButton as={Link} to="/forgot-password" block size="lg">
                Request new reset link →
              </CcureButton>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="auth-form auth-stack">
              <CcurePasswordField
                id="password"
                name="password"
                label="New Password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                showStrength
              />

              <CcurePasswordField
                id="confirm"
                name="confirm"
                label="Confirm Password"
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                placeholder="••••••••"
                required
                error={confirmMismatch ? "Passwords don't match" : undefined}
                hint={
                  confirm && confirm === password && password
                    ? "Passwords match"
                    : undefined
                }
              />

              <CcureButton type="submit" loading={loading} block size="lg">
                {loading ? "Saving password..." : "Save password →"}
              </CcureButton>
            </form>
          )}

          <p className="auth-switch">
            Back to{" "}
            <CcureButton
              as={Link}
              variant="ghost"
              size="sm"
              to="/login"
              className="auth-link"
            >
              Sign in
            </CcureButton>
          </p>

          {/* Reusable Enterprise Security Trust Footer */}
        </CcureCard>
      </div>
    </main>
  );
}
