/**
 * src/pages/ForgotPassword.jsx
 * Password recovery request page.
 *
 * ── Security contract, unchanged by the Checkpoint 3C migration ─────────────
 * `/auth/forgot-password` is deliberately not an account-existence oracle. The
 * backend answers a uniform 200 whether or not the identifier resolves to an
 * account, and CLAUDE.md records that "User not found." was once a fourth
 * distinct failure message on this path and was removed for that reason.
 *
 * This page must not reintroduce the distinction. Concretely:
 *
 *   * one request per submission, whatever was typed — no probe, no pre-check,
 *     nothing whose timing could be compared;
 *   * one confirmation, rendered identically for a registered and an
 *     unregistered identifier — the generic string below is the fallback, and
 *     the backend's own `detail` is shown verbatim when it sends one;
 *   * no wording anywhere that says an account was or was not found.
 *
 * src/__tests__/pages/ForgotPassword.test.jsx asserts all three, including a
 * DOM-level comparison of the two outcomes.
 *
 * The migration changed presentation only. Every handler, piece of state and
 * API call below is unchanged, and the endpoint, method and payload are
 * identical.
 */
import { useState } from "react";
import { Link } from "react-router-dom";
import { forgotPassword } from "@shell/api/auth";
import AuthLayout from "../components/AuthLayout";
import { CcureAlert, CcureButton, CcureInput } from "../../../design-system";
import "../styles/forgot-password.css";

export default function ForgotPassword() {
  const [emailOrUsername, setEmailOrUsername] = useState("");
  const [success, setSuccess] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");
    setLoading(true);

    try {
      const res = await forgotPassword(emailOrUsername.trim());
      setSuccess(
        res.detail ||
          "If this account is registered, you will receive a reset link shortly.",
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
    <AuthLayout pageType="forgot" title="Reset password">
      <h1 className="auth-title">Reset password</h1>
      <p className="auth-sub">
        Enter your account email or username to request a reset link.
      </p>

      {error && (
        <CcureAlert variant="danger" className="fp-message">
          {error}
        </CcureAlert>
      )}

      {success ? (
        // `variant="success"` gives role="status" — polite, matching the
        // previous markup. It must stay polite: this is a confirmation,
        // and it is the same confirmation either way.
        <CcureAlert variant="success" className="fp-message">
          {success}
        </CcureAlert>
      ) : (
        <form onSubmit={handleSubmit} className="auth-form fp-form">
          <CcureInput
            id="emailOrUsername"
            name="emailOrUsername"
            label="Email or Username"
            // type="text", not "email": the endpoint takes either, and
            // type="email" would make the browser reject a username before
            // the request was ever made.
            type="text"
            required
            autoComplete="username"
            value={emailOrUsername}
            onChange={(e) => setEmailOrUsername(e.target.value)}
            placeholder="name@company.com or username"
            // A placeholder disappears the moment the user types, so it
            // cannot be the only guidance. The hint is wired through
            // aria-describedby by CcureInput.
            hint="Enter the email address or username on your account."
          />

          <CcureButton type="submit" loading={loading} block size="lg">
            {loading ? "Sending recovery link..." : "Send recovery link →"}
          </CcureButton>
        </form>
      )}

      <p className="auth-switch">
        Remember your password?{" "}
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
    </AuthLayout>
  );
}
