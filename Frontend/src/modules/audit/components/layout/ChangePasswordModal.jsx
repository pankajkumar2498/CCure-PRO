/**
 * src/modules/audit/components/layout/ChangePasswordModal.jsx — Checkpoint 3C batch 14.
 * ─────────────────────────────────────────────────────────────────────────────
 * Password change dialog, nested inside the account dialog:
 *   • Current password
 *   • New password with a strength meter and the rule checklist
 *   • Confirmation field with inline mismatch validation
 *
 * Preserved: `changePassword(current, next)`, the four rules and the
 * strength threshold (score ≥ 3) that gate submission, the success state and
 * the 2.2 s auto-close. Every field is `type="password"` with
 * `autocomplete="new-password"` (the current-password field keeps it too, as
 * before, so a password manager does not offer a saved credential into a
 * dialog that is about to replace it).
 *
 * On CcureModal (aria-modal, focus trap and restoration to the opener,
 * Escape, named close) and CcurePasswordField (visibility toggle named per
 * field, type stays password). A value never reaches an attribute, a name,
 * a title or a log — only the request body.
 */

import { useEffect, useRef, useState } from "react";
import { changePassword } from "@audit/api/user";
import {
  CcureAlert,
  CcureButton,
  CcureModal,
  CcurePasswordField,
} from "../../../../design-system";
import "../../styles/account-dialog.css";

/* ── Password strength ───────────────────────────────────────────────────── */
function getStrength(pwd) {
  if (!pwd) return { score: 0, label: "", level: "" };
  let score = 0;
  if (pwd.length >= 12) score++;
  if (pwd.length >= 16) score++;
  if (/[A-Z]/.test(pwd)) score++;
  if (/[0-9]/.test(pwd)) score++;
  if (/[^A-Za-z0-9]/.test(pwd)) score++;

  if (score <= 1) return { score, label: "Weak", level: "weak" };
  if (score <= 3) return { score, label: "Fair", level: "fair" };
  if (score === 4) return { score, label: "Good", level: "good" };
  return { score, label: "Strong", level: "strong" };
}

/* ── Main ────────────────────────────────────────────────────────────────── */
export default function ChangePasswordModal({ onClose }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);
  const closeTimer = useRef(null);

  // The 2.2 s auto-close must not fire on an unmounted dialog.
  useEffect(() => () => clearTimeout(closeTimer.current), []);

  const strength = getStrength(next);
  const mismatch = Boolean(confirm) && next !== confirm;
  const canSubmit =
    current && next && confirm && !mismatch && strength.score >= 3;

  const requirements = [
    { ok: next.length >= 12, text: "At least 12 characters" },
    { ok: /[A-Z]/.test(next), text: "One uppercase letter" },
    { ok: /[0-9]/.test(next), text: "One number" },
    {
      ok: /[^A-Za-z0-9]/.test(next),
      text: "One special character (!@#$ etc.)",
    },
  ];

  const handleSubmit = async (e) => {
    e?.preventDefault?.();
    if (!canSubmit || saving) return;
    setSaving(true);
    setError("");
    try {
      await changePassword(current, next);
      setSuccess(true);
      closeTimer.current = setTimeout(onClose, 2200);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to change password");
    } finally {
      setSaving(false);
    }
  };

  return (
    <CcureModal
      open
      onClose={saving ? undefined : onClose}
      title="Change Password"
      size="sm"
      className="acp-modal"
      closeLabel="Close change password dialog"
      closeOnOverlayClick={false}
      closeOnEscape={!saving}
    >
      {success ? (
        <div className="acp-success" role="status">
          <span className="acp-success__icon" aria-hidden="true">
            ✓
          </span>
          <h3 className="acp-success__title">Password Changed!</h3>
          <p>Your password has been updated successfully.</p>
        </div>
      ) : (
        <form className="acp-form" onSubmit={handleSubmit}>
          {error && <CcureAlert variant="danger">{error}</CcureAlert>}

          <CcurePasswordField
            id="acp-current"
            label="Current Password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            placeholder="Enter your current password"
            autoComplete="new-password"
            capsLockWarning={false}
            disabled={saving}
          />

          <CcurePasswordField
            id="acp-next"
            label="New Password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            placeholder="Create a strong password"
            autoComplete="new-password"
            capsLockWarning={false}
            disabled={saving}
          />

          {/* Strength meter: the same five-point score as before, rendered as
              a meter so the level is announced rather than only coloured. */}
          {next && (
            <div className="acp-strength">
              <div
                className={`acp-strength__bar acp-strength__bar--${strength.level}`}
                role="meter"
                aria-valuemin={0}
                aria-valuemax={5}
                aria-valuenow={strength.score}
                aria-valuetext={`${strength.label} password`}
                aria-label="Password strength"
              >
                {[1, 2, 3, 4, 5].map((i) => (
                  <span
                    key={i}
                    className={`acp-strength__seg${i <= strength.score ? " acp-strength__seg--on" : ""}`}
                  />
                ))}
              </div>
              <span
                className={`acp-strength__label acp-strength__label--${strength.level}`}
              >
                {strength.label}
              </span>
            </div>
          )}

          {next && (
            <ul className="acp-reqs" aria-label="Password requirements">
              {requirements.map((r) => (
                <li
                  key={r.text}
                  className={`acp-req${r.ok ? " acp-req--ok" : ""}`}
                >
                  <span className="acp-req__dot" aria-hidden="true" />
                  {r.text}
                  <span className="cc-sr-only">
                    {r.ok ? " (met)" : " (not met)"}
                  </span>
                </li>
              ))}
            </ul>
          )}

          <CcurePasswordField
            id="acp-confirm"
            label="Confirm New Password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="Repeat new password"
            autoComplete="new-password"
            capsLockWarning={false}
            disabled={saving}
            error={mismatch ? "Passwords do not match" : undefined}
          />

          <div className="acp-actions">
            <CcureButton
              variant="secondary"
              onClick={onClose}
              disabled={saving}
            >
              Cancel
            </CcureButton>
            <CcureButton
              type="submit"
              variant="primary"
              loading={saving}
              disabled={!canSubmit || saving}
            >
              {saving ? "Updating…" : "Update Password"}
            </CcureButton>
          </div>
        </form>
      )}
    </CcureModal>
  );
}
