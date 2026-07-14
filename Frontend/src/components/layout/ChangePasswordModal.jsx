/**
 * src/components/layout/ChangePasswordModal.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Password change modal with:
 *   • Old password verification
 *   • New password strength meter
 *   • Confirmation field with inline validation
 */

import { useState } from "react";
import { changePassword } from "../../api/user";

/* ── Icons ───────────────────────────────────────────────────────────────── */
const Icon = ({ d, size = 16 }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d={d} />
  </svg>
);
const IcoClose = () => <Icon d="M18 6L6 18M6 6l12 12" />;
const IcoEye = () => (
  <Icon d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z" />
);
const IcoEyeOff = () => (
  <Icon d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24M1 1l22 22" />
);
const IcoLock = () => (
  <Icon d="M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2zM7 11V7a5 5 0 0 1 10 0v4" />
);
const IcoCheck = () => <Icon d="M20 6L9 17l-5-5" />;

/* ── Password strength ───────────────────────────────────────────────────── */
function getStrength(pwd) {
  if (!pwd) return { score: 0, label: "", color: "" };
  let score = 0;
  if (pwd.length >= 12) score++;
  if (pwd.length >= 16) score++;
  if (/[A-Z]/.test(pwd)) score++;
  if (/[0-9]/.test(pwd)) score++;
  if (/[^A-Za-z0-9]/.test(pwd)) score++;

  if (score <= 1) return { score, label: "Weak", color: "#ef4444" };
  if (score <= 3) return { score, label: "Fair", color: "#f59e0b" };
  if (score === 4) return { score, label: "Good", color: "#3b82f6" };
  return { score, label: "Strong", color: "#22c55e" };
}

/* ── Password field with toggle ─────────────────────────────────────────── */
function PwdField({ label, value, onChange, placeholder, hint }) {
  const [show, setShow] = useState(false);
  return (
    <div className="cpw-field">
      <label className="cpw-label">{label}</label>
      <div className="cpw-input-wrap">
        <IcoLock />
        <input
          className="cpw-input"
          type={show ? "text" : "password"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          autoComplete="new-password"
        />
        <button
          className="cpw-eye"
          type="button"
          onClick={() => setShow((s) => !s)}
        >
          {show ? <IcoEyeOff /> : <IcoEye />}
        </button>
      </div>
      {hint && <span className="cpw-hint">{hint}</span>}
    </div>
  );
}

/* ── Main ────────────────────────────────────────────────────────────────── */
export default function ChangePasswordModal({ onClose }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  const strength = getStrength(next);
  const mismatch = confirm && next !== confirm;
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

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setSaving(true);
    setError("");
    try {
      await changePassword(current, next);
      setSuccess(true);
      setTimeout(onClose, 2200);
    } catch (e) {
      setError(e.response?.data?.detail || "Failed to change password");
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <div className="cpw-overlay" onClick={onClose} />
      <div className="cpw-modal" role="dialog" aria-label="Change Password">
        <div className="cpw-header">
          <span>🔐 Change Password</span>
          <button className="cpw-close" onClick={onClose}>
            <IcoClose />
          </button>
        </div>

        {success ? (
          <div className="cpw-success">
            <div className="cpw-success-icon">
              <IcoCheck />
            </div>
            <h3>Password Changed!</h3>
            <p>Your password has been updated successfully.</p>
          </div>
        ) : (
          <div className="cpw-body">
            {error && <div className="cpw-error">{error}</div>}

            <PwdField
              label="Current Password"
              value={current}
              onChange={setCurrent}
              placeholder="Enter your current password"
            />

            <PwdField
              label="New Password"
              value={next}
              onChange={setNext}
              placeholder="Create a strong password"
            />

            {/* Strength meter */}
            {next && (
              <div className="cpw-strength">
                <div className="cpw-strength-bar">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <div
                      key={i}
                      className="cpw-strength-seg"
                      style={{
                        background:
                          i <= strength.score ? strength.color : "#e2e8f0",
                      }}
                    />
                  ))}
                </div>
                <span
                  className="cpw-strength-label"
                  style={{ color: strength.color }}
                >
                  {strength.label}
                </span>
              </div>
            )}

            {/* Requirements */}
            {next && (
              <ul className="cpw-reqs">
                {requirements.map((r) => (
                  <li
                    key={r.text}
                    className={`cpw-req ${r.ok ? "cpw-req--ok" : ""}`}
                  >
                    <span className="cpw-req-dot" />
                    {r.text}
                  </li>
                ))}
              </ul>
            )}

            <PwdField
              label="Confirm New Password"
              value={confirm}
              onChange={setConfirm}
              placeholder="Repeat new password"
              hint={mismatch ? "Passwords do not match" : ""}
            />
            {mismatch && (
              <span className="cpw-mismatch">⚠ Passwords do not match</span>
            )}

            <div className="cpw-footer">
              <button className="cpw-btn cpw-btn--ghost" onClick={onClose}>
                Cancel
              </button>
              <button
                className="cpw-btn cpw-btn--primary"
                onClick={handleSubmit}
                disabled={!canSubmit || saving}
              >
                {saving ? "Updating…" : "Update Password"}
              </button>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
