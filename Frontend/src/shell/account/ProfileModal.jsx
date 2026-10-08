/**
 * src/shell/account/ProfileModal.jsx — Checkpoint 3C batch 14.
 * ─────────────────────────────────────────────────────────────────────────────
 * The account dialog AppLayout mounts from the account menu ("My Account"):
 *   • Profile Info – view/edit name and email
 *   • Security     – change password, MFA, active sessions
 *
 * ── What is preserved ───────────────────────────────────────────────────────
 * Every API call and its arguments: getProfile / updateProfile({full_name,
 * email}), getSessions / revokeSession(id) / revokeOtherSessions(),
 * enableMfa() → confirmMfa(code) → backup codes, disableMfa(password),
 * refreshUser(true) after a successful confirm or disable, and the pruning of
 * the session list to the current session afterwards (the server revokes the
 * others; showing them would show sessions that no longer exist).
 *
 * ── What changed, and why ───────────────────────────────────────────────────
 * The legacy dialog had `role="dialog"` and nothing else a dialog needs: no
 * aria-modal, no focus trap, no focus restoration, no Escape, an icon-only
 * close control with no name, tabs that were bare buttons, and an overlay
 * click that discarded an in-progress MFA enrolment. On CcureModal + CcureTabs
 * all of that is supplied by the primitives.
 *
 * Two deliberate behaviour changes, both security-motivated:
 *   * MFA enrolment starts from an explicit "Set up MFA" button, not from a
 *     checkbox `onChange` — a toggle a user can flip while tabbing past it
 *     used to fire a POST that mints a new TOTP secret.
 *   * "Sign out all other sessions" asks first. It is a session-wide
 *     revocation and was one click with no way back.
 * And one defect fixed: a failed `enableMfa` used to render its error only
 * inside the wizard, which had not opened, so the failure was invisible.
 *
 * ── Secret material ─────────────────────────────────────────────────────────
 * The TOTP secret and the backup codes are rendered as visible text ONLY
 * while the enrolment step that needs them is on screen, inside <code>
 * elements, and never in an attribute, a name, a title or a log. Leaving the
 * step clears them from state, so they leave the DOM.
 */

import { useState, useEffect } from "react";
import {
  getProfile,
  updateProfile,
  getSessions,
  revokeOtherSessions,
  revokeSession,
} from "../api/user";
import ChangePasswordModal from "./ChangePasswordModal";
import { useAuth } from "../auth/AuthContext";
import {
  enableMfa as enableMfaApi,
  confirmMfa as confirmMfaApi,
  disableMfa as disableMfaApi,
} from "../api/auth";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureConfirmDialog,
  CcureInput,
  CcureLoader,
  CcureEmptyState,
  CcureModal,
  CcurePasswordField,
  CcureTabPanel,
  CcureTabs,
  CcureIcon,
} from "../../design-system";
import "./account-dialog.css";

/* ── Helpers ─────────────────────────────────────────────────────────────── */
function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/**
 * Render a session's device description.
 *
 * The backend records { browser, platform, raw } from the User-Agent, and both
 * labels can be "Unknown" — the parse is a deliberately small table, not a
 * user-agent database. Falls back through the raw string rather than showing
 * "Unknown Unknown", so an unrecognised client is still distinguishable from
 * the others in the list, which is the entire point of showing this column.
 */
function formatDevice(info) {
  if (!info) return "Browser session";

  const browser =
    info.browser && info.browser !== "Unknown" ? info.browser : null;
  const platform =
    info.platform && info.platform !== "Unknown" ? info.platform : null;

  if (browser && platform) return `${browser} on ${platform}`;
  if (browser) return browser;
  if (platform) return platform;
  if (info.raw) return info.raw.slice(0, 60);
  return "Browser session";
}

function getInitials(name, username) {
  const src = name || username || "U";
  return src
    .split(" ")
    .map((w) => w[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);
}

const TABS = [
  { id: "profile", label: "Profile Info" },
  { id: "security", label: "Security" },
];
const TABS_ID = "ac-tabs";

/* ── Profile Tab ─────────────────────────────────────────────────────────── */
function ProfileTab({ profile, onProfileUpdated }) {
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({ full_name: "", email: "" });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (profile) {
      setForm({
        full_name: profile.full_name || "",
        email: profile.email || "",
      });
    }
  }, [profile]);

  const handleSave = async () => {
    if (saving) return;
    setSaving(true);
    setError("");
    setSuccess(false);
    try {
      const updated = await updateProfile({
        full_name: form.full_name || null,
        email: form.email || null,
      });
      onProfileUpdated(updated);
      setEditing(false);
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (e) {
      setError(e.response?.data?.detail || "Failed to update profile");
    } finally {
      setSaving(false);
    }
  };

  if (!profile) {
    return <CcureLoader label="Loading profile…" />;
  }

  return (
    <div className="ac-panel">
      <div className="ac-identity">
        <div className="ac-avatar" aria-hidden="true">
          {getInitials(profile.full_name, profile.username)}
        </div>
        <div>
          <h3 className="ac-identity__name">
            {profile.full_name || profile.username}
          </h3>
          <div className="ac-identity__meta">
            <CcureBadge variant="primary">{profile.role_name}</CcureBadge>
            <span className="ac-identity__org">
              <CcureIcon name="briefcase" />
              {profile.organization_name}
            </span>
          </div>
        </div>
      </div>

      {success && (
        <CcureAlert variant="success">Profile updated successfully</CcureAlert>
      )}
      {error && <CcureAlert variant="danger">{error}</CcureAlert>}

      <form
        className="ac-fields"
        onSubmit={(e) => {
          e.preventDefault();
          if (editing) handleSave();
        }}
      >
        <div className="ac-fields__row">
          <CcureInput
            id="ac-username"
            label="Username"
            value={profile.username}
            readOnly
          />
          <div className="ac-field">
            <span className="ac-field__label" id="ac-status-label">
              Account Status
            </span>
            <div aria-labelledby="ac-status-label">
              <CcureBadge variant={profile.is_active ? "success" : "neutral"}>
                {profile.is_active ? "Active" : "Inactive"}
              </CcureBadge>
            </div>
          </div>
        </div>

        {editing ? (
          <CcureInput
            id="ac-full-name"
            label="Full Name"
            value={form.full_name}
            onChange={(e) =>
              setForm((f) => ({ ...f, full_name: e.target.value }))
            }
            placeholder="Enter your full name"
            autoComplete="name"
            disabled={saving}
          />
        ) : (
          <div className="ac-field">
            <span className="ac-field__label">Full Name</span>
            <div className="ac-field__value">
              {profile.full_name || <span className="ac-empty">Not set</span>}
            </div>
          </div>
        )}

        {editing ? (
          <CcureInput
            id="ac-email"
            label="Email Address"
            type="email"
            value={form.email}
            onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
            placeholder="Enter email address"
            autoComplete="email"
            disabled={saving}
          />
        ) : (
          <div className="ac-field">
            <span className="ac-field__label">Email Address</span>
            <div className="ac-field__value">{profile.email}</div>
          </div>
        )}

        <div className="ac-fields__row">
          <div className="ac-field">
            <span className="ac-field__label">Last Login</span>
            <div className="ac-field__value">
              {formatDate(profile.last_login_at)}
            </div>
          </div>
          <div className="ac-field">
            <span className="ac-field__label">Member Since</span>
            <div className="ac-field__value">
              {formatDate(profile.created_at)}
            </div>
          </div>
        </div>

        <div className="ac-actions">
          {editing ? (
            <>
              <CcureButton
                variant="secondary"
                onClick={() => {
                  setEditing(false);
                  setError("");
                }}
                disabled={saving}
              >
                Cancel
              </CcureButton>
              <CcureButton
                type="submit"
                variant="primary"
                loading={saving}
                disabled={saving}
              >
                {saving ? "Saving…" : "Save Changes"}
              </CcureButton>
            </>
          ) : (
            <CcureButton variant="secondary" onClick={() => setEditing(true)}>
              Edit Profile
            </CcureButton>
          )}
        </div>
      </form>
    </div>
  );
}

/* ── Security Tab ────────────────────────────────────────────────────────── */
function SecurityTab({ onOpenChangePassword }) {
  const { user, refreshUser } = useAuth();
  const mfaEnabled = !!user?.mfa_enabled;

  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [revoking, setRevoking] = useState(null);
  const [revokingOthers, setRevokingOthers] = useState(false);
  const [confirmRevokeOthers, setConfirmRevokeOthers] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  // MFA states
  const [wizardStep, setWizardStep] = useState(0); // 0 = closed, 1 = qr code scanning, 2 = recovery codes
  const [qrCode, setQrCode] = useState("");
  const [secret, setSecret] = useState("");
  const [confirmCode, setConfirmCode] = useState("");
  const [backupCodes, setBackupCodes] = useState([]);
  const [setupLoading, setSetupLoading] = useState(false);
  const [setupError, setSetupError] = useState("");

  const [showDisableForm, setShowDisableForm] = useState(false);
  const [disablePassword, setDisablePassword] = useState("");
  const [disableLoading, setDisableLoading] = useState(false);
  const [disableError, setDisableError] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setLoading(true);
    getSessions()
      .then(setSessions)
      .catch(() => setError("Failed to load sessions"))
      .finally(() => setLoading(false));
  }, []);

  const handleRevoke = async (sessionId) => {
    if (revoking) return;
    setRevoking(sessionId);
    try {
      await revokeSession(sessionId);
      setSessions((s) => s.filter((x) => x.session_id !== sessionId));
    } catch {
      setError("Failed to revoke session");
    } finally {
      setRevoking(null);
    }
  };

  const handleRevokeOthers = async () => {
    // The list is re-fetched rather than filtered locally. The server decides
    // which session it kept — it may have kept none, if this client had no
    // refresh cookie to identify itself with — and guessing that here would
    // show a session that no longer exists.
    if (revokingOthers) return;
    setRevokingOthers(true);
    setError("");
    setNotice("");
    try {
      const result = await revokeOtherSessions();
      const remaining = await getSessions();
      setSessions(remaining);
      setNotice(
        result.revoked === 0
          ? "No other sessions were signed in."
          : `Signed out ${result.revoked} other session${result.revoked === 1 ? "" : "s"}.`,
      );
      setConfirmRevokeOthers(false);
    } catch {
      setError("Failed to sign out other sessions");
      setConfirmRevokeOthers(false);
    } finally {
      setRevokingOthers(false);
    }
  };

  const clearEnrolment = () => {
    // Leaving the wizard removes the secret and the codes from state, and so
    // from the DOM.
    setWizardStep(0);
    setQrCode("");
    setSecret("");
    setConfirmCode("");
    setBackupCodes([]);
    setCopied(false);
  };

  const handleStartMfaSetup = async () => {
    if (setupLoading) return;
    setSetupLoading(true);
    setSetupError("");
    try {
      const res = await enableMfaApi();
      setQrCode(res.qr_code);
      setSecret(res.secret);
      setWizardStep(1);
      setConfirmCode("");
    } catch (err) {
      setSetupError(
        err.response?.data?.detail || "Failed to initiate MFA setup",
      );
    } finally {
      setSetupLoading(false);
    }
  };

  const handleConfirmMfa = async (e) => {
    e?.preventDefault?.();
    if (!confirmCode.trim() || setupLoading) return;
    setSetupLoading(true);
    setSetupError("");
    try {
      const res = await confirmMfaApi(confirmCode.trim());
      setBackupCodes(res.backup_codes || []);
      setWizardStep(2);
      await refreshUser(true);
      setSessions((prev) => prev.filter((s) => s.is_current));
    } catch (err) {
      setSetupError(
        err.response?.data?.detail || "Invalid code. Please try again.",
      );
    } finally {
      setSetupLoading(false);
    }
  };

  const handleDisableMfa = async (e) => {
    e?.preventDefault?.();
    if (!disablePassword || disableLoading) return;
    setDisableLoading(true);
    setDisableError("");
    try {
      await disableMfaApi(disablePassword);
      setShowDisableForm(false);
      setDisablePassword("");
      await refreshUser(true);
      setSessions((prev) => prev.filter((s) => s.is_current));
    } catch (err) {
      setDisableError(
        err.response?.data?.detail || "Failed to disable MFA. Verify password.",
      );
    } finally {
      setDisableLoading(false);
    }
  };

  const handleCopyBackupCodes = () => {
    const text = backupCodes.join("\n");
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (wizardStep > 0) {
    return (
      <div className="ac-panel">
        <ol className="ac-steps" aria-label="MFA setup progress">
          <li
            className={`ac-steps__item${wizardStep === 1 ? " ac-steps__item--active" : ""}`}
            aria-current={wizardStep === 1 ? "step" : undefined}
          >
            <span className="ac-steps__num" aria-hidden="true">
              1
            </span>
            Scan QR Code
          </li>
          <li
            className={`ac-steps__item${wizardStep === 2 ? " ac-steps__item--active" : ""}`}
            aria-current={wizardStep === 2 ? "step" : undefined}
          >
            <span className="ac-steps__num" aria-hidden="true">
              2
            </span>
            Recovery Codes
          </li>
        </ol>

        {wizardStep === 1 && (
          <section
            className="ac-mfa-card"
            aria-labelledby="ac-mfa-wizard-title"
          >
            <h4 className="ac-section__title" id="ac-mfa-wizard-title">
              MFA Setup Wizard
            </h4>

            {setupError && (
              <CcureAlert variant="danger">{setupError}</CcureAlert>
            )}

            <div className="ac-mfa-enrol">
              {qrCode && (
                <div className="ac-qr">
                  <img src={qrCode} alt="QR code for your authenticator app" />
                </div>
              )}
              <div className="ac-mfa-enrol__steps">
                <ol className="ac-list">
                  <li>
                    Scan the QR code with an authenticator app (like Google
                    Authenticator, Authy, or Duo).
                  </li>
                  <li>
                    Alternatively, enter the secret code manually:
                    {/* Visible text, by necessity: the user has to type it
                        into the authenticator. It lives here and nowhere
                        else — no attribute, no name, no title. */}
                    <code className="ac-secret">{secret}</code>
                  </li>
                  <li>
                    Enter the 6-digit code generated by your app below to
                    verify.
                  </li>
                </ol>

                <form className="ac-inline-form" onSubmit={handleConfirmMfa}>
                  <CcureInput
                    id="ac-mfa-code"
                    label="Verification code"
                    fieldClassName="ac-inline-form__field ac-code"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    placeholder="6-digit code"
                    value={confirmCode}
                    onChange={(e) => setConfirmCode(e.target.value)}
                    maxLength={8}
                    disabled={setupLoading}
                  />
                  <CcureButton
                    type="submit"
                    variant="primary"
                    loading={setupLoading}
                    disabled={setupLoading || !confirmCode.trim()}
                  >
                    {setupLoading ? "Verifying..." : "Verify & Enable"}
                  </CcureButton>
                  <CcureButton
                    variant="secondary"
                    onClick={clearEnrolment}
                    disabled={setupLoading}
                  >
                    Cancel
                  </CcureButton>
                </form>
              </div>
            </div>
          </section>
        )}

        {wizardStep === 2 && (
          <section
            className="ac-mfa-card ac-mfa-card--done"
            aria-labelledby="ac-mfa-done-title"
          >
            <h4 className="ac-section__title" id="ac-mfa-done-title">
              <CcureIcon name="check-circle" />
              Multi-Factor Authentication Enabled!
            </h4>
            <p className="ac-section__desc">
              Save these backup recovery codes. You can use them to sign in if
              you lose access to your authenticator device. Each code is
              single-use.
            </p>

            <ul className="ac-codes" aria-label="Backup recovery codes">
              {backupCodes.map((c) => (
                <li key={c}>
                  <code>{c}</code>
                </li>
              ))}
            </ul>

            <div className="ac-actions ac-actions--fill">
              <CcureButton variant="secondary" onClick={handleCopyBackupCodes}>
                {copied ? "Copied! ✓" : "Copy Codes"}
              </CcureButton>
              <CcureButton variant="primary" onClick={clearEnrolment}>
                Done
              </CcureButton>
            </div>
            <span className="cc-sr-only" role="status" aria-live="polite">
              {copied ? "Backup codes copied to the clipboard" : ""}
            </span>
          </section>
        )}
      </div>
    );
  }

  return (
    <div className="ac-panel">
      {/* Password section */}
      <section className="ac-section" aria-labelledby="ac-password-title">
        <h4 className="ac-section__title" id="ac-password-title">
          Password
        </h4>
        <p className="ac-section__desc">
          Regularly update your password to maintain account security.
        </p>
        <CcureButton variant="secondary" onClick={onOpenChangePassword}>
          Change Password
        </CcureButton>
      </section>

      {/* MFA Section */}
      <section className="ac-section ac-mfa" aria-labelledby="ac-mfa-title">
        <div className="ac-mfa__head">
          <div>
            <h4 className="ac-section__title" id="ac-mfa-title">
              Multi-Factor Authentication (MFA)
            </h4>
            <div className="ac-mfa__status">
              {mfaEnabled ? (
                <CcureBadge variant="success">Enabled</CcureBadge>
              ) : (
                <CcureBadge variant="warning">Disabled</CcureBadge>
              )}
              <span className="ac-mfa__kind">
                TOTP / Authenticator &amp; Email Fallback
              </span>
            </div>
          </div>
          {/* An explicit action, never a toggle: a checkbox that starts an
              enrolment on change fires a POST from a stray keypress. */}
          {mfaEnabled ? (
            <CcureButton
              variant="secondary"
              onClick={() => {
                setShowDisableForm(true);
                setDisableError("");
              }}
              disabled={disableLoading || showDisableForm}
            >
              Disable MFA
            </CcureButton>
          ) : (
            <CcureButton
              variant="primary"
              onClick={handleStartMfaSetup}
              loading={setupLoading}
              disabled={setupLoading}
            >
              Set up MFA
            </CcureButton>
          )}
        </div>

        <p className="ac-section__desc">
          Add an extra layer of security to your account using TOTP and email
          fallback OTP.
        </p>

        {/* A failed enrolment start is reported HERE. The legacy dialog only
            rendered this error inside the wizard, which had not opened, so a
            failed start showed nothing at all. */}
        {setupError && !showDisableForm && (
          <CcureAlert variant="danger">{setupError}</CcureAlert>
        )}

        {mfaEnabled && !showDisableForm && (
          <p className="ac-hint">
            To reconfigure, disable MFA (requires password confirmation) and set
            it up again.
          </p>
        )}

        {showDisableForm && (
          <form
            className="ac-mfa-card ac-mfa-card--danger"
            onSubmit={handleDisableMfa}
            aria-labelledby="ac-mfa-disable-title"
          >
            <h5 className="ac-section__title" id="ac-mfa-disable-title">
              Confirm Disabling MFA
            </h5>
            <p className="ac-section__desc">
              Enter your account password to confirm disabling Multi-Factor
              Authentication.
            </p>

            {disableError && (
              <CcureAlert variant="danger">{disableError}</CcureAlert>
            )}

            <div className="ac-inline-form">
              <CcurePasswordField
                id="ac-mfa-disable-password"
                label="Account password"
                fieldClassName="ac-inline-form__field"
                placeholder="Confirm with your password"
                value={disablePassword}
                onChange={(e) => setDisablePassword(e.target.value)}
                autoComplete="current-password"
                capsLockWarning={false}
                disabled={disableLoading}
              />
              <CcureButton
                variant="secondary"
                onClick={() => {
                  setShowDisableForm(false);
                  setDisablePassword("");
                  setDisableError("");
                }}
                disabled={disableLoading}
              >
                Cancel
              </CcureButton>
              <CcureButton
                type="submit"
                variant="danger"
                loading={disableLoading}
                disabled={disableLoading || !disablePassword}
              >
                {disableLoading ? "Confirming..." : "Disable"}
              </CcureButton>
            </div>
          </form>
        )}
      </section>

      {/* Sessions section */}
      <section className="ac-section" aria-labelledby="ac-sessions-title">
        <h4 className="ac-section__title" id="ac-sessions-title">
          Active Sessions
        </h4>
        <p className="ac-section__desc">
          These are all devices / browsers currently logged into your account.
          Signing in on a new device does not sign you out anywhere else, so
          anything here that you do not recognise should be revoked.
        </p>

        {error && <CcureAlert variant="danger">{error}</CcureAlert>}
        {notice && <CcureAlert variant="success">{notice}</CcureAlert>}

        {loading ? (
          <CcureLoader label="Loading sessions…" />
        ) : sessions.length === 0 ? (
          <CcureEmptyState title="No active sessions found." />
        ) : (
          <ul className="ac-sessions" aria-label="Active sessions">
            {sessions.map((s) => {
              const device = formatDevice(s.device_info);
              return (
                <li
                  key={s.session_id}
                  className={`ac-session${s.is_current ? " ac-session--current" : ""}`}
                >
                  <div className="ac-session__info">
                    <div className="ac-session__device">
                      {device}
                      {s.is_current && (
                        <CcureBadge variant="primary" size="sm">
                          Current
                        </CcureBadge>
                      )}
                    </div>
                    <div className="ac-session__meta">
                      <span>IP: {s.ip_address || "Unknown"}</span>
                      <span aria-hidden="true">·</span>
                      <span>Issued: {formatDate(s.issued_at)}</span>
                    </div>
                    <div className="ac-session__meta">
                      Expires: {formatDate(s.expires_at)}
                    </div>
                  </div>
                  {!s.is_current && (
                    <CcureButton
                      variant="ghost"
                      size="sm"
                      aria-label={`Revoke session: ${device}, ${s.ip_address || "unknown IP"}`}
                      onClick={() => handleRevoke(s.session_id)}
                      loading={revoking === s.session_id}
                      disabled={Boolean(revoking)}
                    >
                      Revoke
                    </CcureButton>
                  )}
                </li>
              );
            })}
          </ul>
        )}

        {sessions.length > 1 && (
          <CcureButton
            variant="danger"
            onClick={() => setConfirmRevokeOthers(true)}
            loading={revokingOthers}
            disabled={revokingOthers}
          >
            {revokingOthers ? "Signing out…" : "Sign out all other sessions"}
          </CcureButton>
        )}
      </section>

      <CcureConfirmDialog
        open={confirmRevokeOthers}
        title="Sign out other sessions?"
        subtitle="Every device and browser signed in to your account except this one will be signed out immediately."
        warning="Anyone using those sessions — including you on another device — will have to sign in again."
        confirmLabel="Sign out other sessions"
        tone="danger"
        busy={revokingOthers}
        onConfirm={handleRevokeOthers}
        onCancel={() => setConfirmRevokeOthers(false)}
      />
    </div>
  );
}

/* ── Main ProfileModal ───────────────────────────────────────────────────── */
export default function ProfileModal({ onClose }) {
  const [activeTab, setActiveTab] = useState("profile");
  const [profile, setProfile] = useState(null);
  const [showChangePwd, setShowChangePwd] = useState(false);
  const [loadError, setLoadError] = useState("");

  useEffect(() => {
    getProfile()
      .then(setProfile)
      .catch(() => setLoadError("Failed to load profile"));
  }, []);

  return (
    <>
      <CcureModal
        open
        onClose={onClose}
        title="My Account"
        size="md"
        className="ac-modal"
        closeLabel="Close account dialog"
        /* An overlay click must not discard an in-progress enrolment or a
           half-typed password. Escape and the named close control remain. */
        closeOnOverlayClick={false}
      >
        <CcureTabs
          id={TABS_ID}
          label="Account sections"
          className="ac-tabs"
          tabs={TABS}
          value={activeTab}
          onChange={setActiveTab}
        />

        {loadError && <CcureAlert variant="danger">{loadError}</CcureAlert>}

        <CcureTabPanel
          id="profile"
          tabsId={TABS_ID}
          active={activeTab === "profile"}
        >
          <ProfileTab profile={profile} onProfileUpdated={setProfile} />
        </CcureTabPanel>
        <CcureTabPanel
          id="security"
          tabsId={TABS_ID}
          active={activeTab === "security"}
        >
          {/* The nested dialog restores focus to the opener on close (its
              own focus trap remembers it), so nothing is tracked here. */}
          <SecurityTab onOpenChangePassword={() => setShowChangePwd(true)} />
        </CcureTabPanel>
      </CcureModal>

      {showChangePwd && (
        <ChangePasswordModal onClose={() => setShowChangePwd(false)} />
      )}
    </>
  );
}
