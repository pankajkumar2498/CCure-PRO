/**
 * src/components/layout/ProfileModal.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Full-featured profile modal with tabs:
 *   • Profile Info – view/edit name and email
 *   • Security     – change password, active sessions
 *   • Preferences  – theme, scan defaults, alerts
 */

import { useState, useEffect, useCallback } from "react";
import { getProfile, updateProfile, getSessions, revokeSession } from "../../api/user";
import ChangePasswordModal from "./ChangePasswordModal";
import { useAuth } from "../../context/AuthContext";
import { enableMfa as enableMfaApi, confirmMfa as confirmMfaApi, disableMfa as disableMfaApi } from "../../api/auth";


/* ── Icons ───────────────────────────────────────────────────────────────── */
const Icon = ({ d, size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d={d} />
  </svg>
);
const IcoClose = () => <Icon d="M18 6L6 18M6 6l12 12" />;
const IcoUser  = () => <Icon d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z" />;
const IcoShield = () => <Icon d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />;
const IcoSettings = () => <Icon d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />;
const IcoMonitor = () => <Icon d="M4 4h16c1.1 0 2 .9 2 2v10c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2zM8 20h8M12 16v4" />;
const IcoTrash = () => <Icon d="M3 6h18M19 6l-1 14H6L5 6M9 6V4h6v2" />;
const IcoEdit = () => <Icon d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />;
const IcoCheck = () => <Icon d="M20 6L9 17l-5-5" />;

/* ── Helpers ─────────────────────────────────────────────────────────────── */
function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-IN", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function getInitials(name, username) {
  const src = name || username || "U";
  return src.split(" ").map(w => w[0]).join("").toUpperCase().slice(0, 2);
}

/* ── Profile Tab ─────────────────────────────────────────────────────────── */
function ProfileTab({ profile, onProfileUpdated }) {
  const [editing, setEditing] = useState(false);
  const [form, setForm]       = useState({ full_name: "", email: "" });
  const [saving, setSaving]   = useState(false);
  const [error, setError]     = useState("");
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (profile) {
      setForm({ full_name: profile.full_name || "", email: profile.email || "" });
    }
  }, [profile]);

  const handleSave = async () => {
    setSaving(true); setError(""); setSuccess(false);
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

  if (!profile) return <div className="pm-loading">Loading profile…</div>;

  return (
    <div className="pm-tab-content">
      {/* Avatar section */}
      <div className="pm-avatar-section">
        <div className="pm-avatar-large">
          {getInitials(profile.full_name, profile.username)}
        </div>
        <div className="pm-avatar-info">
          <h3 className="pm-display-name">{profile.full_name || profile.username}</h3>
          <span className="pm-role-badge">{profile.role_name}</span>
          <span className="pm-org-label">🏢 {profile.organization_name}</span>
        </div>
      </div>

      {/* Success banner */}
      {success && (
        <div className="pm-alert pm-alert--success">
          <IcoCheck /> Profile updated successfully
        </div>
      )}
      {error && (
        <div className="pm-alert pm-alert--error">{error}</div>
      )}

      {/* Fields */}
      <div className="pm-fields">
        <div className="pm-field-row">
          <div className="pm-field">
            <label className="pm-label">Username</label>
            <input className="pm-input pm-input--readonly" value={profile.username} readOnly />
          </div>
          <div className="pm-field">
            <label className="pm-label">Account Status</label>
            <div className="pm-status-pill">
              <span className={`pm-dot ${profile.is_active ? "pm-dot--active" : "pm-dot--inactive"}`} />
              {profile.is_active ? "Active" : "Inactive"}
            </div>
          </div>
        </div>

        <div className="pm-field">
          <label className="pm-label">Full Name</label>
          {editing ? (
            <input
              className="pm-input"
              value={form.full_name}
              onChange={e => setForm(f => ({ ...f, full_name: e.target.value }))}
              placeholder="Enter your full name"
            />
          ) : (
            <div className="pm-field-value">{profile.full_name || <span className="pm-empty">Not set</span>}</div>
          )}
        </div>

        <div className="pm-field">
          <label className="pm-label">Email Address</label>
          {editing ? (
            <input
              className="pm-input"
              type="email"
              value={form.email}
              onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
              placeholder="Enter email address"
            />
          ) : (
            <div className="pm-field-value">{profile.email}</div>
          )}
        </div>

        <div className="pm-field-row">
          <div className="pm-field">
            <label className="pm-label">Last Login</label>
            <div className="pm-field-value">{formatDate(profile.last_login_at)}</div>
          </div>
          <div className="pm-field">
            <label className="pm-label">Member Since</label>
            <div className="pm-field-value">{formatDate(profile.created_at)}</div>
          </div>
        </div>
      </div>

      {/* Action buttons */}
      <div className="pm-actions">
        {editing ? (
          <>
            <button className="pm-btn pm-btn--ghost" onClick={() => { setEditing(false); setError(""); }}>
              Cancel
            </button>
            <button className="pm-btn pm-btn--primary" onClick={handleSave} disabled={saving}>
              {saving ? "Saving…" : "Save Changes"}
            </button>
          </>
        ) : (
          <button className="pm-btn pm-btn--outline" onClick={() => setEditing(true)}>
            <IcoEdit /> Edit Profile
          </button>
        )}
      </div>
    </div>
  );
}

/* ── Security Tab ────────────────────────────────────────────────────────── */
function SecurityTab({ onOpenChangePassword }) {
  const { user, refreshUser } = useAuth();
  const mfaEnabled = !!user?.mfa_enabled;

  const [sessions, setSessions]   = useState([]);
  const [loading, setLoading]     = useState(true);
  const [revoking, setRevoking]   = useState(null);
  const [error, setError]         = useState("");

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
    setRevoking(sessionId);
    try {
      await revokeSession(sessionId);
      setSessions(s => s.filter(x => x.session_id !== sessionId));
    } catch {
      setError("Failed to revoke session");
    } finally {
      setRevoking(null);
    }
  };

  const handleStartMfaSetup = async () => {
    setSetupLoading(true);
    setSetupError("");
    try {
      const res = await enableMfaApi();
      setQrCode(res.qr_code);
      setSecret(res.secret);
      setWizardStep(1);
      setConfirmCode("");
    } catch (err) {
      setSetupError(err.response?.data?.detail || "Failed to initiate MFA setup");
    } finally {
      setSetupLoading(false);
    }
  };

  const handleConfirmMfa = async () => {
    if (!confirmCode.trim()) return;
    setSetupLoading(true);
    setSetupError("");
    try {
      const res = await confirmMfaApi(confirmCode.trim());
      setBackupCodes(res.backup_codes || []);
      setWizardStep(2);
      await refreshUser(true);
      setSessions(prev => prev.filter(s => s.is_current));
    } catch (err) {
      setSetupError(err.response?.data?.detail || "Invalid code. Please try again.");
    } finally {
      setSetupLoading(false);
    }
  };

  const handleDisableMfa = async () => {
    if (!disablePassword) return;
    setDisableLoading(true);
    setDisableError("");
    try {
      await disableMfaApi(disablePassword);
      setShowDisableForm(false);
      setDisablePassword("");
      await refreshUser(true);
      setSessions(prev => prev.filter(s => s.is_current));
    } catch (err) {
      setDisableError(err.response?.data?.detail || "Failed to disable MFA. Verify password.");
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

  const handleToggleChange = async (e) => {
    const checked = e.target.checked;
    if (checked) {
      await handleStartMfaSetup();
    } else {
      setShowDisableForm(true);
    }
  };

  if (wizardStep > 0) {
    return (
      <div className="pm-tab-content">
        {/* Step Indicator */}
        <div className="pm-mfa-steps">
          <div className={`pm-mfa-step-item ${wizardStep === 1 ? "pm-mfa-step-item--active" : ""}`}>
            <span className="pm-mfa-step-num">1</span>
            <span>Scan QR Code</span>
          </div>
          <div className="pm-mfa-step-line" />
          <div className={`pm-mfa-step-item ${wizardStep === 2 ? "pm-mfa-step-item--active" : ""}`}>
            <span className="pm-mfa-step-num">2</span>
            <span>Recovery Codes</span>
          </div>
        </div>

        {wizardStep === 1 && (
          <div style={{
            background: "linear-gradient(135deg, rgba(79, 70, 229, 0.06), rgba(79, 70, 229, 0.02))",
            border: "1px solid rgba(79, 70, 229, 0.18)",
            padding: "20px",
            borderRadius: "10px"
          }}>
            <h5 style={{ margin: "0 0 12px 0", fontSize: "15px", fontWeight: 700, color: "var(--text)" }}>MFA Setup Wizard</h5>
            
            {setupError && <div className="pm-alert pm-alert--error" style={{ marginBottom: "12px" }}>{setupError}</div>}
            
            <div style={{ display: "flex", flexDirection: "column", gap: "20px", alignItems: "center" }}>
              {qrCode && (
                <div style={{ background: "white", padding: "10px", borderRadius: "8px", border: "1px solid var(--border)", display: "inline-block" }}>
                  <img src={qrCode} alt="Scan QR Code" style={{ width: "150px", height: "150px", display: "block" }} />
                </div>
              )}
              <div style={{ flex: 1, fontSize: "13px", color: "var(--text-mid)" }}>
                <ol style={{ margin: 0, paddingLeft: "20px", lineHeight: 1.6 }}>
                  <li>Scan the QR code with an authenticator app (like Google Authenticator, Authy, or Duo).</li>
                  <li style={{ marginTop: "4px" }}>Alternatively, enter the secret code manually: <code style={{ color: "var(--accent)", background: "rgba(14, 165, 233, 0.1)", border: "1px solid rgba(14, 165, 233, 0.2)", padding: "3px 8px", borderRadius: "4px", fontSize: "12px", wordBreak: "break-all", display: "block", marginTop: "6px", fontFamily: "monospace", fontWeight: "600" }}>{secret}</code></li>
                  <li style={{ marginTop: "8px" }}>Enter the 6-digit code generated by your app below to verify.</li>
                </ol>

                <div style={{ display: "flex", gap: "8px", marginTop: "16px", alignItems: "center" }}>
                  <input
                    type="text"
                    className="pm-input"
                    placeholder="6-digit code"
                    value={confirmCode}
                    onChange={(e) => setConfirmCode(e.target.value)}
                    maxLength={8}
                    style={{ width: "120px", height: "36px", textAlign: "center", letterSpacing: "2px", fontWeight: "bold" }}
                  />
                  <button className="pm-btn pm-btn--primary" onClick={handleConfirmMfa} disabled={setupLoading} style={{ height: "36px" }}>
                    {setupLoading ? "Verifying..." : "Verify & Enable"}
                  </button>
                  <button className="pm-btn pm-btn--ghost" onClick={() => setWizardStep(0)} style={{ height: "36px" }}>
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {wizardStep === 2 && (
          <div style={{
            background: "linear-gradient(135deg, rgba(16, 185, 129, 0.06), rgba(16, 185, 129, 0.02))",
            border: "1px solid rgba(16, 185, 129, 0.18)",
            padding: "20px",
            borderRadius: "10px"
          }}>
            <h5 style={{ margin: "0 0 8px 0", fontSize: "15px", fontWeight: 700, color: "#16a34a" }}>🎉 Multi-Factor Authentication Enabled!</h5>
            <p style={{ margin: "0 0 16px 0", fontSize: "13px", color: "var(--text-mid)" }}>Save these backup recovery codes. You can use them to sign in if you lose access to your authenticator device. Each code is single-use.</p>
            
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "8px", marginBottom: "16px" }}>
              {backupCodes.map((c, idx) => (
                <div key={idx} style={{ fontFamily: "monospace", fontSize: "14px", background: "var(--bg-white)", border: "1px solid var(--border)", padding: "6px 10px", borderRadius: "6px", textAlign: "center", color: "var(--text)", fontWeight: 700 }}>
                  {c}
                </div>
              ))}
            </div>

            <div style={{ display: "flex", gap: "10px" }}>
              <button className="pm-btn pm-btn--outline" onClick={handleCopyBackupCodes} style={{ flex: 1 }}>
                {copied ? "Copied! ✓" : "Copy Codes"}
              </button>
              <button className="pm-btn pm-btn--primary" onClick={() => setWizardStep(0)} style={{ flex: 1 }}>
                Done
              </button>
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="pm-tab-content">
      {/* Password section */}
      <div className="pm-section">
        <h4 className="pm-section-title">Password</h4>
        <p className="pm-section-desc">
          Regularly update your password to maintain account security.
        </p>
        <button className="pm-btn pm-btn--outline" onClick={onOpenChangePassword}>
          🔐 Change Password
        </button>
      </div>

      <div className="pm-divider" />

      {/* MFA Section */}
      <div className="pm-mfa-card">
        <div className="pm-mfa-header-row">
          <div className="pm-mfa-title-block">
            <h4 className="pm-section-title" style={{ margin: 0 }}>Multi-Factor Authentication (MFA)</h4>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "4px" }}>
              {mfaEnabled ? (
                <span className="pm-glass-badge pm-glass-badge--enabled">
                  <span className="pm-dot-green" />
                  Enabled
                </span>
              ) : (
                <span className="pm-glass-badge pm-glass-badge--disabled">
                  <span className="pm-pulse-amber-dot" />
                  Disabled
                </span>
              )}
              <span style={{ fontSize: "13px", color: "var(--text-muted)", fontWeight: "500" }}>
                TOTP / Authenticator & Email Fallback
              </span>
            </div>
          </div>
          
          <label className="pm-switch">
            <input
              type="checkbox"
              className="pm-switch-input"
              checked={mfaEnabled}
              onChange={handleToggleChange}
              disabled={setupLoading || disableLoading || showDisableForm}
            />
            <span className="pm-switch-track">
              <span className="pm-switch-thumb" />
            </span>
          </label>
        </div>

        <p className="pm-section-desc font-normal" style={{ margin: "8px 0 0 0" }}>
          Add an extra layer of security to your account using TOTP and email fallback OTP.
        </p>

        {mfaEnabled && !showDisableForm && (
          <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "8px 0 0 0", fontStyle: "italic" }}>
            To reconfigure, toggle off (requires password confirmation) and enable again.
          </p>
        )}

        {showDisableForm && (
          <div style={{
            background: "linear-gradient(135deg, rgba(239, 68, 68, 0.06), rgba(239, 68, 68, 0.02))",
            border: "1px solid rgba(239, 68, 68, 0.18)",
            padding: "16px",
            borderRadius: "8px",
            marginTop: "16px"
          }}>
            <h5 style={{ margin: "0 0 8px 0", color: "#dc2626", fontSize: "14px", fontWeight: 700 }}>Confirm Disabling MFA</h5>
            <p style={{ margin: "0 0 12px 0", fontSize: "12.5px", color: "var(--text-mid)" }}>Enter your account password to confirm disabling Multi-Factor Authentication.</p>
            
            {disableError && <div className="pm-alert pm-alert--error" style={{ marginBottom: "12px" }}>{disableError}</div>}
            
            <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
              <div className="pm-field" style={{ flex: 1, margin: 0 }}>
                <input
                  type="password"
                  className="pm-input"
                  placeholder="Confirm with your password"
                  value={disablePassword}
                  onChange={(e) => setDisablePassword(e.target.value)}
                  style={{ height: "36px" }}
                />
              </div>
              <button className="pm-btn pm-btn--ghost" onClick={() => { setShowDisableForm(false); setDisablePassword(""); setDisableError(""); }} style={{ height: "36px", padding: "0 14px" }}>
                Cancel
              </button>
              <button className="pm-btn pm-btn--primary" onClick={handleDisableMfa} disabled={disableLoading} style={{ background: "#dc2626", border: "none", height: "36px", padding: "0 14px", color: "white" }}>
                {disableLoading ? "Confirming..." : "Disable"}
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="pm-divider" />

      {/* Sessions section */}
      <div className="pm-section">
        <h4 className="pm-section-title">Active Sessions</h4>
        <p className="pm-section-desc">
          These are all devices / browsers currently logged into your account.
        </p>

        {error && <div className="pm-alert pm-alert--error">{error}</div>}

        {loading ? (
          <div className="pm-loading">Loading sessions…</div>
        ) : sessions.length === 0 ? (
          <div className="pm-empty-state">No active sessions found.</div>
        ) : (
          <div className="pm-sessions">
            {sessions.map(s => (
              <div key={s.session_id} className={`pm-session-card ${s.is_current ? "pm-session-card--current" : ""}`}>
                <div className="pm-session-icon"><IcoMonitor /></div>
                <div className="pm-session-info">
                  <div className="pm-session-device">
                    {s.device_info?.user_agent_summary || s.device_info?.browser || "Browser Session"}
                    {s.is_current && <span className="pm-current-badge">Current</span>}
                  </div>
                  <div className="pm-session-meta">
                    <span>IP: {s.ip_address || "Unknown"}</span>
                    <span>·</span>
                    <span>Issued: {formatDate(s.issued_at)}</span>
                  </div>
                  <div className="pm-session-expires">
                    Expires: {formatDate(s.expires_at)}
                  </div>
                </div>
                {!s.is_current && (
                  <button
                    className="pm-revoke-btn"
                    onClick={() => handleRevoke(s.session_id)}
                    disabled={revoking === s.session_id}
                    title="Revoke session"
                  >
                    {revoking === s.session_id ? "…" : <IcoTrash />}
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Main ProfileModal ───────────────────────────────────────────────────── */
export default function ProfileModal({ onClose }) {
  const [activeTab, setActiveTab]       = useState("profile");
  const [profile, setProfile]           = useState(null);
  const [showChangePwd, setShowChangePwd] = useState(false);
  const [loadError, setLoadError]       = useState("");

  useEffect(() => {
    getProfile()
      .then(setProfile)
      .catch(() => setLoadError("Failed to load profile"));
  }, []);

  const TABS = [
    { id: "profile",  label: "Profile Info",  Icon: IcoUser },
    { id: "security", label: "Security",      Icon: IcoShield },
  ];

  return (
    <>
      <div className="pm-overlay" onClick={onClose} />
      <div className="pm-modal" role="dialog" aria-label="Account Profile">
        {/* Header */}
        <div className="pm-header">
          <div className="pm-header-left">
            <IcoUser />
            <span>My Account</span>
          </div>
          <button className="pm-close" onClick={onClose}><IcoClose /></button>
        </div>

        {/* Tabs */}
        <div className="pm-tabs">
          {TABS.map(({ id, label, Icon }) => (
            <button
              key={id}
              className={`pm-tab ${activeTab === id ? "pm-tab--active" : ""}`}
              onClick={() => setActiveTab(id)}
            >
              <Icon /> {label}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="pm-body">
          {loadError && <div className="pm-alert pm-alert--error">{loadError}</div>}

          {activeTab === "profile" && (
            <ProfileTab profile={profile} onProfileUpdated={setProfile} />
          )}
          {activeTab === "security" && (
            <SecurityTab onOpenChangePassword={() => setShowChangePwd(true)} />
          )}
        </div>
      </div>

      {showChangePwd && (
        <ChangePasswordModal onClose={() => setShowChangePwd(false)} />
      )}
    </>
  );
}
