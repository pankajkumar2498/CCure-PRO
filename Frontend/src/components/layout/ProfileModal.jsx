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
  const [sessions, setSessions]   = useState([]);
  const [loading, setLoading]     = useState(true);
  const [revoking, setRevoking]   = useState(null);
  const [error, setError]         = useState("");

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
