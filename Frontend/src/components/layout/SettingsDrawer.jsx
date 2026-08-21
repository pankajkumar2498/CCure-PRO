/**
 * src/components/layout/SettingsDrawer.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Slide-in settings drawer with sections:
 *   • Display       – theme, date format, rows per page
 *   • Scan Defaults – default scan type, target discovery
 *   • Notifications – email and in-app alerts
 */

import { useState, useEffect } from "react";
import { getPreferences, updatePreferences } from "../../api/user";

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
const IcoCheck = () => <Icon d="M20 6L9 17l-5-5" />;
const IcoSun = () => (
  <Icon d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z" />
);
const IcoBell = () => (
  <Icon d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 0 1-3.46 0" />
);
const IcoScan = () => (
  <Icon d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2" />
);

/* ── Toggle switch ───────────────────────────────────────────────────────── */
function Toggle({ checked, onChange, id }) {
  return (
    <label className="sd-toggle" htmlFor={id}>
      <input
        id={id}
        type="checkbox"
        className="sd-toggle-input"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span className="sd-toggle-track">
        <span className="sd-toggle-thumb" />
      </span>
    </label>
  );
}

/* ── Option select group ─────────────────────────────────────────────────── */
function OptionGroup({ label, options, value, onChange }) {
  return (
    <div className="sd-option-group">
      <label className="sd-label">{label}</label>
      <div className="sd-options">
        {options.map((opt) => (
          <button
            key={opt.value}
            className={`sd-option ${value === opt.value ? "sd-option--active" : ""}`}
            onClick={() => onChange(opt.value)}
          >
            {opt.icon && <span className="sd-option-icon">{opt.icon}</span>}
            {opt.label}
          </button>
        ))}
      </div>
    </div>
  );
}

/* ── Section wrapper ─────────────────────────────────────────────────────── */
function Section({ title, icon, children }) {
  return (
    <div className="sd-section">
      <div className="sd-section-header">
        <span className="sd-section-icon">{icon}</span>
        <h4 className="sd-section-title">{title}</h4>
      </div>
      <div className="sd-section-body">{children}</div>
    </div>
  );
}

/* ── Row with toggle ─────────────────────────────────────────────────────── */
function ToggleRow({ id, label, hint, checked, onChange }) {
  return (
    <div className="sd-toggle-row">
      <div className="sd-toggle-info">
        <span className="sd-toggle-label">{label}</span>
        {hint && <span className="sd-toggle-hint">{hint}</span>}
      </div>
      <Toggle id={id} checked={checked} onChange={onChange} />
    </div>
  );
}

/* ── Main ────────────────────────────────────────────────────────────────── */
export default function SettingsDrawer({ onClose, onPreferencesUpdated }) {
  const [prefs, setPrefs] = useState(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    getPreferences()
      .then(setPrefs)
      .catch(() => setError("Failed to load preferences"));
  }, []);

  const set = (key) => (val) => {
    setPrefs((p) => ({ ...p, [key]: val }));
    setSaved(false);
  };

  const handleSave = async () => {
    setSaving(true);
    setError("");
    setSaved(false);
    try {
      const updated = await updatePreferences(prefs);
      setPrefs(updated);
      setSaved(true);
      if (onPreferencesUpdated) onPreferencesUpdated(updated);
      setTimeout(() => setSaved(false), 3000);
    } catch (e) {
      setError(e.response?.data?.detail || "Failed to save settings");
    } finally {
      setSaving(false);
    }
  };

  const SCAN_TYPES = [
    { value: "host-discovery", label: "Host Discovery" },
    { value: "asset", label: "Asset Scan" },
    { value: "vulnerability_audit", label: "Vulnerability Audit" },
    { value: "credentialed", label: "Credentialed" },
  ];

  const ROWS_OPTIONS = [
    { value: 10, label: "10" },
    { value: 25, label: "25" },
    { value: 50, label: "50" },
    { value: 100, label: "100" },
  ];

  return (
    <>
      <div className="sd-backdrop" onClick={onClose} />
      <aside className="sd-drawer" role="complementary" aria-label="Settings">
        {/* Header */}
        <div className="sd-header">
          <div className="sd-header-left">
            <IcoScan />
            <span>Settings</span>
          </div>
          <button className="sd-close" onClick={onClose}>
            <IcoClose />
          </button>
        </div>

        {/* Body */}
        <div className="sd-body">
          {error && <div className="sd-error">{error}</div>}

          {!prefs ? (
            <div className="sd-loading">Loading settings…</div>
          ) : (
            <>
              {/* Display Preferences */}
              <Section title="Display" icon={<IcoSun />}>
                <OptionGroup
                  label="Theme"
                  options={[
                    { value: "light", label: "☀ Light" },
                    { value: "dark", label: "🌙 Dark" },
                  ]}
                  value={prefs.theme}
                  onChange={set("theme")}
                />
                <OptionGroup
                  label="Rows per page"
                  options={ROWS_OPTIONS}
                  value={prefs.default_rows_per_page}
                  onChange={set("default_rows_per_page")}
                />
                <ToggleRow
                  id="sd-sidebar"
                  label="Collapsed sidebar by default"
                  hint="Start with the sidebar minimized"
                  checked={prefs.sidebar_collapsed}
                  onChange={set("sidebar_collapsed")}
                />
              </Section>

              <div className="sd-divider" />

              {/* Scan Defaults */}
              <Section title="Scan Defaults" icon={<IcoScan />}>
                <OptionGroup
                  label="Default scan type"
                  options={SCAN_TYPES}
                  value={prefs.default_scan_type}
                  onChange={set("default_scan_type")}
                />
              </Section>

              <div className="sd-divider" />

              {/* Notifications */}
              <Section title="Notifications" icon={<IcoBell />}>
                <ToggleRow
                  id="sd-email"
                  label="Email alerts"
                  hint="Receive scan results and alerts via email"
                  checked={prefs.email_alerts}
                  onChange={set("email_alerts")}
                />
                <ToggleRow
                  id="sd-inapp"
                  label="In-app notifications"
                  hint="Show notification badge in the header"
                  checked={prefs.in_app_alerts}
                  onChange={set("in_app_alerts")}
                />
              </Section>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="sd-footer">
          {saved && (
            <span className="sd-saved">
              <IcoCheck /> Saved
            </span>
          )}
          <button className="sd-btn sd-btn--ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            className="sd-btn sd-btn--primary"
            onClick={handleSave}
            disabled={saving || !prefs}
          >
            {saving ? "Saving…" : "Save Settings"}
          </button>
        </div>
      </aside>
    </>
  );
}
