/**
 * src/modules/audit/components/layout/SettingsDrawer.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Slide-in settings drawer with sections:
 *   • Display       – theme, date format, rows per page
 *   • Scan Defaults – default scan type, target discovery
 *   • Notifications – email and in-app alerts
 *
 * Checkpoint 3C batch 12: presentation moved onto the CCure design system.
 * The contract is unchanged: GET /user/preferences on open, PUT with the
 * whole preferences object on Save, `onPreferencesUpdated(response)` so
 * PreferencesContext applies the theme through `data-theme` exactly as
 * before. The drawer is a modal dialog now — it has a backdrop and blocks
 * the page, which is what `role="complementary"` never said — with a focus
 * trap, Escape, focus restoration (by the owner) and a named close control.
 * Option groups are radio groups, so the chosen theme is announced; the
 * toggles are labelled by their visible text, which they never were.
 */

import { useState, useEffect, useRef } from "react";
import { getPreferences, updatePreferences } from "@audit/api/user";
import {
  CcureAlert,
  CcureButton,
  useFocusTrap,
} from "../../../../design-system";

/* ── Icons (decorative) ──────────────────────────────────────────────────── */
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
    aria-hidden="true"
    focusable="false"
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
/* The input is named by the visible row label through aria-labelledby; the
   wrapping <label> used to be empty, so the checkbox had no name at all. */
function Toggle({ checked, onChange, id, labelledBy }) {
  return (
    <label className="shs-toggle" htmlFor={id}>
      <input
        id={id}
        type="checkbox"
        className="shs-toggle-input"
        checked={Boolean(checked)}
        aria-labelledby={labelledBy}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span className="shs-toggle-track" aria-hidden="true">
        <span className="shs-toggle-thumb" />
      </span>
    </label>
  );
}

/* ── Option select group ─────────────────────────────────────────────────── */
/* A radio group: one choice out of several, announced as such. */
function OptionGroup({ id, label, options, value, onChange }) {
  return (
    <div
      className="shs-option-group"
      role="radiogroup"
      aria-labelledby={`${id}-label`}
    >
      <div className="shs-label" id={`${id}-label`}>
        {label}
      </div>
      <div className="shs-options">
        {options.map((opt) => (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={value === opt.value}
            className={`shs-option ${value === opt.value ? "shs-option--active" : ""}`}
            onClick={() => onChange(opt.value)}
          >
            {opt.icon && (
              <span className="shs-option-icon" aria-hidden="true">
                {opt.icon}
              </span>
            )}
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
    <div className="shs-section">
      <div className="shs-section-header">
        <span className="shs-section-icon" aria-hidden="true">
          {icon}
        </span>
        <h3 className="shs-section-title">{title}</h3>
      </div>
      <div className="shs-section-body">{children}</div>
    </div>
  );
}

/* ── Row with toggle ─────────────────────────────────────────────────────── */
function ToggleRow({ id, label, hint, checked, onChange }) {
  return (
    <div className="shs-toggle-row">
      <div className="shs-toggle-info">
        <span className="shs-toggle-label" id={`${id}-label`}>
          {label}
        </span>
        {hint && <span className="shs-toggle-hint">{hint}</span>}
      </div>
      <Toggle
        id={id}
        labelledBy={`${id}-label`}
        checked={checked}
        onChange={onChange}
      />
    </div>
  );
}

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

/* ── Main ────────────────────────────────────────────────────────────────── */
export default function SettingsDrawer({
  id = "sh-settings",
  onClose,
  onPreferencesUpdated,
}) {
  const [prefs, setPrefs] = useState(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  const drawerRef = useRef(null);
  useFocusTrap(drawerRef, true);
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

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

  return (
    <>
      <div className="shs-backdrop" onClick={onClose} />
      <div
        className="shs-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="shs-title"
        id={id}
        ref={drawerRef}
        tabIndex={-1}
      >
        {/* Header */}
        <div className="shs-header">
          <div className="shs-header-left">
            <IcoScan />
            <h2 className="shs-title" id="shs-title">
              Settings
            </h2>
          </div>
          <button
            type="button"
            className="shs-close"
            onClick={onClose}
            aria-label="Close settings"
          >
            <IcoClose />
          </button>
        </div>

        {/* Body */}
        <div className="shs-body">
          {error && (
            <CcureAlert variant="danger" className="shs-error">
              {error}
            </CcureAlert>
          )}
          {!prefs ? (
            <div className="shs-loading" role="status">
              Loading settings…
            </div>
          ) : (
            <>
              {/* Display Preferences */}
              <Section title="Display" icon={<IcoSun />}>
                <OptionGroup
                  id="shs-theme"
                  label="Theme"
                  options={[
                    { value: "light", label: "☀ Light" },
                    { value: "dark", label: "🌙 Dark" },
                  ]}
                  value={prefs.theme}
                  onChange={set("theme")}
                />
                <OptionGroup
                  id="shs-rows"
                  label="Rows per page"
                  options={ROWS_OPTIONS}
                  value={prefs.default_rows_per_page}
                  onChange={set("default_rows_per_page")}
                />
                <ToggleRow
                  id="shs-sidebar"
                  label="Collapsed sidebar by default"
                  hint="Start with the sidebar minimized"
                  checked={prefs.sidebar_collapsed}
                  onChange={set("sidebar_collapsed")}
                />
              </Section>

              <div className="shs-divider" />

              {/* Scan Defaults */}
              <Section title="Scan Defaults" icon={<IcoScan />}>
                <OptionGroup
                  id="shs-scantype"
                  label="Default scan type"
                  options={SCAN_TYPES}
                  value={prefs.default_scan_type}
                  onChange={set("default_scan_type")}
                />
              </Section>

              <div className="shs-divider" />

              {/* Notifications */}
              <Section title="Notifications" icon={<IcoBell />}>
                <ToggleRow
                  id="shs-email"
                  label="Email alerts"
                  hint="Receive scan results and alerts via email"
                  checked={prefs.email_alerts}
                  onChange={set("email_alerts")}
                />
                <ToggleRow
                  id="shs-inapp"
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
        <div className="shs-footer">
          <span className="shs-saved" role="status" aria-live="polite">
            {saved && (
              <>
                <IcoCheck /> Saved
              </>
            )}
          </span>
          <CcureButton variant="ghost" size="sm" onClick={onClose}>
            Cancel
          </CcureButton>
          <CcureButton
            variant="primary"
            size="sm"
            onClick={handleSave}
            disabled={saving || !prefs}
          >
            {saving ? "Saving…" : "Save Settings"}
          </CcureButton>
        </div>
      </div>
    </>
  );
}
