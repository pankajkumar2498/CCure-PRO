/**
 * src/shell/account/SettingsDrawer.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Slide-in settings drawer with sections:
 *   • Display       – rows per page, sidebar
 *   • Scan Defaults – default scan type, target discovery
 *   • Notifications – email and in-app alerts
 *
 * Checkpoint 3C batch 12: presentation moved onto the CCure design system.
 * The contract is unchanged: GET /user/preferences on open, PUT with the
 * drawer preferences on Save (theme is owned by the header), `onPreferencesUpdated(response)` so
 * PreferencesContext applies the theme through `data-theme` exactly as
 * before. The drawer is a modal dialog now — it has a backdrop and blocks
 * the page, which is what `role="complementary"` never said — with a focus
 * trap, Escape, focus restoration (by the owner) and a named close control.
 * Option groups are radio groups, so the chosen option is announced; the
 * toggles are labelled by their visible text, which they never were.
 */

import { useState, useEffect, useRef } from "react";
import { getPreferences, updatePreferences } from "../api/user";
import {
  CcureAlert,
  CcureButton,
  CcureDrawer,
  CcureLoader,
  CcureRadio,
  CcureSwitch,
} from "../../design-system";
import "./settings-drawer.css";

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

const IcoCheck = () => <Icon d="M20 6L9 17l-5-5" />;
const IcoSun = () => (
  <Icon d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z" />
);
const IcoBell = () => (
  <Icon d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 0 1-3.46 0" />
);

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
          <CcureRadio
            key={opt.value}
            name={id}
            value={opt.value}
            checked={value === opt.value}
            onChange={() => onChange(opt.value)}
          >
            {opt.icon && (
              <span className="shs-option-icon" aria-hidden="true">
                {opt.icon}
              </span>
            )}
            {opt.label}
          </CcureRadio>
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
        {hint && (
          <span className="shs-toggle-hint" id={`${id}-hint`}>
            {hint}
          </span>
        )}
      </div>
      <CcureSwitch
        id={id}
        aria-labelledby={`${id}-label`}
        aria-describedby={hint ? `${id}-hint` : undefined}
        checked={Boolean(checked)}
        onChange={(event) => onChange(event.target.checked)}
      />
    </div>
  );
}

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
  // A product's own settings, rendered between the platform's Display and
  // Notifications sections: `(prefs, set, setProduct) => sections`. They are
  // stored in the same preferences document and saved with the rest. `set(key)`
  // sets a platform preference; `setProduct(namespace, key)` sets one in the
  // product's own block (`prefs.products[namespace]`), which the platform stores
  // without reading.
  productSettings,
}) {
  const [prefs, setPrefs] = useState(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  const savedTimer = useRef(null);
  useEffect(() => () => clearTimeout(savedTimer.current), []);

  useEffect(() => {
    getPreferences()
      .then(setPrefs)
      .catch(() => setError("Failed to load preferences"));
  }, []);

  const set = (key) => (val) => {
    setPrefs((p) => ({ ...p, [key]: val }));
    setSaved(false);
  };

  const setProduct = (namespace, key) => (val) => {
    setPrefs((p) => ({
      ...p,
      products: {
        ...p.products,
        [namespace]: { ...p.products?.[namespace], [key]: val },
      },
    }));
    setSaved(false);
  };

  const handleSave = async () => {
    setSaving(true);
    setError("");
    setSaved(false);
    try {
      const drawerPreferences = { ...prefs };
      delete drawerPreferences.theme;
      const updated = await updatePreferences(drawerPreferences);
      setPrefs(updated);
      setSaved(true);
      if (onPreferencesUpdated) onPreferencesUpdated(updated);
      clearTimeout(savedTimer.current);
      savedTimer.current = setTimeout(() => setSaved(false), 3000);
    } catch (e) {
      setError(e.response?.data?.detail || "Failed to save settings");
    } finally {
      setSaving(false);
    }
  };

  return (
    <CcureDrawer
      open
      id={id}
      title="Settings"
      onClose={onClose}
      closeLabel="Close settings"
      className="shs-drawer"
      footer={
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
      }
    >
      {/* Body */}
      <div className="shs-body">
        {error && (
          <CcureAlert variant="danger" className="shs-error">
            {error}
          </CcureAlert>
        )}
        {!prefs ? (
          <CcureLoader label="Loading settings…" size="sm" />
        ) : (
          <>
            {/* Display Preferences */}
            <Section title="Display" icon={<IcoSun />}>
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

            {productSettings ? (
              <>
                {productSettings(prefs, set, setProduct)}

                <div className="shs-divider" />
              </>
            ) : null}

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
    </CcureDrawer>
  );
}
/* The building blocks a product's own settings section is made of, so it
   renders exactly like the platform's. */
export {
  Icon as SettingsIcon,
  Section as SettingsSection,
  OptionGroup as SettingsOptionGroup,
  ToggleRow as SettingsToggleRow,
};
