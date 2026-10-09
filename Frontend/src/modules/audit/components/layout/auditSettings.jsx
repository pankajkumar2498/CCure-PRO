/**
 * src/modules/audit/components/layout/auditSettings.jsx — Audit's own section
 * of the shared settings drawer.
 * ─────────────────────────────────────────────────────────────────────────────
 * The drawer and the platform preferences (theme, rows per page, sidebar,
 * notification channels) are the shell's; "Scan Defaults" is Audit's. It is
 * passed to `SettingsDrawer` as `productSettings` and renders between the
 * platform's Display and Notifications sections, exactly where it always has.
 */
import {
  SettingsIcon,
  SettingsOptionGroup,
  SettingsSection,
} from "@shell/account/SettingsDrawer";

const SCAN_TYPES = [
  { value: "host-discovery", label: "Host Discovery" },
  { value: "asset", label: "Asset Scan" },
  { value: "vulnerability_audit", label: "Vulnerability Audit" },
  { value: "credentialed", label: "Credentialed" },
];

const IcoScan = () => (
  <SettingsIcon d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2" />
);

// Audit's preferences live in its own block, `prefs.products.audit`. The flat
// `default_scan_type` is what the API returned before the block existed, and it
// is still returned beside it, so it is the fallback for a response without one.
const AUDIT = "audit";

export default function renderAuditSettings(prefs, set, setProduct) {
  const value =
    prefs.products?.[AUDIT]?.default_scan_type ?? prefs.default_scan_type;
  // Against a shell that does not pass `setProduct`, write the flat key as before.
  const onChange = setProduct
    ? setProduct(AUDIT, "default_scan_type")
    : set("default_scan_type");
  return (
    <SettingsSection title="Scan Defaults" icon={<IcoScan />}>
      <SettingsOptionGroup
        id="shs-scantype"
        label="Default scan type"
        options={SCAN_TYPES}
        value={value}
        onChange={onChange}
      />
    </SettingsSection>
  );
}
