/**
 * components/admin/AuditLogDetailsModal.jsx — Checkpoint 3C batch 13.
 *
 * The full-event dialog AuditLogs opens from a row. Same props (`isOpen`,
 * `onClose`, `log`, `loading`), same parsing and masking: `password_hash`
 * and `password` values are never rendered, an `{old, new}` pair is shown as
 * a transition, ISO timestamps are localised.
 *
 * On CcureModal (portalled, `aria-modal`, focus trap and restoration, Escape,
 * a described title) with the changes in a captioned CcureTable. The
 * twenty-three inline style objects and the five severity hex literals are
 * gone: severity is a CcureSeverityBadge and everything else is a token.
 */
import {
  CcureButton,
  CcureModal,
  CcureSeverityBadge,
  CcureTable,
} from "../../../design-system";
import "../styles/audit-log-details.css";

// The User-Agent is client-supplied and the parse is approximate, so this is
// a reading aid rather than evidence — the raw string stays available below.
const parseUserAgent = (ua) => {
  if (!ua) return { browser: "Unknown", os: "Unknown", device: "Unknown" };
  const s = String(ua);
  let os = "Unknown";
  if (s.includes("Windows NT 10.0")) os = "Windows 10/11";
  else if (s.includes("Windows NT 6.3")) os = "Windows 8.1";
  else if (s.includes("Windows NT 6.1")) os = "Windows 7";
  else if (s.includes("Android")) os = "Android";
  else if (s.includes("iPhone") || s.includes("iPad")) os = "iOS";
  else if (s.includes("Macintosh") || s.includes("Mac OS")) os = "macOS";
  else if (s.includes("Linux")) os = "Linux";

  let browser = "Unknown";
  if (s.includes("Edg/")) browser = "Edge";
  else if (s.includes("Firefox/")) browser = "Firefox";
  else if (s.includes("Chrome/") && s.includes("Safari/")) browser = "Chrome";
  else if (s.includes("Safari/") && !s.includes("Chrome/")) browser = "Safari";
  else if (s.includes("curl/")) browser = "curl";
  else if (s.includes("python-requests")) browser = "python-requests";

  let device = "Desktop";
  if (s.includes("iPad") || s.includes("Tablet")) device = "Tablet";
  else if (s.includes("Mobile") || s.includes("iPhone")) device = "Mobile";
  else if (browser === "curl" || browser === "python-requests")
    device = "API client";

  return { browser, os, device };
};

const FIELD_NAMES = {
  is_active: "Account Status",
  is_deleted: "Suspension Status",
  deleted_at: "Suspended At",
  locked_until: "Temporary Lockout",
  role_id: "Role ID",
  email: "Email Address",
  full_name: "Full Name",
  password_hash: "Password",
  mfa_enabled: "MFA Status",
  totp_secret: "MFA Secret Key",
  mfa_backup_codes: "MFA Backup Codes",
  org_id: "Organization ID",
  failed_login_count: "Failed Login Count",
};

const getFriendlyField = (key) => {
  if (FIELD_NAMES[key]) return FIELD_NAMES[key];
  // Fallback: title case the key
  return key.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
};

const formatSingleValue = (k, v) => {
  if (v === null || v === undefined || v === "None") return "None";
  if (k === "password_hash" || k === "password") return "••••••••";

  if (typeof v === "boolean") {
    if (k === "is_active") return v ? "Enabled" : "Disabled";
    if (k === "is_deleted") return v ? "Suspended" : "Active";
    if (k === "mfa_enabled") return v ? "Enabled" : "Disabled";
    return v ? "Enabled" : "Disabled";
  }

  // Check if it is a UTC ISO datetime string
  if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(v)) {
    try {
      return new Date(v).toLocaleString();
    } catch {
      return v;
    }
  }
  return String(v);
};

const getFriendlyValue = (key, val) => {
  if (val && typeof val === "object" && "old" in val && "new" in val) {
    const oldDisplay = formatSingleValue(key, val.old);
    const newDisplay = formatSingleValue(key, val.new);
    return `${oldDisplay} ➔ ${newDisplay}`;
  }
  if (typeof val === "object") {
    return JSON.stringify(val);
  }
  return formatSingleValue(key, val);
};

const CHANGE_COLUMNS = [
  { key: "field", header: "Field", isRowHeader: true },
  { key: "value", header: "Value" },
];

function Field({ label, children, title, span = false, mono = false }) {
  return (
    <div className={`ald-field${span ? " ald-field--span" : ""}`}>
      <dt className="ald-label" title={title}>
        {label}
      </dt>
      <dd className={`ald-value${mono ? " ald-mono" : ""}`}>{children}</dd>
    </div>
  );
}

export default function AuditLogDetailsModal({
  isOpen,
  onClose,
  log,
  loading = false,
}) {
  if (!isOpen || !log) return null;

  const agent = parseUserAgent(log.user_agent);
  const changes = log.details || log.changes || log.payload || {};
  const changeRows = Object.entries(changes).map(([key, value]) => ({
    key,
    field: getFriendlyField(key),
    value: getFriendlyValue(key, value),
  }));
  const severity = String(log.severity || "").toLowerCase();

  return (
    <CcureModal
      open={isOpen}
      onClose={onClose}
      title="Audit log details"
      size="md"
      className="ald-modal"
      footer={
        <CcureButton variant="secondary" onClick={onClose}>
          Close
        </CcureButton>
      }
    >
      <dl className="ald-grid">
        <Field label="Audit Event ID" span mono>
          {log.id || "—"}
        </Field>
        <Field label="Event">
          {log._displayAction || log.action || "Unknown action"}
        </Field>
        <Field label="User">{log._displayActor || log.user || "System"}</Field>
        <Field label="Timestamp">
          {log._displayTime ||
            (log.timestamp
              ? new Date(log.timestamp).toLocaleString()
              : "Invalid Date")}
        </Field>
        <Field label="Target">
          {log._displayTarget || log.target || "n/a"}
        </Field>
        <Field label="Severity">
          {severity ? <CcureSeverityBadge severity={severity} /> : "—"}
        </Field>
        <Field label="Status">
          <span
            className={`ald-status ald-status--${log.status === "success" ? "ok" : "fail"}`}
          >
            {String(log.status || "—").toUpperCase()}
          </span>
        </Field>
        <Field
          label="Request ID"
          title="Correlates this event with the API request and application logs"
          mono
        >
          {log.request_id || "—"}
        </Field>
        <Field label="Session ID" mono>
          {log.session_id !== undefined && log.session_id !== null
            ? String(log.session_id)
            : "—"}
        </Field>
        <Field label="Source IP" mono>
          {log.ip_address || "—"}
        </Field>
        <Field label="Timezone">
          {log.timezone || "UTC"}
          <span className="ald-note"> (stored)</span>
        </Field>
        <Field label="Browser">{agent.browser}</Field>
        <Field label="Operating System">{agent.os}</Field>
        <Field label="Device">{agent.device}</Field>
        {log.user_email && <Field label="Email">{log.user_email}</Field>}
        {log.user_agent && (
          <Field
            label="User-Agent (raw)"
            span
            mono
            title="Client-supplied; a memory aid, never evidence"
          >
            {log.user_agent}
          </Field>
        )}
      </dl>

      {loading && (
        <p className="ald-loading" role="status">
          Loading full event details…
        </p>
      )}

      <section className="ald-changes" aria-labelledby="ald-changes-title">
        <h3 className="ald-changes__title" id="ald-changes-title">
          Change details
        </h3>
        {changeRows.length === 0 ? (
          <p className="ald-note">No changes recorded.</p>
        ) : (
          <CcureTable
            caption="Fields changed by this event"
            columns={CHANGE_COLUMNS}
            rows={changeRows}
            rowKey={(row) => row.key}
            density="compact"
            hoverable={false}
          />
        )}
      </section>
    </CcureModal>
  );
}
