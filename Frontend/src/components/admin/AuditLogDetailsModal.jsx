import Modal from "../layout/Modal";
import Button from "../common/Button";

export default function AuditLogDetailsModal({
  isOpen,
  onClose,
  log,
  loading = false,
}) {
  if (!isOpen || !log) return null;

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
    else if (s.includes("Safari/") && !s.includes("Chrome/"))
      browser = "Safari";
    else if (s.includes("curl/")) browser = "curl";
    else if (s.includes("python-requests")) browser = "python-requests";

    let device = "Desktop";
    if (s.includes("iPad") || s.includes("Tablet")) device = "Tablet";
    else if (s.includes("Mobile") || s.includes("iPhone")) device = "Mobile";
    else if (browser === "curl" || browser === "python-requests")
      device = "API client";

    return { browser, os, device };
  };

  const agent = parseUserAgent(log.user_agent);

  const SEVERITY_COLORS = {
    critical: "#f87171",
    high: "#fb923c",
    medium: "#fbbf24",
    low: "#60a5fa",
    info: "#9ca3af",
  };

  const mono = {
    fontFamily: "monospace",
    fontSize: 12,
    marginTop: 4,
    wordBreak: "break-all",
    userSelect: "all",
  };

  const Field = ({ label, children, title, span }) => (
    <div style={span ? { gridColumn: "1 / -1" } : undefined}>
      <span className="meta-label" title={title}>
        {label}
      </span>
      {children}
    </div>
  );

  const getFriendlyField = (key) => {
    const mapping = {
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
    if (mapping[key]) return mapping[key];

    // Fallback: title case the key
    return key
      .replace(/_/g, " ")
      .replace(/\b\w/g, (char) => char.toUpperCase());
  };

  const getFriendlyValue = (key, val) => {
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
      if (
        typeof v === "string" &&
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(v)
      ) {
        try {
          return new Date(v).toLocaleString();
        } catch {
          return v;
        }
      }
      return String(v);
    };

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

  const renderChangesTable = (changes) => {
    if (!changes || Object.keys(changes).length === 0) {
      return (
        <p className="muted" style={{ fontSize: 13 }}>
          No changes recorded.
        </p>
      );
    }

    return (
      <div className="table-wrap">
        <table className="data-table" style={{ marginTop: 8 }}>
          <thead>
            <tr>
              <th>Field</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(changes).map(([key, value]) => (
              <tr key={key}>
                <td
                  style={{
                    fontWeight: 600,
                    fontSize: 13,
                    color: "var(--text)",
                  }}
                >
                  {getFriendlyField(key)}
                </td>
                <td style={{ fontSize: 13, color: "var(--text-muted)" }}>
                  {getFriendlyValue(key, value)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Audit log details"
      size="medium"
    >
      <section className="stack gap-16">
        <div
          className="detail-grid"
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "16px",
            background: "var(--surface-50)",
            padding: "16px",
            borderRadius: "8px",
            border: "1px solid var(--border)",
          }}
        >
          <div style={{ gridColumn: "1 / -1" }}>
            <span className="meta-label">Audit Event ID</span>
            <div
              style={{
                fontFamily: "monospace",
                fontSize: 12,
                marginTop: 4,
                wordBreak: "break-all",
                userSelect: "all",
              }}
            >
              {log.id || "—"}
            </div>
          </div>
          <div>
            <span className="meta-label">Event</span>
            <div style={{ fontWeight: 500, marginTop: 4 }}>
              {log._displayAction || log.action || "Unknown action"}
            </div>
          </div>
          <div>
            <span className="meta-label">User</span>
            <div style={{ fontWeight: 500, marginTop: 4 }}>
              {log._displayActor || log.user || "System"}
            </div>
          </div>
          <div>
            <span className="meta-label">Timestamp</span>
            <div style={{ fontWeight: 500, marginTop: 4 }}>
              {log._displayTime ||
                (log.timestamp
                  ? new Date(log.timestamp).toLocaleString()
                  : "Invalid Date")}
            </div>
          </div>
          <div>
            <span className="meta-label">Target</span>
            <div style={{ fontWeight: 500, marginTop: 4 }}>
              {log._displayTarget || log.target || "n/a"}
            </div>
          </div>
          <Field label="Severity">
            <div
              style={{
                fontWeight: 700,
                marginTop: 4,
                textTransform: "uppercase",
                fontSize: 12,
                letterSpacing: "0.04em",
                color:
                  SEVERITY_COLORS[String(log.severity || "").toLowerCase()] ||
                  "var(--text)",
              }}
            >
              {log.severity || "—"}
            </div>
          </Field>

          <Field label="Status">
            <div
              style={{
                fontWeight: 600,
                marginTop: 4,
                fontSize: 13,
                color: log.status === "success" ? "var(--ok)" : "var(--danger)",
              }}
            >
              {String(log.status || "—").toUpperCase()}
            </div>
          </Field>

          <Field
            label="Request ID"
            title="Correlates this event with the API request and application logs"
          >
            <div style={mono}>{log.request_id || "—"}</div>
          </Field>

          <Field label="Session ID">
            <div style={mono}>
              {log.session_id !== undefined && log.session_id !== null
                ? String(log.session_id)
                : "—"}
            </div>
          </Field>

          <Field label="Source IP">
            <div style={mono}>{log.ip_address || "—"}</div>
          </Field>

          <Field label="Timezone">
            <div style={{ fontWeight: 500, marginTop: 4 }}>
              {log.timezone || "UTC"}
              <span
                style={{
                  color: "var(--text-faint)",
                  fontSize: 11,
                  marginLeft: 6,
                }}
              >
                (stored)
              </span>
            </div>
          </Field>

          <Field label="Browser">
            <div style={{ fontWeight: 500, marginTop: 4 }}>{agent.browser}</div>
          </Field>

          <Field label="Operating System">
            <div style={{ fontWeight: 500, marginTop: 4 }}>{agent.os}</div>
          </Field>

          <Field label="Device">
            <div style={{ fontWeight: 500, marginTop: 4 }}>{agent.device}</div>
          </Field>

          {log.user_email && (
            <Field label="Email">
              <div style={{ fontWeight: 500, marginTop: 4, fontSize: 13 }}>
                {log.user_email}
              </div>
            </Field>
          )}

          {log.user_agent && (
            <Field
              label="User-Agent (raw)"
              span
              title="Client-supplied; a memory aid, never evidence"
            >
              <div
                style={{ ...mono, fontSize: 11, color: "var(--text-faint)" }}
              >
                {log.user_agent}
              </div>
            </Field>
          )}
        </div>

        {loading && (
          <p
            className="muted"
            style={{ fontSize: 12, margin: 0, color: "var(--text-faint)" }}
          >
            Loading full event details…
          </p>
        )}

        <div className="section-card">
          <p className="meta-label" style={{ marginBottom: 8 }}>
            Change details
          </p>
          {renderChangesTable(log.details || log.changes || log.payload || {})}
        </div>

        <div
          className="modal-actions"
          style={{ display: "flex", justifyContent: "flex-end", marginTop: 16 }}
        >
          <Button type="button" variant="ghost" onClick={onClose}>
            Close
          </Button>
        </div>
      </section>
    </Modal>
  );
}
