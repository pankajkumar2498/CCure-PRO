import Modal from "../layout/Modal";
import Button from "../common/Button";

export default function AuditLogDetailsModal({ isOpen, onClose, log }) {
  if (!isOpen || !log) return null;

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
        </div>

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
