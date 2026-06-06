import Modal from "../layout/Modal";
import Button from "../common/Button";

export default function AuditLogDetailsModal({ isOpen, onClose, log }) {
  if (!isOpen || !log) return null;

  const renderChangesTable = (changes) => {
    if (!changes || Object.keys(changes).length === 0) {
      return <p className="muted" style={{ fontSize: 13 }}>No changes recorded.</p>;
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
                <td style={{ fontWeight: 600, fontSize: 13, color: "var(--text)" }}>{key}</td>
                <td style={{ fontSize: 13, color: "var(--text-muted)", fontFamily: "monospace" }}>
                  {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Audit log details">
      <section className="stack gap-16">
        <div className="detail-grid" style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "16px",
          background: "var(--surface-50)",
          padding: "16px",
          borderRadius: "8px",
          border: "1px solid var(--border)"
        }}>
          <div>
            <span className="meta-label">Event</span>
            <div style={{ fontWeight: 500, marginTop: 4 }}>{log._displayAction || log.action || "Unknown action"}</div>
          </div>
          <div>
            <span className="meta-label">User</span>
            <div style={{ fontWeight: 500, marginTop: 4 }}>{log._displayActor || log.user || "System"}</div>
          </div>
          <div>
            <span className="meta-label">Timestamp</span>
            <div style={{ fontWeight: 500, marginTop: 4 }}>{log._displayTime || (log.timestamp ? new Date(log.timestamp).toLocaleString() : "Invalid Date")}</div>
          </div>
          <div>
            <span className="meta-label">Target</span>
            <div style={{ fontWeight: 500, marginTop: 4 }}>{log._displayTarget || log.target || "n/a"}</div>
          </div>
        </div>

        <div className="section-card">
          <p className="meta-label" style={{ marginBottom: 8 }}>Change details</p>
          {renderChangesTable(log.details || log.changes || log.payload || {})}
        </div>

        <div className="modal-actions" style={{ display: "flex", justifyContent: "flex-end", marginTop: 16 }}>
          <Button type="button" variant="ghost" onClick={onClose}>
            Close
          </Button>
        </div>
      </section>
    </Modal>
  );
}
