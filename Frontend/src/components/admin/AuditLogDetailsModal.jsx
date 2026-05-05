import Modal from "../layout/Modal";
import Button from "../common/Button";

export default function AuditLogDetailsModal({ isOpen, onClose, log }) {
  if (!isOpen || !log) return null;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Audit log details">
      <section className="stack gap-16">
        <div className="detail-grid">
          <div>
            <span className="meta-label">Event</span>
            <p>{log.action || "Unknown action"}</p>
          </div>
          <div>
            <span className="meta-label">Actor</span>
            <p>{log.user || "System"}</p>
          </div>
          <div>
            <span className="meta-label">When</span>
            <p>{new Date(log.timestamp).toLocaleString()}</p>
          </div>
          <div>
            <span className="meta-label">Target</span>
            <p>{log.target || "n/a"}</p>
          </div>
        </div>

        <div className="section-card">
          <p className="meta-label">Change details</p>
          <pre className="code-block">{JSON.stringify(log.details || log.changes || log.payload || {}, null, 2)}</pre>
        </div>

        <div className="modal-actions">
          <Button type="button" variant="ghost" onClick={onClose}>
            Close
          </Button>
        </div>
      </section>
    </Modal>
  );
}
