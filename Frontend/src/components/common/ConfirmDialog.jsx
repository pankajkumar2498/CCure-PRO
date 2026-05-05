import { useEffect, useRef, useState } from "react";
import Button from "./Button";

export default function ConfirmDialog({
  open,
  title,
  subtitle,
  warning,
  confirmLabel = "Confirm",
  confirmType = "danger",
  icon = "⚠️",
  iconClass = "danger",
  onConfirm,
  onCancel,
}) {
  const [busy, setBusy] = useState(false);
  const confirmRef = useRef(null);

  useEffect(() => {
    if (open) {
      confirmRef.current?.focus();
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e) => {
      if (e.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onCancel]);

  if (!open) return null;

  const handleConfirm = async () => {
    setBusy(true);
    try {
      await onConfirm();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="confirm-overlay" onClick={(e) => e.target === e.currentTarget && onCancel()}>
      <div className="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="cdlg-title">
        <div className="confirm-dialog-header">
          <div className={`confirm-dialog-icon confirm-dialog-icon--${iconClass}`}>
            {icon}
          </div>
          <div className="confirm-dialog-titles">
            <div className="confirm-dialog-title" id="cdlg-title">{title}</div>
            <div className="confirm-dialog-subtitle">{subtitle}</div>
          </div>
        </div>

        {warning && <div className="confirm-dialog-warning">{warning}</div>}

        <div className="confirm-dialog-footer">
          <Button type="button" variant="ghost" size="sm" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button
            ref={confirmRef}
            type="button"
            variant={confirmType === "danger" ? "danger" : confirmType === "info" ? "info" : "primary"}
            size="sm"
            loading={busy}
            onClick={handleConfirm}
            disabled={busy}
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
