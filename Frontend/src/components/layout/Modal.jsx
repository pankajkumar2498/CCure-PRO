/**
 * src/components/layout/Modal.jsx
 *
 * Reusable modal component for overlays.
 * Props:
 *   isOpen     — boolean to show/hide
 *   onClose    — function to close modal
 *   children   — modal content
 *
 * Checkpoint 3C batch 12 — the minimal accessibility shim for the legacy
 * modal's remaining consumers (OrganizationManagement, AuditLogDetailsModal,
 * UserManagement, Phase3Results, NetworkMap, ComplianceWorkspace): the panel
 * is a `role="dialog"` with `aria-modal`, named by its title, with the
 * design system's focus trap (contains Tab, restores focus on close). Escape
 * and overlay-click closing are unchanged; the visual styling is unchanged.
 */
import { useEffect, useId, useRef } from "react";
import { useFocusTrap } from "../../design-system";

export default function Modal({
  isOpen,
  onClose,
  title = "",
  subtitle = "",
  size = "large",
  children,
}) {
  const panelRef = useRef(null);
  const titleId = useId();
  useFocusTrap(panelRef, Boolean(isOpen));

  useEffect(() => {
    const handleEsc = (e) => {
      if (e.key === "Escape") onClose();
    };
    if (isOpen) {
      document.addEventListener("keydown", handleEsc);
      document.body.style.overflow = "hidden"; // Prevent scroll
    }
    return () => {
      document.removeEventListener("keydown", handleEsc);
      document.body.style.overflow = "unset";
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className={`modal-panel modal-panel--${size}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? titleId : undefined}
        aria-label={!title ? "Dialog" : undefined}
        ref={panelRef}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-panel-header">
          <div>
            {title && (
              <h2 className="modal-panel-title" id={titleId}>
                {title}
              </h2>
            )}
            {subtitle && <p className="modal-panel-subtitle">{subtitle}</p>}
          </div>
          <button
            type="button"
            className="modal-panel-close"
            onClick={onClose}
            aria-label="Close"
          >
            ×
          </button>
        </div>
        <div className="modal-panel-body">{children}</div>
      </div>
    </div>
  );
}
