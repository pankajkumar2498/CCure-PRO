/**
 * src/components/layout/Modal.jsx
 *
 * Reusable modal component for overlays.
 * Props:
 *   isOpen     — boolean to show/hide
 *   onClose    — function to close modal
 *   children   — modal content
 */
import { useEffect } from "react";

export default function Modal({ isOpen, onClose, title = "", subtitle = "", size = "large", children }) {
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
      <div className={`modal-panel modal-panel--${size}`} onClick={(e) => e.stopPropagation()}>
        <div className="modal-panel-header">
          <div>
            {title && <h2 className="modal-panel-title">{title}</h2>}
            {subtitle && <p className="modal-panel-subtitle">{subtitle}</p>}
          </div>
          <button className="modal-panel-close" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-panel-body">
          {children}
        </div>
      </div>
    </div>
  );
}