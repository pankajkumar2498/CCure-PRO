import { useCallback, useEffect, useId, useRef } from "react";
import { createPortal } from "react-dom";
import useModalEnvironment from "../hooks/useModalEnvironment";
import CcureIconButton from "./CcureIconButton";
import useFocusTrap, { isTopTrap } from "../hooks/useFocusTrap";

/**
 * CcureModal
 *
 * Replaces the pattern in `components/layout/Modal.jsx`, which Phase 0 recorded
 * as carrying no `role="dialog"`, no `aria-modal` and no focus trap — while
 * being the overlay used by the larger surfaces. `ConfirmDialog` had the
 * attributes; `Modal` did not; both existed side by side.
 *
 * What this adds over that component:
 *
 *   * `role="dialog"` + `aria-modal="true"`
 *   * an accessible name, wired from the title or an explicit `aria-label`
 *   * a real focus trap with focus restoration (see useFocusTrap)
 *   * Escape to close, at the dialog rather than the window
 *   * `aria-hidden` on the rest of the app while open
 *   * a portal, so the dialog is not clipped by an ancestor's overflow
 *
 * ── On rendering into a portal ──────────────────────────────────────────────
 * The old modal rendered in place. Any ancestor with `overflow: hidden` or a
 * `transform` then clips or re-anchors a `position: fixed` child, which is why
 * dialogs opened from inside scrollable tables misbehave. A portal to <body>
 * removes the entire class of problem.
 */
export default function CcureModal({
  open,
  onClose,
  title,
  subtitle,
  size = "md",
  footer,
  children,
  closeLabel = "Close dialog",
  closeOnOverlayClick = true,
  closeOnEscape = true,
  initialFocus,
  "aria-label": ariaLabel,
  className = "",
  placement = "center",
  id,
}) {
  const dialogRef = useRef(null);
  const titleId = useId();
  const subtitleId = useId();

  useFocusTrap(dialogRef, open, { initialFocus });
  useModalEnvironment(dialogRef, open);

  // Escape is handled here rather than in the trap because whether a dialog may
  // be dismissed is the owner's decision — a destructive confirmation may
  // legitimately require an explicit choice.
  useEffect(() => {
    if (!open || !closeOnEscape) return undefined;
    const onKey = (e) => {
      if (e.key === "Escape" && isTopTrap(dialogRef.current)) {
        e.preventDefault();
        e.stopImmediatePropagation();
        onClose?.();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, closeOnEscape, onClose]);

  /**
   * Scroll lock, refcounted through a data attribute.
   *
   * The naive version writes `body.style.overflow = "hidden"` on open and
   * `""` on close. With two dialogs open — a confirmation raised from inside a
   * form dialog, which this application does — closing the inner one unlocks
   * the page while the outer is still open, and the background scrolls behind
   * it. Counting means the lock lifts only when the last dialog closes.
   */
  useEffect(() => {
    if (!open) return undefined;
    const body = document.body;
    const depth = Number(body.dataset.ccModalDepth || 0) + 1;
    body.dataset.ccModalDepth = String(depth);
    if (depth === 1) {
      body.dataset.ccScrollLock = body.style.overflow || "";
      body.style.overflow = "hidden";
    }
    return () => {
      const next = Number(body.dataset.ccModalDepth || 1) - 1;
      if (next <= 0) {
        delete body.dataset.ccModalDepth;
        body.style.overflow = body.dataset.ccScrollLock || "";
        delete body.dataset.ccScrollLock;
      } else {
        body.dataset.ccModalDepth = String(next);
      }
    };
  }, [open]);

  const onOverlayMouseDown = useCallback(
    (e) => {
      // mousedown, and only when it both starts and ends on the overlay.
      // Using click meant a drag that began inside the dialog — selecting text
      // in a field and releasing outside — closed the dialog and discarded the
      // user's input.
      if (!closeOnOverlayClick || !isTopTrap(dialogRef.current)) return;
      if (e.target !== e.currentTarget) return;
      const overlay = e.currentTarget;
      const onUp = (up) => {
        if (up.target === overlay) onClose?.();
        document.removeEventListener("mouseup", onUp);
      };
      document.addEventListener("mouseup", onUp);
    },
    [closeOnOverlayClick, onClose],
  );

  if (!open) return null;

  const labelledBy = title ? titleId : undefined;

  return createPortal(
    <div
      className={`cc-modal__overlay cc-ux4g ux4g-modal-backdrop ux4g-modal-backdrop-50 ${placement !== "center" ? "cc-drawer-overlay" : ""}`}
      onMouseDown={onOverlayMouseDown}
    >
      <div
        ref={dialogRef}
        id={id}
        role="dialog"
        aria-modal="true"
        /* Exactly one naming route. A dialog with neither is announced as
           "dialog" and nothing else. */
        aria-labelledby={labelledBy}
        aria-label={!title ? ariaLabel : undefined}
        aria-describedby={subtitle ? subtitleId : undefined}
        /* Lets the trap park focus on the container when the dialog holds no
           focusable child at all. Not in the tab order — it is -1. */
        tabIndex={-1}
        className={`cc-modal cc-ux4g ux4g-modal-box ux4g-modal-${{ sm: "s", md: "m", lg: "l", xl: "l" }[size] || "m"} cc-modal--${size} ${placement !== "center" ? `cc-drawer ux4g-drawer ux4g-drawer-${placement} ux4g-drawer-open` : ""} ${className}`.trim()}
      >
        {(title || onClose) && (
          <div
            className={`cc-modal__header ${placement !== "center" ? "ux4g-drawer-header" : "ux4g-modal-header"}`}
          >
            <div>
              {title ? (
                <h2
                  className={`cc-modal__title ${placement !== "center" ? "ux4g-drawer-title" : "ux4g-modal-header-title"}`}
                  id={titleId}
                >
                  {title}
                </h2>
              ) : null}
              {subtitle ? (
                <p
                  className="cc-modal__subtitle ux4g-modal-header-sub-heading"
                  id={subtitleId}
                >
                  {subtitle}
                </p>
              ) : null}
            </div>
            {onClose ? (
              <CcureIconButton
                className="cc-modal__close"
                onClick={onClose}
                aria-label={closeLabel}
              >
                <span aria-hidden="true">×</span>
              </CcureIconButton>
            ) : null}
          </div>
        )}

        <div
          className={`cc-modal__body ${placement !== "center" ? "ux4g-drawer-body" : "ux4g-modal-body"}`}
        >
          {children}
        </div>

        {footer ? (
          <div className="cc-modal__footer ux4g-modal-actions">{footer}</div>
        ) : null}
      </div>
    </div>,
    document.body,
  );
}
