import { useId, useRef } from "react";
import CcureModal from "../components/CcureModal";
import CcureButton from "../components/CcureButton";
import CcureAlert from "../components/CcureAlert";

/**
 * CcureConfirmDialog
 *
 * "Are you sure?" for an action that cannot be taken back.
 *
 * ── Why this is a pattern and not four call sites ───────────────────────────
 * Measured at the start of Checkpoint 3C batch 5, this application carried
 * **three** implementations of one dialog:
 *
 *   components/common/ConfirmDialog.jsx   shared, 6 consumers
 *   pages/RecycleBin.jsx                  a local copy
 *   pages/SecurityReports.jsx             a byte-identical second local copy
 *
 * and all three had the same gaps: focus was placed but never *trapped*, so a
 * Tab out of the dialog landed on the page behind it; focus was never restored
 * on close; and the dialog was labelled but never described, so a reader
 * announced the title and none of the warning explaining what was about to
 * happen. On a dialog whose confirm button purges a scan, deletes a tenant or
 * removes an account, that warning is the entire content.
 *
 * `CcureModal` already solves all three (`useFocusTrap` traps and restores;
 * `subtitle` wires `aria-describedby`). This pattern is that modal plus a
 * two-button footer and a warning region — composition of approved primitives,
 * not new architecture. It is filed under patterns/ rather than components/
 * because "confirm a destructive action" is a security-UI concept, the same
 * way CcureScanStatus is: the primitive answers *how a dialog behaves*, the
 * pattern answers *what this dialog is for*.
 *
 * ── Initial focus is Cancel, deliberately ───────────────────────────────────
 * All three legacy implementations focused the **confirm** button on open. A
 * dialog that opens with the destructive action focused turns a stray Enter —
 * from the keypress that opened it, or from a user who types ahead — into a
 * purge. The least-destructive control takes focus here, which is the standard
 * treatment for an irreversible confirmation and the only behavioural change
 * this pattern makes. `initialFocus="confirm"` restores the old placement for
 * a non-destructive confirmation where it is the sensible default.
 *
 * The dialog is deliberately NOT dismissible by clicking the overlay. Losing a
 * confirmation to a misplaced click is harmless; the habit it builds — that
 * clicking anywhere dismisses — is not, on a control set where the adjacent
 * dialog is a purge.
 */
export default function CcureConfirmDialog({
  open,
  title,
  subtitle,
  warning,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  /** "danger" for anything irreversible; "info" for a reversible change. */
  tone = "danger",
  busy = false,
  onConfirm,
  onCancel,
  initialFocus = "cancel",
  className = "",
}) {
  const warningId = useId();
  const cancelRef = useRef(null);
  const confirmRef = useRef(null);

  if (!open) return null;

  const confirmVariant = tone === "danger" ? "danger" : "primary";

  return (
    <CcureModal
      open={open}
      onClose={busy ? undefined : onCancel}
      title={title}
      subtitle={subtitle}
      size="sm"
      className={`cc-confirm ${className}`.trim()}
      /* A confirmation is a question. Dismissing it by clicking past it is how
         an operator ends up unsure whether the action ran. */
      closeOnOverlayClick={false}
      /* Escape still cancels — it is unambiguous, and it is the one dismissal
         users reach for. It is disabled while the action is in flight so a
         keypress cannot close the dialog over a request that is still running. */
      closeOnEscape={!busy}
      initialFocus={initialFocus === "confirm" ? confirmRef : cancelRef}
      footer={
        <>
          <CcureButton
            ref={cancelRef}
            variant="secondary"
            onClick={onCancel}
            disabled={busy}
          >
            {cancelLabel}
          </CcureButton>
          <CcureButton
            ref={confirmRef}
            variant={confirmVariant}
            onClick={onConfirm}
            loading={busy}
          >
            {confirmLabel}
          </CcureButton>
        </>
      }
    >
      {warning ? (
        /* `live={false}`: this is part of the dialog's initial content, not an
           event that happened afterwards. The dialog's own describedby is what
           gets it read out; announcing it a second time as an alert would
           interrupt that. */
        <CcureAlert
          id={warningId}
          variant={tone === "danger" ? "danger" : "warning"}
          live={false}
        >
          {warning}
        </CcureAlert>
      ) : null}
    </CcureModal>
  );
}
