/**
 * src/modules/audit/config/notificationPresentation.js — how Audit's
 * notifications look in the shared notification panel.
 * ─────────────────────────────────────────────────────────────────────────────
 * The types and the `scan` category are the ones Audit raises
 * (`Backend/scans/notification_vocabulary.py`). The shell's panel does not know
 * them: the composition root passes this to `NotificationPresentationProvider`.
 * Moved here from the shell's panel with its values unchanged; B.13 replaced
 * each emoji with the CcureIcon of the same meaning.
 */
export const AUDIT_NOTIFICATION_TYPES = {
  scan_completed: { icon: "check-circle", tone: "success" },
  scan_failed: { icon: "x-circle", tone: "danger" },
  scan_paused: { icon: "pause-circle", tone: "warning" },
  vulnerability_found: { icon: "alert-octagon", tone: "danger" },
};

export const AUDIT_NOTIFICATION_CATEGORIES = [{ id: "scan", label: "Scans" }];
