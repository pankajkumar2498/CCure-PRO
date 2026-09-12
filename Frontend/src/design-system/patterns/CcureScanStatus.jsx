import CcureBadge from "../components/CcureBadge";

/**
 * CcureScanStatus
 *
 * The canonical rendering of a scan's lifecycle state.
 *
 * ── Why this exists ─────────────────────────────────────────────────────────
 * Three implementations of the same concept were found, using three different
 * mechanisms:
 *
 *   ScanHistory.jsx      STATUS_STYLE (inline hex) + STATUS_LABELS
 *   ArchivedScans.jsx    STATUS_STYLE (near-identical hex) + local StatusBadge
 *   SecurityDashboard    local ScanStatus() using db-status--* CSS classes
 *
 * ── The defect this fixes ───────────────────────────────────────────────────
 * `ArchivedScans.jsx` falls back to the **running** style for any status it
 * does not recognise:
 *
 *     const s = STATUS_STYLE[status] || STATUS_STYLE.running;
 *
 * An unrecognised status therefore displays as a scan in progress. That is not
 * a cosmetic default — it is a false statement about a scan, on a page whose
 * entire job is to report what happened. An unknown status here renders as
 * "Unknown", neutral, and says so.
 *
 * ── The vocabulary is the application's ─────────────────────────────────────
 * Taken from `ScanHistory.jsx`, which carries the most complete map, plus the
 * two states the dashboard adds. Both spellings of the completed and cancelled
 * states are carried because the API returns both — dropping either would
 * silently render real scans as unknown.
 */

const STATUSES = {
  // Terminal, successful
  complete: { label: "Completed", variant: "success" },
  completed: { label: "Completed", variant: "success" },

  // In flight
  running: { label: "Running", variant: "warning", live: true },
  queued: { label: "Queued", variant: "info" },
  pending: { label: "Pending", variant: "info" },

  // Terminal, unsuccessful. `unreachable` is distinct from `failed` on
  // purpose: "the scanner broke" and "the host never answered" send an
  // operator to different places.
  failed: { label: "Failed", variant: "danger" },
  unreachable: { label: "Host Unreachable", variant: "danger" },

  // Terminal, deliberate
  cancelled: { label: "Cancelled", variant: "neutral" },
  canceled: { label: "Cancelled", variant: "neutral" },
};

/** The statuses this component knows, for tests and for callers building
 *  filters. Not a claim about what the backend may emit. */
export const SCAN_STATUSES = Object.keys(STATUSES);

export default function CcureScanStatus({
  status,
  size = "sm",
  className = "",
  ...rest
}) {
  const key = status == null ? "" : String(status).trim().toLowerCase();
  const known = STATUSES[key];

  // Never guess. An unrecognised status is reported as unknown, and the raw
  // value is kept in the title so an operator can see what the API actually
  // said rather than being told a different scan state.
  const label = known ? known.label : "Unknown";
  const variant = known ? known.variant : "neutral";

  return (
    <CcureBadge
      size={size}
      variant={variant}
      className={className}
      title={
        known
          ? undefined
          : status
            ? `Unrecognised status: ${status}`
            : undefined
      }
      {...rest}
    >
      {/* Only a running scan pulses. Animating a settled state would suggest
          work is still happening. */}
      {known?.live ? (
        <span className="cc-scan-status__pulse" aria-hidden="true" />
      ) : null}
      {label}
    </CcureBadge>
  );
}
