/**
 * CcureAlert
 *
 * An inline, in-flow message. (A transient, out-of-flow one is CcureToast.)
 *
 * The `role` is chosen by severity rather than fixed, and that choice is the
 * substance of this component:
 *
 *   * `danger` / `warning`  → role="alert"  (implicitly aria-live="assertive")
 *     Interrupts whatever the screen reader is saying. Correct for "your scan
 *     failed" and "this will delete 400 findings"; wrong for anything routine,
 *     because a UI that interrupts constantly gets its announcements ignored.
 *
 *   * `success` / `info`    → role="status" (implicitly aria-live="polite")
 *     Announced at the next natural pause.
 *
 * `live={false}` opts out entirely, and it is not a footnote. An alert rendered
 * as part of the initial page — a standing "this scan ran without credentials"
 * banner — is not an *event*. Announcing it as one makes every page load read
 * its banners aloud before the user has asked for anything. Live regions are
 * for things that change after the page settles.
 */
const ICONS = {
  info: "ℹ",
  success: "✓",
  warning: "⚠",
  danger: "✕",
};

export default function CcureAlert({
  variant = "info",
  title,
  children,
  onDismiss,
  dismissLabel = "Dismiss",
  live = true,
  className = "",
  ...rest
}) {
  const assertive = variant === "danger" || variant === "warning";
  const role = live ? (assertive ? "alert" : "status") : undefined;

  return (
    <div
      className={`cc-alert cc-ux4g ux4g-alert ux4g-alert-${variant === "danger" ? "error" : variant} cc-alert--${variant} ${className}`.trim()}
      role={role}
      {...rest}
    >
      {/* The glyph duplicates information the variant colour and the text both
          already carry, so it is hidden from assistive tech. Its job is to keep
          the meaning legible for a user who cannot distinguish the colours —
          WCAG 1.4.1, which colour-only status styling fails. */}
      <span className="cc-alert__icon ux4g-alert-icon" aria-hidden="true">
        {ICONS[variant] ?? ICONS.info}
      </span>

      <div className="cc-alert__body ux4g-alert-content">
        {title ? (
          <div className="cc-alert__title ux4g-alert-title">{title}</div>
        ) : null}
        <div className="ux4g-alert-message">{children}</div>
      </div>

      {onDismiss ? (
        <button
          type="button"
          className="cc-alert__dismiss ux4g-alert-close"
          onClick={onDismiss}
          /* An icon-only control needs a name. "×" is announced as "times" or
             skipped entirely depending on the reader. */
          aria-label={dismissLabel}
        >
          <span aria-hidden="true">×</span>
        </button>
      ) : null}
    </div>
  );
}
