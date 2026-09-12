import { useId } from "react";

/**
 * The four "the data is not here yet, or is not here at all" primitives:
 * Loader, Skeleton, EmptyState and Progress.
 *
 * They live together because they are answers to one question — what a surface
 * shows when it has nothing to show — and keeping them adjacent makes it
 * harder to reach for the wrong one. The distinction that matters:
 *
 *   Loader     — work is happening and the shape of the result is unknown
 *   Skeleton   — work is happening and the shape IS known (rows, a card)
 *   EmptyState — work finished and there is genuinely nothing
 *   Progress   — work is happening and its extent is measurable
 *
 * Rendering an EmptyState while still loading is the common bug in this class,
 * and on a security console it is a serious one: "No findings" and "not
 * assessed yet" mean opposite things to whoever is reading the screen.
 */

/* ── Loader ─────────────────────────────────────────────────────────────── */

export function CcureLoader({
  label = "Loading…",
  inline = false,
  className = "",
}) {
  return (
    <div
      className={["cc-loader", inline ? "cc-loader--inline" : "", className]
        .filter(Boolean)
        .join(" ")}
      // status + polite: a loading indicator should be announced once, at the
      // next natural pause, not interrupt what the reader is saying.
      role="status"
      aria-live="polite"
    >
      <span className="cc-loader__spinner" aria-hidden="true" />
      {/* The label is always rendered for assistive tech; `inline` only
          changes the layout, never whether the state is announced. A spinner
          with no accessible text is silent. */}
      <span className={label ? undefined : "cc-sr-only"}>
        {label || "Loading…"}
      </span>
    </div>
  );
}

/* ── Skeleton ───────────────────────────────────────────────────────────── */

/**
 * A placeholder block. `aria-hidden` deliberately: a screen reader must not
 * announce a row of grey boxes, and the surrounding region should carry a
 * single `role="status"` saying what is loading. `CcureTable` renders these
 * inside its own rows, and `CcureTableStatus` is what speaks for them.
 */
export function CcureSkeleton({
  width = "100%",
  height,
  variant = "text",
  radius,
  className = "",
  style,
}) {
  return (
    <span
      className={["cc-skeleton", `cc-skeleton--${variant}`, className]
        .filter(Boolean)
        .join(" ")}
      aria-hidden="true"
      // Dimensions are the one thing that must stay inline: they are per-
      // instance values, not a design decision a token could carry.
      style={{ width, height, borderRadius: radius, ...style }}
    />
  );
}

/* ── Empty state ────────────────────────────────────────────────────────── */

export function CcureEmptyState({
  icon,
  title = "Nothing to show",
  description,
  action,
  className = "",
}) {
  return (
    <div className={`cc-empty ${className}`.trim()}>
      {icon ? (
        <span className="cc-empty__icon" aria-hidden="true">
          {icon}
        </span>
      ) : null}
      <p className="cc-empty__title">{title}</p>
      {description ? (
        <p className="cc-empty__description">{description}</p>
      ) : null}
      {action ? <div className="cc-empty__action">{action}</div> : null}
    </div>
  );
}

/* ── Progress ───────────────────────────────────────────────────────────── */

/**
 * A determinate or indeterminate progress bar.
 *
 * When `value` is null the value is **unknown**: `aria-valuenow` is omitted
 * rather than set to 0. Those are different statements — "0% done" is a
 * measurement, "we do not know how far along this is" is not — and a scan
 * whose progress cannot be determined must not report itself as having made no
 * progress.
 *
 * `animated` splits that unknown into two: `true` (the default) is "unknown
 * and still moving" and slides; `false` is "unknown and stopped" — a failed
 * scan whose last percentage never arrived — which paints an empty track. Both
 * omit aria-valuenow; neither prints a number.
 *
 * `<div role="progressbar">` rather than `<progress>`: the native element
 * cannot be styled consistently across browsers without overriding the same
 * vendor pseudo-elements this design system exists to avoid, and it brings no
 * semantics the role does not.
 */
export function CcureProgress({
  value = null,
  max = 100,
  label,
  showValue = true,
  variant = "primary",
  animated = true,
  className = "",
}) {
  const labelId = useId();

  // `animated: false` with no value is "unknown, and no longer moving" — a
  // failed scan whose last reported percentage never arrived. It must still
  // omit aria-valuenow (nothing was measured) while not sliding forever, which
  // would suggest work is ongoing. Rendering it as 0 instead would assert that
  // the scan made no progress, which is a different and unsupported claim.
  const unknown = value == null;
  const indeterminate = unknown && animated;
  const clamped = unknown ? 0 : Math.min(Math.max(value, 0), max);
  const pct = max > 0 ? (clamped / max) * 100 : 0;

  return (
    <div
      className={[
        "cc-progress",
        `cc-progress--${variant}`,
        indeterminate ? "cc-progress--indeterminate" : "",
        className,
      ]
        .filter(Boolean)
        .join(" ")}
    >
      {label || (showValue && !unknown) ? (
        <div className="cc-progress__labels">
          <span id={labelId}>{label}</span>
          {/* No percentage is shown for an unknown value in either mode —
              printing "0%" is the assertion this component exists to avoid. */}
          {showValue && !unknown ? (
            <span className="cc-progress__value">{Math.round(pct)}%</span>
          ) : null}
        </div>
      ) : null}

      <div
        className="cc-progress__track"
        role="progressbar"
        aria-labelledby={label ? labelId : undefined}
        aria-label={!label ? "Progress" : undefined}
        aria-valuemin={0}
        aria-valuemax={max}
        // Omitted entirely when indeterminate — that is how the role says
        // "unknown". Setting it to 0 would assert no progress.
        aria-valuenow={unknown ? undefined : clamped}
        aria-valuetext={
          indeterminate
            ? "In progress"
            : unknown
              ? "Progress unknown"
              : undefined
        }
      >
        <div
          className="cc-progress__bar"
          // An unknown, non-animating value paints no bar at all — an empty
          // track reads as "nothing to report", which is what it is.
          style={
            indeterminate ? undefined : { width: unknown ? "0%" : `${pct}%` }
          }
        />
      </div>
    </div>
  );
}
