/**
 * CcureBadge
 *
 * The generic status/label pill. The application currently carries at least
 * eighteen distinct ad-hoc badge classes — `auth-brand-badge`, `ns-chip`,
 * `method-chip`, `mini-stat-badge`, `pm-status-pill`, `port-pill`,
 * `sqb-pill`, `scan-card-badge` and more — each with its own colours, several
 * with hardcoded hex that does not respond to the theme.
 *
 * ── Colour is never the only carrier of meaning ─────────────────────────────
 * `children` is required. A badge that conveys its state purely through hue
 * fails WCAG 1.4.1, and on this product that is not a formality: severity and
 * scan status are exactly what a colour-blind operator must be able to read.
 * The optional `dot` is decorative reinforcement, never the message.
 *
 * ── This is the GENERIC primitive ───────────────────────────────────────────
 * Security semantics — severity bands, scan status, credential state — are
 * Checkpoint 3B patterns built ON this, not variants added to it. The reason
 * is concrete: UX4G has four status colours and vulnerability severity has
 * five bands, so Critical and High would both map to "danger" and lose the
 * distinction that matters most to whoever is triaging. Do not add
 * `variant="critical"` here.
 */
const VARIANTS = new Set([
  "neutral",
  "primary",
  "success",
  "warning",
  "danger",
  "info",
]);

export default function CcureBadge({
  variant = "neutral",
  size = "sm",
  dot = false,
  mono = false,
  children,
  className = "",
  ...rest
}) {
  const safeVariant = VARIANTS.has(variant) ? variant : "neutral";

  return (
    <span
      className={[
        "cc-badge",
        `cc-badge--${safeVariant}`,
        `cc-badge--${size}`,
        mono ? "cc-badge--mono" : "",
        className,
      ]
        .filter(Boolean)
        .join(" ")}
      {...rest}
    >
      {dot ? <span className="cc-badge__dot" aria-hidden="true" /> : null}
      {children}
    </span>
  );
}
