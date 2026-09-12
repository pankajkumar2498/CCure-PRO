import { useId } from "react";

/**
 * CcureCard
 *
 * A titled surface. Thin on purpose: 34 files contain something card-shaped
 * and they differ almost entirely in their contents, so the reusable part is
 * the surface, the header layout and the heading semantics — not a layout
 * system.
 *
 * Two things it does that the hand-rolled versions do not:
 *
 *   * **The title is a real heading**, at a level the caller chooses. A card
 *     title rendered as a styled `<div>` is invisible to the heading-navigation
 *     most screen-reader users rely on to move around a dense page, and this
 *     application's pages are very dense.
 *   * **`as="section"` + `aria-labelledby`** wires the region to its title, so
 *     the card is announced as a named landmark rather than as loose content.
 *     Only when there is a title — an unnamed region is worse than none,
 *     because it adds a landmark that says nothing.
 *
 * `bodyFlush` exists for the common case of a table filling the card: the
 * table supplies its own cell padding, and doubling it wastes a lot of
 * horizontal space on a console that has none to spare.
 */
export default function CcureCard({
  as: Tag = "section",
  title,
  subtitle,
  headingLevel = 2,
  actions,
  footer,
  raised = false,
  flush = false,
  bodyFlush = false,
  children,
  className = "",
  ...rest
}) {
  const titleId = useId();
  const Heading = `h${Math.min(Math.max(headingLevel, 1), 6)}`;
  const hasHeader = Boolean(title || subtitle || actions);

  return (
    <Tag
      className={[
        "cc-card",
        raised ? "cc-card--raised" : "",
        flush ? "cc-card--flush" : "",
        className,
      ]
        .filter(Boolean)
        .join(" ")}
      // A section with no accessible name is not a useful landmark, so the
      // association is made only when a title exists.
      aria-labelledby={title ? titleId : undefined}
      {...rest}
    >
      {hasHeader ? (
        <div className="cc-card__header">
          <div className="cc-card__heading">
            {title ? (
              <Heading className="cc-card__title" id={titleId}>
                {title}
              </Heading>
            ) : null}
            {subtitle ? <p className="cc-card__subtitle">{subtitle}</p> : null}
          </div>
          {actions ? <div className="cc-card__actions">{actions}</div> : null}
        </div>
      ) : null}

      <div
        className={`cc-card__body${bodyFlush ? " cc-card__body--flush" : ""}`}
      >
        {children}
      </div>

      {footer ? <div className="cc-card__footer">{footer}</div> : null}
    </Tag>
  );
}
