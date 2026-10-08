import { forwardRef } from "react";

/**
 * CcurePage and CcurePageHeader — the one page structure for every module.
 *
 *   Application shell (header, sidebar)
 *   └── main
 *       └── CcurePage                  inset, entrance
 *           ├── CcurePageHeader        breadcrumb · title + badges · subtitle · actions
 *           ├── tabs (when a page has them)
 *           └── page content           cards, tables, forms, alerts …
 *
 * The values are the Common Platform's (B.13 §1.1), so a page moves between
 * products without its title, gutter or actions shifting. A page does not draw
 * its own header or pad its own root: it composes these two, and its own class
 * on CcurePage arranges only what is inside.
 *
 * The title is always the page's `<h1>`. A page has exactly one, which is what
 * a screen-reader user jumps to and what the document outline hangs from.
 */

export const CcurePage = forwardRef(function CcurePage(
  { as: Tag = "div", className = "", children, ...rest },
  ref,
) {
  return (
    <Tag ref={ref} className={`cc-page ${className}`.trim()} {...rest}>
      {children}
    </Tag>
  );
});

export function CcurePageHeader({
  title,
  /* Status beside the title — a scan's state, a scan number, a detected
     platform. Rendered after the <h1>, never inside it, so the page's name
     stays the heading's whole accessible name. */
  badges,
  subtitle,
  /* Navigation above the title: a CcureBreadcrumb, a back link or a pipeline
     stepper. */
  breadcrumb,
  actions,
  titleId,
  className = "",
  /* Supplementary text under the subtitle — a note, a status line, a short
     explanation with a link. Block content is allowed here; the subtitle is
     one paragraph. */
  children,
}) {
  return (
    <header className={`cc-page-header ${className}`.trim()}>
      {breadcrumb ? (
        <div className="cc-page-header__breadcrumb">{breadcrumb}</div>
      ) : null}
      <div className="cc-page-header__row">
        <div className="cc-page-header__heading">
          <div className="cc-page-header__titleline">
            <h1 className="cc-page-header__title" id={titleId}>
              {title}
            </h1>
            {badges ? (
              <div className="cc-page-header__badges">{badges}</div>
            ) : null}
          </div>
          {subtitle ? (
            <p className="cc-page-header__subtitle">{subtitle}</p>
          ) : null}
          {children ? (
            <div className="cc-page-header__description">{children}</div>
          ) : null}
        </div>
        {actions ? (
          <div className="cc-page-header__actions">{actions}</div>
        ) : null}
      </div>
    </header>
  );
}

export default CcurePage;
