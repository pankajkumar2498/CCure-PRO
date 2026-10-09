/**
 * CcureBreadcrumb
 *
 * A labelled `<nav>` containing an ordered list. The list matters: it is what
 * tells a screen reader how many levels there are and which one is being read,
 * and it is why the separator can be hidden rather than announced.
 *
 * The last item is the current page and is **not a link** — it is `<span>`
 * with `aria-current="page"`. A link to where you already are is a trap for
 * keyboard users and announces as an actionable choice that does nothing.
 *
 * Items accept either `href` (a real anchor, so middle-click and "open in new
 * tab" work) or `onClick` (a button, for router navigation without a full
 * page load). Not both — a router link that is also an anchor needs the
 * caller's Link component, which the design system deliberately does not
 * depend on: this layer is meant to be reusable across CCure products that
 * may not share a router.
 */
export default function CcureBreadcrumb({
  items = [],
  label = "Breadcrumb",
  separator = "/",
  className = "",
}) {
  if (items.length === 0) return null;

  return (
    <nav
      aria-label={label}
      className={`cc-breadcrumb cc-ux4g ux4g-breadcrumb ${className}`.trim()}
    >
      <ol className="cc-breadcrumb__list ux4g-breadcrumb-list">
        {items.map((item, index) => {
          const isLast = index === items.length - 1;
          const key = item.key ?? item.href ?? `${item.label}-${index}`;

          return (
            <li key={key} className="cc-breadcrumb__item ux4g-breadcrumb-item">
              {isLast ? (
                <span className="cc-breadcrumb__current" aria-current="page">
                  {item.label}
                </span>
              ) : item.href ? (
                <a
                  className="cc-breadcrumb__link ux4g-breadcrumb-link"
                  href={item.href}
                >
                  {item.label}
                </a>
              ) : item.onClick ? (
                <button
                  type="button"
                  className="cc-breadcrumb__link ux4g-breadcrumb-link"
                  onClick={item.onClick}
                >
                  {item.label}
                </button>
              ) : (
                // An ancestor with no destination is still a level in the
                // hierarchy and must keep its position in the list.
                <span>{item.label}</span>
              )}

              {/* Decorative: the ordered list already conveys the structure,
                  and hearing "slash" between every crumb is noise. */}
              {!isLast ? (
                <span className="cc-breadcrumb__separator" aria-hidden="true">
                  {separator}
                </span>
              ) : null}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
