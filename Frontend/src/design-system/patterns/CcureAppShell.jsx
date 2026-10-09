import { useEffect, useRef, useState } from "react";
import CcureBadge from "../components/CcureBadge";
import CcureButton from "../components/CcureButton";
import CcureIconButton from "../components/CcureIconButton";
import CcureDrawer from "../components/CcureDrawer";
import useMediaQuery from "../hooks/useMediaQuery";
import CcureIcon from "../icons/CcureIcon";

/**
 * CcureAppShell
 *
 * The UX4G-aligned application chrome: skip link, sidebar, header, main and
 * (optional) footer. Proven in the spike; adopted by AppLayout in batch 12.
 *
 * It is deliberately presentational. Navigation items, the active route, the
 * user block and every action are passed in, so this component has no opinion
 * about routing, permissions or authentication — which is what lets AppLayout
 * keep SIDEBAR_SECTIONS and canSeeNavItem exactly as they were
 * and hand this component only what survived the filter.
 *
 * ── Landmarks ───────────────────────────────────────────────────────────────
 * Each named where more than one of a type can exist. `<nav>` and `<aside>`
 * are announced by name in a screen reader's landmark list, and two unnamed
 * `<nav>`s are announced as "navigation, navigation".
 *
 * ── The skip link ───────────────────────────────────────────────────────────
 * Phase 0 measured zero in the application. This one is the first element in
 * the DOM, so it is the first Tab stop from the address bar, and it targets a
 * `tabIndex={-1}` main — see shell.css for why the tabindex is required rather
 * than decorative.
 *
 * ── Batch 12 additions (all optional, all additive) ─────────────────────────
 *   * `collapsed` / `onToggleCollapsed` — a desktop rail mode with a real
 *     toggle (`aria-expanded`, `aria-controls`); labels are hidden visually
 *     and carried on `title` so the icon-only rail is still named.
 *   * item `active`, `badge`, `badgeVariant`, `disabled` — the host decides
 *     what is current (AppLayout's rule is query-aware, not path equality),
 *     and a disabled item is rendered but announced as unavailable rather
 *     than silently dropped.
 *   * `headerLeft` — controls that sit beside the title (org switcher, search).
 *   * `navRef` / `onNavScroll` — so the host can persist the nav scroll.
 *   * `mainClassName` — AppLayout adds `page-main`, which every page and every
 *     harness readiness check keys on.
 *   * `className` — on the shell root, so a host can scope its own rules.
 *   * `title` and the footer are rendered only when supplied: an empty `<h1>`
 *     is worse than none, and this product's pages carry their own h1.
 */
export default function CcureAppShell({
  brand = { name: "CCure Audit", sub: "PRO" },
  identity,
  sections = [],
  currentPath = "",
  onNavigate,
  title,
  meta,
  headerLeft,
  headerActions,
  sidebarFooter,
  footerLinks = [],
  footerNote,
  collapsed = false,
  onToggleCollapsed,
  navRef,
  onNavScroll,
  mainClassName = "",
  className = "",
  children,
}) {
  const [navOpen, setNavOpen] = useState(false);
  const mainRef = useRef(null);
  const mobile = useMediaQuery("(max-width: 768px)");
  useEffect(() => {
    if (!mobile) setNavOpen(false);
  }, [mobile]);
  const hasFooter = Boolean(identity || footerNote || footerLinks.length);

  const sidebarContent = (
    <>
      <div className="cc-sidebar__brand">
        <span className="cc-sidebar__brand-mark" aria-hidden="true">
          {/* One mark for the whole application, so every product's sidebar
              opens on the same brand. */}
          {brand.mark ?? <CcureIcon name="shield" />}
        </span>
        <span className="cc-sidebar__brand-text">
          <span className="cc-sidebar__brand-name">{brand.name}</span>
          {brand.sub ? (
            <span className="cc-sidebar__brand-sub">{brand.sub}</span>
          ) : null}
        </span>
        {onToggleCollapsed ? (
          <CcureIconButton
            size="sm"
            className="cc-sidebar__collapse"
            onClick={onToggleCollapsed}
            aria-expanded={!collapsed}
            aria-controls="cc-sidebar"
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            <span aria-hidden="true">{collapsed ? "›" : "‹"}</span>
          </CcureIconButton>
        ) : null}
      </div>

      {/* Named, because the footer also contains a nav. */}
      <nav
        className="cc-sidebar__nav"
        aria-label="Sections"
        ref={navRef}
        onScroll={onNavScroll}
      >
        {sections.map((section) => (
          <div className="cc-sidebar__section" key={section.label}>
            {/* The heading is associated with its list via aria-labelledby
                  rather than left as a floating div, so the group is announced
                  as a named set instead of as loose links. */}
            <div
              className="cc-sidebar__section-label"
              id={`cc-navsec-${slug(section.label)}`}
            >
              {section.label}
            </div>
            <ul
              className="cc-sidebar__list"
              aria-labelledby={`cc-navsec-${slug(section.label)}`}
            >
              {section.items.map((item) => {
                const active = item.active ?? item.route === currentPath;
                const disabled = Boolean(item.disabled);
                return (
                  <li key={item.id ?? item.route}>
                    <CcureButton
                      as="a"
                      variant="ghost"
                      size="sm"
                      disabled={disabled}
                      className={`cc-sidebar__link${disabled ? " cc-sidebar__link--disabled" : ""}`}
                      href={disabled ? undefined : item.route}
                      /* "page" rather than "true": it names *what* is
                           current, which is what a reader announces. */
                      aria-current={active ? "page" : undefined}
                      aria-disabled={disabled || undefined}
                      title={collapsed ? item.label : undefined}
                      onClick={(e) => {
                        if (disabled) {
                          e.preventDefault();
                          return;
                        }
                        if (
                          onNavigate &&
                          !e.metaKey &&
                          !e.ctrlKey &&
                          !e.shiftKey &&
                          !e.altKey &&
                          e.button === 0
                        ) {
                          e.preventDefault();
                          onNavigate(item.route, item);
                          setNavOpen(false);
                        }
                      }}
                    >
                      <span className="cc-sidebar__icon" aria-hidden="true">
                        {item.icon ?? "•"}
                      </span>
                      <span className="cc-sidebar__label">{item.label}</span>
                      {disabled ? (
                        <span className="cc-sidebar__tag">
                          <CcureBadge variant="neutral">Soon</CcureBadge>
                        </span>
                      ) : null}
                      {!disabled && item.badge > 0 ? (
                        <span className="cc-sidebar__tag">
                          <CcureBadge variant={item.badgeVariant || "neutral"}>
                            {item.badge}
                            <span className="cc-sr-only">
                              {" "}
                              {item.badgeLabel || "items"}
                            </span>
                          </CcureBadge>
                        </span>
                      ) : null}
                    </CcureButton>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {sidebarFooter ? (
        <div className="cc-sidebar__footer">{sidebarFooter}</div>
      ) : null}
    </>
  );

  return (
    <div
      className={`cc-shell${collapsed ? " cc-shell--collapsed" : ""}${className ? ` ${className}` : ""}`}
    >
      <a
        className="cc-skip-link"
        href="#cc-main"
        onClick={() => mainRef.current?.focus()}
      >
        Skip to main content
      </a>
      {mobile ? (
        <CcureDrawer
          open={navOpen}
          onClose={() => setNavOpen(false)}
          placement="left"
          id="cc-sidebar"
          title="Navigation"
          closeLabel="Close navigation"
          className="cc-sidebar-drawer"
        >
          {sidebarContent}
        </CcureDrawer>
      ) : (
        <aside
          id="cc-sidebar"
          className="cc-sidebar"
          data-collapsed={collapsed}
          aria-label="Primary"
        >
          {sidebarContent}
        </aside>
      )}
      <header className="cc-header cc-ux4g ux4g-navbar">
        <div className="cc-header__left">
          <CcureIconButton
            size="sm"
            className="cc-header__nav-toggle"
            onClick={() => setNavOpen((v) => !v)}
            aria-expanded={navOpen}
            aria-controls={!mobile || navOpen ? "cc-sidebar" : undefined}
            aria-label={navOpen ? "Close navigation" : "Open navigation"}
          >
            <CcureIcon name="menu" size="1.25em" />
          </CcureIconButton>
          {/* h1 on the shell only when the host asks for one: this product's
              pages carry their own h1 (batches 10–11), so AppLayout does not. */}
          {title ? <h1 className="cc-header__title">{title}</h1> : null}
          {meta ? <span className="cc-header__meta">{meta}</span> : null}
          {headerLeft}
        </div>
        <div className="cc-header__right">{headerActions}</div>
      </header>

      <main
        id="cc-main"
        ref={mainRef}
        className={`cc-main${mainClassName ? ` ${mainClassName}` : ""}`}
        /* Focusable so the skip link actually moves focus here, not just the
           viewport. Negative, so it never enters the natural tab order. */
        tabIndex={-1}
      >
        {children}
      </main>

      {hasFooter ? (
        <footer className="cc-footer">
          <div>
            {identity ? <div>{identity}</div> : null}
            {footerNote ? <div>{footerNote}</div> : null}
          </div>
          {footerLinks.length > 0 ? (
            <nav aria-label="Footer">
              <ul className="cc-footer__links">
                {footerLinks.map((link) => (
                  <li key={link.href}>
                    <a href={link.href}>{link.label}</a>
                  </li>
                ))}
              </ul>
            </nav>
          ) : null}
        </footer>
      ) : null}
    </div>
  );
}

const slug = (s) =>
  String(s)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
