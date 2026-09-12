import { forwardRef } from "react";

/**
 * CcureButton
 *
 * A native <button>, deliberately. Every alternative — a styled <div>, an <a>
 * without href, a UX4G class on a span — loses Enter/Space activation, the
 * disabled semantics and the implicit `button` role, all of which then have to
 * be re-implemented by hand and are re-implemented wrongly.
 *
 * `type` defaults to "button". React does not default it and HTML's own default
 * is "submit", so a button placed inside a form for an unrelated purpose
 * submits that form. This codebase has 19 forms and 310 buttons; the default is
 * the safer one.
 *
 * Loading sets `disabled` as well as `aria-busy`. Announcing busy while leaving
 * the control activatable invites the double-submit the loading state exists to
 * prevent.
 */
const CcureButton = forwardRef(function CcureButton(
  {
    variant = "primary",
    size = "md",
    type = "button",
    loading = false,
    block = false,
    disabled = false,
    className = "",
    /* Render as something other than `<button>` — in practice a router `Link`.
       An action that navigates is a link and must stay one: only a link can be
       opened in a new tab, copied, or announced as "link" rather than
       "button". Before this existed, pages reached for `<Link className=
       "auth-btn">` and hand-copied the button's own class names, which is how
       a control comes to look like a button and behave like neither. */
    as: Component = "button",
    children,
    ...rest
  },
  ref,
) {
  const classes = [
    "cc-btn",
    `cc-btn--${variant}`,
    `cc-btn--${size}`,
    block ? "cc-btn--block" : "",
    className,
  ]
    .filter(Boolean)
    .join(" ");

  const isButton = Component === "button";

  /* `type` and `disabled` are button-only attributes. React would pass both
     through to an `<a>`, where `disabled` is not merely inert but invalid —
     and an anchor that looks disabled while still following its href is worse
     than one that never looked disabled at all. A non-button that must be
     unavailable says so with aria-disabled and is given no href by its caller. */
  const elementProps = isButton
    ? { type, disabled: disabled || loading }
    : { "aria-disabled": disabled || loading || undefined };

  return (
    <Component
      ref={ref}
      className={classes}
      aria-busy={loading || undefined}
      {...elementProps}
      {...rest}
    >
      {loading && <span className="cc-btn__spinner" aria-hidden="true" />}
      {/* The label is not hidden while loading. Replacing it with a bare
          spinner removes the button's accessible name, so a screen reader
          announces "busy, button" with no indication of which button. */}
      <span>{children}</span>
    </Component>
  );
});

export default CcureButton;
