import { ICONS } from "./icons";

/**
 * CcureIcon — the application's one icon primitive.
 *
 * Decorative by default: `aria-hidden` and not focusable, because the control or
 * text beside it carries the meaning. An icon that stands alone and *is* the
 * meaning takes a `title`, which makes it `role="img"` with that accessible name.
 *
 * Sized in `em` by default so it matches the text it sits beside — the same
 * reason the emoji it replaces looked right in a button and in a heading alike.
 *
 * An unknown name renders nothing rather than a placeholder glyph. The unit
 * suite checks every literal name in the source against the set, so a typo is a
 * failing test, not an invisible icon in production.
 *
 * `data-icon` carries the name, so a test can say which icon is drawn without
 * comparing path data.
 */
export default function CcureIcon({
  name,
  size = "1em",
  strokeWidth = 2,
  title,
  className = "",
}) {
  const shapes = ICONS[name];
  if (!shapes) return null;
  const labelled = Boolean(title);
  return (
    <svg
      className={`cc-icon ${className}`.trim()}
      data-icon={name}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      focusable="false"
      aria-hidden={labelled ? undefined : "true"}
      role={labelled ? "img" : undefined}
      aria-label={labelled ? title : undefined}
    >
      {shapes.map(([Shape, attributes], index) => (
        <Shape key={index} {...attributes} />
      ))}
    </svg>
  );
}
