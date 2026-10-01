/**
 * src/shell/navigation/navIcons.jsx — icons the shared header pieces draw.
 * Decorative only: the control's text or aria-label carries the meaning.
 * Same geometry and attributes as the product layouts' own icon helper, so a
 * shared piece renders identically wherever it is placed.
 */
export const Icon = ({
  d,
  size = 16,
  viewBox = "0 0 24 24",
  fill = "none",
}) => (
  <svg
    width={size}
    height={size}
    viewBox={viewBox}
    fill={fill}
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    <path d={d} />
  </svg>
);

export const IcoUser = () => (
  <Icon d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z" />
);
