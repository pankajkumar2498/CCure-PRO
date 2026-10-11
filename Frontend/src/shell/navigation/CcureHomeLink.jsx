/**
 * src/shell/navigation/CcureHomeLink.jsx — the way back to CCure Home.
 * ─────────────────────────────────────────────────────────────────────────────
 * Every product's header offers it (D12-8), so the shell owns what is shared:
 * the address, the accessible name and the label. A product supplies only its
 * own layout classes. A link, not a button: it navigates, and can be opened
 * in a new tab.
 */
import { Link } from "react-router-dom";
import { CcureButton } from "../../design-system";

export const CCURE_HOME_PATH = "/";

const HomeIcon = () => (
  <svg
    width={16}
    height={16}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    <path d="M3 10.5 12 3l9 7.5M5 9v11h5v-6h4v6h5V9" />
  </svg>
);

export default function CcureHomeLink({
  className = "",
  labelClassName = "",
  variant = "ghost",
  size = "sm",
}) {
  return (
    <CcureButton
      as={Link}
      to={CCURE_HOME_PATH}
      variant={variant}
      size={size}
      className={className}
      aria-label="CCurePRO Home"
    >
      <HomeIcon />
      <span className={labelClassName || undefined}>CCurePRO Home</span>
    </CcureButton>
  );
}
