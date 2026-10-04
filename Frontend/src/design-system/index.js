/**
 * @ccure/design-system — public surface
 * ─────────────────────────────────────────────────────────────────────────────
 * Application code imports from here, never from a file inside the folder and
 * never from `ux4g-web-components` directly. That indirection is the whole
 * point of the layer: it is what allows the UX4G version underneath to change
 * without a single page being edited, and it is enforced by
 * src/__tests__/design-system/guardrails.test.js.
 *
 * The eventual cross-product package (Audit, Policy, Rank, IR) is this
 * directory, extracted. Keeping the surface explicit from the start is what
 * makes that extraction a move rather than a rewrite.
 *
 * NOTE: styles are imported here as a side effect, so a consumer gets tokens
 * and component CSS by importing the module. The order matters and is
 * documented in tokens/index.css — UX4G first, CCure after.
 */

import "./tokens/index.css";
import "./components/components.css";
import "./patterns/shell.css";
import "./patterns/security-patterns.css";

/* ── Actions ─────────────────────────────────────────────────────────────── */
export { default as CcureButton } from "./components/CcureButton";
export { default as CcureCheckbox } from "./components/CcureCheckbox";

/* ── Forms ───────────────────────────────────────────────────────────────── */
export {
  default as CcureInput,
  CcureSelect,
  CcureField,
} from "./components/CcureInput";

/* ── Surfaces and status ─────────────────────────────────────────────────── */
export { default as CcureCard } from "./components/CcureCard";
export { default as CcureBadge } from "./components/CcureBadge";
export { default as CcureAlert } from "./components/CcureAlert";

/* ── Overlays ────────────────────────────────────────────────────────────── */
export { default as CcureModal } from "./components/CcureModal";
export {
  default as CcureToastProvider,
  CcureToastProvider as ToastProvider,
  useCcureToast,
} from "./components/CcureToast";

/* ── Data display ────────────────────────────────────────────────────────── */
export {
  default as CcureTable,
  CcureTableStatus,
} from "./components/CcureTable";
export {
  default as CcureTabs,
  CcureTabPanel,
  useCcureTabs,
} from "./components/CcureTabs";
export { default as CcurePagination } from "./components/CcurePagination";
export { default as CcureBreadcrumb } from "./components/CcureBreadcrumb";

/* ── Feedback: loading, empty, progress ──────────────────────────────────── */
export {
  CcureLoader,
  CcureSkeleton,
  CcureEmptyState,
  CcureProgress,
} from "./components/CcureFeedback";

/* ── Security patterns ───────────────────────────────────────────────────────
   Security *meaning*, built on the generic primitives above. A pattern here
   answers "what security concept is this?"; a primitive answers "how should
   this behave and look?". Patterns receive already-decided values — no
   severity, risk or status is calculated in the design system. */
export {
  default as CcureSeverityBadge,
  SEVERITIES,
  normalizeSeverity,
} from "./patterns/CcureSeverityBadge";
export {
  default as CcureScanStatus,
  SCAN_STATUSES,
} from "./patterns/CcureScanStatus";
export { default as CcureScanProgress } from "./patterns/CcureScanProgress";
export {
  default as CcurePasswordField,
  PASSWORD_RULES,
  gradePassword,
} from "./patterns/CcurePasswordField";
export { default as CcureConfirmDialog } from "./patterns/CcureConfirmDialog";

/* ── Application chrome ──────────────────────────────────────────────────── */
export { default as CcureAppShell } from "./patterns/CcureAppShell";

/* ── Hooks ───────────────────────────────────────────────────────────────── */
export { default as useFocusTrap } from "./hooks/useFocusTrap";
