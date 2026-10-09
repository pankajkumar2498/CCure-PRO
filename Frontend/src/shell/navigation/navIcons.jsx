/**
 * src/shell/navigation/navIcons.jsx — icons the shared header pieces draw.
 * Decorative only: the control's text or aria-label carries the meaning.
 * Drawn by the design system's CcureIcon, the one icon set every module uses,
 * so a shared piece renders identically wherever it is placed.
 */
import { CcureIcon } from "../../design-system";

export const IcoUser = () => <CcureIcon name="user" size={16} />;

export const IcoSettings = () => <CcureIcon name="settings" size={16} />;
