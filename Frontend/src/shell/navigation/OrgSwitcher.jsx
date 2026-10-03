/**
 * src/shell/navigation/OrgSwitcher.jsx — the organisation switcher.
 * ─────────────────────────────────────────────────────────────────────────────
 * Tenancy is a platform concern: the shell's HTTP client already sends the
 * chosen organisation (`activeOrgId`) with every request. The state lives in
 * `useOrganizationSwitcher`; this is the menu. Moved from Audit's AppLayout
 * unchanged.
 */
import { useRef } from "react";
import { CcureBadge } from "../../design-system";
import useDismiss from "./useDismiss";
import "./navigation.css";

/* Shown only to an account the backend says may switch organisation
   (`canSwitchOrganisation`). A real menu button: the legacy control was a
   `<div onClick>` with no name, no state and no keyboard path. Selecting an
   organisation asks the backend (AuthContext.switchOrganisation); the document
   reloads only after it accepts. */
export default function OrgSwitcher({
  selectedOrg,
  orgs,
  loading,
  open,
  onToggle,
  onClose,
  onSwitch,
}) {
  const btnRef = useRef(null);
  const menuRef = useRef(null);
  useDismiss(menuRef, open, onClose, btnRef);
  return (
    <div className="sh-menu-anchor">
      <button
        type="button"
        ref={btnRef}
        className="sh-org-btn"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls="sh-org-menu"
        aria-label={`Switch organization. Current: ${selectedOrg}`}
        onClick={onToggle}
      >
        <span className="sh-org-name">{selectedOrg}</span>
        <CcureBadge variant="primary" size="sm">
          ENTERPRISE
        </CcureBadge>
        <span className="sh-chevron" aria-hidden="true">
          ▼
        </span>
      </button>
      {open && (
        <div
          className="sh-menu sh-menu--org"
          ref={menuRef}
          id="sh-org-menu"
          role="menu"
          aria-label="Switch Organization"
        >
          <div className="sh-menu-title">Switch Organization</div>
          {loading ? (
            <div className="sh-menu-note">Loading...</div>
          ) : orgs.length === 0 ? (
            <div className="sh-menu-note">No organizations found</div>
          ) : (
            orgs.map((org) => (
              <button
                key={org.id}
                type="button"
                role="menuitem"
                className={`sh-menu-item${org.name === selectedOrg ? " sh-menu-item--current" : ""}`}
                aria-current={org.name === selectedOrg ? "true" : undefined}
                onClick={() => onSwitch(org)}
              >
                <span className="sh-menu-check" aria-hidden="true">
                  {org.name === selectedOrg ? "✓" : ""}
                </span>
                {org.name}
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}
