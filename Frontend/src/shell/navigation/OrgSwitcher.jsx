/**
 * src/shell/navigation/OrgSwitcher.jsx — the organisation switcher.
 * ─────────────────────────────────────────────────────────────────────────────
 * Tenancy is a platform concern: the shell's HTTP client already sends the
 * chosen organisation (`activeOrgId`) with every request. The state lives in
 * `useOrganizationSwitcher`; this is the menu. Moved from Audit's AppLayout
 * unchanged.
 */
import {
  CcureBadge,
  CcureButton,
  CcureDropdown,
  CcureLoader,
  CcureMenuItem,
} from "../../design-system";
import "./navigation.css";

export default function OrgSwitcher({
  selectedOrg,
  orgs,
  loading,
  open,
  onToggle,
  onClose,
  onSwitch,
}) {
  return (
    <CcureDropdown
      open={open}
      onOpenChange={(next) => (next ? onToggle() : onClose())}
      id="sh-org-menu"
      label="Switch Organization"
      className="sh-menu-anchor"
      menuClassName="sh-menu--org"
      trigger={({ ref, buttonProps }) => (
        <CcureButton
          {...buttonProps}
          ref={ref}
          variant="secondary"
          size="sm"
          className="sh-org-btn"
          aria-label={`Switch organization. Current: ${selectedOrg}`}
        >
          <span className="sh-org-name">{selectedOrg}</span>
          <CcureBadge variant="primary" size="sm">
            ENTERPRISE
          </CcureBadge>
          <span className="sh-chevron" aria-hidden="true">
            ▼
          </span>
        </CcureButton>
      )}
    >
      <div className="sh-menu-title" role="presentation">
        Switch Organization
      </div>
      {loading ? (
        <CcureLoader label="Loading..." size="sm" />
      ) : orgs.length === 0 ? (
        <div className="sh-menu-note">No organizations found</div>
      ) : (
        orgs.map((org) => (
          <CcureMenuItem
            key={org.id}
            className={`sh-menu-item${org.name === selectedOrg ? " sh-menu-item--current" : ""}`}
            aria-current={org.name === selectedOrg ? "true" : undefined}
            onClick={() => onSwitch(org)}
          >
            <span className="sh-menu-check" aria-hidden="true">
              {org.name === selectedOrg ? "✓" : ""}
            </span>
            {org.name}
          </CcureMenuItem>
        ))
      )}
    </CcureDropdown>
  );
}
