/** Account data/actions stay in the shell; all menu behavior is shared. */
import { useState } from "react";
import { CcureButton, CcureDropdown, CcureMenuItem } from "../../design-system";
import { IcoUser } from "./navIcons";
import "./navigation.css";

export default function AccountMenu({ user, onLogout, onOpenProfile }) {
  const [open, setOpen] = useState(false);
  return (
    <CcureDropdown
      open={open}
      onOpenChange={setOpen}
      id="sh-profile-menu"
      label="Account"
      align="end"
      className="sh-menu-anchor"
      menuClassName="sh-menu--profile"
      trigger={({ ref, buttonProps }) => (
        <CcureButton
          {...buttonProps}
          ref={ref}
          variant="ghost"
          size="sm"
          className="sh-user-btn"
          aria-label={`Account menu for ${user?.username || "Profile"}`}
        >
          <span className="sh-avatar" aria-hidden="true">
            <IcoUser />
          </span>
          <span className="sh-user-name hide-on-mobile">
            {user?.username || "Profile"}
          </span>
          <span className="sh-chevron" aria-hidden="true">
            ▼
          </span>
        </CcureButton>
      )}
    >
      <div className="sh-menu-head" role="presentation">
        <span className="sh-avatar sh-avatar--lg" aria-hidden="true">
          <IcoUser />
        </span>
        <span className="sh-menu-head-text">
          <span className="sh-menu-name">{user?.username || "User"}</span>
          <span className="sh-menu-email">{user?.email || ""}</span>
        </span>
      </div>
      <div className="sh-menu-body" role="presentation">
        <CcureMenuItem onClick={onOpenProfile}>My Account</CcureMenuItem>
        <CcureMenuItem className="sh-signout" onClick={onLogout}>
          Sign Out
        </CcureMenuItem>
      </div>
    </CcureDropdown>
  );
}
