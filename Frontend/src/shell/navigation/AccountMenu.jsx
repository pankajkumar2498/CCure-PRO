/**
 * src/shell/navigation/AccountMenu.jsx — the signed-in user's account menu.
 * ─────────────────────────────────────────────────────────────────────────────
 * Shared by every product's header: the user's name and email, "My Account"
 * (the host opens the account dialog) and "Sign Out". Moved from Audit's
 * AppLayout unchanged; the host supplies `onLogout` and `onOpenProfile`.
 */
import { useCallback, useRef, useState } from "react";
import { IcoUser } from "./navIcons";
import useDismiss from "./useDismiss";
import "./navigation.css";

export default function AccountMenu({ user, onLogout, onOpenProfile }) {
  const [open, setOpen] = useState(false);
  const btnRef = useRef(null);
  const menuRef = useRef(null);
  const close = useCallback(() => setOpen(false), []);
  useDismiss(menuRef, open, close, btnRef);

  return (
    <div className="sh-menu-anchor">
      <button
        type="button"
        ref={btnRef}
        className="sh-user-btn"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls="sh-profile-menu"
        aria-label={`Account menu for ${user?.username || "Profile"}`}
        onClick={() => setOpen((o) => !o)}
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
      </button>
      {open && (
        <div
          className="sh-menu sh-menu--profile"
          ref={menuRef}
          id="sh-profile-menu"
          role="menu"
          aria-label="Account"
        >
          <div className="sh-menu-head">
            <span className="sh-avatar sh-avatar--lg" aria-hidden="true">
              <IcoUser />
            </span>
            <span className="sh-menu-head-text">
              <span className="sh-menu-name">{user?.username || "User"}</span>
              <span className="sh-menu-email">{user?.email || ""}</span>
            </span>
          </div>
          <div className="sh-menu-body">
            <button
              type="button"
              role="menuitem"
              className="cc-btn cc-btn--primary cc-btn--sm cc-btn--block"
              onClick={() => {
                close();
                onOpenProfile();
              }}
            >
              My Account
            </button>
            <button
              type="button"
              role="menuitem"
              className="cc-btn cc-btn--ghost cc-btn--sm cc-btn--block sh-signout"
              onClick={onLogout}
            >
              Sign Out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
