/**
 * src/shell/navigation/AdminMenu.jsx — the platform's Administration menu.
 * ─────────────────────────────────────────────────────────────────────────────
 * Links to the shared administration screens (`/admin/*`) the signed-in user
 * may see, from the shell's one list (`SHARED_ADMIN_NAV`) and the shared
 * visibility rule (`canSeeNavItem`) — the same gates as Audit's sidebar, the
 * route guard and the backend. With nothing visible the menu is not rendered,
 * rather than shown empty.
 */
import { useCallback, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { SHARED_ADMIN_NAV } from "../admin/adminNav";
import { canSeeNavItem } from "../auth/navVisibility";
import useDismiss from "./useDismiss";
import "./navigation.css";

export default function AdminMenu({ user }) {
  const [open, setOpen] = useState(false);
  const btnRef = useRef(null);
  const menuRef = useRef(null);
  const close = useCallback(() => setOpen(false), []);
  useDismiss(menuRef, open, close, btnRef);

  const items = SHARED_ADMIN_NAV.filter((item) => canSeeNavItem(user, item));
  if (items.length === 0) return null;

  return (
    <div className="sh-menu-anchor">
      <button
        type="button"
        ref={btnRef}
        className="sh-org-btn"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls="sh-admin-menu"
        onClick={() => setOpen((o) => !o)}
      >
        <span className="sh-org-name">Administration</span>
        <span className="sh-chevron" aria-hidden="true">
          ▼
        </span>
      </button>
      {open && (
        <div
          className="sh-menu sh-menu--org"
          ref={menuRef}
          id="sh-admin-menu"
          role="menu"
          aria-label="Administration"
        >
          {items.map((item) => (
            <Link
              key={item.id}
              to={item.route}
              role="menuitem"
              className="sh-menu-item"
              onClick={close}
            >
              {item.label}
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
