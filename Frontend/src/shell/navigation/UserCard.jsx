/**
 * src/shell/navigation/UserCard.jsx — who is signed in: avatar, name, role.
 * The host layout places it and supplies its own controls as children (Audit
 * puts its settings button there). Moved from Audit's sidebar footer unchanged.
 */
import { IcoUser } from "./navIcons";
import "./navigation.css";

export default function UserCard({ user, children }) {
  return (
    <div className="sh-user">
      <span className="sh-avatar" aria-hidden="true">
        <IcoUser />
      </span>
      <span className="sh-user-info">
        <span className="sh-user-info-name" title={user?.username || "User"}>
          {user?.username || "User"}
        </span>
        <span className="sh-user-info-role" title={user?.role?.name || ""}>
          {user?.role?.name || "Member"}
        </span>
      </span>
      {children}
    </div>
  );
}
