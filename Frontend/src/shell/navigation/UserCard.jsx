/**
 * src/shell/navigation/UserCard.jsx — who is signed in: avatar, name, role.
 * The host layout places it and supplies its own controls as children (Audit
 * puts its settings button there). Moved from Audit's sidebar footer unchanged.
 */
import { IcoUser } from "./navIcons";
import { assignmentLabels } from "../auth/authorization";
import "./navigation.css";

export default function UserCard({ user, children }) {
  // the labels of the account's live roles, from the backend; an account holding
  // none is shown as having none, never as a generic "Member"
  const roleLabel = assignmentLabels(user).join(", ") || "No role assigned";
  return (
    <div className="sh-user">
      <span className="sh-avatar" aria-hidden="true">
        <IcoUser />
      </span>
      <span className="sh-user-info">
        <span className="sh-user-info-name" title={user?.username || "User"}>
          {user?.username || "User"}
        </span>
        <span className="sh-user-info-role" title={roleLabel}>
          {roleLabel}
        </span>
      </span>
      {children}
    </div>
  );
}
