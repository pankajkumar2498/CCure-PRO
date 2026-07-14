import EmptyState from "../common/EmptyState";
import Loader from "../common/Loader";
import Button from "../common/Button";

const statusConfig = {
  active: { label: "Active", className: "chip chip--active" },
  inactive: { label: "Inactive", className: "chip chip--inactive" },
  locked: { label: "Locked", className: "chip chip--danger" },
};

function TableRow({
  user,
  currentUser,
  roleName,
  organizationName,
  showOrganizationColumn,
  onEdit,
  onResetPassword,
  onResetMfa,
  onToggleStatus,
  onUnlock,
  onDelete,
  canUpdateUsers,
  canDeleteUsers,
}) {
  const isLocked =
    user.locked_until && new Date(user.locked_until) > new Date();
  const status = isLocked
    ? statusConfig.locked
    : user.is_active
      ? statusConfig.active
      : statusConfig.inactive;
  const isSelf = currentUser && String(currentUser.id) === String(user.id);

  return (
    <tr>
      <td>
        <div className="table-cell-identity">
          <span className="table-username">{user.username}</span>
          <span className="table-subtext">{user.email}</span>
        </div>
      </td>
      <td>{user.full_name || "—"}</td>
      <td>{roleName || "—"}</td>
      {showOrganizationColumn && <td>{organizationName || "—"}</td>}
      <td>
        <span className={status.className}>{status.label}</span>
      </td>
      <td>
        {user.last_login_at
          ? new Date(user.last_login_at).toLocaleString()
          : "Never"}
      </td>
      <td>
        <div className="action-btns table-action-cell">
          {canUpdateUsers && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              title="Edit user"
              onClick={() => onEdit(user)}
            >
              ✏️ Edit
            </Button>
          )}
          {canUpdateUsers && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              title="Reset password"
              onClick={() => onResetPassword(user)}
            >
              🔑 Reset
            </Button>
          )}
          {canUpdateUsers && user.mfa_enabled && !isSelf && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              title="Reset MFA"
              onClick={() => onResetMfa(user)}
            >
              🛡️ Reset MFA
            </Button>
          )}
          {isLocked && canUpdateUsers && (
            <Button
              type="button"
              variant="info"
              size="sm"
              title="Unlock user"
              onClick={() => onUnlock(user)}
            >
              Unlock
            </Button>
          )}
          {!isSelf && (canUpdateUsers || canDeleteUsers) && (
            <>
              {canUpdateUsers && (
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  title={user.is_active ? "Deactivate user" : "Activate user"}
                  onClick={() => onToggleStatus(user)}
                >
                  {user.is_active ? "⏻ Deactivate" : "▶ Activate"}
                </Button>
              )}
              {canDeleteUsers && (
                <Button
                  type="button"
                  variant="danger"
                  size="sm"
                  title="Delete user"
                  onClick={() => onDelete(user)}
                >
                  🗑️ Delete
                </Button>
              )}
            </>
          )}
          {!canUpdateUsers && !canDeleteUsers && (
            <span className="text-muted">Read only</span>
          )}
        </div>
      </td>
    </tr>
  );
}

export default function UserTable({
  users,
  roles,
  organizations,
  showOrganizationColumn = true,
  loading,
  refreshing = false,
  currentUser,
  onEdit,
  onResetPassword,
  onResetMfa,
  onToggleStatus,
  onUnlock,
  onDelete,
  canUpdateUsers = false,
  canDeleteUsers = false,
}) {
  return (
    <div className="card card--admin-table">
      <div className="table-card-header">
        <div>
          <h3 className="card-title">Users</h3>
          <p className="card-subtitle">
            Review users, role assignment, account status, and organization.
          </p>
        </div>
      </div>

      {loading ? (
        <div className="table-loading-shell">
          <Loader label="Loading users..." />
        </div>
      ) : users.length === 0 ? (
        <EmptyState
          icon="👥"
          title="No users found"
          description="Try a different search term or add a new user to get started."
        />
      ) : (
        <div
          style={{
            opacity: refreshing ? 0.6 : 1,
            transition: "opacity 0.15s ease-in-out",
          }}
        >
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>User</th>
                  <th>Full name</th>
                  <th>Role</th>
                  {showOrganizationColumn && <th>Organization</th>}
                  <th>Status</th>
                  <th>Last login</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => {
                  const roleName = roles.find(
                    (role) => String(role.id) === String(user.role_id),
                  )?.name;
                  const organizationName = organizations.find(
                    (organization) =>
                      String(organization.id) ===
                      String(user.organization_id || user.org_id),
                  )?.name;

                  return (
                    <TableRow
                      key={user.id}
                      user={user}
                      roleName={roleName}
                      organizationName={organizationName}
                      showOrganizationColumn={showOrganizationColumn}
                      currentUser={currentUser}
                      onEdit={onEdit}
                      onResetPassword={onResetPassword}
                      onResetMfa={onResetMfa}
                      onToggleStatus={onToggleStatus}
                      onUnlock={onUnlock}
                      onDelete={onDelete}
                      canUpdateUsers={canUpdateUsers}
                      canDeleteUsers={canDeleteUsers}
                    />
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
