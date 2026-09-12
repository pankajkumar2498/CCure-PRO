/**
 * components/admin/UserTable.jsx — Checkpoint 3C batch 13.
 *
 * Same props and the same per-row gating as before: edit / reset password /
 * unlock / deactivate need `canUpdateUsers`, delete needs `canDeleteUsers`,
 * MFA reset needs the user to have MFA on, and nobody can deactivate, delete
 * or MFA-reset THEMSELVES. A row with neither permission says "Read only".
 *
 * On CcureTable: a caption, `scope` on every header, the username cell as the
 * row header. Every action button carries the username in its accessible
 * name ("Delete alice") — a table of ten identical "Delete" buttons is
 * unusable from a screen reader — while the visible label stays short.
 */
import {
  CcureBadge,
  CcureButton,
  CcureEmptyState,
  CcureLoader,
  CcureTable,
} from "../../design-system";

const STATUS = {
  active: { label: "Active", variant: "success" },
  inactive: { label: "Inactive", variant: "neutral" },
  locked: { label: "Locked", variant: "danger" },
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
    ? STATUS.locked
    : user.is_active
      ? STATUS.active
      : STATUS.inactive;
  const isSelf = currentUser && String(currentUser.id) === String(user.id);
  const who = user.username;

  return (
    <tr>
      <th scope="row">
        <div className="um-identity">
          <span className="um-identity__name">{user.username}</span>
          <span className="um-identity__sub">{user.email}</span>
        </div>
      </th>
      <td>{user.full_name || "—"}</td>
      <td>{roleName || "—"}</td>
      {showOrganizationColumn && <td>{organizationName || "—"}</td>}
      <td>
        <CcureBadge variant={status.variant}>{status.label}</CcureBadge>
      </td>
      <td className="cc-table__cell--nowrap">
        {user.last_login_at
          ? new Date(user.last_login_at).toLocaleString()
          : "Never"}
      </td>
      <td className="cc-table__cell--end">
        <div className="um-actions">
          {canUpdateUsers && (
            <CcureButton
              variant="ghost"
              size="sm"
              aria-label={`Edit ${who}`}
              onClick={() => onEdit(user)}
            >
              Edit
            </CcureButton>
          )}
          {canUpdateUsers && (
            <CcureButton
              variant="ghost"
              size="sm"
              aria-label={`Reset password for ${who}`}
              onClick={() => onResetPassword(user)}
            >
              Reset password
            </CcureButton>
          )}
          {canUpdateUsers && user.mfa_enabled && !isSelf && (
            <CcureButton
              variant="ghost"
              size="sm"
              aria-label={`Reset MFA for ${who}`}
              onClick={() => onResetMfa(user)}
            >
              Reset MFA
            </CcureButton>
          )}
          {isLocked && canUpdateUsers && (
            <CcureButton
              variant="secondary"
              size="sm"
              aria-label={`Unlock ${who}`}
              onClick={() => onUnlock(user)}
            >
              Unlock
            </CcureButton>
          )}
          {!isSelf && (canUpdateUsers || canDeleteUsers) && (
            <>
              {canUpdateUsers && (
                <CcureButton
                  variant="secondary"
                  size="sm"
                  aria-label={
                    user.is_active ? `Deactivate ${who}` : `Activate ${who}`
                  }
                  onClick={() => onToggleStatus(user)}
                >
                  {user.is_active ? "Deactivate" : "Activate"}
                </CcureButton>
              )}
              {canDeleteUsers && (
                <CcureButton
                  variant="danger"
                  size="sm"
                  aria-label={`Delete ${who}`}
                  onClick={() => onDelete(user)}
                >
                  Delete
                </CcureButton>
              )}
            </>
          )}
          {!canUpdateUsers && !canDeleteUsers && (
            <span className="um-readonly">Read only</span>
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
  const columns = [
    { key: "user", header: "User" },
    { key: "full_name", header: "Full name" },
    { key: "role", header: "Role" },
    ...(showOrganizationColumn
      ? [{ key: "organization", header: "Organization" }]
      : []),
    { key: "status", header: "Status" },
    { key: "last_login", header: "Last login" },
    { key: "actions", header: "Actions", align: "end" },
  ];

  if (loading) {
    return (
      <div className="um-table-state">
        <CcureLoader label="Loading users..." />
      </div>
    );
  }

  if (users.length === 0) {
    return (
      <CcureEmptyState
        icon="👥"
        title="No users found"
        description="Try a different search term or add a new user to get started."
      />
    );
  }

  return (
    <div
      className={`um-table${refreshing ? " um-table--refreshing" : ""}`}
      aria-busy={refreshing || undefined}
    >
      <CcureTable
        caption="Users: role assignment, account status, and organization"
        columns={columns}
        density="compact"
      >
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
      </CcureTable>
    </div>
  );
}
