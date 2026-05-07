import EmptyState from "../common/EmptyState";
import Loader from "../common/Loader";
import Button from "../common/Button";

const statusConfig = {
  active: { label: "Active", className: "chip chip--active" },
  inactive: { label: "Inactive", className: "chip chip--inactive" },
  locked: { label: "Locked", className: "chip chip--danger" },
};

function TableRow({ user, currentUser, roleName, organizationName, showOrganizationColumn, onEdit, onToggleStatus, onUnlock, onDelete }) {
  const isLocked = user.locked_until && new Date(user.locked_until) > new Date();
  const status = isLocked ? statusConfig.locked : user.is_active ? statusConfig.active : statusConfig.inactive;
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
      <td>{user.last_login_at ? new Date(user.last_login_at).toLocaleString() : "Never"}</td>
      <td>
        <div className="action-btns table-action-cell">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            title="Edit user"
            onClick={() => onEdit(user)}
          >
            ✏️ Edit
          </Button>
          {isLocked && (
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
          {!isSelf && (
            <>
              <Button
                type="button"
                variant="secondary"
                size="sm"
                title={user.is_active ? "Deactivate user" : "Activate user"}
                onClick={() => onToggleStatus(user)}
              >
                {user.is_active ? "⏻ Deactivate" : "▶ Activate"}
              </Button>
              <Button
                type="button"
                variant="danger"
                size="sm"
                title="Delete user"
                onClick={() => onDelete(user)}
              >
                🗑️ Delete
              </Button>
            </>
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
  search,
  onSearch,
  page,
  pageSize,
  onPageChange,
  totalCount,
  currentUser,
  onEdit,
  onToggleStatus,
  onUnlock,
  onDelete,
}) {
  const startIndex = Math.min((page - 1) * pageSize + 1, totalCount);
  const endIndex = Math.min(startIndex + users.length - 1, totalCount);
  const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));

  return (
    <div className="card card--admin-table">
      <div className="table-card-header">
        <div>
          <h3 className="card-title">Users</h3>
          <p className="card-subtitle">Review users, role assignment, account status, and organization.</p>
        </div>
        <div className="table-controls">
          <label className="field-label" htmlFor="user-search">
            Search users
          </label>
          <div className="search-field">
            <span className="search-icon">🔍</span>
            <input
              id="user-search"
              className="field-input"
              type="search"
              placeholder="Search by name, username, email, or organization"
              value={search}
              onChange={(event) => onSearch(event.target.value)}
            />
          </div>
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
        <>
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
                  const roleName = roles.find((role) => String(role.id) === String(user.role_id))?.name;
                  const organizationName = organizations.find(
                    (organization) => String(organization.id) === String(user.organization_id || user.org_id)
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
                      onToggleStatus={onToggleStatus}
                      onUnlock={onUnlock}
                      onDelete={onDelete}
                    />
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="pagination-row">
            <div className="pagination-summary">
              Showing {startIndex}–{endIndex} of {totalCount} users
            </div>
            <div className="pagination-controls">
              <Button type="button" variant="ghost" size="sm" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>
                Prev
              </Button>
              <span className="pagination-page">
                Page {page} of {totalPages}
              </span>
              <Button type="button" variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}>
                Next
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
