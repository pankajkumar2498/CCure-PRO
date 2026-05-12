import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../../components/layout/AppLayout";
import Button from "../../components/common/Button";
import ConfirmDialog from "../../components/common/ConfirmDialog";
import EmptyState from "../../components/common/EmptyState";
import Loader from "../../components/common/Loader";
import { useToasts, ToastContainer } from "../../components/common/Toast";
import { listOrganizations, listRoles, listUsers, purgeUser, restoreUser } from "../../api/admin";
import { useAuth } from "../../context/AuthContext";
import { can, denyMessage } from "../../auth/permissions";

const PAGE_SIZE = 10;

function formatDate(value) {
  if (!value) return "Never";
  return new Date(value).toLocaleString();
}

function resolveOrganizationName(user, organizations) {
  return organizations.find(
    (organization) => String(organization.id) === String(user.organization_id || user.org_id)
  )?.name || "—";
}

function resolveRoleName(user, roles) {
  return roles.find((role) => String(role.id) === String(user.role_id))?.name || "—";
}

export default function DeletedUsers() {
  const navigate = useNavigate();
  const { user: currentUser } = useAuth();
  const canDeleteUsers = can(currentUser, "users", "delete");
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [organizations, setOrganizations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [confirmConfig, setConfirmConfig] = useState(null);
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();

  const loadData = useCallback(async () => {
    setLoading(true);
    setError("");
    const isSuperadmin = currentUser?.role?.name?.toLowerCase() === "superadmin";

    try {
      const [usersData, rolesData, organizationsData] = await Promise.all([
        listUsers({ skip: 0, limit: 100, scope: "deleted" }),
        listRoles(),
        isSuperadmin ? listOrganizations().catch(() => null) : Promise.resolve(null),
      ]);

      setUsers(usersData.users || []);
      setRoles(rolesData.roles || []);
      setOrganizations(organizationsData?.organizations || []);
    } catch (err) {
      console.error(err);
      setError("Failed to load deleted users.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    setPage(1);
  }, [search]);

  const filteredUsers = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return users;

    return users.filter((user) => {
      const organizationName = resolveOrganizationName(user, organizations);
      const roleName = resolveRoleName(user, roles);
      return [user.username, user.full_name, user.email, organizationName, roleName]
        .join(" ")
        .toLowerCase()
        .includes(query);
    });
  }, [organizations, roles, search, users]);

  const totalCount = filteredUsers.length;
  const pageCount = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
  const pagedUsers = filteredUsers.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const startIndex = totalCount === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const endIndex = totalCount === 0 ? 0 : Math.min(startIndex + pagedUsers.length - 1, totalCount);

  useEffect(() => {
    if (page > pageCount) {
      setPage(pageCount);
    }
  }, [page, pageCount]);

  const handleRestore = (user) => {
    if (!canDeleteUsers) {
      pushToast(denyMessage, "error");
      return;
    }
    setConfirmConfig({
      title: `Restore ${user.username}`,
      subtitle: "This will return the account to the normal user list.",
      warning: "For safety, restored users stay inactive until an admin explicitly activates them.",
      confirmLabel: "Restore user",
      confirmType: "info",
      icon: "↺",
      iconClass: "info",
      onConfirm: async () => {
        setBusyId(user.id);
        try {
          await restoreUser(user.id);
          setUsers((prev) => prev.filter((entry) => entry.id !== user.id));
          pushToast("User restored successfully. The account remains inactive.", "success");
        } catch (err) {
          pushToast(err?.response?.data?.detail || "Failed to restore user.", "error");
        } finally {
          setBusyId(null);
          setConfirmConfig(null);
        }
      },
      onCancel: () => setConfirmConfig(null),
    });
  };

  const handlePermanentDelete = (user) => {
    if (!canDeleteUsers) {
      pushToast(denyMessage, "error");
      return;
    }
    setConfirmConfig({
      title: `Permanently delete ${user.username}?`,
      subtitle: "This action cannot be undone. The user record will be removed from the system.",
      warning: "Audit and ownership history will be preserved where supported, but the user account itself cannot be recovered after purge.",
      confirmLabel: "Delete permanently",
      confirmType: "danger",
      icon: "🗑️",
      iconClass: "danger",
      onConfirm: async () => {
        setBusyId(user.id);
        try {
          await purgeUser(user.id);
          setUsers((prev) => prev.filter((entry) => entry.id !== user.id));
          pushToast("User permanently deleted.", "success");
        } catch (err) {
          pushToast(err?.response?.data?.detail || "Failed to permanently delete user.", "error");
        } finally {
          setBusyId(null);
          setConfirmConfig(null);
        }
      },
      onCancel: () => setConfirmConfig(null),
    });
  };

  return (
    <AppLayout pageTitle="Deleted Users">
      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Deleted Users</h2>
            <p className="page-subtitle">{users.length} deleted user{users.length !== 1 ? "s" : ""} available for restore or permanent deletion</p>
            <p className="page-note">This works like the scan Recycle Bin. Only deleted users in your allowed organization scope appear here.</p>
          </div>
          <div className="page-actions-row">
            <Button type="button" variant="ghost" size="sm" onClick={() => navigate("/admin/users")} disabled={busyId !== null}>
              Active users
            </Button>
            <Button type="button" variant="ghost" size="sm" onClick={loadData} disabled={loading || busyId !== null}>
              {loading ? "Refreshing..." : "Refresh"}
            </Button>
          </div>
        </div>

        {error && <div className="alert alert--error">{error}</div>}

        <div className="card card--admin-table">
          <div className="table-card-header">
            <div>
              <h3 className="card-title">Deleted Users</h3>
              <p className="card-subtitle">Restore accounts safely or permanently delete them from the database.</p>
            </div>
            <div className="table-controls">
              <label className="field-label" htmlFor="deleted-user-search">
                Search deleted users
              </label>
              <div className="search-field">
                <span className="search-icon">🔍</span>
                <input
                  id="deleted-user-search"
                  className="field-input"
                  type="search"
                  placeholder="Search by name, username, email, or organization"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                />
              </div>
            </div>
          </div>

          {loading ? (
            <div className="table-loading-shell">
              <Loader label="Loading deleted users..." />
            </div>
          ) : totalCount === 0 ? (
            <EmptyState
              icon="🗑️"
              title="Deleted Users is empty"
              description="Soft-deleted users will appear here for restore or permanent deletion."
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
                      <th>Organization</th>
                      <th>Deleted</th>
                      <th>Last login</th>
                      <th style={{ textAlign: "right" }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pagedUsers.map((user) => (
                      <tr key={user.id}>
                        <td>
                          <div className="table-cell-identity">
                            <span className="table-username">{user.username}</span>
                            <span className="table-subtext">{user.email}</span>
                          </div>
                        </td>
                        <td>{user.full_name || "—"}</td>
                        <td>{resolveRoleName(user, roles)}</td>
                        <td>{resolveOrganizationName(user, organizations)}</td>
                        <td>{formatDate(user.deleted_at)}</td>
                        <td>{formatDate(user.last_login_at)}</td>
                        <td>
                          <div className="action-btns table-action-cell">
                            {canDeleteUsers ? (
                              <>
                                <Button
                                  type="button"
                                  variant="secondary"
                                  size="sm"
                                  onClick={() => handleRestore(user)}
                                  disabled={busyId === user.id}
                                >
                                  Restore
                                </Button>
                                <Button
                                  type="button"
                                  variant="danger"
                                  size="sm"
                                  onClick={() => handlePermanentDelete(user)}
                                  disabled={busyId === user.id}
                                >
                                  Delete permanently
                                </Button>
                              </>
                            ) : (
                              <span className="text-muted">Read only</span>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="pagination-row">
                <div className="pagination-summary">
                  Showing {startIndex}-{endIndex} of {totalCount} deleted users
                </div>
                <div className="pagination-controls">
                  <Button type="button" variant="ghost" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
                    Prev
                  </Button>
                  <span className="pagination-page">
                    Page {page} of {pageCount}
                  </span>
                  <Button type="button" variant="ghost" size="sm" disabled={page >= pageCount} onClick={() => setPage(page + 1)}>
                    Next
                  </Button>
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      <ConfirmDialog
        open={Boolean(confirmConfig)}
        title={confirmConfig?.title}
        subtitle={confirmConfig?.subtitle}
        warning={confirmConfig?.warning}
        confirmLabel={confirmConfig?.confirmLabel}
        confirmType={confirmConfig?.confirmType}
        icon={confirmConfig?.icon}
        iconClass={confirmConfig?.iconClass}
        onConfirm={confirmConfig?.onConfirm}
        onCancel={confirmConfig?.onCancel}
      />

      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </AppLayout>
  );
}
