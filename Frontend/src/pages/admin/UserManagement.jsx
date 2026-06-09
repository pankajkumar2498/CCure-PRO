import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import AppLayout from "../../components/layout/AppLayout";
import {
  listUsers,
  listRoles,
  listOrganizations,
  createUser,
  updateUser,
  changeUserRole,
  changeUserStatus,
  deleteUser,
  moveUserOrganization,
  resetUserPassword,
} from "../../api/admin";
import Button from "../../components/common/Button";
import Modal from "../../components/layout/Modal";
import UserTable from "../../components/admin/UserTable";
import UserForm from "../../components/admin/UserForm";
import ConfirmDialog from "../../components/common/ConfirmDialog";
import { useToasts, ToastContainer } from "../../components/common/Toast";
import { can, denyMessage, isOrgAdmin, isSuperAdmin } from "../../auth/permissions";

const PAGE_SIZE = 10;

export default function UserManagement() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { user: currentUser } = useAuth();

  // Data
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [organizations, setOrganizations] = useState([]);
  const [totalCount, setTotalCount] = useState(0);

  // UI state
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // Filters — initialise org from URL param if Superadmin linked here from Orgs page
  const [search, setSearch] = useState("");
  const [selectedOrgId, setSelectedOrgId] = useState(searchParams.get("org_id") || "");
  const [page, setPage] = useState(1);

  // Modals
  const [modalOpen, setModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState("create");
  const [selectedUser, setSelectedUser] = useState(null);
  const [confirmConfig, setConfirmConfig] = useState(null);
  const [resetModalOpen, setResetModalOpen] = useState(false);
  const [userToReset, setUserToReset] = useState(null);
  const [newPassword, setNewPassword] = useState("");
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();

  const isSuperadmin = isSuperAdmin(currentUser);
  const orgAdmin = isOrgAdmin(currentUser);
  const canCreateUsers = can(currentUser, "users", "create");
  const canUpdateUsers = can(currentUser, "users", "update");
  const canDeleteUsers = can(currentUser, "users", "delete");
  const assignableRoles = useMemo(() => {
    if (isSuperadmin) return roles;

    return roles.filter((role) => {
      const roleName = String(role.name || "").toLowerCase().replace(/\s+/g, "_");
      return roleName !== "superadmin";
    });
  }, [roles, isSuperadmin]);

  // ── Data loading (server-side) ────────────────────────────────────────────
  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await listUsers({
        skip: (page - 1) * PAGE_SIZE,
        limit: PAGE_SIZE,
        q: search.trim() || undefined,
        organization_id: isSuperadmin && selectedOrgId ? selectedOrgId : undefined,
      });
      setUsers(data.users || []);
      setTotalCount(data.total || 0);
    } catch {
      setError("Unable to load users. Please try again.");
    } finally {
      setLoading(false);
    }
  }, [page, search, selectedOrgId, isSuperadmin]);

  // Load roles + orgs once on mount (these rarely change)
  useEffect(() => {
    // Superadmins need the full list of roles and orgs for filters/dropdowns.
    // Org admins only manage their own users and don't need these global lists.
    if (isSuperadmin) {
      listRoles()
        .then(d => setRoles(d.roles || []))
        .catch(() => {});
      listOrganizations()
        .then(d => setOrganizations(d.organizations || []))
        .catch(() => {});
    } else {
      // Org admins still need the roles list to assign roles (filtered in assignableRoles)
      listRoles()
        .then(d => setRoles(d.roles || []))
        .catch(() => {});
    }
  }, []);

  // Reload users when filters/page change
  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  // Reset to page 1 when search or org filter changes
  useEffect(() => {
    setPage(1);
  }, [search, selectedOrgId]);

  // Resolve the display name of the currently filtered org
  const filteredOrgName = selectedOrgId
    ? (organizations.find(o => String(o.id) === String(selectedOrgId))?.name || "")
    : "";

  // ── Modal helpers ─────────────────────────────────────────────────────────
  const openCreateModal = () => {
    if (!canCreateUsers) {
      pushToast(denyMessage, "error");
      return;
    }
    setModalMode("create");
    setSelectedUser(null);
    setModalOpen(true);
  };

  const openEditModal = (user) => {
    if (!canUpdateUsers) {
      pushToast(denyMessage, "error");
      return;
    }
    setSelectedUser(user);
    setModalMode("edit");
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setSelectedUser(null);
  };

  // ── CRUD handlers ─────────────────────────────────────────────────────────
  const handleCreateUser = async (data) => {
    if (!canCreateUsers) {
      pushToast(denyMessage, "error");
      return;
    }
    setBusy(true);
    try {
      await createUser(data);
      pushToast("User created successfully.", "success");
      closeModal();
      await loadUsers();
    } catch (err) {
      pushToast(err?.response?.data?.detail || "Failed to create user.", "error");
    } finally {
      setBusy(false);
    }
  };

  const handleUpdateUser = async (data) => {
    if (!canUpdateUsers) {
      pushToast(denyMessage, "error");
      return;
    }
    if (!selectedUser) return;
    setBusy(true);
    try {
      await updateUser(selectedUser.id, {
        full_name: data.full_name,
        email: data.email,
      });

      if (String(data.role_id) !== String(selectedUser.role_id)) {
        await changeUserRole(selectedUser.id, data.role_id);
      }

      if (
        data.organization_id &&
        String(data.organization_id) !== String(selectedUser.organization_id || selectedUser.org_id)
      ) {
        await moveUserOrganization(selectedUser.id, data.organization_id);
        if (currentUser.id === selectedUser.id) {
          pushToast("Organization changed. You will need to log in again.", "warning");
        }
      }

      pushToast("User updated successfully.", "success");
      closeModal();
      await loadUsers();
    } catch (err) {
      pushToast(err?.response?.data?.detail || "Failed to update user.", "error");
    } finally {
      setBusy(false);
    }
  };

  const handleToggleStatus = (user) => {
    if (!canUpdateUsers) {
      pushToast(denyMessage, "error");
      return;
    }
    const action = user.is_active ? "Deactivate" : "Activate";
    setConfirmConfig({
      title: `${action} user`,
      subtitle: `This will ${action.toLowerCase()} ${user.username}.`,
      warning: "Users can be re-activated later by an administrator.",
      confirmLabel: action,
      confirmType: "info",
      icon: "⏻",
      iconClass: "info",
      onConfirm: async () => {
        setBusy(true);
        try {
          await changeUserStatus(user.id, { is_active: !user.is_active });
          setUsers((prev) =>
            prev.map((u) =>
              u.id === user.id ? { ...u, is_active: !u.is_active } : u
            )
          );
          pushToast(`User ${user.username} ${user.is_active ? "deactivated" : "activated"}.`, "success");
        } catch (err) {
          pushToast(err?.response?.data?.detail || "Unable to update user status.", "error");
        } finally {
          setBusy(false);
          setConfirmConfig(null);
        }
      },
      onCancel: () => setConfirmConfig(null),
    });
  };

  const handleUnlockUser = async (user) => {
    if (!canUpdateUsers) {
      pushToast(denyMessage, "error");
      return;
    }
    setBusy(true);
    try {
      await changeUserStatus(user.id, { locked_until: null });
      setUsers((prev) =>
        prev.map((u) => (u.id === user.id ? { ...u, locked_until: null } : u))
      );
      pushToast("User unlocked successfully.", "success");
    } catch (err) {
      pushToast(err?.response?.data?.detail || "Unable to unlock user.", "error");
    } finally {
      setBusy(false);
    }
  };

  const handleOpenResetModal = (user) => {
    if (!canUpdateUsers) {
      pushToast(denyMessage, "error");
      return;
    }
    setUserToReset(user);
    setNewPassword("");
    setResetModalOpen(true);
  };

  const handleResetPasswordSubmit = async (e) => {
    e.preventDefault();
    if (!newPassword.trim() || !userToReset) return;
    setBusy(true);
    try {
      await resetUserPassword(userToReset.id, newPassword);
      pushToast(`Password reset successfully for ${userToReset.username}.`, "success");
      if (currentUser && String(currentUser.id) === String(userToReset.id)) {
        pushToast("You reset your own password. Please log in again using the new password.", "warning");
      }
      setResetModalOpen(false);
      setUserToReset(null);
      setNewPassword("");
    } catch (err) {
      let errMsg = "Failed to reset password.";
      if (err.response?.data?.detail) {
        const detail = err.response.data.detail;
        errMsg = Array.isArray(detail) ? detail.map(d => d.msg).join(", ") : detail;
      }
      pushToast(errMsg, "error");
    } finally {
      setBusy(false);
    }
  };

  const handleDeleteUser = (user) => {
    if (!canDeleteUsers) {
      pushToast(denyMessage, "error");
      return;
    }
    setConfirmConfig({
      title: `Move ${user.username} to Deleted Users`,
      subtitle: "This is a soft delete. The user will be removed from the active user list.",
      warning: "The account becomes inactive immediately and can later be restored from Deleted Users.",
      confirmLabel: "Move to deleted users",
      confirmType: "danger",
      icon: "🗑️",
      iconClass: "danger",
      onConfirm: async () => {
        setBusy(true);
        try {
          await deleteUser(user.id);
          setUsers((prev) => prev.filter((u) => u.id !== user.id));
          setTotalCount((prev) => Math.max(0, prev - 1));
          pushToast("User moved to Deleted Users.", "success");
        } catch (err) {
          pushToast(err?.response?.data?.detail || "Unable to delete user.", "error");
        } finally {
          setBusy(false);
          setConfirmConfig(null);
        }
      },
      onCancel: () => setConfirmConfig(null),
    });
  };

  // ── Subtitle for page header ──────────────────────────────────────────────
  const subtitle = isSuperadmin
    ? filteredOrgName
      ? `Viewing ${totalCount} user${totalCount !== 1 ? "s" : ""} in ${filteredOrgName}`
      : `${totalCount} total users across all organizations`
    : `${totalCount} user${totalCount !== 1 ? "s" : ""} in your organization`;

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <AppLayout pageTitle="User Management">
      <div className="page-inner">
        {/* Header */}
        <div className="page-title-row">
          <div>
            <h2 className="page-title">User Management</h2>
            <p className="page-subtitle">{subtitle}</p>
            {orgAdmin && (
              <p className="page-note">
                Org admins can only manage users in their own organization.
              </p>
            )}
          </div>
          <div className="page-actions-row">
            {canDeleteUsers && (
              <Button type="button" variant="ghost" size="sm" onClick={() => navigate("/admin/users/deleted")} disabled={busy}>
                Deleted users
              </Button>
            )}
            <Button type="button" variant="ghost" size="sm" onClick={loadUsers} disabled={loading || busy}>
              {loading ? "Refreshing..." : "Refresh"}
            </Button>
            {canCreateUsers && (
              <Button type="button" variant="primary" size="sm" onClick={openCreateModal} disabled={busy}>
                + Create user
              </Button>
            )}
          </div>
        </div>

        {error && <div className="alert alert--error">{error}</div>}

        {/* Filters toolbar */}
        <div className="table-filters-row">
          <div className="search-box">
            <span className="search-icon">🔍</span>
            <input
              type="text"
              placeholder="Search by username, email or name..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="search-input"
            />
          </div>
          {isSuperadmin && (
            <select
              className="org-filter-select"
              value={selectedOrgId}
              onChange={(e) => setSelectedOrgId(e.target.value)}
              title="Filter by organization"
            >
              <option value="">All Organizations</option>
              {organizations.map((org) => (
                <option key={org.id} value={org.id}>{org.name}</option>
              ))}
            </select>
          )}
        </div>

        {/* Table — server-side data, no client-side slicing */}
        <UserTable
          users={users}
          roles={roles}
          organizations={organizations}
          showOrganizationColumn={!orgAdmin}
          loading={loading}
          search={search}
          onSearch={setSearch}
          page={page}
          pageSize={PAGE_SIZE}
          onPageChange={setPage}
          totalCount={totalCount}
          currentUser={currentUser}
          onEdit={openEditModal}
          onResetPassword={handleOpenResetModal}
          onToggleStatus={handleToggleStatus}
          onUnlock={handleUnlockUser}
          onDelete={handleDeleteUser}
          canUpdateUsers={canUpdateUsers}
          canDeleteUsers={canDeleteUsers}
        />
      </div>

      <Modal
        isOpen={modalOpen}
        title={modalMode === "create" ? "Create new user" : selectedUser ? `Edit ${selectedUser.username}` : "Edit user"}
        size="medium"
        onClose={closeModal}
      >
        <UserForm
          mode={modalMode}
          user={selectedUser}
          roles={assignableRoles}
          organizations={organizations}
          currentUser={currentUser}
          onSubmit={modalMode === "create" ? handleCreateUser : handleUpdateUser}
          onCancel={closeModal}
          busy={busy}
        />
      </Modal>

      <Modal
        isOpen={resetModalOpen}
        title={`Reset Password for ${userToReset?.username || ""}`}
        size="small"
        onClose={() => {
          setResetModalOpen(false);
          setUserToReset(null);
          setNewPassword("");
        }}
      >
        <div className="card card--admin-form" style={{ background: "transparent", border: "none", padding: 0, boxShadow: "none" }}>
          <div className="form-card-header" style={{ padding: 0, marginBottom: 20 }}>
            <div>
              <h3 className="card-title">Reset User Password</h3>
              <p className="card-subtitle">
                Enter a new secure password for <strong>{userToReset?.username}</strong>.
              </p>
            </div>
          </div>

          <form className="form-horizontal" onSubmit={handleResetPasswordSubmit}>
            <div className="alert alert--warning" style={{ marginBottom: 16 }}>
              ⚠️ Resetting the password will immediately terminate all active sessions for this user.
            </div>

            <div className="field">
              <label htmlFor="reset-new-password">New Password</label>
              <input
                id="reset-new-password"
                className="field-input"
                type="password"
                placeholder="Enter new secure password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                disabled={busy}
                required
              />
              <span className="field-hint">
                Must be at least 12 characters and contain uppercase, lowercase, numbers, and special characters.
              </span>
            </div>

            <div className="form-action-row" style={{ marginTop: 24 }}>
              <Button
                type="button"
                variant="ghost"
                size="md"
                onClick={() => {
                  setResetModalOpen(false);
                  setUserToReset(null);
                  setNewPassword("");
                }}
                disabled={busy}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                variant="primary"
                size="md"
                loading={busy}
                disabled={busy || !newPassword.trim()}
              >
                Reset Password
              </Button>
            </div>
          </form>
        </div>
      </Modal>

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
