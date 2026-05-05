import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
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
} from "../../api/admin";
import Button from "../../components/common/Button";
import Modal from "../../components/layout/Modal";
import UserTable from "../../components/admin/UserTable";
import UserForm from "../../components/admin/UserForm";
import ConfirmDialog from "../../components/common/ConfirmDialog";
import { useToasts, ToastContainer } from "../../components/common/Toast";

const PAGE_SIZE = 10;

export default function UserManagement() {
  const navigate = useNavigate();
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [organizations, setOrganizations] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [modalOpen, setModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState("create");
  const [selectedUser, setSelectedUser] = useState(null);
  const [confirmConfig, setConfirmConfig] = useState(null);
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();

  const loadData = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const [usersData, rolesData, organizationsData] = await Promise.all([
        listUsers({ skip: 0, limit: 100 }),
        listRoles(),
        listOrganizations().catch(() => null),
      ]);

      setUsers(usersData.users || []);
      setTotalCount(usersData.total ?? (usersData.users || []).length);
      setRoles(rolesData.roles || []);
      setOrganizations(organizationsData?.organizations || []);
    } catch (err) {
      console.error(err);
      setError("Unable to load users and roles. Please try again.");
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

  const normalizedRoleName = (currentUser?.role?.name || "").toLowerCase().replace(/\s+/g, "_");
  const isOrgAdmin = normalizedRoleName === "org_admin";
  const currentOrganizationName = currentUser?.organization?.name || "";

  const filteredUsers = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return users;

    return users.filter((user) => {
      const roleName = roles.find((role) => String(role.id) === String(user.role_id))?.name || "";
      const organizationName = organizations.find(
        (organization) => String(organization.id) === String(user.organization_id || user.org_id)
      )?.name || "";

      return [user.username, user.full_name, user.email, roleName, organizationName]
        .join(" ")
        .toLowerCase()
        .includes(query);
    });
  }, [organizations, roles, search, users]);

  const pageCount = Math.max(1, Math.ceil(filteredUsers.length / PAGE_SIZE));
  const pagedUsers = filteredUsers.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  useEffect(() => {
    if (page > pageCount) {
      setPage(pageCount);
    }
  }, [page, pageCount]);

  const openCreateModal = () => {
    setModalMode("create");
    setSelectedUser(null);
    setModalOpen(true);
  };

  const openEditModal = (user) => {
    setSelectedUser(user);
    setModalMode("edit");
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setSelectedUser(null);
  };

  const handleCreateUser = async (data) => {
    setBusy(true);
    try {
      await createUser(data);
      pushToast("User created successfully.", "success");
      closeModal();
      await loadData();
    } catch (err) {
      pushToast(err?.response?.data?.detail || "Failed to create user.", "error");
    } finally {
      setBusy(false);
    }
  };

  const handleUpdateUser = async (data) => {
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

      pushToast("User updated successfully.", "success");
      closeModal();
      await loadData();
    } catch (err) {
      pushToast(err?.response?.data?.detail || "Failed to update user.", "error");
    } finally {
      setBusy(false);
    }
  };

  const handleToggleStatus = (user) => {
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
          setUsers((prevUsers) =>
            prevUsers.map((existingUser) =>
              existingUser.id === user.id
                ? { ...existingUser, is_active: !existingUser.is_active }
                : existingUser
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
    setBusy(true);
    try {
      await changeUserStatus(user.id, { locked_until: null });
      setUsers((prevUsers) =>
        prevUsers.map((existingUser) =>
          existingUser.id === user.id ? { ...existingUser, locked_until: null } : existingUser
        )
      );
      pushToast("User unlocked successfully.", "success");
    } catch (err) {
      pushToast(err?.response?.data?.detail || "Unable to unlock user.", "error");
    } finally {
      setBusy(false);
    }
  };

  const handleDeleteUser = (user) => {
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
          setUsers((prevUsers) => prevUsers.filter((existingUser) => existingUser.id !== user.id));
          setTotalCount((prevCount) => Math.max(0, prevCount - 1));
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

  return (
    <AppLayout pageTitle="User Management">
      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h2 className="page-title">User Management</h2>
            <p className="page-subtitle">{totalCount} users in your organization</p>
            <p className="page-note">
              {isOrgAdmin && currentOrganizationName
                ? `Showing active users in ${currentOrganizationName}. Org admins can only manage users in their own org.`
                : "Showing active users in your organization. Org admins can only manage users in their own org."}
            </p>
          </div>
          <div className="page-actions-row">
            <Button type="button" variant="ghost" size="sm" onClick={() => navigate("/admin/deleted-users")} disabled={busy}>
              Deleted users
            </Button>
            <Button type="button" variant="ghost" size="sm" onClick={loadData} disabled={loading || busy}>
              {loading ? "Refreshing..." : "Refresh"}
            </Button>
            <Button type="button" variant="primary" size="sm" onClick={openCreateModal} disabled={busy}>
              + Create user
            </Button>
          </div>
        </div>

        {error && <div className="alert alert--error">{error}</div>}

        <UserTable
          users={pagedUsers}
          roles={roles}
          organizations={organizations}
          showOrganizationColumn={!isOrgAdmin}
          loading={loading}
          search={search}
          onSearch={setSearch}
          page={page}
          pageSize={PAGE_SIZE}
          onPageChange={setPage}
          totalCount={filteredUsers.length}
          onEdit={openEditModal}
          onToggleStatus={handleToggleStatus}
          onUnlock={handleUnlockUser}
          onDelete={handleDeleteUser}
        />
      </div>

      <Modal
        isOpen={modalOpen}
        title={modalMode === "create" ? "Create new user" : selectedUser ? `Edit ${selectedUser.username}` : "Edit user"}
        onClose={closeModal}
      >
        <UserForm
          mode={modalMode}
          user={selectedUser}
          roles={roles}
          organizations={organizations}
          currentUser={currentUser}
          onSubmit={modalMode === "create" ? handleCreateUser : handleUpdateUser}
          onCancel={closeModal}
          busy={busy}
        />
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
