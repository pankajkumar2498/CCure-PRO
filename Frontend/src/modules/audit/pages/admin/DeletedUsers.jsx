/**
 * src/modules/audit/pages/admin/DeletedUsers.jsx
 * Soft-deleted accounts — restore, or purge from the database.
 *
 * ── Contract, unchanged by the Checkpoint 3C migration ──────────────────────
 * Every request, permission check, filter, page calculation and state
 * transition below is what it was before. The migration changed presentation
 * only. Specifically preserved:
 *
 *   * `listUsers({ skip: 0, limit: 100, scope: "deleted" })` — the scope is
 *     load-bearing; without it this lists live accounts on a page whose second
 *     button deletes them permanently;
 *   * the organisation list is requested only for a superadmin, and the role
 *     name that decides it is read from `currentUser.role.name`. `role` is an
 *     object throughout this application; comparing it to a string silently
 *     takes the non-superadmin path and leaves the column empty;
 *   * `loadData` keeps `currentUser?.role?.name` in its dependency list. It was
 *     excluded once, and a render where auth had not yet hydrated then loaded
 *     the page as a non-superadmin and never retried;
 *   * both actions stay gated on `users:delete`, at render *and* inside the
 *     handler, and both require an explicit confirmation — restore included,
 *     because returning an account somebody deliberately deleted is a decision
 *     of its own;
 *   * the restore confirmation states that a restored account stays INACTIVE.
 *     The backend enforces it; this wording is the only thing telling the
 *     administrator that restoring is not re-enabling;
 *   * client-side search and 10-per-page paging are unchanged, including the
 *     effect that pulls the user back when a filter shortens the list.
 *
 * src/__tests__/pages/admin/DeletedUsers.test.jsx asserts all of this and was
 * written against the pre-migration page.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import { useToasts, ToastContainer } from "@audit/components/common/Toast";
import {
  listOrganizations,
  listRoles,
  listUsers,
  purgeUser,
  restoreUser,
} from "@audit/api/admin";
import { useAuth } from "@shell/auth/AuthContext";
import { can, denyMessage } from "@shell/auth/permissions";
import {
  CcureAlert,
  CcureButton,
  CcureConfirmDialog,
  CcureEmptyState,
  CcureInput,
  CcureLoader,
  CcurePagination,
  CcureTable,
} from "../../../../design-system";
import "../../styles/deleted-users.css";

const PAGE_SIZE = 10;

function formatDate(value) {
  if (!value) return "Never";
  return new Date(value).toLocaleString();
}

function resolveOrganizationName(user, organizations) {
  return (
    organizations.find(
      (organization) =>
        String(organization.id) === String(user.organization_id || user.org_id),
    )?.name || "—"
  );
}

function resolveRoleName(user, roles) {
  return (
    roles.find((role) => String(role.id) === String(user.role_id))?.name || "—"
  );
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
    const isSuperadmin =
      currentUser?.role?.name?.toLowerCase() === "superadmin";

    try {
      const [usersData, rolesData, organizationsData] = await Promise.all([
        listUsers({ skip: 0, limit: 100, scope: "deleted" }),
        listRoles(),
        isSuperadmin
          ? listOrganizations().catch(() => null)
          : Promise.resolve(null),
      ]);

      setUsers(usersData.users || []);
      setRoles(rolesData.roles || []);
      setOrganizations(organizationsData?.organizations || []);
    } catch {
      setError("Failed to load deleted users.");
    } finally {
      setLoading(false);
    }
    // The role name is read above to decide whether to ask for the
    // organization list. It was excluded, so a render where auth had not yet
    // hydrated loaded the page with `isSuperadmin` false and never retried —
    // a superadmin saw an empty organization column. It is a primitive, so it
    // settles once and reloads at most one extra time.
  }, [currentUser?.role?.name]);

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
      return [
        user.username,
        user.full_name,
        user.email,
        organizationName,
        roleName,
      ]
        .join(" ")
        .toLowerCase()
        .includes(query);
    });
  }, [organizations, roles, search, users]);

  const totalCount = filteredUsers.length;
  const pageCount = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
  const pagedUsers = filteredUsers.slice(
    (page - 1) * PAGE_SIZE,
    page * PAGE_SIZE,
  );

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
      warning:
        "For safety, restored users stay inactive until an admin explicitly activates them.",
      confirmLabel: "Restore user",
      tone: "info",
      onConfirm: async () => {
        setBusyId(user.id);
        try {
          await restoreUser(user.id);
          setUsers((prev) => prev.filter((entry) => entry.id !== user.id));
          pushToast(
            "User restored successfully. The account remains inactive.",
            "success",
          );
        } catch (err) {
          pushToast(
            err?.response?.data?.detail || "Failed to restore user.",
            "error",
          );
        } finally {
          setBusyId(null);
          setConfirmConfig(null);
        }
      },
    });
  };

  const handlePermanentDelete = (user) => {
    if (!canDeleteUsers) {
      pushToast(denyMessage, "error");
      return;
    }
    setConfirmConfig({
      title: `Permanently delete ${user.username}?`,
      subtitle:
        "This action cannot be undone. The user record will be removed from the system.",
      warning:
        "Audit and ownership history will be preserved where supported, but the user account itself cannot be recovered after purge.",
      confirmLabel: "Delete permanently",
      tone: "danger",
      onConfirm: async () => {
        setBusyId(user.id);
        try {
          await purgeUser(user.id);
          setUsers((prev) => prev.filter((entry) => entry.id !== user.id));
          pushToast("User permanently deleted.", "success");
        } catch (err) {
          pushToast(
            err?.response?.data?.detail || "Failed to permanently delete user.",
            "error",
          );
        } finally {
          setBusyId(null);
          setConfirmConfig(null);
        }
      },
    });
  };

  /* Declared columns, so CcureTable owns the caption, `scope="col"` on every
     header and `scope="row"` on the identifying cell — the username, which is
     what a reader needs announced alongside every other cell in the row. */
  const columns = [
    {
      key: "username",
      header: "User",
      isRowHeader: true,
      cell: (user) => (
        <span className="du-identity">
          <span className="du-username">{user.username}</span>
          <span className="du-email">{user.email}</span>
        </span>
      ),
    },
    {
      key: "full_name",
      header: "Full name",
      cell: (user) => user.full_name || "—",
    },
    {
      key: "role",
      header: "Role",
      cell: (user) => resolveRoleName(user, roles),
    },
    {
      key: "organization",
      header: "Organization",
      cell: (user) => resolveOrganizationName(user, organizations),
    },
    {
      key: "deleted_at",
      header: "Deleted",
      nowrap: true,
      cell: (user) => (
        <span className="du-muted">{formatDate(user.deleted_at)}</span>
      ),
    },
    {
      key: "last_login_at",
      header: "Last login",
      nowrap: true,
      cell: (user) => (
        <span className="du-muted">{formatDate(user.last_login_at)}</span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      align: "end",
      cell: (user) => {
        if (!canDeleteUsers) {
          return <span className="du-muted">Read only</span>;
        }
        return (
          <div className="du-actions">
            <CcureButton
              variant="secondary"
              size="sm"
              onClick={() => handleRestore(user)}
              loading={busyId === user.id}
              /* One "Restore" per row is N identical entries in a screen
                 reader's control list, with no way to tell which account each
                 belongs to. The username disambiguates. */
              aria-label={`Restore ${user.username}`}
            >
              Restore
            </CcureButton>
            <CcureButton
              variant="danger"
              size="sm"
              onClick={() => handlePermanentDelete(user)}
              loading={busyId === user.id}
              aria-label={`Delete ${user.username} permanently`}
            >
              Delete permanently
            </CcureButton>
          </div>
        );
      },
    },
  ];

  return (
    <AppLayout pageTitle="Deleted Users">
      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Deleted Users</h2>
            <p className="page-subtitle">
              {users.length} deleted user{users.length !== 1 ? "s" : ""}{" "}
              available for restore or permanent deletion
            </p>
            <p className="page-note">
              This works like the scan Recycle Bin. Only deleted users in your
              allowed organization scope appear here.
            </p>
          </div>
          <div className="du-toolbar">
            <CcureButton
              variant="ghost"
              size="sm"
              onClick={() => navigate("/admin/users")}
              disabled={busyId !== null}
            >
              Active users
            </CcureButton>
            <CcureButton
              variant="ghost"
              size="sm"
              onClick={loadData}
              loading={loading}
              disabled={busyId !== null}
            >
              Refresh
            </CcureButton>
          </div>
        </div>

        {error && (
          <CcureAlert variant="danger" className="du-message">
            {error}
          </CcureAlert>
        )}

        <div className="du-panel">
          <div className="du-panel-header">
            <div>
              <h3 className="du-panel-title">Deleted Users</h3>
              <p className="du-panel-subtitle">
                Restore accounts safely or permanently delete them from the
                database.
              </p>
            </div>
            <CcureInput
              id="deleted-user-search"
              type="search"
              label="Search deleted users"
              placeholder="Search by name, username, email, or organization"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              fieldClassName="du-search"
            />
          </div>

          {loading ? (
            <div className="du-loading">
              <CcureLoader label="Loading deleted users…" />
            </div>
          ) : totalCount === 0 ? (
            <CcureEmptyState
              title="Deleted Users is empty"
              description="Soft-deleted users will appear here for restore or permanent deletion."
            />
          ) : (
            <>
              <CcureTable
                caption={`Deleted users — ${totalCount} account${totalCount !== 1 ? "s" : ""}`}
                columns={columns}
                rows={pagedUsers}
                rowKey={(user) => user.id}
                density="comfortable"
              />
              <CcurePagination
                page={page}
                pageSize={PAGE_SIZE}
                total={totalCount}
                onPageChange={setPage}
                itemNoun="deleted users"
                disabled={busyId !== null}
              />
            </>
          )}
        </div>
      </div>

      <CcureConfirmDialog
        open={Boolean(confirmConfig)}
        title={confirmConfig?.title}
        subtitle={confirmConfig?.subtitle}
        warning={confirmConfig?.warning}
        confirmLabel={confirmConfig?.confirmLabel}
        tone={confirmConfig?.tone}
        busy={busyId !== null}
        onConfirm={confirmConfig?.onConfirm}
        onCancel={() => setConfirmConfig(null)}
      />

      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </AppLayout>
  );
}
