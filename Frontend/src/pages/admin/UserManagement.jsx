import { useCallback, useEffect, useMemo, useState, useRef } from "react";
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
  resetUserMfa,
  listPendingUsers,
  approveUser,
} from "../../api/admin";
import Button from "../../components/common/Button";
import Modal from "../../components/layout/Modal";
import UserTable from "../../components/admin/UserTable";
import UserForm from "../../components/admin/UserForm";
import ConfirmDialog from "../../components/common/ConfirmDialog";
import { useToasts, ToastContainer } from "../../components/common/Toast";
import {
  can,
  denyMessage,
  isOrgAdmin,
  isSuperAdmin,
} from "../../auth/permissions";

const PAGE_SIZE = 10;

// Turn the backend's email_risk blob into something an administrator can act on.
//
// The point of this queue is a decision, and "flagged" alone does not support
// one. `radiant-flow.org` — a throwaway domain that reached this deployment on
// 18 Aug 2026 — appears on no published blocklist, so the only thing that
// separates it from a small real company is a handful of weak signals shown
// together: nothing on any list, registered recently, no mail exchanger. Each is
// individually too weak to refuse a signup over. Read side by side by a person,
// they are usually decisive.
const RISK_LABELS = {
  disposable: "on a maintained disposable-email blocklist",
  denylisted: "on this deployment's blocked-domain list",
  no_mx: "domain publishes no mail exchanger",
  young_domain: "domain registered recently",
  suspicious_name: "domain name resembles a throwaway mail service",
  reserved_tld: "reserved / non-routable top-level domain",
  hard_bounce: "verification email hard-bounced (mailbox does not exist)",
  unassessed: "some checks could not be completed",
};

export function describeEmailRisk(risk) {
  if (!risk || typeof risk !== "object") return "";

  const parts = [];
  if (RISK_LABELS[risk.reason]) parts.push(RISK_LABELS[risk.reason]);
  for (const flag of risk.flags || []) {
    if (RISK_LABELS[flag] && !parts.includes(RISK_LABELS[flag])) {
      parts.push(RISK_LABELS[flag]);
    }
  }
  if (!parts.length) return "";
  return parts.join(" · ");
}

// Facts about the domain, shown for **every** pending account rather than only
// flagged ones.
//
// This exists because of a specific measured failure. `radiant-flow.org` is a
// real throwaway domain, and it trips nothing: it is on no blocklist, publishes
// valid MX, and its registration is 513 days old — comfortably past any age
// threshold that would not also catch real companies. So it earns no flag and
// no badge, and an approval queue that only speaks up when something is flagged
// would show the reviewer precisely nothing about it.
//
// Age alone is not a verdict and must not be styled as one. But "513 days"
// beside a name nobody recognises reads very differently from "7853 days", and
// that comparison is the judgement the automation cannot make and a person can.
export function describeEmailDomain(risk) {
  if (!risk || typeof risk !== "object") return "";

  const bits = [];
  if (risk.domain) bits.push(risk.domain);

  const age = risk.signals?.domain_age_days;
  if (typeof age === "number") {
    const years = age / 365;
    bits.push(
      years >= 2
        ? `registered ${Math.floor(years)} years ago`
        : `registered ${age} days ago`,
    );
  } else if (risk.signals?.rdap_status === "unassessed") {
    bits.push("registration date unavailable");
  }

  const mx = risk.signals?.mx_status;
  if (mx === "ok") bits.push("accepts mail");
  else if (mx === "no_mx") bits.push("no mail exchanger");
  else if (mx === "nxdomain") bits.push("domain does not resolve");

  if (risk.reason === "allowlisted") bits.push("known provider");

  return bits.length > 1 ? bits.join(" · ") : "";
}

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
  const [refreshing, setRefreshing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const isFirstLoad = useRef(true);
  const searchTimer = useRef(null);

  // Filters — initialise org from URL param if Superadmin linked here from Orgs page
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [selectedOrgId, setSelectedOrgId] = useState(
    searchParams.get("org_id") || "",
  );
  const [page, setPage] = useState(1);

  const handleSearchChange = (val) => {
    setSearchInput(val);
    clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => {
      setSearch(val);
      setPage(1);
    }, 350);
  };

  useEffect(() => {
    return () => {
      if (searchTimer.current) {
        clearTimeout(searchTimer.current);
      }
    };
  }, []);

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
      const roleName = String(role.name || "")
        .toLowerCase()
        .replace(/\s+/g, "_");
      return roleName !== "superadmin";
    });
  }, [roles, isSuperadmin]);

  // ── Data loading (server-side) ────────────────────────────────────────────
  const loadUsers = useCallback(
    async (quiet = false) => {
      if (!quiet) setLoading(true);
      else setRefreshing(true);
      setError("");
      try {
        const data = await listUsers({
          skip: (page - 1) * PAGE_SIZE,
          limit: PAGE_SIZE,
          q: search.trim() || undefined,
          organization_id:
            isSuperadmin && selectedOrgId ? selectedOrgId : undefined,
        });
        setUsers(data.users || []);
        setTotalCount(data.total || 0);
      } catch {
        setError("Unable to load users. Please try again.");
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [page, search, selectedOrgId, isSuperadmin],
  );

  // ── Accounts awaiting approval ────────────────────────────────────────────
  // Self-registered accounts sit with approved_at NULL and cannot sign in. The
  // approve endpoint existed with nothing calling it, so the only way to release
  // an account was curl — which meant in practice that a pending user waited
  // forever. Surfaced above the user table because it is the only queue here
  // with someone actually waiting on it.
  const [pending, setPending] = useState([]);
  const [approvingId, setApprovingId] = useState(null);

  const loadPending = useCallback(async () => {
    try {
      const data = await listPendingUsers();
      setPending(Array.isArray(data) ? data : []);
    } catch {
      // Non-fatal: the rest of the page is still usable, and an admin who
      // cannot list pending accounts is no worse off than before this existed.
      setPending([]);
    }
  }, []);

  useEffect(() => {
    loadPending();
  }, [loadPending]);

  const handleApprove = useCallback(
    async (user, { allowlistDomain = false } = {}) => {
      const domain = (user.email || "").split("@").pop();
      if (
        allowlistDomain &&
        !window.confirm(
          `Allow every future signup from "${domain}"?\n\n` +
            `This approves ${user.username} AND adds ${domain} to the ` +
            `platform-wide allow list, for all organisations, permanently. ` +
            `Choose "Approve only" instead if you just want to admit this one person.`,
        )
      ) {
        return;
      }
      setApprovingId(user.id);
      try {
        await approveUser(user.id, { allowlistDomain });
        pushToast(
          allowlistDomain
            ? `${user.username} approved and ${domain} added to the allow list.`
            : `${user.username} approved. They have been emailed and can now sign in.`,
          "success",
        );
        await Promise.all([loadPending(), loadUsers(true)]);
      } catch (err) {
        // The backend refuses to approve an unverified mailbox; surface that
        // reason rather than a generic failure, because it is actionable —
        // the user has to click their verification link first.
        pushToast(
          err?.response?.data?.detail ||
            err?.response?.data?.message ||
            "Could not approve this account.",
          "error",
        );
      } finally {
        setApprovingId(null);
      }
    },
    [loadPending, loadUsers, pushToast],
  );

  // Load roles + orgs once on mount (these rarely change)
  useEffect(() => {
    // Superadmins need the full list of roles and orgs for filters/dropdowns.
    // Org admins only manage their own users and don't need these global lists.
    if (isSuperadmin) {
      listRoles()
        .then((d) => setRoles(d.roles || []))
        .catch(() => {});
      listOrganizations()
        .then((d) => setOrganizations(d.organizations || []))
        .catch(() => {});
    } else {
      // Org admins still need the roles list to assign roles (filtered in assignableRoles)
      listRoles()
        .then((d) => setRoles(d.roles || []))
        .catch(() => {});
    }
  }, []);

  // Reload users when filters/page change
  useEffect(() => {
    if (isFirstLoad.current) {
      loadUsers(false);
      isFirstLoad.current = false;
    } else {
      loadUsers(true);
    }
  }, [loadUsers]);

  // Resolve the display name of the currently filtered org
  const filteredOrgName = selectedOrgId
    ? organizations.find((o) => String(o.id) === String(selectedOrgId))?.name ||
      ""
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
      await loadUsers(true);
    } catch (err) {
      pushToast(
        err?.response?.data?.detail || "Failed to create user.",
        "error",
      );
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
        String(data.organization_id) !==
          String(selectedUser.organization_id || selectedUser.org_id)
      ) {
        await moveUserOrganization(selectedUser.id, data.organization_id);
        if (currentUser.id === selectedUser.id) {
          pushToast(
            "Organization changed. You will need to log in again.",
            "warning",
          );
        }
      }

      pushToast("User updated successfully.", "success");
      closeModal();
      await loadUsers(true);
    } catch (err) {
      pushToast(
        err?.response?.data?.detail || "Failed to update user.",
        "error",
      );
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
              u.id === user.id ? { ...u, is_active: !u.is_active } : u,
            ),
          );
          pushToast(
            `User ${user.username} ${user.is_active ? "deactivated" : "activated"}.`,
            "success",
          );
        } catch (err) {
          pushToast(
            err?.response?.data?.detail || "Unable to update user status.",
            "error",
          );
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
        prev.map((u) => (u.id === user.id ? { ...u, locked_until: null } : u)),
      );
      pushToast("User unlocked successfully.", "success");
    } catch (err) {
      pushToast(
        err?.response?.data?.detail || "Unable to unlock user.",
        "error",
      );
    } finally {
      setBusy(false);
    }
  };

  const handleResetMfa = (user) => {
    if (!canUpdateUsers) {
      pushToast(denyMessage, "error");
      return;
    }
    setConfirmConfig({
      title: `Reset MFA for ${user.username}`,
      subtitle: `This will completely disable Multi-Factor Authentication for ${user.username}.`,
      warning:
        "This action will immediately terminate all active sessions for this user.",
      confirmLabel: "Reset MFA",
      confirmType: "danger",
      icon: "🛡️",
      iconClass: "danger",
      onConfirm: async () => {
        setBusy(true);
        try {
          await resetUserMfa(user.id);
          setUsers((prev) =>
            prev.map((u) =>
              u.id === user.id ? { ...u, mfa_enabled: false } : u,
            ),
          );
          pushToast(`MFA reset successfully for ${user.username}.`, "success");
        } catch (err) {
          pushToast(
            err?.response?.data?.detail || "Failed to reset MFA.",
            "error",
          );
        } finally {
          setBusy(false);
          setConfirmConfig(null);
        }
      },
      onCancel: () => setConfirmConfig(null),
    });
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
      pushToast(
        `Password reset successfully for ${userToReset.username}.`,
        "success",
      );
      if (currentUser && String(currentUser.id) === String(userToReset.id)) {
        pushToast(
          "You reset your own password. Please log in again using the new password.",
          "warning",
        );
      }
      setResetModalOpen(false);
      setUserToReset(null);
      setNewPassword("");
    } catch (err) {
      let errMsg = "Failed to reset password.";
      if (err.response?.data?.detail) {
        const detail = err.response.data.detail;
        errMsg = Array.isArray(detail)
          ? detail.map((d) => d.msg).join(", ")
          : detail;
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
      subtitle:
        "This is a soft delete. The user will be removed from the active user list.",
      warning:
        "The account becomes inactive immediately and can later be restored from Deleted Users.",
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
          pushToast(
            err?.response?.data?.detail || "Unable to delete user.",
            "error",
          );
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

  const startIndex = totalCount === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const endIndex = Math.min(startIndex + users.length - 1, totalCount);
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));

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
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => navigate("/admin/users/deleted")}
                disabled={busy}
              >
                Deleted users
              </Button>
            )}
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => loadUsers(true)}
              disabled={loading || refreshing || busy}
            >
              {refreshing ? "Refreshing..." : "Refresh"}
            </Button>
            {canCreateUsers && (
              <Button
                type="button"
                variant="primary"
                size="sm"
                onClick={openCreateModal}
                disabled={busy}
              >
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
              value={searchInput}
              onChange={(e) => handleSearchChange(e.target.value)}
              className="search-input"
            />
          </div>
          {isSuperadmin && (
            <select
              className="org-filter-select"
              value={selectedOrgId}
              onChange={(e) => {
                setSelectedOrgId(e.target.value);
                setPage(1);
              }}
              title="Filter by organization"
            >
              <option value="">All Organizations</option>
              {organizations.map((org) => (
                <option key={org.id} value={org.id}>
                  {org.name}
                </option>
              ))}
            </select>
          )}
        </div>

        {totalCount > 0 && (
          <div className="pagination-row" style={{ marginBottom: 16 }}>
            <div className="pagination-summary">
              Showing {startIndex}–{endIndex} of {totalCount} users
            </div>
            <div className="pagination-controls">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={page <= 1 || refreshing}
                onClick={() => setPage(page - 1)}
              >
                Prev
              </Button>
              <span className="pagination-page">
                Page {page} of {totalPages}
              </span>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={page >= totalPages || refreshing}
                onClick={() => setPage(page + 1)}
              >
                Next
              </Button>
            </div>
          </div>
        )}

        {/* Accounts awaiting approval. Only rendered when there are any, so the
            page is unchanged for deployments with self-registration disabled. */}
        {canUpdateUsers && pending.length > 0 && (
          <div
            style={{
              border: "1px solid #f59e0b",
              background: "rgba(245,158,11,0.08)",
              borderRadius: 10,
              padding: "16px 18px",
              marginBottom: 20,
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                marginBottom: 4,
              }}
            >
              <strong style={{ fontSize: 15 }}>
                {pending.length} account{pending.length === 1 ? "" : "s"}{" "}
                awaiting approval
              </strong>
            </div>
            <p style={{ margin: "0 0 14px 0", fontSize: 13, opacity: 0.85 }}>
              These accounts cannot sign in yet. Approving one enables sign-in
              and emails the account holder. An account whose email is still
              unverified cannot be approved &mdash; the owner must click their
              verification link first.
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {pending.map((p) => (
                <div
                  key={p.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 12,
                    flexWrap: "wrap",
                    padding: "10px 12px",
                    background: "rgba(0,0,0,0.04)",
                    borderRadius: 8,
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 600, fontSize: 14 }}>
                      {p.username}
                      <span
                        style={{
                          marginLeft: 10,
                          fontSize: 11,
                          fontWeight: 600,
                          padding: "2px 8px",
                          borderRadius: 999,
                          background: p.is_verified ? "#dcfce7" : "#fee2e2",
                          color: p.is_verified ? "#166534" : "#991b1b",
                        }}
                      >
                        {p.is_verified
                          ? "email verified"
                          : "email not verified"}
                      </span>
                      {/* An "email verified" badge on its own is misleading
                          here: a throwaway inbox can receive and click the
                          verification link perfectly well, which is exactly how
                          the two temp-mail accounts of 18 Aug 2026 arrived
                          looking legitimate. The domain verdict sits beside it
                          so the two facts are read together. */}
                      {p.is_email_flagged && (
                        <span
                          style={{
                            marginLeft: 8,
                            fontSize: 11,
                            fontWeight: 600,
                            padding: "2px 8px",
                            borderRadius: 999,
                            background:
                              p.email_risk?.reason === "disposable" ||
                              p.email_risk?.reason === "denylisted"
                                ? "#fee2e2"
                                : "#fef3c7",
                            color:
                              p.email_risk?.reason === "disposable" ||
                              p.email_risk?.reason === "denylisted"
                                ? "#991b1b"
                                : "#92400e",
                          }}
                          title={describeEmailRisk(p.email_risk)}
                        >
                          {p.email_risk?.reason === "disposable"
                            ? "disposable domain"
                            : p.email_risk?.reason === "denylisted"
                              ? "blocked domain"
                              : "email risk"}
                        </span>
                      )}
                    </div>
                    <div
                      style={{
                        fontSize: 12,
                        opacity: 0.75,
                        wordBreak: "break-all",
                      }}
                    >
                      {p.email}
                      {p.full_name ? ` · ${p.full_name}` : ""}
                      {p.created_at
                        ? ` · requested ${new Date(p.created_at).toLocaleString()}`
                        : ""}
                    </div>
                    {p.is_email_flagged && describeEmailRisk(p.email_risk) && (
                      <div
                        style={{
                          fontSize: 12,
                          marginTop: 4,
                          color: "#92400e",
                          fontWeight: 500,
                        }}
                      >
                        {describeEmailRisk(p.email_risk)}
                      </div>
                    )}
                    {describeEmailDomain(p.email_risk) && (
                      <div style={{ fontSize: 12, marginTop: 3, opacity: 0.7 }}>
                        {describeEmailDomain(p.email_risk)}
                      </div>
                    )}
                  </div>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    <Button
                      onClick={() => handleApprove(p)}
                      disabled={!p.is_verified || approvingId === p.id}
                      title={
                        p.is_verified
                          ? "Approve this account only. The domain stays as it is."
                          : "Cannot approve until the email address is verified"
                      }
                    >
                      {approvingId === p.id
                        ? "Approving…"
                        : p.is_email_flagged
                          ? "Approve only"
                          : "Approve"}
                    </Button>
                    {/* Offered only for a flagged account, because for anything
                        else there is nothing to allow — and a button that is
                        always present is one an admin eventually clicks by
                        habit. */}
                    {p.is_email_flagged && (
                      <Button
                        variant="secondary"
                        onClick={() =>
                          handleApprove(p, { allowlistDomain: true })
                        }
                        disabled={!p.is_verified || approvingId === p.id}
                        title={`Approve and permanently allow every address at ${(p.email || "").split("@").pop()}`}
                      >
                        Approve + allow domain
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Table — server-side data, no client-side slicing */}
        <UserTable
          users={users}
          roles={roles}
          organizations={organizations}
          showOrganizationColumn={!orgAdmin}
          loading={loading}
          refreshing={refreshing}
          currentUser={currentUser}
          onEdit={openEditModal}
          onResetPassword={handleOpenResetModal}
          onResetMfa={handleResetMfa}
          onToggleStatus={handleToggleStatus}
          onUnlock={handleUnlockUser}
          onDelete={handleDeleteUser}
          canUpdateUsers={canUpdateUsers}
          canDeleteUsers={canDeleteUsers}
        />
      </div>

      <Modal
        isOpen={modalOpen}
        title={
          modalMode === "create"
            ? "Create new user"
            : selectedUser
              ? `Edit ${selectedUser.username}`
              : "Edit user"
        }
        size="medium"
        onClose={closeModal}
      >
        <UserForm
          mode={modalMode}
          user={selectedUser}
          roles={assignableRoles}
          organizations={organizations}
          currentUser={currentUser}
          onSubmit={
            modalMode === "create" ? handleCreateUser : handleUpdateUser
          }
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
        <div
          className="card card--admin-form"
          style={{
            background: "transparent",
            border: "none",
            padding: 0,
            boxShadow: "none",
          }}
        >
          <div
            className="form-card-header"
            style={{ padding: 0, marginBottom: 20 }}
          >
            <div>
              <h3 className="card-title">Reset User Password</h3>
              <p className="card-subtitle">
                Enter a new secure password for{" "}
                <strong>{userToReset?.username}</strong>.
              </p>
            </div>
          </div>

          <form
            className="form-horizontal"
            onSubmit={handleResetPasswordSubmit}
          >
            <div className="alert alert--warning" style={{ marginBottom: 16 }}>
              ⚠️ Resetting the password will immediately terminate all active
              sessions for this user.
            </div>

            <div className="field">
              <label className="field-label" htmlFor="reset-new-password">
                New Password
              </label>
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
                Must be at least 12 characters and contain uppercase, lowercase,
                numbers, and special characters.
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
