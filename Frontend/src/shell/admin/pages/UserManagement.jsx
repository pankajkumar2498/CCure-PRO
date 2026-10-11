import { useCallback, useEffect, useMemo, useState, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAuth } from "../../auth/AuthContext";
import ProductFrame from "../../layout/ProductFrame";
import {
  listUsers,
  listOrganizations,
  createUser,
  updateUser,
  changeUserStatus,
  deleteUser,
  moveUserOrganization,
  resetUserPassword,
  resetUserMfa,
  listPendingUsers,
  approveUser,
} from "../../api/admin";
import UserTable from "../components/UserTable";
import UserRolesPanel from "../components/UserRolesPanel";
import { listAssignableRoles } from "../../api/rbac";
import UserForm from "../components/UserForm";
import RegistrationSettingsDialog from "../components/RegistrationSettingsDialog";
import { useToasts, ToastContainer } from "../../feedback/Toast";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureConfirmDialog,
  CcureInput,
  CcureModal,
  CcurePagination,
  CcurePasswordField,
  CcureSelect,
  CcurePage,
  CcurePageHeader,
} from "../../../design-system";
import "../styles/user-management.css";
import {
  can,
  denyMessage,
  canSwitchOrganisation,
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
  const [searchParams, setSearchParams] = useSearchParams();
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

  // cross-organisation reach as the backend reports it; an account without it is
  // bound to its own organisation
  const isSuperadmin = canSwitchOrganisation(currentUser);
  const orgAdmin = !isSuperadmin;
  const canCreateUsers = can(currentUser, "platform.user.create");
  const canUpdateUsers = can(currentUser, "platform.user.update");
  const canDeleteUsers = can(currentUser, "platform.user.delete");
  const canManageRoles = can(currentUser, "platform.role.read");
  const canReadRegistration = can(currentUser, "platform.registration.read", {
    scope: "platform",
  });
  const registrationOpen =
    canReadRegistration && searchParams.get("registration") === "settings";
  const setRegistrationOpen = (open) => {
    setSearchParams(
      (previous) => {
        const next = new URLSearchParams(previous);
        if (open) next.set("registration", "settings");
        else next.delete("registration");
        return next;
      },
      { replace: true },
    );
  };
  const [rolesUser, setRolesUser] = useState(null);
  // The backend decides which roles may be handed out (`assignable`, from the
  // assignment rules: organisation boundary, ceilings, hierarchy — RBAC-7). The form
  // offers exactly those; no role label is consulted, and the backend refuses an
  // escalation whatever the form sends.
  const assignableRoles = useMemo(
    () => roles.filter((role) => role.assignable !== false),
    [roles],
  );

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

  const performApprove = useCallback(
    async (user, { allowlistDomain = false } = {}) => {
      const domain = (user.email || "").split("@").pop();
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

  /* Approving one account is a reversible, single-account decision and goes
     straight through. Adding the domain to the platform-wide allow list is
     neither, so it asks first — in the page's own confirmation dialog rather
     than window.confirm, which is unstyled, blocks the event loop and cannot
     be reached by the tests. The wording is the sentence the native prompt
     carried, and the permission and approval calls are unchanged. */
  const handleApprove = useCallback(
    (user, { allowlistDomain = false } = {}) => {
      if (!allowlistDomain) return performApprove(user);
      const domain = (user.email || "").split("@").pop();
      setConfirmConfig({
        title: `Allow every future signup from "${domain}"?`,
        subtitle: `${user.username} is approved either way; this also changes the platform allow list.`,
        warning:
          `This approves ${user.username} AND adds ${domain} to the ` +
          `platform-wide allow list, for all organisations, permanently. ` +
          `Choose "Approve only" instead if you just want to admit this one person.`,
        confirmLabel: "Approve + allow domain",
        confirmType: "danger",
        onConfirm: () => {
          setConfirmConfig(null);
          return performApprove(user, { allowlistDomain: true });
        },
        onCancel: () => setConfirmConfig(null),
      });
      return undefined;
    },
    [performApprove],
  );

  // Load roles + orgs once on mount (these rarely change)
  useEffect(() => {
    // The roles offered are the ones the backend marks assignable for the signed-in
    // account; organisations are listed only for an account with cross-organisation
    // reach (it is the only one that places users in other organisations).
    listAssignableRoles()
      .then((d) => setRoles(d.roles || []))
      .catch(() => {});
    if (isSuperadmin) {
      listOrganizations()
        .then((d) => setOrganizations(d.organizations || []))
        .catch(() => {});
    }
    // `isSuperadmin` decides which lists are fetched, so it belongs here: on a
    // render where auth had not yet hydrated it reads false, and without the
    // dependency the organization list was never fetched once it flipped. It
    // is a boolean derived from the session, so it settles after at most one
    // additional pass.
  }, [isSuperadmin]);

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

  const closeResetModal = () => {
    setResetModalOpen(false);
    setUserToReset(null);
    setNewPassword("");
  };

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <ProductFrame pageTitle="User Management">
      <CcurePage className="um-page">
        {/* Header */}
        <CcurePageHeader
          title="User Management"
          subtitle={subtitle}
          actions={
            <div className="um-toolbar">
              {canDeleteUsers && (
                <CcureButton
                  variant="ghost"
                  size="sm"
                  onClick={() => navigate("/admin/users/deleted")}
                  disabled={busy}
                >
                  Deleted users
                </CcureButton>
              )}
              <CcureButton
                variant="ghost"
                size="sm"
                onClick={() => loadUsers(true)}
                loading={refreshing}
                disabled={loading || refreshing || busy}
              >
                {refreshing ? "Refreshing..." : "Refresh"}
              </CcureButton>
              {canReadRegistration && (
                <CcureButton
                  variant="secondary"
                  size="sm"
                  onClick={() => setRegistrationOpen(true)}
                  disabled={busy}
                >
                  Registration settings
                </CcureButton>
              )}
              {canCreateUsers && (
                <CcureButton
                  variant="primary"
                  size="sm"
                  onClick={openCreateModal}
                  disabled={busy}
                >
                  + Create user
                </CcureButton>
              )}
            </div>
          }
        >
          {orgAdmin && (
            <p className="um-note">
              Org admins can only manage users in their own organization.
            </p>
          )}
        </CcurePageHeader>

        {error && <CcureAlert variant="danger">{error}</CcureAlert>}

        {/* Filters toolbar */}
        <div className="um-filters">
          <CcureInput
            id="um-search"
            type="search"
            label="Search users"
            fieldClassName="um-filter um-search"
            placeholder="Search by username, email or name..."
            value={searchInput}
            onChange={(e) => handleSearchChange(e.target.value)}
            autoComplete="off"
          />
          {isSuperadmin && (
            <CcureSelect
              id="um-org-filter"
              label="Filter by organization"
              fieldClassName="um-filter um-org-filter"
              value={selectedOrgId}
              onChange={(e) => {
                setSelectedOrgId(e.target.value);
                setPage(1);
              }}
            >
              <option value="">All Organizations</option>
              {organizations.map((org) => (
                <option key={org.id} value={org.id}>
                  {org.name}
                </option>
              ))}
            </CcureSelect>
          )}
        </div>

        {totalCount > 0 && (
          <CcurePagination
            className="um-pagination"
            page={page}
            pageSize={PAGE_SIZE}
            total={totalCount}
            onPageChange={setPage}
            disabled={refreshing}
            itemNoun="users"
            label="User pages"
          />
        )}

        {/* Accounts awaiting approval. Only rendered when there are any, so the
            page is unchanged for deployments with self-registration disabled. */}
        {canUpdateUsers && pending.length > 0 && (
          <section className="um-pending" aria-labelledby="um-pending-title">
            <h2 className="um-pending__title" id="um-pending-title">
              {pending.length} account{pending.length === 1 ? "" : "s"} awaiting
              approval
            </h2>
            <p className="um-pending__lead">
              These accounts cannot sign in yet. Approving one enables sign-in
              and emails the account holder. An account whose email is still
              unverified cannot be approved &mdash; the owner must click their
              verification link first.
            </p>
            <ul className="um-pending__list">
              {pending.map((p) => {
                const riskText = describeEmailRisk(p.email_risk);
                const domainText = describeEmailDomain(p.email_risk);
                const blocked =
                  p.email_risk?.reason === "disposable" ||
                  p.email_risk?.reason === "denylisted";
                return (
                  <li key={p.id} className="um-pending-item">
                    <div className="um-pending-item__who">
                      <div className="um-pending-item__name">
                        {p.username}
                        <CcureBadge
                          variant={p.is_verified ? "success" : "danger"}
                        >
                          {p.is_verified
                            ? "email verified"
                            : "email not verified"}
                        </CcureBadge>
                        {/* An "email verified" badge on its own is misleading
                            here: a throwaway inbox can receive and click the
                            verification link perfectly well, which is exactly how
                            the two temp-mail accounts of 18 Aug 2026 arrived
                            looking legitimate. The domain verdict sits beside it
                            so the two facts are read together. */}
                        {p.is_email_flagged && (
                          <CcureBadge
                            variant={blocked ? "danger" : "warning"}
                            title={riskText}
                          >
                            {p.email_risk?.reason === "disposable"
                              ? "disposable domain"
                              : p.email_risk?.reason === "denylisted"
                                ? "blocked domain"
                                : "email risk"}
                          </CcureBadge>
                        )}
                      </div>
                      <div className="um-pending-item__meta">
                        {p.email}
                        {p.full_name ? ` · ${p.full_name}` : ""}
                        {p.created_at
                          ? ` · requested ${new Date(p.created_at).toLocaleString()}`
                          : ""}
                      </div>
                      {p.is_email_flagged && riskText && (
                        <div className="um-pending-item__risk">{riskText}</div>
                      )}
                      {domainText && (
                        <div className="um-pending-item__domain">
                          {domainText}
                        </div>
                      )}
                    </div>
                    <div className="um-pending-item__actions">
                      <CcureButton
                        size="sm"
                        onClick={() => handleApprove(p)}
                        disabled={!p.is_verified || approvingId === p.id}
                        loading={approvingId === p.id}
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
                      </CcureButton>
                      {/* Offered only for a flagged account, because for anything
                          else there is nothing to allow — and a button that is
                          always present is one an admin eventually clicks by
                          habit. */}
                      {p.is_email_flagged && (
                        <CcureButton
                          variant="secondary"
                          size="sm"
                          onClick={() =>
                            handleApprove(p, { allowlistDomain: true })
                          }
                          disabled={!p.is_verified || approvingId === p.id}
                          title={`Approve and permanently allow every address at ${(p.email || "").split("@").pop()}`}
                        >
                          Approve + allow domain
                        </CcureButton>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          </section>
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
          onManageRoles={setRolesUser}
          canManageRoles={canManageRoles}
          canUpdateUsers={canUpdateUsers}
          canDeleteUsers={canDeleteUsers}
        />
      </CcurePage>

      {registrationOpen && (
        <RegistrationSettingsDialog
          onClose={() => setRegistrationOpen(false)}
        />
      )}

      <CcureModal
        open={modalOpen}
        title={
          modalMode === "create"
            ? "Create new user"
            : selectedUser
              ? `Edit ${selectedUser.username}`
              : "Edit user"
        }
        size="md"
        onClose={busy ? undefined : closeModal}
        closeOnOverlayClick={false}
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
      </CcureModal>

      <CcureModal
        open={!!rolesUser}
        title={`Roles for ${rolesUser?.username || ""}`}
        subtitle="Role assignments in the platform RBAC model."
        size="lg"
        onClose={() => setRolesUser(null)}
      >
        {rolesUser && (
          <UserRolesPanel user={rolesUser} currentUser={currentUser} />
        )}
      </CcureModal>

      <CcureModal
        open={resetModalOpen}
        title={`Reset Password for ${userToReset?.username || ""}`}
        subtitle={`Enter a new secure password for ${userToReset?.username || "this user"}.`}
        size="sm"
        onClose={busy ? undefined : closeResetModal}
        closeOnOverlayClick={false}
      >
        <form className="um-form" onSubmit={handleResetPasswordSubmit}>
          <CcureAlert variant="warning" live={false}>
            Resetting the password will immediately terminate all active
            sessions for this user.
          </CcureAlert>

          <CcurePasswordField
            id="um-reset-password"
            label="New Password"
            placeholder="Enter new secure password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            disabled={busy}
            required
            autoComplete="new-password"
            capsLockWarning={false}
            hint="Must be at least 12 characters and contain uppercase, lowercase, numbers, and special characters."
          />

          <div className="um-form__actions">
            <CcureButton
              variant="secondary"
              onClick={closeResetModal}
              disabled={busy}
            >
              Cancel
            </CcureButton>
            <CcureButton
              type="submit"
              variant="primary"
              loading={busy}
              disabled={busy || !newPassword.trim()}
            >
              Reset Password
            </CcureButton>
          </div>
        </form>
      </CcureModal>

      <CcureConfirmDialog
        open={Boolean(confirmConfig)}
        title={confirmConfig?.title}
        subtitle={confirmConfig?.subtitle}
        warning={confirmConfig?.warning}
        confirmLabel={confirmConfig?.confirmLabel}
        tone={confirmConfig?.confirmType === "danger" ? "danger" : "info"}
        busy={busy}
        onConfirm={confirmConfig?.onConfirm}
        onCancel={confirmConfig?.onCancel}
      />

      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </ProductFrame>
  );
}
