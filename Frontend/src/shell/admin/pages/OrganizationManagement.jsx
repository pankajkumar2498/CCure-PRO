/**
 * src/shell/admin/pages/OrganizationManagement.jsx
 * Tenants — provision, edit, activate/deactivate, delete.
 *
 * ── Contract, unchanged by the Checkpoint 3C migration ──────────────────────
 * Every request, payload, permission check and state transition below is what
 * it was before. The migration changed presentation only. Specifically
 * preserved:
 *
 *   * the four authorisations stay four distinct tests, and they are not
 *     interchangeable —
 *       create  → `organizations:create`
 *       update  → `organizations:update`
 *       delete  → superadmin **and** `organizations:delete`, a conjunction,
 *                 because a permission alone would let an org_admin who held
 *                 it delete somebody else's tenant
 *       manage  → `canManageOrg`: a superadmin may manage any organisation,
 *                 an org_admin only their own;
 *   * `changeOrganizationStatus(id, { is_active: !org.is_active })` sends the
 *     inverted value, never a literal;
 *   * both destructive actions require an explicit confirmation carrying the
 *     consequence — deletion reaches users, assets and scans; deactivation
 *     cuts off everyone inside the tenant;
 *   * `loadData(true)` is the quiet reload used after a successful write, so
 *     the table does not blank out.
 *
 * ── Scope boundary ──────────────────────────────────────────────────────────
 * `components/admin/OrganizationForm` is deliberately NOT migrated here: it
 * carries admin password provisioning, a credential-handling surface with its
 * own review, and keeps working exactly as it did.
 *
 * The create and edit dialogs now use `CcureModal`. This page was the last
 * consumer of `components/layout/Modal`, which the post-migration cleanup
 * deleted once it had none; overlay-click and Escape closing are CcureModal
 * defaults, so the dialogs behave as they did while gaining its focus trap,
 * scroll lock and focus restoration.
 *
 * src/__tests__/pages/admin/OrganizationManagement.test.jsx asserts all of the
 * above and was written against the pre-migration page.
 */
import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../auth/AuthContext";
import ProductFrame from "../../layout/ProductFrame";
import {
  listOrganizations,
  createOrganization,
  updateOrganization,
  changeOrganizationStatus,
  deleteOrganization,
} from "../../api/admin";
import { formatDateTime } from "../../utils/date";
import { useToasts, ToastContainer } from "../../feedback/Toast";
import OrganizationForm from "../components/OrganizationForm";
import { can, denyMessage, isSuperAdmin } from "../../auth/permissions";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureConfirmDialog,
  CcureLoader,
  CcureModal,
  CcureTable,
} from "../../../design-system";
import "../styles/organization-management.css";

export default function OrganizationManagement() {
  const navigate = useNavigate();
  const { user: currentUser } = useAuth();
  const [orgs, setOrgs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);

  // Modal states
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [selectedOrg, setSelectedOrg] = useState(null);
  const [confirmConfig, setConfirmConfig] = useState(null);
  const [formData, setFormData] = useState({
    name: "",
    slug: "",
    plan: "community",
    max_assets: 500,
    max_users: 10,
  });
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();
  const isSuperadmin = isSuperAdmin(currentUser);
  const canCreateOrganizations = can(currentUser, "organizations", "create");
  const canUpdateOrganizations = can(currentUser, "organizations", "update");
  const canDeleteOrganizations =
    isSuperadmin && can(currentUser, "organizations", "delete");

  const canManageOrg = (org) =>
    isSuperadmin ||
    (canUpdateOrganizations && String(org.id) === String(currentUser?.org_id));

  const loadData = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    else setRefreshing(true);
    try {
      const data = await listOrganizations();
      setOrgs(data.organizations);
    } catch {
      setError(
        "Failed to load organizations. This area is for Superadmins only.",
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleCreateOrg = async (data) => {
    if (!canCreateOrganizations) {
      pushToast(denyMessage, "error");
      return;
    }
    setBusy(true);
    try {
      await createOrganization(data);
      pushToast("Organization created successfully.", "success");
      setIsCreateModalOpen(false);
      setFormData({
        name: "",
        slug: "",
        plan: "community",
        max_assets: 500,
        max_users: 10,
      });
      loadData(true);
    } catch (err) {
      pushToast(
        err.response?.data?.detail || "Failed to create organization.",
        "error",
      );
    } finally {
      setBusy(false);
    }
  };

  const handleUpdateOrg = async (data) => {
    if (!canUpdateOrganizations) {
      pushToast(denyMessage, "error");
      return;
    }
    if (!selectedOrg) return;
    setBusy(true);
    try {
      await updateOrganization(selectedOrg.id, {
        name: data.name,
        slug: data.slug,
        plan: data.plan,
        max_assets: data.max_assets,
        max_users: data.max_users,
      });
      pushToast("Organization updated successfully.", "success");
      setIsEditModalOpen(false);
      loadData(true);
    } catch (err) {
      pushToast(
        err.response?.data?.detail || "Failed to update organization.",
        "error",
      );
    } finally {
      setBusy(false);
    }
  };

  const handleToggleStatus = (org) => {
    if (!canUpdateOrganizations) {
      pushToast(denyMessage, "error");
      return;
    }
    const action = org.is_active ? "Deactivate" : "Activate";
    setConfirmConfig({
      title: `${action} organization`,
      subtitle: `This will ${action.toLowerCase()} ${org.name}.`,
      warning: org.is_active
        ? "Users in this organization may lose access while the tenant is inactive."
        : "Users in this organization will be able to access the tenant again.",
      confirmLabel: action,
      tone: "info",
      onConfirm: async () => {
        setBusy(true);
        try {
          await changeOrganizationStatus(org.id, { is_active: !org.is_active });
          pushToast(
            `Organization ${org.name} ${org.is_active ? "deactivated" : "activated"}.`,
            "success",
          );
          await loadData(true);
        } catch (err) {
          pushToast(
            err.response?.data?.detail ||
              "Unable to update organization status.",
            "error",
          );
        } finally {
          setBusy(false);
          setConfirmConfig(null);
        }
      },
    });
  };

  const handleDeleteOrg = (org) => {
    if (!canDeleteOrganizations) {
      pushToast(denyMessage, "error");
      return;
    }
    setConfirmConfig({
      title: `Delete ${org.name}`,
      subtitle: "Are you sure you want to delete this organization?",
      warning:
        "This is a destructive tenant-level action. Users, assets, scans, and related organization data may be removed.",
      confirmLabel: "Delete organization",
      tone: "danger",
      onConfirm: async () => {
        setBusy(true);
        try {
          await deleteOrganization(org.id);
          pushToast("Organization deleted successfully.", "success");
          await loadData(true);
        } catch (err) {
          pushToast(
            err.response?.data?.detail || "Unable to delete organization.",
            "error",
          );
        } finally {
          setBusy(false);
          setConfirmConfig(null);
        }
      },
    });
  };

  const openEditModal = (org) => {
    setSelectedOrg(org);
    setFormData({
      name: org.name,
      slug: org.slug,
      plan: org.plan,
      max_assets: org.max_assets,
      max_users: org.max_users,
      is_active: org.is_active,
    });
    setIsEditModalOpen(true);
  };

  /* Declared columns, so CcureTable owns the caption, `scope="col"` on every
     header and `scope="row"` on the organisation name — the identity a reader
     needs announced alongside every quota and status in the row. */
  const columns = [
    {
      key: "name",
      header: "Name",
      isRowHeader: true,
      cell: (org) => <span className="om-name">{org.name}</span>,
    },
    { key: "slug", header: "Slug", mono: true, cell: (org) => org.slug },
    {
      key: "plan",
      header: "Plan",
      cell: (org) => <CcureBadge variant="info">{org.plan}</CcureBadge>,
    },
    {
      key: "max_assets",
      header: "Max Assets",
      mono: true,
      align: "end",
      cell: (org) => org.max_assets,
    },
    {
      key: "max_users",
      header: "Max Users",
      mono: true,
      align: "end",
      cell: (org) => org.max_users,
    },
    {
      key: "status",
      header: "Status",
      cell: (org) => (
        <CcureBadge variant={org.is_active ? "success" : "neutral"}>
          {org.is_active ? "Active" : "Inactive"}
        </CcureBadge>
      ),
    },
    {
      key: "created_at",
      header: "Created",
      nowrap: true,
      cell: (org) => (
        <span className="om-muted">{formatDateTime(org.created_at)}</span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      align: "end",
      cell: (org) => {
        if (!canManageOrg(org)) {
          return <span className="om-muted">—</span>;
        }
        return (
          <div className="om-actions">
            {canDeleteOrganizations && (
              <CcureButton
                variant="ghost"
                size="sm"
                onClick={() => navigate(`/admin/users?org_id=${org.id}`)}
                /* Every emoji here is decorative and every control carries its
                   own row-specific name, so a reader listing the eight buttons
                   on a two-row table gets eight distinct entries rather than
                   four pairs. */
                aria-label={`View users in ${org.name}`}
              >
                <span aria-hidden="true">👥</span> Users
              </CcureButton>
            )}
            <CcureButton
              variant="ghost"
              size="sm"
              onClick={() => openEditModal(org)}
              disabled={busy}
              aria-label={`Edit ${org.name}`}
            >
              <span aria-hidden="true">✏️</span> Edit
            </CcureButton>
            <CcureButton
              variant="secondary"
              size="sm"
              onClick={() => handleToggleStatus(org)}
              disabled={busy}
              aria-label={`${org.is_active ? "Deactivate" : "Activate"} ${org.name}`}
            >
              <span aria-hidden="true">{org.is_active ? "⏻" : "▶"}</span>{" "}
              {org.is_active ? "Deactivate" : "Activate"}
            </CcureButton>
            {canDeleteOrganizations && (
              <CcureButton
                variant="danger"
                size="sm"
                onClick={() => handleDeleteOrg(org)}
                disabled={busy}
                aria-label={`Delete ${org.name}`}
              >
                <span aria-hidden="true">🗑️</span> Delete
              </CcureButton>
            )}
          </div>
        );
      },
    },
  ];

  if (loading) {
    return (
      <ProductFrame pageTitle="Organization Management">
        <div className="om-loading">
          <CcureLoader label="Loading organizations…" />
        </div>
      </ProductFrame>
    );
  }

  return (
    <ProductFrame pageTitle="Organization Management">
      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Organizations</h2>
            <p className="page-subtitle">
              Manage multi-tenant organizations and their subscription plans
            </p>
          </div>
          <div className="om-toolbar">
            <CcureButton
              variant="ghost"
              size="sm"
              onClick={() => loadData(true)}
              loading={refreshing}
              disabled={busy}
            >
              Refresh
            </CcureButton>
            {canCreateOrganizations && (
              <CcureButton
                variant="primary"
                size="sm"
                onClick={() => setIsCreateModalOpen(true)}
                disabled={busy}
              >
                + New Organization
              </CcureButton>
            )}
          </div>
        </div>

        {error && (
          <CcureAlert variant="danger" className="om-message">
            {error}
          </CcureAlert>
        )}

        <CcureTable
          caption={`Organizations — ${orgs.length} tenant${orgs.length !== 1 ? "s" : ""}`}
          columns={columns}
          rows={orgs}
          rowKey={(org) => org.id}
          density="comfortable"
          emptyMessage="No organizations are available yet. Create one to get started."
        />
      </div>

      {/* Create Org dialog — CcureModal + OrganizationForm. This page was the
          last consumer of the legacy shared Modal, which is now deleted;
          overlay-click and Escape closing are CcureModal defaults, so the
          dialog behaves as it did. */}
      {isCreateModalOpen && (
        <CcureModal
          open={isCreateModalOpen}
          title="Provision New Organization"
          size="md"
          onClose={() => setIsCreateModalOpen(false)}
        >
          <OrganizationForm
            mode="create"
            organization={formData}
            onSubmit={handleCreateOrg}
            onCancel={() => setIsCreateModalOpen(false)}
            busy={busy}
          />
        </CcureModal>
      )}

      {/* Edit Org dialog — likewise. */}
      {isEditModalOpen && (
        <CcureModal
          open={isEditModalOpen}
          title={selectedOrg ? `Edit ${selectedOrg.name}` : "Edit organization"}
          size="md"
          onClose={() => setIsEditModalOpen(false)}
        >
          <OrganizationForm
            mode="edit"
            organization={selectedOrg}
            onSubmit={handleUpdateOrg}
            onCancel={() => setIsEditModalOpen(false)}
            busy={busy}
          />
        </CcureModal>
      )}

      <CcureConfirmDialog
        open={Boolean(confirmConfig)}
        title={confirmConfig?.title}
        subtitle={confirmConfig?.subtitle}
        warning={confirmConfig?.warning}
        confirmLabel={confirmConfig?.confirmLabel}
        tone={confirmConfig?.tone}
        busy={busy}
        onConfirm={confirmConfig?.onConfirm}
        onCancel={() => setConfirmConfig(null)}
      />
      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </ProductFrame>
  );
}
