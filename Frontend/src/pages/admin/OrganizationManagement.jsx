import { useEffect, useState, useCallback } from "react";
import { useAuth } from "../../context/AuthContext";
import AppLayout from "../../components/layout/AppLayout";
import {
  listOrganizations,
  createOrganization,
  updateOrganization,
  changeOrganizationStatus,
  deleteOrganization,
} from "../../api/admin";
import Modal from "../../components/layout/Modal";
import { formatDateTime } from "../../utils/date";
import Button from "../../components/common/Button";
import { useToasts, ToastContainer } from "../../components/common/Toast";
import OrganizationForm from "../../components/admin/OrganizationForm";
import ConfirmDialog from "../../components/common/ConfirmDialog";

export default function OrganizationManagement() {
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
  const [formData, setFormData] = useState({ name: "", slug: "", plan: "community", max_assets: 500, max_users: 10 });
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();
  const roleName = currentUser?.role?.name?.toLowerCase() || "";
  const isSuperadmin = roleName === "superadmin";
  const canCreateOrganizations = currentUser?.role?.permissions?.some(
    (permission) => permission.resource === "organizations" && permission.action === "create"
  );
  const canUpdateOrganizations = currentUser?.role?.permissions?.some(
    (permission) => permission.resource === "organizations" && permission.action === "update"
  );

  const canManageOrg = (org) => (
    isSuperadmin || (canUpdateOrganizations && String(org.id) === String(currentUser?.org_id))
  );

  const loadData = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    else setRefreshing(true);
    try {
      const data = await listOrganizations();
      setOrgs(data.organizations);
    } catch (err) {
      setError("Failed to load organizations. This area is for Superadmins only.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleCreateOrg = async (data) => {
    setBusy(true);
    try {
      await createOrganization(data);
      pushToast("Organization created successfully.", "success");
      setIsCreateModalOpen(false);
      setFormData({ name: "", slug: "", plan: "community", max_assets: 500, max_users: 10 });
      loadData(true);
    } catch (err) {
      pushToast(err.response?.data?.detail || "Failed to create organization.", "error");
    } finally {
      setBusy(false);
    }
  };

  const handleUpdateOrg = async (data) => {
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
      pushToast(err.response?.data?.detail || "Failed to update organization.", "error");
    } finally {
      setBusy(false);
    }
  };

  const handleToggleStatus = (org) => {
    const action = org.is_active ? "Deactivate" : "Activate";
    setConfirmConfig({
      title: `${action} organization`,
      subtitle: `This will ${action.toLowerCase()} ${org.name}.`,
      warning: org.is_active
        ? "Users in this organization may lose access while the tenant is inactive."
        : "Users in this organization will be able to access the tenant again.",
      confirmLabel: action,
      confirmType: "info",
      icon: org.is_active ? "⏻" : "▶",
      iconClass: "info",
      onConfirm: async () => {
        setBusy(true);
        try {
          await changeOrganizationStatus(org.id, { is_active: !org.is_active });
          pushToast(`Organization ${org.name} ${org.is_active ? "deactivated" : "activated"}.`, "success");
          await loadData(true);
        } catch (err) {
          pushToast(err.response?.data?.detail || "Unable to update organization status.", "error");
        } finally {
          setBusy(false);
          setConfirmConfig(null);
        }
      },
      onCancel: () => setConfirmConfig(null),
    });
  };

  const handleDeleteOrg = (org) => {
    setConfirmConfig({
      title: `Delete ${org.name}`,
      subtitle: "Are you sure you want to delete this organization?",
      warning: "This is a destructive tenant-level action. Users, assets, scans, and related organization data may be removed.",
      confirmLabel: "Delete organization",
      confirmType: "danger",
      icon: "🗑️",
      iconClass: "danger",
      onConfirm: async () => {
        setBusy(true);
        try {
          await deleteOrganization(org.id);
          pushToast("Organization deleted successfully.", "success");
          await loadData(true);
        } catch (err) {
          pushToast(err.response?.data?.detail || "Unable to delete organization.", "error");
        } finally {
          setBusy(false);
          setConfirmConfig(null);
        }
      },
      onCancel: () => setConfirmConfig(null),
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
      is_active: org.is_active
    });
    setIsEditModalOpen(true);
  };

  if (loading) {
    return (
      <AppLayout pageTitle="Organization Management">
        <div style={{ display: "flex", justifyContent: "center", padding: 60 }}>
          <div className="spinner" />
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout pageTitle="Organization Management">
      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Organizations</h2>
            <p className="page-subtitle">Manage multi-tenant organizations and their subscription plans</p>
          </div>
          <div className="page-actions-row">
            <Button type="button" variant="ghost" size="sm" onClick={() => loadData(true)} disabled={refreshing || busy}>
              {refreshing ? "Refreshing..." : "Refresh"}
            </Button>
            {canCreateOrganizations && (
              <Button type="button" variant="primary" size="sm" onClick={() => setIsCreateModalOpen(true)} disabled={busy}>
                + New Organization
              </Button>
            )}
          </div>
        </div>

        {error && <div className="alert alert--error">{error}</div>}

        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Slug</th>
                <th>Plan</th>
                <th>Max Assets</th>
                <th>Max Users</th>
                <th>Status</th>
                <th>Created</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {orgs.map(o => (
                <tr key={o.id}>
                  <td><strong>{o.name}</strong></td>
                  <td><code className="ip-code">{o.slug}</code></td>
                  <td><span className="chip chip--info">{o.plan}</span></td>
                  <td><code className="ip-code">{o.max_assets}</code></td>
                  <td><code className="ip-code">{o.max_users}</code></td>
                  <td>
                    <span className={`chip ${o.is_active ? "chip--active" : "chip--inactive"}`}>
                      {o.is_active ? "Active" : "Inactive"}
                    </span>
                  </td>
                  <td className="text-muted" style={{ fontSize: 12 }}>
                    {formatDateTime(o.created_at)}
                  </td>
                  <td>
                    {canManageOrg(o) ? (
                      <div className="action-btns table-action-cell">
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          title="Edit organization"
                          onClick={() => openEditModal(o)}
                          disabled={busy}
                        >
                          ✏️ Edit
                        </Button>
                        <Button
                          type="button"
                          variant="secondary"
                          size="sm"
                          title={o.is_active ? "Deactivate organization" : "Activate organization"}
                          onClick={() => handleToggleStatus(o)}
                          disabled={busy}
                        >
                          {o.is_active ? "⏻ Deactivate" : "▶ Activate"}
                        </Button>
                        {isSuperadmin && (
                          <Button
                            type="button"
                            variant="danger"
                            size="sm"
                            title="Delete organization"
                            onClick={() => handleDeleteOrg(o)}
                            disabled={busy}
                          >
                            🗑️ Delete
                          </Button>
                        )}
                      </div>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </td>
                </tr>
              ))}
              {orgs.length === 0 && (
                <tr>
                  <td colSpan="8" className="table-empty-cell">
                    No organizations are available yet. Create one to get started.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Org Modal */}
      {isCreateModalOpen && (
        <Modal
          isOpen={isCreateModalOpen}
          title="Provision New Organization"
          onClose={() => setIsCreateModalOpen(false)}
        >
          <OrganizationForm
            mode="create"
            organization={formData}
            onSubmit={handleCreateOrg}
            onCancel={() => setIsCreateModalOpen(false)}
            busy={busy}
          />
        </Modal>
      )}

      {/* Edit Org Modal */}
      {isEditModalOpen && (
        <Modal
          isOpen={isEditModalOpen}
          title={selectedOrg ? `Edit ${selectedOrg.name}` : "Edit organization"}
          onClose={() => setIsEditModalOpen(false)}
        >
          <OrganizationForm
            mode="edit"
            organization={selectedOrg}
            onSubmit={handleUpdateOrg}
            onCancel={() => setIsEditModalOpen(false)}
            busy={busy}
          />
        </Modal>
      )}
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
