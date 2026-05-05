import { useEffect, useState, useCallback } from "react";
import AppLayout from "../../components/layout/AppLayout";
import { listRoles, listRolePermissions } from "../../api/admin";
import Button from "../../components/common/Button";
import { useToasts, ToastContainer } from "../../components/common/Toast";

export default function RoleManagement() {
  const [roles, setRoles] = useState([]);
  const [selectedRole, setSelectedRole] = useState(null);
  const [permissions, setPermissions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadingPerms, setLoadingPerms] = useState(false);
  const [error, setError] = useState("");
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();

  const loadRoles = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listRoles();
      setRoles(data.roles);
      if (data.roles.length > 0) {
        handleSelectRole(data.roles[0]);
      }
    } catch (err) {
      setError("Failed to load roles.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRoles();
  }, [loadRoles]);

  const handleSelectRole = async (role) => {
    setSelectedRole(role);
    setLoadingPerms(true);
    try {
      const data = await listRolePermissions(role.id);
      setPermissions(data.permissions);
    } catch (err) {
      pushToast("Failed to load permissions for this role.", "error");
    } finally {
      setLoadingPerms(false);
    }
  };

  if (loading) {
    return (
      <AppLayout pageTitle="Roles & Permissions">
        <div style={{ display: "flex", justifyContent: "center", padding: 60 }}>
          <div className="spinner" />
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout pageTitle="Roles & Permissions">
      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Roles & Permissions</h2>
            <p className="page-subtitle">View system roles and their granular access control</p>
          </div>
        </div>

        {error && <div className="alert alert--error">{error}</div>}

        <div className="admin-grid">
          {/* Roles List */}
          <div className="card role-card">
            <div className="card__header role-card__header">
              <h3>Roles</h3>
            </div>
            <div className="role-list">
              {roles.map((r) => (
                <Button
                  key={r.id}
                  type="button"
                  variant="ghost"
                  size="md"
                  className={`role-list-item ${selectedRole?.id === r.id ? "role-list-item--selected" : ""}`}
                  onClick={() => handleSelectRole(r)}
                >
                  <div className="role-list-item__title">{r.name}</div>
                  <div className="role-list-item__subtitle">{r.description || "No description"}</div>
                </Button>
              ))}
            </div>
          </div>

          {/* Permissions List */}
          <div className="card">
            <div style={{ marginBottom: 20 }}>
               <h3 style={{ fontSize: 18, marginBottom: 4 }}>Permissions for <span style={{ color: "var(--primary)" }}>{selectedRole?.name}</span></h3>
               <p className="muted" style={{ fontSize: 14 }}>Granted capabilities for this role</p>
            </div>

            {loadingPerms ? (
              <div className="section-loader">
                <div className="spinner" />
              </div>
            ) : (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Resource</th>
                      <th>Action</th>
                      <th>Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {permissions.map(p => (
                      <tr key={p.id}>
                        <td><code className="ip-code" style={{ background: 'rgba(37, 99, 235, 0.05)', color: 'var(--primary)' }}>{p.resource}</code></td>
                        <td><span className="method-chip" style={{ background: p.action === 'manage' ? '#fef2f2' : '#f0f9ff', color: p.action === 'manage' ? '#dc2626' : '#0369a1' }}>{p.action}</span></td>
                        <td style={{ fontSize: 13 }}>{p.description || "Allows access to " + p.resource}</td>
                      </tr>
                    ))}
                    {permissions.length === 0 && (
                      <tr>
                        <td colSpan="3" style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>No permissions assigned to this role.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </AppLayout>
  );
}
