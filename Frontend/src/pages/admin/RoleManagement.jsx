import { useEffect, useState, useCallback } from "react";
import AppLayout from "../../components/layout/AppLayout";
import { listRoles, listRolePermissions } from "../../api/admin";

export default function RoleManagement() {
  const [roles, setRoles] = useState([]);
  const [selectedRole, setSelectedRole] = useState(null);
  const [permissions, setPermissions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadingPerms, setLoadingPerms] = useState(false);
  const [error, setError] = useState("");

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
      alert("Failed to load permissions for this role");
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

        <div style={{ display: "grid", gridTemplateColumns: "300px 1fr", gap: 24, marginTop: 20 }}>
          {/* Roles List */}
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--border)", fontWeight: 600 }}>Roles</div>
            <div style={{ display: "flex", flexDirection: "column" }}>
              {roles.map(r => (
                <button
                  key={r.id}
                  onClick={() => handleSelectRole(r)}
                  style={{
                    padding: "16px 20px",
                    textAlign: "left",
                    background: selectedRole?.id === r.id ? "rgba(37, 99, 235, 0.1)" : "transparent",
                    border: "none",
                    borderLeft: selectedRole?.id === r.id ? "4px solid var(--primary)" : "4px solid transparent",
                    color: selectedRole?.id === r.id ? "var(--primary)" : "var(--text)",
                    cursor: "pointer",
                    fontWeight: selectedRole?.id === r.id ? 600 : 400,
                    transition: "all 0.2s"
                  }}
                >
                  <div style={{ fontSize: 14 }}>{r.name}</div>
                  <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>{r.description || "No description"}</div>
                </button>
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
              <div style={{ display: "flex", justifyContent: "center", padding: 40 }}>
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
    </AppLayout>
  );
}
