import { useEffect, useState, useCallback } from "react";
import AppLayout from "../../components/layout/AppLayout";
import { listOrganizations, createOrganization, updateOrganization } from "../../api/admin";
import Modal from "../../components/layout/Modal";
import { formatDateTime } from "../../utils/date";

export default function OrganizationManagement() {
  const [orgs, setOrgs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);

  // Modal states
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [selectedOrg, setSelectedOrg] = useState(null);
  const [formData, setFormData] = useState({ name: "", slug: "", plan: "community", max_assets: 500, max_users: 10 });

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

  const handleCreateOrg = async (e) => {
    e.preventDefault();
    try {
      await createOrganization(formData);
      setIsCreateModalOpen(false);
      setFormData({ name: "", slug: "", plan: "community", max_assets: 500, max_users: 10 });
      loadData(true);
    } catch (err) {
      alert(err.response?.data?.detail || "Failed to create organization");
    }
  };

  const handleUpdateOrg = async (e) => {
    e.preventDefault();
    try {
      await updateOrganization(selectedOrg.id, formData);
      setIsEditModalOpen(false);
      loadData(true);
    } catch (err) {
      alert(err.response?.data?.detail || "Failed to update organization");
    }
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
          <div style={{ display: "flex", gap: 10 }}>
             <button className="btn btn--ghost" onClick={() => loadData(true)} disabled={refreshing}>
               {refreshing ? "Refreshing..." : "Refresh"}
             </button>
             <button className="btn btn--primary" onClick={() => setIsCreateModalOpen(true)}>
               + New Organization
             </button>
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
                  <td><span className="method-chip" style={{ background: '#e0f2fe', color: '#0369a1' }}>{o.plan}</span></td>
                  <td style={{ fontFamily: "var(--mono)" }}>{o.max_assets}</td>
                  <td style={{ fontFamily: "var(--mono)" }}>{o.max_users}</td>
                  <td>
                    {o.is_active ? (
                      <span style={{ color: "var(--ok)", fontSize: 12 }}>● Active</span>
                    ) : (
                      <span style={{ color: "var(--text-muted)", fontSize: 12 }}>○ Inactive</span>
                    )}
                  </td>
                  <td style={{ fontSize: 12, color: "var(--text-muted)" }}>
                    {formatDateTime(o.created_at)}
                  </td>
                  <td>
                    <div className="action-btns" style={{ justifyContent: "flex-end" }}>
                      <button className="action-btn" onClick={() => openEditModal(o)}>Configure</button>
                    </div>
                  </td>
                </tr>
              ))}
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
          <form onSubmit={handleCreateOrg} className="auth-form" style={{ padding: 0, boxShadow: 'none', background: 'transparent' }}>
            <div className="form-group">
              <label>Organization Name</label>
              <input 
                type="text" 
                className="form-input" 
                required 
                placeholder="e.g. Acme Corp"
                value={formData.name}
                onChange={e => setFormData({...formData, name: e.target.value})}
              />
            </div>
            <div className="form-group">
              <label>Slug (URL Identifier)</label>
              <input 
                type="text" 
                className="form-input" 
                required 
                placeholder="e.g. acme-corp"
                value={formData.slug}
                onChange={e => setFormData({...formData, slug: e.target.value})}
              />
            </div>
            <div className="form-group">
              <label>Subscription Plan</label>
              <select 
                className="form-input" 
                value={formData.plan}
                onChange={e => setFormData({...formData, plan: e.target.value})}
              >
                <option value="community">Community</option>
                <option value="professional">Professional</option>
                <option value="enterprise">Enterprise</option>
              </select>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div className="form-group">
                <label>Max Assets</label>
                <input 
                  type="number" 
                  className="form-input" 
                  value={formData.max_assets}
                  onChange={e => setFormData({...formData, max_assets: parseInt(e.target.value)})}
                />
              </div>
              <div className="form-group">
                <label>Max Users</label>
                <input 
                  type="number" 
                  className="form-input" 
                  value={formData.max_users}
                  onChange={e => setFormData({...formData, max_users: parseInt(e.target.value)})}
                />
              </div>
            </div>
            <button type="submit" className="btn btn--primary" style={{ width: "100%", marginTop: 20 }}>Provision Organization</button>
          </form>
        </Modal>
      )}

      {/* Edit Org Modal */}
      {isEditModalOpen && (
        <Modal 
          isOpen={isEditModalOpen} 
          title={`Configure: ${selectedOrg.name}`} 
          onClose={() => setIsEditModalOpen(false)}
        >
          <form onSubmit={handleUpdateOrg} className="auth-form" style={{ padding: 0, boxShadow: 'none', background: 'transparent' }}>
            <div className="form-group">
              <label>Organization Name</label>
              <input 
                type="text" 
                className="form-input" 
                required 
                value={formData.name}
                onChange={e => setFormData({...formData, name: e.target.value})}
              />
            </div>
            <div className="form-group">
              <label>Subscription Plan</label>
              <select 
                className="form-input" 
                value={formData.plan}
                onChange={e => setFormData({...formData, plan: e.target.value})}
              >
                <option value="community">Community</option>
                <option value="professional">Professional</option>
                <option value="enterprise">Enterprise</option>
              </select>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div className="form-group">
                <label>Max Assets</label>
                <input 
                  type="number" 
                  className="form-input" 
                  value={formData.max_assets}
                  onChange={e => setFormData({...formData, max_assets: parseInt(e.target.value)})}
                />
              </div>
              <div className="form-group">
                <label>Max Users</label>
                <input 
                  type="number" 
                  className="form-input" 
                  value={formData.max_users}
                  onChange={e => setFormData({...formData, max_users: parseInt(e.target.value)})}
                />
              </div>
            </div>
            <div className="form-group" style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 10 }}>
               <input 
                 type="checkbox" 
                 checked={formData.is_active} 
                 onChange={e => setFormData({...formData, is_active: e.target.checked})}
               />
               <label style={{ marginBottom: 0 }}>Organization Active</label>
            </div>
            <button type="submit" className="btn btn--primary" style={{ width: "100%", marginTop: 20 }}>Save Configuration</button>
          </form>
        </Modal>
      )}
    </AppLayout>
  );
}
