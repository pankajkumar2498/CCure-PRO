import { useEffect, useState, useCallback } from "react";
import AppLayout from "../../components/layout/AppLayout";
import { useAuth } from "../../context/AuthContext";
import { listUsers, listRoles, createUser, updateUser, changeUserRole, changeUserStatus, deleteUser } from "../../api/admin";
import Modal from "../../components/layout/Modal";
import { formatDateTime } from "../../utils/date";

export default function UserManagement() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);

  // Modal states
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [formData, setFormData] = useState({ username: "", email: "", full_name: "", role_id: "", password: "" });

  const loadData = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    else setRefreshing(true);
    try {
      const [usersData, rolesData] = await Promise.all([
        listUsers({ skip: 0, limit: 100 }),
        listRoles()
      ]);
      setUsers(usersData.users);
      setTotal(usersData.total);
      setRoles(rolesData.roles);
    } catch (err) {
      setError("Failed to load user management data.");
      console.error(err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    try {
      await createUser(formData);
      setIsCreateModalOpen(false);
      setFormData({ username: "", email: "", full_name: "", role_id: "", password: "" });
      loadData(true);
    } catch (err) {
      alert(err.response?.data?.detail || "Failed to create user");
    }
  };

  const handleUpdateUser = async (e) => {
    e.preventDefault();
    try {
      await updateUser(selectedUser.id, { full_name: formData.full_name, email: formData.email });
      if (formData.role_id !== selectedUser.role_id) {
        await changeUserRole(selectedUser.id, formData.role_id);
      }
      setIsEditModalOpen(false);
      loadData(true);
    } catch (err) {
      alert(err.response?.data?.detail || "Failed to update user");
    }
  };

  const toggleUserStatus = async (user) => {
    const action = user.is_active ? "deactivate" : "activate";
    if (!window.confirm(`Are you sure you want to ${action} user ${user.username}?`)) return;
    try {
      await changeUserStatus(user.id, { is_active: !user.is_active });
      loadData(true);
    } catch (err) {
      alert("Failed to change user status");
    }
  };

  const handleUnlockUser = async (user) => {
    try {
      await changeUserStatus(user.id, { locked_until: null });
      loadData(true);
      alert("User unlocked successfully");
    } catch (err) {
      alert("Failed to unlock user");
    }
  };

  const handleDeleteUser = async (user) => {
    if (!window.confirm(`Are you sure you want to delete user ${user.username}? This is a soft delete.`)) return;
    try {
      await deleteUser(user.id);
      loadData(true);
    } catch (err) {
      alert("Failed to delete user");
    }
  };

  const openEditModal = (user) => {
    setSelectedUser(user);
    setFormData({
      username: user.username,
      email: user.email,
      full_name: user.full_name || "",
      role_id: user.role_id,
      password: ""
    });
    setIsEditModalOpen(true);
  };

  if (loading) {
    return (
      <AppLayout pageTitle="User Management">
        <div style={{ display: "flex", justifyContent: "center", padding: 60 }}>
          <div className="spinner" />
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout pageTitle="User Management">
      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h2 className="page-title">User Management</h2>
            <p className="page-subtitle">{total} Users in your organization</p>
          </div>
          <div style={{ display: "flex", gap: 10 }}>
             <button className="btn btn--ghost" onClick={() => loadData(true)} disabled={refreshing}>
               {refreshing ? "Refreshing..." : "Refresh"}
             </button>
             <button className="btn btn--primary" onClick={() => setIsCreateModalOpen(true)}>
               + Create User
             </button>
          </div>
        </div>

        {error && <div className="alert alert--error">{error}</div>}

        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Full Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Last Login</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => {
                const roleName = roles.find(r => r.id === u.role_id)?.name || u.role_id;
                const isLocked = u.locked_until && new Date(u.locked_until) > new Date();
                
                return (
                  <tr key={u.id}>
                    <td><code className="ip-code">{u.username}</code></td>
                    <td>{u.full_name || "—"}</td>
                    <td>{u.email}</td>
                    <td><span className="method-chip">{roleName}</span></td>
                    <td>
                      {isLocked ? (
                        <span style={{ color: "var(--danger)", fontSize: 12 }}>🔒 Locked</span>
                      ) : u.is_active ? (
                        <span style={{ color: "var(--ok)", fontSize: 12 }}>● Active</span>
                      ) : (
                        <span style={{ color: "var(--text-muted)", fontSize: 12 }}>○ Inactive</span>
                      )}
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      {u.last_login_at ? formatDateTime(u.last_login_at) : "Never"}
                    </td>
                    <td>
                      <div className="action-btns" style={{ justifyContent: "flex-end" }}>
                        <button className="action-btn" onClick={() => openEditModal(u)}>Edit</button>
                        {isLocked && (
                          <button className="action-btn" onClick={() => handleUnlockUser(u)}>Unlock</button>
                        )}
                        <button 
                          className="action-btn" 
                          onClick={() => toggleUserStatus(u)}
                        >
                          {u.is_active ? "Deactivate" : "Activate"}
                        </button>
                        <button className="action-btn action-btn--danger" onClick={() => handleDeleteUser(u)}>Delete</button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create User Modal */}
      {isCreateModalOpen && (
        <Modal 
          isOpen={isCreateModalOpen} 
          title="Create New User" 
          onClose={() => setIsCreateModalOpen(false)}
        >
          <form onSubmit={handleCreateUser} className="auth-form" style={{ padding: 0, boxShadow: 'none', background: 'transparent' }}>
            <div className="form-group">
              <label>Username</label>
              <input 
                type="text" 
                className="form-input" 
                required 
                value={formData.username}
                onChange={e => setFormData({...formData, username: e.target.value})}
              />
            </div>
            <div className="form-group">
              <label>Full Name</label>
              <input 
                type="text" 
                className="form-input" 
                value={formData.full_name}
                onChange={e => setFormData({...formData, full_name: e.target.value})}
              />
            </div>
            <div className="form-group">
              <label>Email</label>
              <input 
                type="email" 
                className="form-input" 
                required 
                value={formData.email}
                onChange={e => setFormData({...formData, email: e.target.value})}
              />
            </div>
            <div className="form-group">
              <label>Password</label>
              <input 
                type="password" 
                className="form-input" 
                required 
                value={formData.password}
                onChange={e => setFormData({...formData, password: e.target.value})}
              />
            </div>
            <div className="form-group">
              <label>Role</label>
              <select 
                className="form-input" 
                required 
                value={formData.role_id}
                onChange={e => setFormData({...formData, role_id: parseInt(e.target.value)})}
              >
                <option value="">Select a role</option>
                {roles.map(r => (
                  <option key={r.id} value={r.id}>{r.name}</option>
                ))}
              </select>
            </div>
            <button type="submit" className="btn btn--primary" style={{ width: "100%", marginTop: 20 }}>Create User</button>
          </form>
        </Modal>
      )}

      {/* Edit User Modal */}
      {isEditModalOpen && (
        <Modal 
          isOpen={isEditModalOpen} 
          title={`Edit User: ${selectedUser.username}`} 
          onClose={() => setIsEditModalOpen(false)}
        >
          <form onSubmit={handleUpdateUser} className="auth-form" style={{ padding: 0, boxShadow: 'none', background: 'transparent' }}>
            <div className="form-group">
              <label>Full Name</label>
              <input 
                type="text" 
                className="form-input" 
                value={formData.full_name}
                onChange={e => setFormData({...formData, full_name: e.target.value})}
              />
            </div>
            <div className="form-group">
              <label>Email</label>
              <input 
                type="email" 
                className="form-input" 
                required 
                value={formData.email}
                onChange={e => setFormData({...formData, email: e.target.value})}
              />
            </div>
            <div className="form-group">
              <label>Role</label>
              <select 
                className="form-input" 
                required 
                value={formData.role_id}
                onChange={e => setFormData({...formData, role_id: parseInt(e.target.value)})}
              >
                {roles.map(r => (
                  <option key={r.id} value={r.id}>{r.name}</option>
                ))}
              </select>
            </div>
            <button type="submit" className="btn btn--primary" style={{ width: "100%", marginTop: 20 }}>Save Changes</button>
          </form>
        </Modal>
      )}
    </AppLayout>
  );
}
