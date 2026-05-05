import { useEffect, useState, useCallback } from "react";
import AppLayout from "../../components/layout/AppLayout";
import { listAuditLogs } from "../../api/admin";
import { formatDateTime } from "../../utils/date";

export default function AuditLogs() {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [filters, setFilters] = useState({ action: "", resource_type: "", status: "" });

  const loadData = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    else setRefreshing(true);
    try {
      const params = {
        skip: 0,
        limit: 100,
        ...Object.fromEntries(Object.entries(filters).filter(([_, v]) => v !== ""))
      };
      const data = await listAuditLogs(params);
      setLogs(data.logs);
      setTotal(data.total);
    } catch (err) {
      setError("Failed to load audit logs.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [filters]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleFilterChange = (e) => {
    setFilters({ ...filters, [e.target.name]: e.target.value });
  };

  if (loading) {
    return (
      <AppLayout pageTitle="Audit Logs">
        <div style={{ display: "flex", justifyContent: "center", padding: 60 }}>
          <div className="spinner" />
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout pageTitle="Audit Logs">
      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Audit Logs</h2>
            <p className="page-subtitle">Immutable trail of system activities and user actions</p>
          </div>
          <button className="btn btn--ghost" onClick={() => loadData(true)} disabled={refreshing}>
            {refreshing ? "Syncing..." : "Sync Logs"}
          </button>
        </div>

        {error && <div className="alert alert--error">{error}</div>}

        <div className="filter-bar" style={{ marginBottom: 20 }}>
          <div className="filter-group">
            <label>Action</label>
            <select name="action" className="form-input" style={{ width: 180 }} value={filters.action} onChange={handleFilterChange}>
              <option value="">All Actions</option>
              <option value="user.login">Login</option>
              <option value="user.login_failed">Login Failed</option>
              <option value="user.created">User Created</option>
              <option value="user.updated">User Updated</option>
              <option value="user.deleted">User Deleted</option>
              <option value="scan.created">Scan Created</option>
            </select>
          </div>
          <div className="filter-group">
            <label>Resource</label>
            <select name="resource_type" className="form-input" style={{ width: 150 }} value={filters.resource_type} onChange={handleFilterChange}>
              <option value="">All Resources</option>
              <option value="user">User</option>
              <option value="scan">Scan</option>
              <option value="organization">Organization</option>
            </select>
          </div>
          <div className="filter-group">
            <label>Status</label>
            <select name="status" className="form-input" style={{ width: 120 }} value={filters.status} onChange={handleFilterChange}>
              <option value="">All Status</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
              <option value="denied">Denied</option>
            </select>
          </div>
        </div>

        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Target ID</th>
                <th>Status</th>
                <th>IP Address</th>
                <th>Changes</th>
              </tr>
            </thead>
            <tbody>
              {logs.map(log => (
                <tr key={log.id}>
                  <td style={{ fontSize: 12, color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                    {formatDateTime(log.created_at)}
                  </td>
                  <td><strong style={{ fontSize: 13 }}>{log.action}</strong></td>
                  <td><span className="method-chip" style={{ fontSize: 11 }}>{log.resource_type || "—"}</span></td>
                  <td><code style={{ fontSize: 11 }}>{log.resource_id || "—"}</code></td>
                  <td>
                    <span style={{ 
                      color: log.status === 'success' ? 'var(--ok)' : 'var(--danger)',
                      fontSize: 12,
                      fontWeight: 600
                    }}>
                      {log.status.toUpperCase()}
                    </span>
                  </td>
                  <td><code style={{ fontSize: 12 }}>{log.ip_address || "—"}</code></td>
                  <td>
                    {log.changes ? (
                      <button 
                        className="btn btn--ghost" 
                        style={{ padding: "2px 8px", fontSize: 11 }}
                        onClick={() => alert(JSON.stringify(log.changes, null, 2))}
                      >
                        View Changes
                      </button>
                    ) : "—"}
                  </td>
                </tr>
              ))}
              {logs.length === 0 && (
                <tr>
                  <td colSpan="7" style={{ textAlign: "center", padding: 60, color: "var(--text-muted)" }}>
                    No audit logs found matching your criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {logs.length > 0 && (
           <p className="muted" style={{ textAlign: "center", marginTop: 16, fontSize: 12 }}>
             Showing latest {logs.length} of {total} events
           </p>
        )}
      </div>
    </AppLayout>
  );
}
