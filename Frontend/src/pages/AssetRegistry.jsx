/**
 * src/pages/AssetRegistry.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Full asset registry page.
 * - Paginated table with sort, filter, search
 * - Inline managed/unmanaged toggle (RBAC: assets:update)
 * - Click-to-drill-down to /assets/:id
 * - Export CSV button
 */
import { useState, useEffect, useCallback, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import AppLayout from "../components/layout/AppLayout";
import { useAuth } from "../context/AuthContext";
import { canPermission } from "../auth/permissions";
import { getAssets, updateAsset } from "../api/assets";
import "../styles/dashboard.css";

const ago = (iso) => {
  if (!iso) return "—";
  const m = Math.floor((Date.now() - new Date(iso)) / 60000);
  if (m < 1) return "now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
};

const riskColor = (score) =>
  score >= 75 ? "#ef4444" : score >= 50 ? "#f97316" : score >= 25 ? "#eab308" : "#22c55e";

const SEV_CLASS = {
  Critical: "db-sev-badge--critical", High: "db-sev-badge--high",
  Medium: "db-sev-badge--medium", Low: "db-sev-badge--low", Info: "db-sev-badge--info"
};

export default function AssetRegistry() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { user } = useAuth();
  const canUpdate = canPermission(user, { resource: "assets", action: "update" });

  const [assets, setAssets] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [search, setSearch] = useState(searchParams.get("search") || "");
  const [riskLevel, setRiskLevel] = useState(searchParams.get("risk_level") || "");
  const [osFamily, setOsFamily] = useState(searchParams.get("os_family") || "");
  const [managed, setManaged] = useState(searchParams.get("is_managed") || "");
  const [sortBy, setSortBy] = useState("risk_score");
  const [sortDir, setSortDir] = useState("desc");
  const [skip, setSkip] = useState(0);
  const LIMIT = 50;

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await getAssets({
        search: search || undefined,
        risk_level: riskLevel || undefined,
        os_family: osFamily || undefined,
        is_managed: managed === "" ? undefined : managed === "true",
        sort_by: sortBy,
        sort_dir: sortDir,
        skip,
        limit: LIMIT,
      });
      setAssets(r.data?.assets || []);
      setTotal(r.data?.total || 0);
    } catch {
      setError("Failed to load assets");
    } finally {
      setLoading(false);
    }
  }, [search, riskLevel, osFamily, managed, sortBy, sortDir, skip]);

  useEffect(() => { load(); }, [load]);

  // Search debounce
  const searchTimer = useRef(null);
  const handleSearch = (v) => {
    clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => { setSearch(v); setSkip(0); }, 350);
  };

  const handleSort = (col) => {
    if (sortBy === col) setSortDir(d => d === "desc" ? "asc" : "desc");
    else { setSortBy(col); setSortDir("desc"); }
  };

  const SortIcon = ({ col }) => sortBy !== col ? "↕" : sortDir === "desc" ? "↓" : "↑";

  const handleToggleManaged = async (asset, e) => {
    e.stopPropagation();
    try {
      await updateAsset(asset.id, { is_managed: !asset.is_managed });
      setAssets(prev => prev.map(a => a.id === asset.id ? { ...a, is_managed: !a.is_managed } : a));
    } catch { /* silent */ }
  };

  return (
    <AppLayout pageTitle="Asset Registry" onNewScan={() => navigate("/scan")}>
      <div className="db-page">

        {/* Header */}
        <div className="db-page-header">
          <div>
            <div className="db-page-title">Asset Registry</div>
            <div className="db-page-subtitle">{total.toLocaleString()} total assets discovered · RBAC-scoped</div>
          </div>
          <div className="db-header-actions">
            <button className="db-btn db-btn--ghost" onClick={load}>↻ Refresh</button>
            <button className="db-btn db-btn--primary" onClick={() => navigate("/scan")}>+ New Scan</button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div style={{ padding: "0 28px", borderBottom: "1px solid var(--border)", display: "flex", gap: 24, background: "var(--bg-white)" }}>
          {[
            { id: "", label: "Asset Inventory" },
            { id: "services", label: "Services & Ports" },
            { id: "tls", label: "TLS / Certificates" },
          ].map(tab => {
            const currentTab = searchParams.get("tab") || "";
            const active = currentTab === tab.id;
            return (
              <div
                key={tab.id}
                onClick={() => setSearchParams(tab.id ? { tab: tab.id } : {})}
                style={{
                  padding: "16px 4px",
                  fontSize: "0.85rem",
                  fontWeight: active ? 700 : 500,
                  color: active ? "var(--accent)" : "var(--text-muted)",
                  borderBottom: `2px solid ${active ? "var(--accent)" : "transparent"}`,
                  cursor: "pointer",
                  transition: "all 0.2s"
                }}
              >
                {tab.label}
              </div>
            );
          })}
        </div>

        {(!searchParams.get("tab") || searchParams.get("tab") === "") && (
          <>
            {/* Filters */}
            <div style={{ padding: "12px 28px", background: "var(--bg-white)", borderBottom: "1px solid var(--border)", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
              <input
                type="text"
                placeholder="Search IP, hostname, FQDN…"
                defaultValue={search}
                onChange={e => handleSearch(e.target.value)}
                style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border)", fontSize: "0.78rem", width: 220, color: "var(--text)", background: "var(--bg-white)" }}
              />
              <select value={riskLevel} onChange={e => { setRiskLevel(e.target.value); setSkip(0); }}
                style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border)", fontSize: "0.78rem", color: "var(--text)", background: "var(--bg-white)" }}>
                <option value="">All Risk Levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
              <select value={osFamily} onChange={e => { setOsFamily(e.target.value); setSkip(0); }}
                style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border)", fontSize: "0.78rem", color: "var(--text)", background: "var(--bg-white)" }}>
                <option value="">All OS Families</option>
                <option value="Linux">Linux</option>
                <option value="Windows">Windows</option>
                <option value="macOS">macOS</option>
                <option value="Unknown">Unknown</option>
              </select>
              <select value={managed} onChange={e => { setManaged(e.target.value); setSkip(0); }}
                style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border)", fontSize: "0.78rem", color: "var(--text)", background: "var(--bg-white)" }}>
                <option value="">All Assets</option>
                <option value="true">Managed Only</option>
                <option value="false">Unmanaged Only</option>
              </select>
              <div style={{ marginLeft: "auto", fontSize: "0.72rem", color: "var(--text-muted)" }}>
                {total.toLocaleString()} assets · Page {Math.floor(skip / LIMIT) + 1} of {Math.ceil(total / LIMIT) || 1}
              </div>
            </div>

            {/* Table */}
            <div style={{ padding: "16px 28px" }}>
              {error && (
                <div className="db-alert db-alert--critical" style={{ marginBottom: 12 }}>
                  <span className="db-alert-icon">⚠</span>
                  <div>{error}</div>
                  <button className="db-btn db-btn--ghost" onClick={load}>Retry</button>
                </div>
              )}

              <div className="db-card" style={{ padding: 0 }}>
                <div className="db-table-wrap">
                  <table className="db-table">
                    <thead>
                      <tr>
                        <th style={{ cursor: "pointer" }} onClick={() => handleSort("ip_address")}>IP / Host <SortIcon col="ip_address" /></th>
                        <th>OS</th>
                        <th>Category</th>
                        <th style={{ cursor: "pointer" }} onClick={() => handleSort("risk_score")}>Risk <SortIcon col="risk_score" /></th>
                        <th>C</th><th>H</th><th>M</th>
                        <th>Tags</th>
                        <th style={{ cursor: "pointer" }} onClick={() => handleSort("last_seen_at")}>Last Seen <SortIcon col="last_seen_at" /></th>
                        <th>Managed</th>
                      </tr>
                    </thead>
                    <tbody>
                      {loading && Array.from({ length: 8 }).map((_, i) => (
                        <tr key={i}>
                          {Array.from({ length: 10 }).map((_, j) => (
                            <td key={j}><div className="db-skeleton" style={{ height: 12, borderRadius: 3 }} /></td>
                          ))}
                        </tr>
                      ))}
                      {!loading && assets.length === 0 && (
                        <tr><td colSpan={10} style={{ textAlign: "center", padding: 32, color: "var(--text-muted)" }}>
                          No assets match your filters. Run a scan to populate the registry.
                        </td></tr>
                      )}
                      {!loading && assets.map((a) => (
                        <tr key={a.id} style={{ cursor: "pointer" }} onClick={() => navigate(`/assets/${a.id}`)}>
                          <td>
                            <div className="mono" style={{ fontWeight: 600 }}>{a.ip_address}</div>
                            {a.hostname && <div style={{ fontSize: "0.65rem", color: "var(--text-faint)" }}>{a.hostname}</div>}
                            {a.fqdn && a.fqdn !== a.hostname && <div style={{ fontSize: "0.62rem", color: "var(--text-faint)" }}>{a.fqdn}</div>}
                          </td>
                          <td>
                            <span className="db-tag">{a.os_name || a.os_family || "Unknown"}</span>
                            {(a.os_name || a.os_family) && a.os_confidence && (
                              <div style={{ fontSize: "0.6rem", color: "var(--text-faint)", marginTop: 2 }}>
                                Conf: {a.os_confidence}%
                              </div>
                            )}
                          </td>
                          <td style={{ color: "var(--text-muted)", fontSize: "0.72rem" }}>
                            {a.device_category || "—"}
                          </td>
                          <td>
                            <div className="db-risk-cell">
                              <div className="db-risk-bar-mini">
                                <div className="db-risk-bar-fill" style={{ width: `${a.risk_score}%`, background: riskColor(a.risk_score) }} />
                              </div>
                              <span style={{ fontWeight: 700, fontSize: "0.78rem", color: riskColor(a.risk_score) }}>{a.risk_score}</span>
                            </div>
                            <span className={`db-sev-badge ${SEV_CLASS[a.risk_level?.charAt(0).toUpperCase() + a.risk_level?.slice(1).toLowerCase()] || "db-sev-badge--info"}`}
                              style={{ marginTop: 3, display: "inline-block" }}>
                              {a.risk_level}
                            </span>
                          </td>
                          <td style={{ color: "#f87171", fontWeight: 700 }}>{a.vuln_counts?.critical || 0}</td>
                          <td style={{ color: "#fb923c", fontWeight: 700 }}>{a.vuln_counts?.high || 0}</td>
                          <td style={{ color: "#fbbf24" }}>{a.vuln_counts?.medium || 0}</td>
                          <td>
                            <div style={{ display: "flex", flexWrap: "wrap", gap: 2 }}>
                              {(a.tags || []).slice(0, 3).map(tag => (
                                <span key={tag} className="db-tag">{tag}</span>
                              ))}
                            </div>
                          </td>
                          <td style={{ color: "var(--text-muted)", fontSize: "0.72rem" }}>{ago(a.last_seen_at)}</td>
                          <td onClick={canUpdate ? e => handleToggleManaged(a, e) : undefined}>
                            <span className="db-tag" style={a.is_managed
                              ? { background: "rgba(34,197,94,0.08)", color: "#4ade80", border: "1px solid rgba(34,197,94,0.2)", cursor: canUpdate ? "pointer" : "default" }
                              : { background: "rgba(239,68,68,0.08)", color: "#f87171", border: "1px solid rgba(239,68,68,0.2)", cursor: canUpdate ? "pointer" : "default" }
                            }>
                              {a.is_managed ? "✔ Managed" : "✗ Unmanaged"}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div style={{ padding: "10px 16px", display: "flex", alignItems: "center", justifyContent: "space-between", borderTop: "1px solid var(--border)" }}>
                  <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                    Showing {skip + 1}–{Math.min(skip + LIMIT, total)} of {total.toLocaleString()}
                  </span>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button
                      className="db-btn db-btn--ghost"
                      disabled={skip === 0}
                      onClick={() => setSkip(s => Math.max(0, s - LIMIT))}
                      style={{ opacity: skip === 0 ? 0.4 : 1 }}
                    >
                      ← Prev
                    </button>
                    <button
                      className="db-btn db-btn--ghost"
                      disabled={skip + LIMIT >= total}
                      onClick={() => setSkip(s => s + LIMIT)}
                      style={{ opacity: skip + LIMIT >= total ? 0.4 : 1 }}
                    >
                      Next →
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        {searchParams.get("tab") === "services" && (
          <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>
            <div style={{ fontSize: "2.5rem", marginBottom: 16 }}>🔌</div>
            <h3 style={{ color: "var(--text)", marginBottom: 8 }}>Services & Ports View</h3>
            <p>This module provides a unified view of all discovered services, open ports, and protocols across your infrastructure.</p>
            <div style={{ display: "inline-block", marginTop: 16, padding: "4px 8px", background: "rgba(14,165,233,0.1)", color: "var(--accent)", borderRadius: 4, fontSize: "0.75rem", fontWeight: 700 }}>AVAILABLE SOON</div>
          </div>
        )}

        {searchParams.get("tab") === "tls" && (
          <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>
            <div style={{ fontSize: "2.5rem", marginBottom: 16 }}>🔐</div>
            <h3 style={{ color: "var(--text)", marginBottom: 8 }}>TLS / Certificates Inventory</h3>
            <p>Track certificate expiration dates, weak cipher suites, and TLS grades across all monitored assets.</p>
            <div style={{ display: "inline-block", marginTop: 16, padding: "4px 8px", background: "rgba(14,165,233,0.1)", color: "var(--accent)", borderRadius: 4, fontSize: "0.75rem", fontWeight: 700 }}>AVAILABLE SOON</div>
          </div>
        )}

      </div>
    </AppLayout>
  );
}
