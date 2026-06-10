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
import { getAssets, updateAsset, getGlobalServices, getGlobalCertificates, getServiceAssets } from "../api/assets";
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
  const [searchInput, setSearchInput] = useState(searchParams.get("search") || "");
  const [search, setSearch] = useState(searchParams.get("search") || "");
  const [riskLevel, setRiskLevel] = useState(searchParams.get("risk_level") || "");
  const [osFamily, setOsFamily] = useState(searchParams.get("os_family") || "");
  const [managed, setManaged] = useState(searchParams.get("is_managed") || "");
  const [sortBy, setSortBy] = useState("risk_score");
  const [sortDir, setSortDir] = useState("desc");
  const [skip, setSkip] = useState(0);
  const LIMIT = 50;

  // Services State
  const [services, setServices] = useState([]);
  const [servicesTotal, setServicesTotal] = useState(0);
  const [servicesLoading, setServicesLoading] = useState(false);
  const [servicesError, setServicesError] = useState(null);
  const [servicesSearchInput, setServicesSearchInput] = useState("");
  const [servicesSearch, setServicesSearch] = useState("");
  const [servicesSortBy, setServicesSortBy] = useState("asset_count");
  const [servicesSortDir, setServicesSortDir] = useState("desc");
  const [servicesSkip, setServicesSkip] = useState(0);
  
  // Services Filter State
  const [servicesPort, setServicesPort] = useState("");
  const [servicesProtocol, setServicesProtocol] = useState("");
  const [servicesAssetType, setServicesAssetType] = useState("");
  const [servicesSubnet, setServicesSubnet] = useState("");

  // Services Modal State
  const [activeService, setActiveService] = useState(null);
  const [modalSearchInput, setModalSearchInput] = useState("");
  const [modalSearch, setModalSearch] = useState("");
  const [modalAssets, setModalAssets] = useState([]);
  const [modalAssetsTotal, setModalAssetsTotal] = useState(0);
  const [modalAssetsLoading, setModalAssetsLoading] = useState(false);
  const [modalAssetsError, setModalAssetsError] = useState(null);
  const [modalAssetsSkip, setModalAssetsSkip] = useState(0);

  // Certificates State
  const [certs, setCerts] = useState([]);
  const [certsTotal, setCertsTotal] = useState(0);
  const [certsLoading, setCertsLoading] = useState(false);
  const [certsError, setCertsError] = useState(null);
  const [certsSearchInput, setCertsSearchInput] = useState("");
  const [certsSearch, setCertsSearch] = useState("");
  const [certsSortBy, setCertsSortBy] = useState("expiration");
  const [certsSortDir, setCertsSortDir] = useState("asc");
  const [certsSkip, setCertsSkip] = useState(0);

  const currentTab = searchParams.get("tab") || "assets";

  // Sync search input and query when URL params change
  useEffect(() => {
    const s = searchParams.get("search") || "";
    setSearchInput(s);
    setSearch(s);
  }, [searchParams]);

  const load = useCallback(async () => {
    if (currentTab !== "assets") return;
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
  }, [search, riskLevel, osFamily, managed, sortBy, sortDir, skip, currentTab]);

  const loadServices = useCallback(async () => {
    if (currentTab !== "services") return;
    setServicesLoading(true);
    setServicesError(null);
    try {
      const r = await getGlobalServices({
        search: servicesSearch || undefined,
        port: servicesPort ? parseInt(servicesPort, 10) : undefined,
        protocol: servicesProtocol || undefined,
        asset_type: servicesAssetType || undefined,
        subnet: servicesSubnet || undefined,
        sort_by: servicesSortBy,
        sort_dir: servicesSortDir,
        skip: servicesSkip,
        limit: LIMIT,
      });
      setServices(r.data?.services || []);
      setServicesTotal(r.data?.total || 0);
    } catch {
      setServicesError("Failed to load services");
    } finally {
      setServicesLoading(false);
    }
  }, [servicesSearch, servicesPort, servicesProtocol, servicesAssetType, servicesSubnet, servicesSortBy, servicesSortDir, servicesSkip, currentTab]);

  const loadCertificates = useCallback(async () => {
    if (currentTab !== "tls") return;
    setCertsLoading(true);
    setCertsError(null);
    try {
      const r = await getGlobalCertificates({
        search: certsSearch || undefined,
        sort_by: certsSortBy,
        sort_dir: certsSortDir,
        skip: certsSkip,
        limit: LIMIT,
      });
      setCerts(r.data?.certificates || []);
      setCertsTotal(r.data?.total || 0);
    } catch {
      setCertsError("Failed to load certificates");
    } finally {
      setCertsLoading(false);
    }
  }, [certsSearch, certsSortBy, certsSortDir, certsSkip, currentTab]);

  const loadModalAssets = useCallback(async () => {
    if (!activeService) return;
    setModalAssetsLoading(true);
    setModalAssetsError(null);
    try {
      const r = await getServiceAssets({
        service_name: activeService.service_name,
        port: activeService.port,
        protocol: activeService.protocol,
        search: modalSearch || undefined,
        skip: modalAssetsSkip,
        limit: 10,
      });
      setModalAssets(r.data?.assets || []);
      setModalAssetsTotal(r.data?.total || 0);
    } catch {
      setModalAssetsError("Failed to load assets for service");
    } finally {
      setModalAssetsLoading(false);
    }
  }, [activeService, modalSearch, modalAssetsSkip]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadServices(); }, [loadServices]);
  useEffect(() => { loadCertificates(); }, [loadCertificates]);
  useEffect(() => { loadModalAssets(); }, [loadModalAssets]);

  const modalSearchTimer = useRef(null);
  const handleModalSearchChange = (v) => {
    setModalSearchInput(v);
    clearTimeout(modalSearchTimer.current);
    modalSearchTimer.current = setTimeout(() => { setModalSearch(v); setModalAssetsSkip(0); }, 350);
  };

  // Search debounce
  const searchTimer = useRef(null);
  const handleSearchChange = (v) => {
    setSearchInput(v);
    clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => { setSearch(v); setSkip(0); }, 350);
  };

  const servicesSearchTimer = useRef(null);
  const handleServicesSearchChange = (v) => {
    setServicesSearchInput(v);
    clearTimeout(servicesSearchTimer.current);
    servicesSearchTimer.current = setTimeout(() => { setServicesSearch(v); setServicesSkip(0); }, 350);
  };

  const certsSearchTimer = useRef(null);
  const handleCertsSearchChange = (v) => {
    setCertsSearchInput(v);
    clearTimeout(certsSearchTimer.current);
    certsSearchTimer.current = setTimeout(() => { setCertsSearch(v); setCertsSkip(0); }, 350);
  };

  const handleSort = (col) => {
    if (sortBy === col) setSortDir(d => d === "desc" ? "asc" : "desc");
    else { setSortBy(col); setSortDir("desc"); }
  };

  const handleServicesSort = (col) => {
    if (servicesSortBy === col) setServicesSortDir(d => d === "desc" ? "asc" : "desc");
    else { setServicesSortBy(col); setServicesSortDir("asc"); }
  };

  const handleCertsSort = (col) => {
    if (certsSortBy === col) setCertsSortDir(d => d === "desc" ? "asc" : "desc");
    else { setCertsSortBy(col); setCertsSortDir("asc"); }
  };

  const SortIcon = ({ col }) => sortBy !== col ? "↕" : sortDir === "desc" ? "↓" : "↑";
  const ServicesSortIcon = ({ col }) => servicesSortBy !== col ? "↕" : servicesSortDir === "desc" ? "↓" : "↑";
  const CertsSortIcon = ({ col }) => certsSortBy !== col ? "↕" : certsSortDir === "desc" ? "↓" : "↑";

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
            <div className="db-page-title">
              {currentTab === "services" 
                ? "Services & Ports Inventory" 
                : currentTab === "tls" 
                  ? "TLS / Certificates Inventory" 
                  : "Asset Registry"
              }
            </div>
            <div className="db-page-subtitle">
              {currentTab === "services" 
                ? `${servicesTotal.toLocaleString()} services discovered · Global View`
                : currentTab === "tls"
                  ? `${certsTotal.toLocaleString()} certificates discovered · Global View`
                  : `${total.toLocaleString()} total assets discovered · RBAC-scoped`
              }
            </div>
          </div>
          <div className="db-header-actions">
            <button className="db-btn db-btn--ghost" onClick={
              currentTab === "tls" 
                ? loadCertificates 
                : currentTab === "services" 
                  ? loadServices 
                  : load
            }>↻ Refresh</button>
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
                value={searchInput}
                onChange={e => handleSearchChange(e.target.value)}
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
                        <th>Owner</th>
                        <th>Employee ID</th>
                        <th>Serial</th>
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
                          {Array.from({ length: 13 }).map((_, j) => (
                            <td key={j}><div className="db-skeleton" style={{ height: 12, borderRadius: 3 }} /></td>
                          ))}
                        </tr>
                      ))}
                      {!loading && assets.length === 0 && (
                        <tr><td colSpan={13} style={{ textAlign: "center", padding: 32, color: "var(--text-muted)" }}>
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
                            <span style={{ fontWeight: 600, color: a.owner ? "var(--text)" : "var(--text-faint)" }}>
                              {a.owner || "—"}
                            </span>
                          </td>
                          <td className="mono" style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                            {a.emp_id || "—"}
                          </td>
                          <td className="mono" style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                            {a.serial || "—"}
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
          <>
            {/* Filters */}
            <div style={{ padding: "12px 28px", background: "var(--bg-white)", borderBottom: "1px solid var(--border)", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
              <input
                type="text"
                placeholder="Search service, product…"
                value={servicesSearchInput}
                onChange={e => handleServicesSearchChange(e.target.value)}
                style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border)", fontSize: "0.78rem", width: 180, color: "var(--text)", background: "var(--bg-white)" }}
              />
              <input
                type="number"
                placeholder="Port"
                value={servicesPort}
                onChange={e => { setServicesPort(e.target.value); setServicesSkip(0); }}
                style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border)", fontSize: "0.78rem", width: 80, color: "var(--text)", background: "var(--bg-white)" }}
              />
              <select
                value={servicesProtocol}
                onChange={e => { setServicesProtocol(e.target.value); setServicesSkip(0); }}
                style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border)", fontSize: "0.78rem", width: 120, color: "var(--text)", background: "var(--bg-white)" }}
              >
                <option value="">All Protocols</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
              </select>
              <select
                value={servicesAssetType}
                onChange={e => { setServicesAssetType(e.target.value); setServicesSkip(0); }}
                style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border)", fontSize: "0.78rem", width: 140, color: "var(--text)", background: "var(--bg-white)" }}
              >
                <option value="">All Asset Types</option>
                <option value="server">Server</option>
                <option value="workstation">Workstation</option>
                <option value="laptop">Laptop</option>
                <option value="printer">Printer</option>
                <option value="network">Network Device</option>
                <option value="iot">IoT</option>
                <option value="unknown">Unknown</option>
              </select>
              <input
                type="text"
                placeholder="Subnet / Segment…"
                value={servicesSubnet}
                onChange={e => { setServicesSubnet(e.target.value); setServicesSkip(0); }}
                style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border)", fontSize: "0.78rem", width: 160, color: "var(--text)", background: "var(--bg-white)" }}
              />
              <button
                className="db-btn db-btn--ghost"
                onClick={() => {
                  setServicesSearchInput("");
                  setServicesSearch("");
                  setServicesPort("");
                  setServicesProtocol("");
                  setServicesAssetType("");
                  setServicesSubnet("");
                  setServicesSkip(0);
                }}
                style={{ fontSize: "0.75rem", padding: "6px 12px" }}
              >
                Clear Filters
              </button>
              <div style={{ marginLeft: "auto", fontSize: "0.72rem", color: "var(--text-muted)" }}>
                {servicesTotal.toLocaleString()} services · Page {Math.floor(servicesSkip / LIMIT) + 1} of {Math.ceil(servicesTotal / LIMIT) || 1}
              </div>
            </div>

            {/* Table */}
            <div style={{ padding: "16px 28px" }}>
              {servicesError && (
                <div className="db-alert db-alert--critical" style={{ marginBottom: 12 }}>
                  <span className="db-alert-icon">⚠</span>
                  <div>{servicesError}</div>
                  <button className="db-btn db-btn--ghost" onClick={loadServices}>Retry</button>
                </div>
              )}

              <div className="db-card" style={{ padding: 0 }}>
                <div className="db-table-wrap">
                  <table className="db-table">
                    <thead>
                      <tr>
                        <th style={{ cursor: "pointer" }} onClick={() => handleServicesSort("service_name")}>Service Name <ServicesSortIcon col="service_name" /></th>
                        <th style={{ cursor: "pointer" }} onClick={() => handleServicesSort("port")}>Port <ServicesSortIcon col="port" /></th>
                        <th style={{ cursor: "pointer" }} onClick={() => handleServicesSort("protocol")}>Protocol <ServicesSortIcon col="protocol" /></th>
                        <th style={{ cursor: "pointer" }} onClick={() => handleServicesSort("asset_count")}>Asset Count <ServicesSortIcon col="asset_count" /></th>
                        <th>Exposure Risk</th>
                        <th style={{ cursor: "pointer" }} onClick={() => handleServicesSort("last_seen")}>Last Seen <ServicesSortIcon col="last_seen" /></th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {servicesLoading && Array.from({ length: 8 }).map((_, i) => (
                        <tr key={i}>
                          {Array.from({ length: 7 }).map((_, j) => (
                            <td key={j}><div className="db-skeleton" style={{ height: 12, borderRadius: 3 }} /></td>
                          ))}
                        </tr>
                      ))}
                      {!servicesLoading && services.length === 0 && (
                        <tr><td colSpan={7} style={{ textAlign: "center", padding: 32, color: "var(--text-muted)" }}>
                          No services found. Run a scan to populate the inventory.
                        </td></tr>
                      )}
                      {!servicesLoading && services.map((s, idx) => {
                        // Risk Level badge styling
                        const rc = s.risk_level === "Critical" 
                          ? { bg: "rgba(239,68,68,0.12)", color: "#f87171", border: "1px solid rgba(239,68,68,0.25)", text: "CRITICAL EXPOSURE" }
                          : s.risk_level === "High"
                            ? { bg: "rgba(249,115,22,0.12)", color: "#fb923c", border: "1px solid rgba(249,115,22,0.25)", text: "HIGH EXPOSURE" }
                            : s.risk_level === "Medium"
                              ? { bg: "rgba(234,179,8,0.1)", color: "#facc15", border: "1px solid rgba(234,179,8,0.2)", text: "MEDIUM EXPOSURE" }
                              : { bg: "rgba(156,163,175,0.08)", color: "var(--text-muted)", border: "1px solid rgba(156,163,175,0.15)", text: "STANDARD" };

                        return (
                          <tr key={idx}>
                            <td>
                              {s.service_name === "unknown" ? (
                                <span style={{ color: "var(--text-faint)", fontStyle: "italic" }}>(Unknown Service)</span>
                              ) : (
                                <span style={{ fontWeight: 600 }}>{s.service_name}</span>
                              )}
                            </td>
                            <td className="mono" style={{ fontWeight: 700 }}>{s.port}</td>
                            <td style={{ fontSize: "0.75rem", textTransform: "uppercase" }}>{s.protocol}</td>
                            <td>
                              <span style={{ fontWeight: 600 }}>{s.asset_count}</span>
                              <span style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginLeft: 4 }}>
                                {s.asset_count === 1 ? "asset" : "assets"}
                              </span>
                            </td>
                            <td>
                              <span className="db-tag" style={rc} title={s.risk_reason || ""}>
                                {rc.text}
                              </span>
                            </td>
                            <td style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>{ago(s.last_seen)}</td>
                            <td>
                              <button
                                className="db-btn db-btn--ghost"
                                onClick={() => {
                                  setActiveService(s);
                                  setModalAssetsSkip(0);
                                  setModalSearchInput("");
                                  setModalSearch("");
                                }}
                                style={{ fontSize: "0.72rem", padding: "4px 10px" }}
                              >
                                View Assets
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div style={{ padding: "10px 16px", display: "flex", alignItems: "center", justifyContent: "space-between", borderTop: "1px solid var(--border)" }}>
                  <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                    Showing {servicesSkip + 1}–{Math.min(servicesSkip + LIMIT, servicesTotal)} of {servicesTotal.toLocaleString()}
                  </span>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button
                      className="db-btn db-btn--ghost"
                      disabled={servicesSkip === 0}
                      onClick={() => setServicesSkip(s => Math.max(0, s - LIMIT))}
                      style={{ opacity: servicesSkip === 0 ? 0.4 : 1 }}
                    >
                      ← Prev
                    </button>
                    <button
                      className="db-btn db-btn--ghost"
                      disabled={servicesSkip + LIMIT >= servicesTotal}
                      onClick={() => setServicesSkip(s => s + LIMIT)}
                      style={{ opacity: servicesSkip + LIMIT >= servicesTotal ? 0.4 : 1 }}
                    >
                      Next →
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        {searchParams.get("tab") === "tls" && (
          <>
            {/* Filters */}
            <div style={{ padding: "12px 28px", background: "var(--bg-white)", borderBottom: "1px solid var(--border)", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
              <input
                type="text"
                placeholder="Search common name, issuer, IP…"
                value={certsSearchInput}
                onChange={e => handleCertsSearchChange(e.target.value)}
                style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border)", fontSize: "0.78rem", width: 240, color: "var(--text)", background: "var(--bg-white)" }}
              />
              <div style={{ marginLeft: "auto", fontSize: "0.72rem", color: "var(--text-muted)" }}>
                {certsTotal.toLocaleString()} certificates · Page {Math.floor(certsSkip / LIMIT) + 1} of {Math.ceil(certsTotal / LIMIT) || 1}
              </div>
            </div>

            {/* Table */}
            <div style={{ padding: "16px 28px" }}>
              {certsError && (
                <div className="db-alert db-alert--critical" style={{ marginBottom: 12 }}>
                  <span className="db-alert-icon">⚠</span>
                  <div>{certsError}</div>
                  <button className="db-btn db-btn--ghost" onClick={loadCertificates}>Retry</button>
                </div>
              )}

              <div className="db-card" style={{ padding: 0 }}>
                <div className="db-table-wrap">
                  <table className="db-table">
                    <thead>
                      <tr>
                        <th style={{ cursor: "pointer" }} onClick={() => handleCertsSort("subject")}>Common Name / Subject <CertsSortIcon col="subject" /></th>
                        <th style={{ cursor: "pointer" }} onClick={() => handleCertsSort("port")}>Port <CertsSortIcon col="port" /></th>
                        <th style={{ cursor: "pointer" }} onClick={() => handleCertsSort("grade")}>Grade <CertsSortIcon col="grade" /></th>
                        <th>Issuer</th>
                        <th style={{ cursor: "pointer" }} onClick={() => handleCertsSort("expiration")}>Expiration <CertsSortIcon col="expiration" /></th>
                        <th style={{ cursor: "pointer" }} onClick={() => handleCertsSort("hostname")}>Asset <CertsSortIcon col="hostname" /></th>
                        <th>Issues</th>
                      </tr>
                    </thead>
                    <tbody>
                      {certsLoading && Array.from({ length: 8 }).map((_, i) => (
                        <tr key={i}>
                          {Array.from({ length: 7 }).map((_, j) => (
                            <td key={j}><div className="db-skeleton" style={{ height: 12, borderRadius: 3 }} /></td>
                          ))}
                        </tr>
                      ))}
                      {!certsLoading && certs.length === 0 && (
                        <tr><td colSpan={7} style={{ textAlign: "center", padding: 32, color: "var(--text-muted)" }}>
                          No certificates found. Run a scan to populate the inventory.
                        </td></tr>
                      )}
                      {!certsLoading && certs.map((c) => {
                        const cn = c.cert_subject?.common_name || c.cert_subject || "—";
                        const issuerCn = c.cert_issuer?.common_name || c.cert_issuer || "—";
                        
                        // Grade colors mapping
                        const gradeColors = {
                          "A": { bg: "rgba(34,197,94,0.1)", color: "#4ade80", border: "1px solid rgba(34,197,94,0.2)" },
                          "B": { bg: "rgba(34,197,94,0.08)", color: "#86efac", border: "1px solid rgba(34,197,94,0.15)" },
                          "C": { bg: "rgba(234,179,8,0.1)", color: "#fde047", border: "1px solid rgba(234,179,8,0.2)" },
                          "F": { bg: "rgba(239,68,68,0.1)", color: "#f87171", border: "1px solid rgba(239,68,68,0.2)" },
                        };
                        const gc = gradeColors[c.grade] || { bg: "rgba(107,114,128,0.1)", color: "var(--text-muted)", border: "1px solid rgba(107,114,128,0.2)" };

                        // Expiration formatting
                        const expirationDate = c.cert_not_after ? new Date(c.cert_not_after) : null;
                        const isExpired = c.cert_is_expired || (expirationDate && expirationDate < new Date());
                        const isNearExpiry = expirationDate && !isExpired && (expirationDate - new Date() < 30 * 24 * 60 * 60 * 1000);

                        return (
                          <tr key={c.id}>
                            <td>
                              <div style={{ fontWeight: 600, maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={cn}>{cn}</div>
                              {c.protocol_version && <div style={{ fontSize: "0.65rem", color: "var(--text-faint)" }}>{c.protocol_version}</div>}
                            </td>
                            <td className="mono" style={{ fontSize: "0.75rem" }}>
                              {c.port}/{c.protocol?.toUpperCase()}
                            </td>
                            <td>
                              <span className="db-tag" style={gc}>
                                {c.grade}
                              </span>
                            </td>
                            <td>
                              <div style={{ fontSize: "0.75rem", color: "var(--text)", maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={issuerCn}>{issuerCn}</div>
                              {c.cipher_suite && <div style={{ fontSize: "0.6rem", color: "var(--text-faint)" }} title={c.cipher_suite}>{c.cipher_suite}</div>}
                            </td>
                            <td>
                              {c.cert_not_after ? (
                                <div>
                                  <div className="mono" style={{ fontSize: "0.75rem", color: isExpired ? "#f87171" : isNearExpiry ? "#fbbf24" : "var(--text)" }}>
                                    {new Date(c.cert_not_after).toLocaleDateString()}
                                  </div>
                                  {isExpired && <span style={{ fontSize: "0.6rem", color: "#f87171", fontWeight: 700 }}>EXPIRED</span>}
                                  {isNearExpiry && <span style={{ fontSize: "0.6rem", color: "#fbbf24", fontWeight: 700 }}>EXPIRING SOON</span>}
                                </div>
                              ) : "—"}
                            </td>
                            <td>
                              <div onClick={() => navigate(`/assets/${c.asset_id}`)} style={{ color: "var(--accent)", cursor: "pointer", fontWeight: 600 }}>
                                {c.asset_hostname || "—"}
                              </div>
                              {c.asset_ip && <div className="mono" style={{ fontSize: "0.65rem", color: "var(--text-faint)" }}>{c.asset_ip}</div>}
                            </td>
                            <td>
                              <div style={{ display: "flex", flexWrap: "wrap", gap: 3, maxWidth: 240 }}>
                                {c.cert_is_self_signed && <span className="db-tag" style={{ background: "rgba(239,68,68,0.06)", color: "#f87171", border: "1px solid rgba(239,68,68,0.15)", fontSize: "0.65rem" }}>Self-Signed</span>}
                                {c.is_weak_cipher && <span className="db-tag" style={{ background: "rgba(234,179,8,0.06)", color: "#fbbf24", border: "1px solid rgba(234,179,8,0.15)", fontSize: "0.65rem" }}>Weak Cipher</span>}
                                {(c.issues || []).map(issue => (
                                  <span key={issue} className="db-tag" style={{ fontSize: "0.65rem" }}>{issue}</span>
                                ))}
                                {!c.cert_is_self_signed && !c.is_weak_cipher && (!c.issues || c.issues.length === 0) && <span style={{ color: "var(--text-faint)", fontSize: "0.72rem" }}>No issues</span>}
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div style={{ padding: "10px 16px", display: "flex", alignItems: "center", justifyContent: "space-between", borderTop: "1px solid var(--border)" }}>
                  <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                    Showing {certsSkip + 1}–{Math.min(certsSkip + LIMIT, certsTotal)} of {certsTotal.toLocaleString()}
                  </span>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button
                      className="db-btn db-btn--ghost"
                      disabled={certsSkip === 0}
                      onClick={() => setCertsSkip(s => Math.max(0, s - LIMIT))}
                      style={{ opacity: certsSkip === 0 ? 0.4 : 1 }}
                    >
                      ← Prev
                    </button>
                    <button
                      className="db-btn db-btn--ghost"
                      disabled={certsSkip + LIMIT >= certsTotal}
                      onClick={() => setCertsSkip(s => s + LIMIT)}
                      style={{ opacity: certsSkip + LIMIT >= certsTotal ? 0.4 : 1 }}
                    >
                      Next →
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        {activeService && (
          <div className="modal-backdrop" onClick={() => setActiveService(null)}>
            <div className="modal" onClick={e => e.stopPropagation()} style={{ width: "min(900px, 95vw)" }}>
              <div className="modal-header">
                <h3 className="modal-title" style={{ fontSize: "1.05rem", fontWeight: 700 }}>
                  Associated Assets for {activeService.service_name === "unknown" ? <span style={{ fontStyle: "italic" }}>(Unknown Service)</span> : <strong style={{ color: "var(--accent)" }}>{activeService.service_name}</strong>}
                  <span style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginLeft: 8, fontWeight: 400 }}>
                    on Port {activeService.port}/{activeService.protocol?.toUpperCase()}
                  </span>
                </h3>
                <button className="modal-close" onClick={() => setActiveService(null)}>✕</button>
              </div>
              <div className="modal-body" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                <input
                  type="text"
                  placeholder="Search assets by hostname or IP address…"
                  value={modalSearchInput}
                  onChange={e => handleModalSearchChange(e.target.value)}
                  style={{
                    padding: "8px 12px",
                    borderRadius: 8,
                    border: "1px solid var(--border)",
                    fontSize: "0.82rem",
                    width: "100%",
                    color: "var(--text)",
                    background: "var(--bg-white)"
                  }}
                />

                {modalAssetsError && (
                  <div className="db-alert db-alert--critical">
                    <span className="db-alert-icon">⚠</span>
                    <div>{modalAssetsError}</div>
                  </div>
                )}

                <div className="db-table-wrap" style={{ border: "1px solid var(--border)", borderRadius: 8, overflow: "hidden" }}>
                  <table className="db-table">
                    <thead>
                      <tr>
                        <th>Asset Name</th>
                        <th>IP Address</th>
                        <th>Asset Type</th>
                        <th>Port Status</th>
                        <th>Version / Product</th>
                        <th>Last Scan Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {modalAssetsLoading && Array.from({ length: 5 }).map((_, i) => (
                        <tr key={i}>
                          {Array.from({ length: 6 }).map((_, j) => (
                            <td key={j}><div className="db-skeleton" style={{ height: 12, borderRadius: 3 }} /></td>
                          ))}
                        </tr>
                      ))}
                      {!modalAssetsLoading && modalAssets.length === 0 && (
                        <tr>
                          <td colSpan={6} style={{ textAlign: "center", padding: 24, color: "var(--text-muted)", fontSize: "0.82rem" }}>
                            No assets match the current criteria.
                          </td>
                        </tr>
                      )}
                      {!modalAssetsLoading && modalAssets.map((asset, idx) => {
                        const productText = [asset.service_product, asset.service_version]
                          .filter(Boolean)
                          .join(" ") || "—";
                        
                        return (
                          <tr key={idx}>
                            <td>
                              <span
                                onClick={() => {
                                  setActiveService(null);
                                  navigate(`/assets/${asset.asset_id}`);
                                }}
                                style={{
                                  color: "var(--accent)",
                                  cursor: "pointer",
                                  fontWeight: 600,
                                  textDecoration: "underline"
                                }}
                              >
                                {asset.asset_hostname}
                              </span>
                            </td>
                            <td className="mono" style={{ fontSize: "0.8rem" }}>{asset.asset_ip}</td>
                            <td style={{ fontSize: "0.78rem" }}>{asset.asset_type}</td>
                            <td>
                              <span
                                className="db-tag"
                                style={
                                  asset.state === "open"
                                    ? { background: "rgba(34,197,94,0.08)", color: "#4ade80", border: "1px solid rgba(34,197,94,0.2)" }
                                    : { background: "rgba(107,114,128,0.08)", color: "var(--text-muted)", border: "1px solid rgba(107,114,128,0.15)" }
                                }
                              >
                                {asset.state || "unknown"}
                              </span>
                            </td>
                            <td style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>{productText}</td>
                            <td style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{ago(asset.last_scan_time)}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Modal Pagination Footer */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", paddingTop: 4 }}>
                  <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                    Showing {modalAssetsSkip + 1}–{Math.min(modalAssetsSkip + 10, modalAssetsTotal)} of {modalAssetsTotal.toLocaleString()}
                  </span>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button
                      className="db-btn db-btn--ghost"
                      disabled={modalAssetsSkip === 0}
                      onClick={() => setModalAssetsSkip(s => Math.max(0, s - 10))}
                      style={{ padding: "4px 10px", fontSize: "0.72rem", opacity: modalAssetsSkip === 0 ? 0.4 : 1 }}
                    >
                      ← Prev
                    </button>
                    <button
                      className="db-btn db-btn--ghost"
                      disabled={modalAssetsSkip + 10 >= modalAssetsTotal}
                      onClick={() => setModalAssetsSkip(s => s + 10)}
                      style={{ padding: "4px 10px", fontSize: "0.72rem", opacity: modalAssetsSkip + 10 >= modalAssetsTotal ? 0.4 : 1 }}
                    >
                      Next →
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

      </div>
    </AppLayout>
  );
}
