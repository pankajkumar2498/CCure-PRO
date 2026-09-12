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
import { CcureTabs, useFocusTrap } from "../design-system";
import "../styles/asset-registry.css";
import {
  getAssets,
  updateAsset,
  getGlobalServices,
  getGlobalCertificates,
  getServiceAssets,
} from "../api/assets";
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

/* The BAND is what the risk bar communicates. The score itself is printed
   beside it, so the number is available whatever the colour does — and the
   thresholds are the ones `riskColor` already used, unchanged. */
const riskBand = (score) =>
  score >= 75 ? "crit" : score >= 50 ? "high" : score >= 25 ? "med" : "low";

const SEV_CLASS = {
  Critical: "db-sev-badge--critical",
  High: "db-sev-badge--high",
  Medium: "db-sev-badge--medium",
  Low: "db-sev-badge--low",
  Info: "db-sev-badge--info",
};

const getCategoryLabel = (cat) => {
  const labels = {
    router: "Router",
    switch: "Switch",
    firewall: "Firewall",
    wireless_ap: "Wireless AP",
    printer: "Printer",
    iot: "IoT/ICS",
    server: "Server",
    endpoint: "Endpoint",
    voip: "VoIP",
    storage: "Storage",
    network_appliance: "Net Appliance",
    scada_ics: "Industrial/OT",
    virtual_machine: "Virtual Machine",
    unknown: "Unknown",
  };
  return labels[cat] || cat || "—";
};

export default function AssetRegistry() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { user } = useAuth();
  const canUpdate = canPermission(user, {
    resource: "assets",
    action: "update",
  });

  const [assets, setAssets] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [searchInput, setSearchInput] = useState(
    searchParams.get("search") || "",
  );
  const [search, setSearch] = useState(searchParams.get("search") || "");
  const [riskLevel, setRiskLevel] = useState(
    searchParams.get("risk_level") || "",
  );
  const [osFamily, setOsFamily] = useState(searchParams.get("os_family") || "");
  const [verificationStatus, setVerificationStatus] = useState(
    searchParams.get("verification_status") || "",
  );
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

  /* The drill-down is a real dialog now. `useFocusTrap` contains focus while
     it is open and restores it to the control that opened it on close — the
     same hook every other CCure dialog uses. Escape closes it, which a
     click-outside handler alone never gave a keyboard user.

     Stage 1 remediation (after batch 11): the hook's signature is
     `(ref, active)`. Batch 10 passed the boolean as the ref, so the trap
     never armed and the dialog's ref was undefined. The container also
     carries tabindex="-1", which the hook requires as its focus fallback. */
  const serviceDialogRef = useRef(null);
  useFocusTrap(serviceDialogRef, Boolean(activeService));

  useEffect(() => {
    if (!activeService) return undefined;
    const onKey = (e) => {
      if (e.key === "Escape") setActiveService(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [activeService]);

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
        verification_status: verificationStatus || undefined,
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
  }, [
    search,
    riskLevel,
    osFamily,
    verificationStatus,
    managed,
    sortBy,
    sortDir,
    skip,
    currentTab,
  ]);

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
  }, [
    servicesSearch,
    servicesPort,
    servicesProtocol,
    servicesAssetType,
    servicesSubnet,
    servicesSortBy,
    servicesSortDir,
    servicesSkip,
    currentTab,
  ]);

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

  useEffect(() => {
    load();
  }, [load]);
  useEffect(() => {
    loadServices();
  }, [loadServices]);
  useEffect(() => {
    loadCertificates();
  }, [loadCertificates]);
  useEffect(() => {
    loadModalAssets();
  }, [loadModalAssets]);

  const modalSearchTimer = useRef(null);
  const handleModalSearchChange = (v) => {
    setModalSearchInput(v);
    clearTimeout(modalSearchTimer.current);
    modalSearchTimer.current = setTimeout(() => {
      setModalSearch(v);
      setModalAssetsSkip(0);
    }, 350);
  };

  // Search debounce
  const searchTimer = useRef(null);
  const handleSearchChange = (v) => {
    setSearchInput(v);
    clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => {
      setSearch(v);
      setSkip(0);
    }, 350);
  };

  const servicesSearchTimer = useRef(null);
  const handleServicesSearchChange = (v) => {
    setServicesSearchInput(v);
    clearTimeout(servicesSearchTimer.current);
    servicesSearchTimer.current = setTimeout(() => {
      setServicesSearch(v);
      setServicesSkip(0);
    }, 350);
  };

  const certsSearchTimer = useRef(null);
  const handleCertsSearchChange = (v) => {
    setCertsSearchInput(v);
    clearTimeout(certsSearchTimer.current);
    certsSearchTimer.current = setTimeout(() => {
      setCertsSearch(v);
      setCertsSkip(0);
    }, 350);
  };

  const handleSort = (col) => {
    if (sortBy === col) setSortDir((d) => (d === "desc" ? "asc" : "desc"));
    else {
      setSortBy(col);
      setSortDir("desc");
    }
  };

  const handleServicesSort = (col) => {
    if (servicesSortBy === col)
      setServicesSortDir((d) => (d === "desc" ? "asc" : "desc"));
    else {
      setServicesSortBy(col);
      setServicesSortDir("asc");
    }
  };

  const handleCertsSort = (col) => {
    if (certsSortBy === col)
      setCertsSortDir((d) => (d === "desc" ? "asc" : "desc"));
    else {
      setCertsSortBy(col);
      setCertsSortDir("asc");
    }
  };

  const SortIcon = ({ col }) =>
    sortBy !== col ? "↕" : sortDir === "desc" ? "↓" : "↑";
  const ServicesSortIcon = ({ col }) =>
    servicesSortBy !== col ? "↕" : servicesSortDir === "desc" ? "↓" : "↑";
  const CertsSortIcon = ({ col }) =>
    certsSortBy !== col ? "↕" : certsSortDir === "desc" ? "↓" : "↑";

  const handleToggleManaged = async (asset, e) => {
    e.stopPropagation();
    try {
      await updateAsset(asset.id, { is_managed: !asset.is_managed });
      setAssets((prev) =>
        prev.map((a) =>
          a.id === asset.id ? { ...a, is_managed: !a.is_managed } : a,
        ),
      );
    } catch {
      /* silent */
    }
  };

  return (
    <AppLayout pageTitle="Asset Registry" onNewScan={() => navigate("/scan")}>
      <div className="db-page">
        {/* Header */}
        <div className="db-page-header">
          <div>
            <h1 className="db-page-title">
              {currentTab === "services"
                ? "Services & Ports Inventory"
                : currentTab === "tls"
                  ? "TLS / Certificates Inventory"
                  : "Asset Registry"}
            </h1>
            <div className="db-page-subtitle">
              {currentTab === "services"
                ? `${servicesTotal.toLocaleString()} services discovered · Global View`
                : currentTab === "tls"
                  ? `${certsTotal.toLocaleString()} certificates discovered · Global View`
                  : `${total.toLocaleString()} total assets discovered · RBAC-scoped`}
            </div>
          </div>
          <div className="db-header-actions">
            <button
              className="db-btn db-btn--ghost"
              onClick={
                currentTab === "tls"
                  ? loadCertificates
                  : currentTab === "services"
                    ? loadServices
                    : load
              }
            >
              ↻ Refresh
            </button>
            <button
              className="db-btn db-btn--primary"
              onClick={() => navigate("/scan")}
            >
              + New Scan
            </button>
          </div>
        </div>

        {/* Was `<div onClick>` — no role, no tabindex, no key handler, so
            two of the three views were unreachable without a mouse. CcureTabs
            implements the WAI-ARIA pattern; the URL stays the source of truth
            exactly as before, so every existing link keeps working. */}
        <CcureTabs
          tabs={[
            { id: "", label: "Asset Inventory" },
            { id: "services", label: "Services & Ports" },
            { id: "tls", label: "TLS / Certificates" },
          ]}
          value={searchParams.get("tab") || ""}
          onChange={(id) => setSearchParams(id ? { tab: id } : {})}
          label="Asset registry views"
          className="ar-tabs"
        />

        {(!searchParams.get("tab") || searchParams.get("tab") === "") && (
          <>
            {/* Filters */}
            <div className="ar-p-sm-xl ar-bg-surface ar-border-b ar-flex ar-gap-sm ar-wrap ar-ai-center">
              <input
                aria-label="Search assets"
                type="text"
                placeholder="Search IP, hostname, FQDN…"
                value={searchInput}
                onChange={(e) => handleSearchChange(e.target.value)}
                className="ar-input ar-input--w220"
              />
              <select
                aria-label="Risk level"
                value={riskLevel}
                onChange={(e) => {
                  setRiskLevel(e.target.value);
                  setSkip(0);
                }}
                className="ar-p-2xs-sm ar-r-md ar-bordered ar-t-sm ar-c-text ar-bg-surface"
              >
                <option value="">All Risk Levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
              <select
                aria-label="Operating system"
                value={osFamily}
                onChange={(e) => {
                  setOsFamily(e.target.value);
                  setSkip(0);
                }}
                className="ar-p-2xs-sm ar-r-md ar-bordered ar-t-sm ar-c-text ar-bg-surface"
              >
                <option value="">All OS Families</option>
                <option value="Linux">Linux</option>
                <option value="Windows">Windows</option>
                <option value="macOS">macOS</option>
                <option value="Unknown">Unknown</option>
              </select>
              <select
                aria-label="Managed state"
                value={managed}
                onChange={(e) => {
                  setManaged(e.target.value);
                  setSkip(0);
                }}
                className="ar-p-2xs-sm ar-r-md ar-bordered ar-t-sm ar-c-text ar-bg-surface"
              >
                <option value="">All Assets</option>
                <option value="true">Managed Only</option>
                <option value="false">Unmanaged Only</option>
              </select>
              <select
                aria-label="Verification status"
                value={verificationStatus}
                onChange={(e) => {
                  setVerificationStatus(e.target.value);
                  setSkip(0);
                }}
                className="ar-p-2xs-sm ar-r-md ar-bordered ar-t-sm ar-c-text ar-bg-surface"
              >
                <option value="">Verification Status</option>
                <option value="verified">Verified</option>
                <option value="unverified">Unverified</option>
                <option value="pending">Pending</option>
              </select>
              <div className="ar-push ar-t-xs ar-c-secondary">
                {total.toLocaleString()} assets · Page{" "}
                {Math.floor(skip / LIMIT) + 1} of{" "}
                {Math.ceil(total / LIMIT) || 1}
              </div>
            </div>

            {/* Table */}
            <div className="ar-p-md-xl">
              {error && (
                <div
                  className="db-alert db-alert--critical ar-mb-sm"
                  role="alert"
                >
                  <span className="db-alert-icon">⚠</span>
                  <div>{error}</div>
                  <button className="db-btn db-btn--ghost" onClick={load}>
                    Retry
                  </button>
                </div>
              )}

              <div className="db-card ar-p-0">
                <div className="db-table-wrap">
                  <table className="db-table">
                    <caption className="cc-sr-only">
                      {`Asset inventory — ${total} assets`}
                    </caption>
                    <caption className="cc-sr-only">
                      {`Services and ports — ${servicesTotal} services`}
                    </caption>
                    <caption className="cc-sr-only">
                      {`TLS certificates — ${certsTotal} certificates`}
                    </caption>
                    <thead>
                      <tr>
                        <th
                          scope="col"
                          className="ar-clickable"
                          onClick={() => handleSort("ip_address")}
                        >
                          IP / Host <SortIcon col="ip_address" />
                        </th>
                        <th scope="col">OS</th>
                        <th scope="col">Category</th>
                        <th
                          scope="col"
                          title="Open services discovered on this asset"
                        >
                          Ports
                        </th>
                        <th scope="col">Owner</th>
                        <th scope="col">Employee ID</th>
                        <th scope="col">Serial</th>
                        <th
                          scope="col"
                          className="ar-clickable"
                          onClick={() => handleSort("risk_score")}
                        >
                          Risk <SortIcon col="risk_score" />
                        </th>
                        <th scope="col" title="Critical">
                          <span aria-hidden="true">C</span>
                          <span className="cc-sr-only">Critical</span>
                        </th>
                        <th scope="col" title="High">
                          <span aria-hidden="true">H</span>
                          <span className="cc-sr-only">High</span>
                        </th>
                        <th scope="col" title="Medium">
                          <span aria-hidden="true">M</span>
                          <span className="cc-sr-only">Medium</span>
                        </th>
                        <th scope="col">Tags</th>
                        <th
                          scope="col"
                          className="ar-clickable"
                          onClick={() => handleSort("last_seen_at")}
                        >
                          Last Seen <SortIcon col="last_seen_at" />
                        </th>
                        <th scope="col">Managed</th>
                      </tr>
                    </thead>
                    <tbody>
                      {loading &&
                        Array.from({ length: 8 }).map((_, i) => (
                          <tr key={i}>
                            {Array.from({ length: 13 }).map((_, j) => (
                              <td key={j}>
                                <div className="db-skeleton ar-skel" />
                              </td>
                            ))}
                          </tr>
                        ))}
                      {!loading && assets.length === 0 && (
                        <tr>
                          <td colSpan={14} className="ar-ta-center ar-p-2xl-lg">
                            <div className="ar-c-secondary ar-t-sm ar-fw-semibold ar-mb-2xs">
                              No assets discovered in the registry.
                            </div>
                            <div className="ar-empty-note">
                              Run a <strong>Basic Network Scan</strong>on your
                              target subnets or IP ranges to discover live
                              network assets and populate the inventory.
                            </div>
                          </td>
                        </tr>
                      )}
                      {!loading &&
                        assets.map((a) => (
                          <tr
                            key={a.id}
                            className="ar-clickable"
                            onClick={() => navigate(`/assets/${a.id}`)}
                          >
                            <td>
                              <div className="mono ar-fw-semibold">
                                {a.ip_address}
                              </div>
                              {a.hostname && (
                                <div className="ar-t-xs ar-muted">
                                  {a.hostname}
                                </div>
                              )}
                              {a.fqdn && a.fqdn !== a.hostname && (
                                <div className="ar-t-xs ar-c-secondary">
                                  {a.fqdn}
                                </div>
                              )}
                            </td>
                            <td>
                              <span className="db-tag">
                                {a.os_name || a.os_family || "Unknown"}
                              </span>
                              {(a.os_name || a.os_family) &&
                                a.os_confidence && (
                                  <div className="ar-t-xs ar-muted ar-mt-3xs">
                                    Conf: {a.os_confidence}%
                                  </div>
                                )}
                            </td>
                            <td className="ar-c-secondary ar-t-xs">
                              {getCategoryLabel(a.device_category)}
                            </td>
                            {/* Exposure at a glance. The count comes from the
                                asset's open services; a dash distinguishes "no
                                open ports found" from "never port-scanned". */}
                            <td
                              className={`ar-ports${a.open_ports_count ? " ar-ports--on" : ""}`}
                            >
                              {a.open_ports_count ?? "—"}
                            </td>
                            <td>
                              <span className="ar-certflag ar-certflag--bad">
                                {a.owner || "—"}
                              </span>
                            </td>
                            <td className="mono ar-t-xs ar-c-secondary">
                              {a.emp_id || "—"}
                            </td>
                            <td className="mono ar-t-xs ar-c-secondary">
                              {a.serial || "—"}
                            </td>
                            <td>
                              <div className="db-risk-cell">
                                <div className="db-risk-bar-mini">
                                  {/* The WIDTH is per-instance data, so it
                                      stays inline for the same reason
                                      CcureSkeleton keeps its dimensions
                                      inline. The COLOUR carried the meaning
                                      and is now a band class. */}
                                  <div
                                    className={`db-risk-bar-fill ar-riskbar-fill ar-riskbar-fill--${riskBand(
                                      a.risk_score,
                                    )}`}
                                    style={{ width: `${a.risk_score}%` }}
                                  />
                                </div>
                                <span
                                  className={`ar-riskscore ar-riskscore--${riskBand(
                                    a.risk_score,
                                  )}`}
                                >
                                  {a.risk_score}
                                </span>
                              </div>
                              <span
                                className={`db-sev-badge ${SEV_CLASS[a.risk_level?.charAt(0).toUpperCase() + a.risk_level?.slice(1).toLowerCase()] || "db-sev-badge--info"} ar-mt-3xs ar-iblock`}
                              >
                                {a.risk_level}
                              </span>
                            </td>
                            <td className="ar-vuln ar-vuln--crit">
                              {a.vuln_counts?.critical || 0}
                            </td>
                            <td className="ar-vuln ar-vuln--high">
                              {a.vuln_counts?.high || 0}
                            </td>
                            <td className="ar-vuln ar-vuln--med">
                              {a.vuln_counts?.medium || 0}
                            </td>
                            <td>
                              <div className="ar-flex ar-wrap ar-gap-3xs">
                                {(a.tags || []).slice(0, 3).map((tag) => (
                                  <span key={tag} className="db-tag">
                                    {tag}
                                  </span>
                                ))}
                              </div>
                            </td>
                            <td className="ar-c-secondary ar-t-xs">
                              {ago(a.last_seen_at)}
                            </td>
                            <td
                              onClick={
                                canUpdate
                                  ? (e) => handleToggleManaged(a, e)
                                  : undefined
                              }
                            >
                              <span
                                className={`db-tag ar-managed ar-managed--${
                                  a.is_managed ? "on" : "off"
                                }${canUpdate ? " ar-managed--actionable" : ""}`}
                              >
                                {a.is_managed ? "✔ Managed" : "✗ Unmanaged"}
                              </span>
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="ar-p-sm-md ar-flex ar-ai-center ar-jc-between ar-border-t">
                  <span className="ar-t-xs ar-c-secondary">
                    Showing {skip + 1}–{Math.min(skip + LIMIT, total)} of{" "}
                    {total.toLocaleString()}
                  </span>
                  <div className="ar-flex ar-gap-2xs">
                    <button
                      className="db-btn db-btn--ghost"
                      disabled={skip === 0}
                      onClick={() => setSkip((s) => Math.max(0, s - LIMIT))}
                    >
                      ← Prev
                    </button>
                    <button
                      className="db-btn db-btn--ghost"
                      disabled={skip + LIMIT >= total}
                      onClick={() => setSkip((s) => s + LIMIT)}
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
            <div className="ar-p-sm-xl ar-bg-surface ar-border-b ar-flex ar-gap-sm ar-wrap ar-ai-center">
              <input
                aria-label="Search services"
                type="text"
                placeholder="Search service, product…"
                value={servicesSearchInput}
                onChange={(e) => handleServicesSearchChange(e.target.value)}
                className="ar-input ar-input--w180"
              />
              <input
                aria-label="Port"
                type="number"
                placeholder="Port"
                value={servicesPort}
                onChange={(e) => {
                  setServicesPort(e.target.value);
                  setServicesSkip(0);
                }}
                className="ar-input ar-input--w80"
              />
              <select
                aria-label="Protocol"
                value={servicesProtocol}
                onChange={(e) => {
                  setServicesProtocol(e.target.value);
                  setServicesSkip(0);
                }}
                className="ar-input ar-input--w120"
              >
                <option value="">All Protocols</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
              </select>
              <select
                aria-label="Asset type"
                value={servicesAssetType}
                onChange={(e) => {
                  setServicesAssetType(e.target.value);
                  setServicesSkip(0);
                }}
                className="ar-input ar-input--w140"
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
                aria-label="Subnet"
                type="text"
                placeholder="Subnet / Segment…"
                value={servicesSubnet}
                onChange={(e) => {
                  setServicesSubnet(e.target.value);
                  setServicesSkip(0);
                }}
                className="ar-input ar-input--w160"
              />
              <button
                className="db-btn db-btn--ghost ar-t-xs ar-p-2xs-sm"
                onClick={() => {
                  setServicesSearchInput("");
                  setServicesSearch("");
                  setServicesPort("");
                  setServicesProtocol("");
                  setServicesAssetType("");
                  setServicesSubnet("");
                  setServicesSkip(0);
                }}
              >
                Clear Filters
              </button>
              <div className="ar-push ar-t-xs ar-c-secondary">
                {servicesTotal.toLocaleString()} services · Page{" "}
                {Math.floor(servicesSkip / LIMIT) + 1} of{" "}
                {Math.ceil(servicesTotal / LIMIT) || 1}
              </div>
            </div>

            {/* Table */}
            <div className="ar-p-md-xl">
              {servicesError && (
                <div
                  className="db-alert db-alert--critical ar-mb-sm"
                  role="alert"
                >
                  <span className="db-alert-icon">⚠</span>
                  <div>{servicesError}</div>
                  <button
                    className="db-btn db-btn--ghost"
                    onClick={loadServices}
                  >
                    Retry
                  </button>
                </div>
              )}

              <div className="db-card ar-p-0">
                <div className="db-table-wrap">
                  <table className="db-table">
                    <thead>
                      <tr>
                        <th
                          scope="col"
                          className="ar-clickable"
                          onClick={() => handleServicesSort("service_name")}
                        >
                          Service Name <ServicesSortIcon col="service_name" />
                        </th>
                        <th
                          scope="col"
                          className="ar-clickable"
                          onClick={() => handleServicesSort("port")}
                        >
                          Port <ServicesSortIcon col="port" />
                        </th>
                        <th
                          scope="col"
                          className="ar-clickable"
                          onClick={() => handleServicesSort("protocol")}
                        >
                          Protocol <ServicesSortIcon col="protocol" />
                        </th>
                        <th
                          scope="col"
                          className="ar-clickable"
                          onClick={() => handleServicesSort("asset_count")}
                        >
                          Asset Count <ServicesSortIcon col="asset_count" />
                        </th>
                        <th scope="col">Exposure Risk</th>
                        <th
                          scope="col"
                          className="ar-clickable"
                          onClick={() => handleServicesSort("last_seen")}
                        >
                          Last Seen <ServicesSortIcon col="last_seen" />
                        </th>
                        <th scope="col">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {servicesLoading &&
                        Array.from({ length: 8 }).map((_, i) => (
                          <tr key={i}>
                            {Array.from({ length: 7 }).map((_, j) => (
                              <td key={j}>
                                <div className="db-skeleton ar-skel" />
                              </td>
                            ))}
                          </tr>
                        ))}
                      {!servicesLoading && services.length === 0 && (
                        <tr>
                          <td colSpan={7} className="ar-ta-center ar-p-2xl-lg">
                            <div className="ar-c-secondary ar-t-sm ar-fw-semibold ar-mb-2xs">
                              No network services or open ports discovered yet.
                            </div>
                            <div className="ar-empty-note">
                              Run an <strong>Asset Discovery Scan</strong> on
                              active targets to perform port scanning, banner
                              grabbing, and service identification.
                            </div>
                          </td>
                        </tr>
                      )}
                      {!servicesLoading &&
                        services.map((s, idx) => {
                          // Risk Level badge styling
                          /* The LABEL is the fact; the band is the
                             presentation. Both were bundled into one object of
                             rgba values plus a `text` field. */
                          const rc =
                            s.risk_level === "Critical"
                              ? { band: "crit", text: "CRITICAL EXPOSURE" }
                              : s.risk_level === "High"
                                ? { band: "high", text: "HIGH EXPOSURE" }
                                : s.risk_level === "Medium"
                                  ? { band: "med", text: "MEDIUM EXPOSURE" }
                                  : { band: "low", text: "LOW EXPOSURE" };

                          return (
                            <tr key={idx}>
                              <td>
                                {s.service_name === "unknown" ? (
                                  <span className="ar-muted ar-italic">
                                    (Unknown Service)
                                  </span>
                                ) : (
                                  <span className="ar-fw-semibold">
                                    {s.service_name}
                                  </span>
                                )}
                              </td>
                              <td className="mono ar-fw-bold">{s.port}</td>
                              <td className="ar-t-xs ar-upper">{s.protocol}</td>
                              <td>
                                <span className="ar-fw-semibold">
                                  {s.asset_count}
                                </span>
                                <span className="ar-t-xs ar-c-secondary ar-ml-2xs">
                                  {s.asset_count === 1 ? "asset" : "assets"}
                                </span>
                              </td>
                              <td>
                                <span
                                  className={`db-tag ar-exposure ar-exposure--${rc.band}`}
                                  title={s.risk_reason || ""}
                                >
                                  {rc.text}
                                </span>
                              </td>
                              <td className="ar-t-xs ar-c-secondary">
                                {ago(s.last_seen)}
                              </td>
                              <td>
                                <button
                                  className="db-btn db-btn--ghost ar-t-xs ar-p-2xs-sm"
                                  onClick={() => {
                                    setActiveService(s);
                                    setModalAssetsSkip(0);
                                    setModalSearchInput("");
                                    setModalSearch("");
                                  }}
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
                <div className="ar-p-sm-md ar-flex ar-ai-center ar-jc-between ar-border-t">
                  <span className="ar-t-xs ar-c-secondary">
                    Showing {servicesSkip + 1}–
                    {Math.min(servicesSkip + LIMIT, servicesTotal)} of{" "}
                    {servicesTotal.toLocaleString()}
                  </span>
                  <div className="ar-flex ar-gap-2xs">
                    <button
                      className="db-btn db-btn--ghost"
                      disabled={servicesSkip === 0}
                      onClick={() =>
                        setServicesSkip((s) => Math.max(0, s - LIMIT))
                      }
                    >
                      ← Prev
                    </button>
                    <button
                      className="db-btn db-btn--ghost"
                      disabled={servicesSkip + LIMIT >= servicesTotal}
                      onClick={() => setServicesSkip((s) => s + LIMIT)}
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
            <div className="ar-p-sm-xl ar-bg-surface ar-border-b ar-flex ar-gap-sm ar-wrap ar-ai-center">
              <input
                aria-label="Search certificates"
                type="text"
                placeholder="Search common name, issuer, IP…"
                value={certsSearchInput}
                onChange={(e) => handleCertsSearchChange(e.target.value)}
                className="ar-input ar-input--w240"
              />
              <div className="ar-push ar-t-xs ar-c-secondary">
                {certsTotal.toLocaleString()} certificates · Page{" "}
                {Math.floor(certsSkip / LIMIT) + 1} of{" "}
                {Math.ceil(certsTotal / LIMIT) || 1}
              </div>
            </div>

            {/* Table */}
            <div className="ar-p-md-xl">
              {certsError && (
                <div
                  className="db-alert db-alert--critical ar-mb-sm"
                  role="alert"
                >
                  <span className="db-alert-icon">⚠</span>
                  <div>{certsError}</div>
                  <button
                    className="db-btn db-btn--ghost"
                    onClick={loadCertificates}
                  >
                    Retry
                  </button>
                </div>
              )}

              <div className="db-card ar-p-0">
                <div className="db-table-wrap">
                  <table className="db-table">
                    <thead>
                      <tr>
                        <th
                          scope="col"
                          className="ar-clickable"
                          onClick={() => handleCertsSort("subject")}
                        >
                          Common Name / Subject <CertsSortIcon col="subject" />
                        </th>
                        <th
                          scope="col"
                          className="ar-clickable"
                          onClick={() => handleCertsSort("port")}
                        >
                          Port <CertsSortIcon col="port" />
                        </th>
                        <th
                          scope="col"
                          className="ar-clickable"
                          onClick={() => handleCertsSort("grade")}
                        >
                          Grade <CertsSortIcon col="grade" />
                        </th>
                        <th scope="col">Issuer</th>
                        <th
                          scope="col"
                          className="ar-clickable"
                          onClick={() => handleCertsSort("expiration")}
                        >
                          Expiration <CertsSortIcon col="expiration" />
                        </th>
                        <th
                          scope="col"
                          className="ar-clickable"
                          onClick={() => handleCertsSort("hostname")}
                        >
                          Asset <CertsSortIcon col="hostname" />
                        </th>
                        <th scope="col">Issues</th>
                      </tr>
                    </thead>
                    <tbody>
                      {certsLoading &&
                        Array.from({ length: 8 }).map((_, i) => (
                          <tr key={i}>
                            {Array.from({ length: 7 }).map((_, j) => (
                              <td key={j}>
                                <div className="db-skeleton ar-skel" />
                              </td>
                            ))}
                          </tr>
                        ))}
                      {!certsLoading && certs.length === 0 && (
                        <tr>
                          <td colSpan={7} className="ar-ta-center ar-p-2xl-lg">
                            <div className="ar-c-secondary ar-t-sm ar-fw-semibold ar-mb-2xs">
                              No TLS certificates discovered in the inventory.
                            </div>
                            <div className="ar-empty-note">
                              TLS audits run during vulnerability scans. Run a{" "}
                              <strong>Vulnerability Audit Scan</strong> on hosts
                              with open SSL/TLS ports (such as HTTPS 443, SMTPS
                              465, or IMAPS 993) to populate the certificates
                              registry.
                            </div>
                          </td>
                        </tr>
                      )}
                      {!certsLoading &&
                        certs.map((c) => {
                          const cn =
                            (typeof c.cert_subject === "object"
                              ? c.cert_subject?.common_name
                              : c.cert_subject) || "—";
                          const issuerCn =
                            (typeof c.cert_issuer === "object"
                              ? c.cert_issuer?.common_name
                              : c.cert_issuer) || "—";

                          // Grade colors mapping
                          /* The grade letter is printed inside the
                             chip, so the colour reinforces a value that is
                             always legible on its own. */
                          const gradeBand =
                            { A: "a", B: "b", C: "c", D: "d", F: "f" }[
                              c.grade
                            ] || "unknown";

                          // Expiration formatting
                          const expirationDate = c.cert_not_after
                            ? new Date(c.cert_not_after)
                            : null;
                          const isExpired =
                            c.cert_is_expired ||
                            (expirationDate && expirationDate < new Date());
                          const isNearExpiry =
                            expirationDate &&
                            !isExpired &&
                            expirationDate - new Date() <
                              30 * 24 * 60 * 60 * 1000;

                          return (
                            <tr key={c.id}>
                              <td>
                                <div
                                  className="ar-fw-semibold ar-truncate-lg"
                                  title={cn}
                                >
                                  {cn}
                                </div>
                                {c.protocol_version && (
                                  <div className="ar-t-xs ar-muted">
                                    {c.protocol_version}
                                  </div>
                                )}
                              </td>
                              <td className="mono ar-t-xs">
                                {c.port}/{c.protocol?.toUpperCase()}
                              </td>
                              <td>
                                <span
                                  className={`db-tag ar-grade ar-grade--${gradeBand}`}
                                >
                                  {c.grade}
                                </span>
                              </td>
                              <td>
                                <div
                                  className="ar-t-sm ar-truncate"
                                  title={issuerCn}
                                >
                                  {issuerCn}
                                </div>
                                {c.cipher_suite && (
                                  <div
                                    className="ar-t-xs ar-muted"
                                    title={c.cipher_suite}
                                  >
                                    {c.cipher_suite}
                                  </div>
                                )}
                              </td>
                              <td>
                                {c.cert_not_after ? (
                                  <div>
                                    <div
                                      className={`mono ar-t-sm ar-expiry${
                                        isExpired
                                          ? " ar-expiry--expired"
                                          : isNearExpiry
                                            ? " ar-expiry--soon"
                                            : ""
                                      }`}
                                    >
                                      {new Date(
                                        c.cert_not_after,
                                      ).toLocaleDateString()}
                                    </div>
                                    {isExpired && (
                                      <span className="ar-t-xs ar-muted">
                                        EXPIRED
                                      </span>
                                    )}
                                    {isNearExpiry && (
                                      <span className="ar-certflag ar-certflag--warn">
                                        EXPIRING SOON
                                      </span>
                                    )}
                                  </div>
                                ) : (
                                  "—"
                                )}
                              </td>
                              <td>
                                <div
                                  onClick={() =>
                                    navigate(`/assets/${c.asset_id}`)
                                  }
                                  className="ar-c-link ar-clickable ar-fw-semibold"
                                >
                                  {c.asset_hostname || "—"}
                                </div>
                                {c.asset_ip && (
                                  <div className="mono ar-t-xs ar-muted">
                                    {c.asset_ip}
                                  </div>
                                )}
                              </td>
                              <td>
                                <div className="ar-issues">
                                  {c.cert_is_self_signed && (
                                    <span className="db-tag ar-issue ar-issue--bad">
                                      Self-Signed
                                    </span>
                                  )}
                                  {c.is_weak_cipher && (
                                    <span className="db-tag ar-issue ar-issue--warn">
                                      Weak Cipher
                                    </span>
                                  )}
                                  {(c.issues || []).map((issue) => (
                                    <span
                                      className="db-tag ar-t-xs"
                                      key={issue}
                                    >
                                      {issue}
                                    </span>
                                  ))}
                                  {!c.cert_is_self_signed &&
                                    !c.is_weak_cipher &&
                                    (!c.issues || c.issues.length === 0) && (
                                      <span className="ar-c-secondary ar-t-xs">
                                        No issues
                                      </span>
                                    )}
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="ar-p-sm-md ar-flex ar-ai-center ar-jc-between ar-border-t">
                  <span className="ar-t-xs ar-c-secondary">
                    Showing {certsSkip + 1}–
                    {Math.min(certsSkip + LIMIT, certsTotal)} of{" "}
                    {certsTotal.toLocaleString()}
                  </span>
                  <div className="ar-flex ar-gap-2xs">
                    <button
                      className="db-btn db-btn--ghost"
                      disabled={certsSkip === 0}
                      onClick={() =>
                        setCertsSkip((s) => Math.max(0, s - LIMIT))
                      }
                    >
                      ← Prev
                    </button>
                    <button
                      className="db-btn db-btn--ghost"
                      disabled={certsSkip + LIMIT >= certsTotal}
                      onClick={() => setCertsSkip((s) => s + LIMIT)}
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
          <div
            className="modal-backdrop"
            onClick={() => setActiveService(null)}
          >
            <div
              className="modal ar-modal-wide"
              role="dialog"
              aria-modal="true"
              aria-labelledby="ar-service-dialog-title"
              ref={serviceDialogRef}
              tabIndex={-1}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="modal-header">
                <h2
                  className="modal-title ar-modal-title"
                  id="ar-service-dialog-title"
                >
                  Associated Assets for{" "}
                  {activeService.service_name === "unknown" ? (
                    <span className="ar-muted ar-italic">
                      (Unknown Service)
                    </span>
                  ) : (
                    <strong className="ar-c-link">
                      {activeService.service_name}
                    </strong>
                  )}{" "}
                  <span className="ar-t-sm ar-c-secondary ar-ml-xs ar-fw-regular">
                    on Port {activeService.port}/
                    {activeService.protocol?.toUpperCase()}
                  </span>
                </h2>
                <button
                  className="modal-close"
                  onClick={() => setActiveService(null)}
                  aria-label="Close the associated-assets dialog"
                >
                  <span aria-hidden="true">✕</span>
                </button>
              </div>
              <div className="modal-body ar-flex ar-col ar-gap-md">
                <input
                  aria-label="Search assets in this service"
                  type="text"
                  placeholder="Search assets by hostname or IP address…"
                  value={modalSearchInput}
                  onChange={(e) => handleModalSearchChange(e.target.value)}
                  className="ar-p-xs-sm ar-r-md ar-bordered ar-t-sm ar-w-full ar-c-text ar-bg-surface"
                />

                {modalAssetsError && (
                  <div className="db-alert db-alert--critical" role="alert">
                    <span className="db-alert-icon">⚠</span>
                    <div>{modalAssetsError}</div>
                  </div>
                )}

                <div className="db-table-wrap ar-bordered ar-r-md ar-ovh">
                  <table className="db-table">
                    <thead>
                      <tr>
                        <th scope="col">Asset Name</th>
                        <th scope="col">IP Address</th>
                        <th scope="col">Asset Type</th>
                        <th scope="col">Port Status</th>
                        <th scope="col">Version / Product</th>
                        <th scope="col">Last Scan Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {modalAssetsLoading &&
                        Array.from({ length: 5 }).map((_, i) => (
                          <tr key={i}>
                            {Array.from({ length: 6 }).map((_, j) => (
                              <td key={j}>
                                <div className="db-skeleton ar-skel" />
                              </td>
                            ))}
                          </tr>
                        ))}
                      {!modalAssetsLoading && modalAssets.length === 0 && (
                        <tr>
                          <td
                            colSpan={6}
                            className="ar-ta-center ar-p-lg ar-c-secondary ar-t-sm"
                          >
                            No assets match the current criteria.
                          </td>
                        </tr>
                      )}
                      {!modalAssetsLoading &&
                        modalAssets.map((asset, idx) => {
                          const productText =
                            [asset.service_product, asset.service_version]
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
                                  className="ar-linkish"
                                >
                                  {asset.asset_hostname}
                                </span>
                              </td>
                              <td className="mono ar-t-sm">{asset.asset_ip}</td>
                              <td className="ar-t-sm">{asset.asset_type}</td>
                              <td>
                                <span
                                  className={`db-tag ar-portstate ar-portstate--${
                                    asset.state === "open" ? "open" : "other"
                                  }`}
                                >
                                  {asset.state}
                                </span>
                              </td>
                              <td className="ar-t-sm ar-c-secondary">
                                {productText}
                              </td>
                              <td className="ar-t-xs ar-c-secondary">
                                {ago(asset.last_scan_time)}
                              </td>
                            </tr>
                          );
                        })}
                    </tbody>
                  </table>
                </div>

                {/* Modal Pagination Footer */}
                <div className="ar-flex ar-ai-center ar-jc-between ar-pt-2xs">
                  <span className="ar-t-xs ar-c-secondary">
                    Showing {modalAssetsSkip + 1}–
                    {Math.min(modalAssetsSkip + 10, modalAssetsTotal)} of{" "}
                    {modalAssetsTotal.toLocaleString()}
                  </span>
                  <div className="ar-flex ar-gap-2xs">
                    {/* The services table behind this dialog has its own
                        Prev/Next, so two paginators share a screen. Named for
                        what they page so a reader can tell them apart. */}
                    <button
                      className="db-btn db-btn--ghost ar-pagebtn"
                      aria-label="Previous page of associated assets"
                      disabled={modalAssetsSkip === 0}
                      onClick={() =>
                        setModalAssetsSkip((s) => Math.max(0, s - 10))
                      }
                    >
                      ← Prev
                    </button>
                    <button
                      className="db-btn db-btn--ghost ar-pagebtn"
                      aria-label="Next page of associated assets"
                      disabled={modalAssetsSkip + 10 >= modalAssetsTotal}
                      onClick={() => setModalAssetsSkip((s) => s + 10)}
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
