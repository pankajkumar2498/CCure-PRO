/**
 * src/modules/audit/pages/AssetRegistry.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Full asset registry page.
 * - Paginated table with sort, filter, search
 * - Inline managed/unmanaged toggle (RBAC: assets:update)
 * - Click-to-drill-down to /assets/:id
 * - Export CSV button
 *
 * Checkpoint 3C batch 16: no longer reads dashboard.css. The three tables are
 * CcureTable, so every sortable column is a real button with aria-sort; each
 * drill-down (the asset address, a certificate's asset, an asset in the
 * services dialog) is a link rather than a click handler; and the managed
 * state is a toggle button. Every request, parameter, direction rule, PATCH
 * body and permission check is unchanged.
 */
import { useState, useEffect, useCallback, useRef } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import { useAuth } from "@shell/auth/AuthContext";
import { canPermission } from "@shell/auth/permissions";
import {
  CcureTabPanel,
  CcureAlert,
  CcureButton,
  CcureSeverityBadge,
  CcureTable,
  CcureTabs,
  CcureInput,
  CcureSelect,
  CcureCard,
  CcureModal,
  CcurePage,
  CcurePageHeader,
  CcureIcon,
} from "../../../design-system";
import "../styles/asset-registry.css";
import {
  getAssets,
  updateAsset,
  getGlobalServices,
  getGlobalCertificates,
  getServiceAssets,
} from "@audit/api/assets";

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

/* CcureTable states a sort as aria-sort ("ascending" / "descending"); the API
   takes sort_dir ("asc" / "desc"). Only the column key is handed back to the
   page: the direction rules stay the page's own — a newly chosen asset column
   starts descending, a newly chosen service or certificate column ascending,
   and choosing the current column again flips it. */
const tableSort = (key, dir) => ({
  key,
  direction: dir === "desc" ? "descending" : "ascending",
});

/* A single letter is what a sighted reader scans; the word is what a screen
   reader announces. */
const CountHeader = ({ letter, word }) => (
  <span title={word}>
    <span aria-hidden="true">{letter}</span>
    <span className="cc-sr-only">{word}</span>
  </span>
);

const ASSET_COLUMNS = [
  { key: "ip_address", header: "IP / Host", sortable: true },
  { key: "os", header: "OS" },
  { key: "category", header: "Category" },
  {
    key: "ports",
    header: <span title="Open services discovered on this asset">Ports</span>,
  },
  { key: "owner", header: "Owner" },
  { key: "emp_id", header: "Employee ID" },
  { key: "serial", header: "Serial" },
  { key: "risk_score", header: "Risk", sortable: true },
  { key: "critical", header: <CountHeader letter="C" word="Critical" /> },
  { key: "high", header: <CountHeader letter="H" word="High" /> },
  { key: "medium", header: <CountHeader letter="M" word="Medium" /> },
  { key: "tags", header: "Tags" },
  { key: "last_seen_at", header: "Last Seen", sortable: true },
  { key: "managed", header: "Managed" },
];

const SERVICE_COLUMNS = [
  { key: "service_name", header: "Service Name", sortable: true },
  { key: "port", header: "Port", sortable: true },
  { key: "protocol", header: "Protocol", sortable: true },
  { key: "asset_count", header: "Asset Count", sortable: true },
  { key: "exposure", header: "Exposure Risk" },
  { key: "last_seen", header: "Last Seen", sortable: true },
  { key: "actions", header: "Actions" },
];

const CERT_COLUMNS = [
  { key: "subject", header: "Common Name / Subject", sortable: true },
  { key: "port", header: "Port", sortable: true },
  { key: "grade", header: "Grade", sortable: true },
  { key: "issuer", header: "Issuer" },
  { key: "expiration", header: "Expiration", sortable: true },
  { key: "hostname", header: "Asset", sortable: true },
  { key: "issues", header: "Issues" },
];

const SERVICE_ASSET_COLUMNS = [
  { key: "name", header: "Asset Name" },
  { key: "ip", header: "IP Address" },
  { key: "type", header: "Asset Type" },
  { key: "state", header: "Port Status" },
  { key: "product", header: "Version / Product" },
  { key: "scanned", header: "Last Scan Time" },
];

export default function AssetRegistry() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { user } = useAuth();
  const canUpdate = canPermission(user, "audit.asset.update");

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
  // The shared modal owns focus, isolation, scroll locking and Escape.

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
      <CcurePage className="ar-page">
        {/* Header */}
        <CcurePageHeader
          title={
            <>
              {currentTab === "services"
                ? "Services & Ports Inventory"
                : currentTab === "tls"
                  ? "TLS / Certificates Inventory"
                  : "Asset Registry"}
            </>
          }
          subtitle={
            <>
              {currentTab === "services"
                ? `${servicesTotal.toLocaleString()} services discovered · Global View`
                : currentTab === "tls"
                  ? `${certsTotal.toLocaleString()} certificates discovered · Global View`
                  : `${total.toLocaleString()} total assets discovered · RBAC-scoped`}
            </>
          }
          actions={
            <div className="ar-header-actions">
              <CcureButton
                variant="secondary"
                size="sm"
                onClick={
                  currentTab === "tls"
                    ? loadCertificates
                    : currentTab === "services"
                      ? loadServices
                      : load
                }
              >
                <CcureIcon name="refresh-cw" /> Refresh
              </CcureButton>
              <CcureButton
                variant="primary"
                size="sm"
                onClick={() => navigate("/scan")}
              >
                + New Scan
              </CcureButton>
            </div>
          }
        />

        {/* Was `<div onClick>` — no role, no tabindex, no key handler, so
            two of the three views were unreachable without a mouse. CcureTabs
            implements the WAI-ARIA pattern; the URL stays the source of truth
            exactly as before, so every existing link keeps working. */}
        <CcureTabs
          id="asset-registry"
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

        <CcureTabPanel
          tabsId="asset-registry"
          id={searchParams.get("tab") || ""}
          active
        >
          {(!searchParams.get("tab") || searchParams.get("tab") === "") && (
            <>
              {/* Filters */}
              <div className="ar-filterbar ar-flex ar-gap-sm ar-wrap ar-ai-center">
                <CcureInput
                  aria-label="Search assets"
                  type="text"
                  placeholder="Search IP, hostname, FQDN…"
                  value={searchInput}
                  onChange={(e) => handleSearchChange(e.target.value)}
                  fieldClassName="ar-input--w220"
                />
                <CcureSelect
                  aria-label="Risk level"
                  value={riskLevel}
                  onChange={(e) => {
                    setRiskLevel(e.target.value);
                    setSkip(0);
                  }}
                >
                  <option value="">All Risk Levels</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </CcureSelect>
                <CcureSelect
                  aria-label="Operating system"
                  value={osFamily}
                  onChange={(e) => {
                    setOsFamily(e.target.value);
                    setSkip(0);
                  }}
                >
                  <option value="">All OS Families</option>
                  <option value="Linux">Linux</option>
                  <option value="Windows">Windows</option>
                  <option value="macOS">macOS</option>
                  <option value="Unknown">Unknown</option>
                </CcureSelect>
                <CcureSelect
                  aria-label="Managed state"
                  value={managed}
                  onChange={(e) => {
                    setManaged(e.target.value);
                    setSkip(0);
                  }}
                >
                  <option value="">All Assets</option>
                  <option value="true">Managed Only</option>
                  <option value="false">Unmanaged Only</option>
                </CcureSelect>
                <CcureSelect
                  aria-label="Verification status"
                  value={verificationStatus}
                  onChange={(e) => {
                    setVerificationStatus(e.target.value);
                    setSkip(0);
                  }}
                >
                  <option value="">Verification Status</option>
                  <option value="verified">Verified</option>
                  <option value="unverified">Unverified</option>
                  <option value="pending">Pending</option>
                </CcureSelect>
                <div className="ar-push ar-t-xs ar-c-secondary">
                  {total.toLocaleString()} assets · Page{" "}
                  {Math.floor(skip / LIMIT) + 1} of{" "}
                  {Math.ceil(total / LIMIT) || 1}
                </div>
              </div>

              {/* Table */}
              <div className="ar-results">
                {error && (
                  <CcureAlert variant="danger" className="ar-mb-sm">
                    <span className="ar-alert-row">
                      {error}
                      <CcureButton variant="secondary" size="sm" onClick={load}>
                        Retry
                      </CcureButton>
                    </span>
                  </CcureAlert>
                )}

                <CcureCard as={"div"} bodyFlush className="ar-card">
                  {/* One caption. The batch 10 table carried three — its own
                    and the services and certificates tables' — so a reader
                    heard two names for tables that were not on the screen. */}
                  <CcureTable
                    caption={`Asset inventory — ${total} assets`}
                    columns={ASSET_COLUMNS}
                    sort={tableSort(sortBy, sortDir)}
                    onSortChange={({ key }) => handleSort(key)}
                    density="compact"
                    loading={loading}
                    loadingRows={8}
                  >
                    {!loading && assets.length === 0 && (
                      <tr>
                        <td
                          colSpan={ASSET_COLUMNS.length}
                          className="ar-ta-center ar-p-2xl-lg"
                        >
                          <div className="ar-c-secondary ar-t-sm ar-fw-semibold ar-mb-2xs">
                            No assets discovered in the registry.
                          </div>
                          <div className="ar-empty-note">
                            Run a <strong>Basic Network Scan</strong>on your
                            target subnets or IP ranges to discover live network
                            assets and populate the inventory.
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
                            {/* The row navigated for a mouse only. The address
                              is the keyboard route to the same place, and as
                              a link it can also be opened in a new tab. The
                              row keeps its click target. */}
                            <Link
                              to={`/assets/${a.id}`}
                              className="ar-rowlink ar-mono ar-fw-semibold"
                              onClick={(e) => e.stopPropagation()}
                            >
                              {a.ip_address}
                            </Link>
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
                            <span className="ar-chip">
                              {a.os_name || a.os_family || "Unknown"}
                            </span>
                            {(a.os_name || a.os_family) && a.os_confidence && (
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
                          <td className="ar-mono ar-t-xs ar-c-secondary">
                            {a.emp_id || "—"}
                          </td>
                          <td className="ar-mono ar-t-xs ar-c-secondary">
                            {a.serial || "—"}
                          </td>
                          <td>
                            <div className="ar-risk-cell">
                              <div className="ar-riskbar">
                                {/* The WIDTH is per-instance data, so it stays
                                  inline for the same reason CcureSkeleton
                                  keeps its dimensions inline. The COLOUR
                                  carried the meaning and is a band class. */}
                                <div
                                  className={`ar-riskbar-fill ar-riskbar-fill--${riskBand(
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
                            <CcureSeverityBadge
                              severity={a.risk_level}
                              className="ar-mt-3xs"
                            />
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
                                <span key={tag} className="ar-chip">
                                  {tag}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="ar-c-secondary ar-t-xs">
                            {ago(a.last_seen_at)}
                          </td>
                          <td>
                            {/* Was a click handler on the cell, so only a mouse
                              could change it. The button's name stays
                              "Managed" plus the asset, and aria-pressed
                              carries the value; the visible word is the same
                              value for a sighted reader. Without
                              assets:update the value is shown and nothing is
                              offered. */}
                            {canUpdate ? (
                              <CcureButton
                                variant="ghost"
                                size="sm"
                                type="button"
                                aria-pressed={a.is_managed ? "true" : "false"}
                                aria-label={`Managed: ${a.hostname || a.ip_address}`}
                                className={`ar-chip ar-toggle ar-managed ar-managed--${
                                  a.is_managed ? "on" : "off"
                                }`}
                                onClick={(e) => handleToggleManaged(a, e)}
                              >
                                {a.is_managed ? (
                                  <>
                                    <CcureIcon name="check" /> Managed
                                  </>
                                ) : (
                                  <>
                                    <CcureIcon name="x" /> Unmanaged
                                  </>
                                )}
                              </CcureButton>
                            ) : (
                              <span
                                className={`ar-chip ar-managed ar-managed--${
                                  a.is_managed ? "on" : "off"
                                }`}
                              >
                                {a.is_managed ? (
                                  <>
                                    <CcureIcon name="check" /> Managed
                                  </>
                                ) : (
                                  <>
                                    <CcureIcon name="x" /> Unmanaged
                                  </>
                                )}
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                  </CcureTable>

                  {/* Pagination */}
                  <div className="ar-p-sm-md ar-flex ar-ai-center ar-jc-between ar-border-t">
                    <span className="ar-t-xs ar-c-secondary">
                      Showing {skip + 1}–{Math.min(skip + LIMIT, total)} of{" "}
                      {total.toLocaleString()}
                    </span>
                    <div className="ar-flex ar-gap-2xs">
                      <CcureButton
                        variant="secondary"
                        size="sm"
                        disabled={skip === 0}
                        onClick={() => setSkip((s) => Math.max(0, s - LIMIT))}
                      >
                        ← Prev
                      </CcureButton>
                      <CcureButton
                        variant="secondary"
                        size="sm"
                        disabled={skip + LIMIT >= total}
                        onClick={() => setSkip((s) => s + LIMIT)}
                      >
                        Next →
                      </CcureButton>
                    </div>
                  </div>
                </CcureCard>
              </div>
            </>
          )}

          {searchParams.get("tab") === "services" && (
            <>
              {/* Filters */}
              <div className="ar-filterbar ar-flex ar-gap-sm ar-wrap ar-ai-center">
                <CcureInput
                  aria-label="Search services"
                  type="text"
                  placeholder="Search service, product…"
                  value={servicesSearchInput}
                  onChange={(e) => handleServicesSearchChange(e.target.value)}
                  fieldClassName="ar-input--w180"
                />
                <CcureInput
                  aria-label="Port"
                  type="number"
                  placeholder="Port"
                  value={servicesPort}
                  onChange={(e) => {
                    setServicesPort(e.target.value);
                    setServicesSkip(0);
                  }}
                  fieldClassName="ar-input--w80"
                />
                <CcureSelect
                  aria-label="Protocol"
                  value={servicesProtocol}
                  onChange={(e) => {
                    setServicesProtocol(e.target.value);
                    setServicesSkip(0);
                  }}
                  fieldClassName="ar-input--w120"
                >
                  <option value="">All Protocols</option>
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </CcureSelect>
                <CcureSelect
                  aria-label="Asset type"
                  value={servicesAssetType}
                  onChange={(e) => {
                    setServicesAssetType(e.target.value);
                    setServicesSkip(0);
                  }}
                  fieldClassName="ar-input--w140"
                >
                  <option value="">All Asset Types</option>
                  <option value="server">Server</option>
                  <option value="workstation">Workstation</option>
                  <option value="laptop">Laptop</option>
                  <option value="printer">Printer</option>
                  <option value="network">Network Device</option>
                  <option value="iot">IoT</option>
                  <option value="unknown">Unknown</option>
                </CcureSelect>
                <CcureInput
                  aria-label="Subnet"
                  type="text"
                  placeholder="Subnet / Segment…"
                  value={servicesSubnet}
                  onChange={(e) => {
                    setServicesSubnet(e.target.value);
                    setServicesSkip(0);
                  }}
                  fieldClassName="ar-input--w160"
                />
                <CcureButton
                  variant="secondary"
                  size="sm"
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
                </CcureButton>
                <div className="ar-push ar-t-xs ar-c-secondary">
                  {servicesTotal.toLocaleString()} services · Page{" "}
                  {Math.floor(servicesSkip / LIMIT) + 1} of{" "}
                  {Math.ceil(servicesTotal / LIMIT) || 1}
                </div>
              </div>

              {/* Table */}
              <div className="ar-results">
                {servicesError && (
                  <CcureAlert variant="danger" className="ar-mb-sm">
                    <span className="ar-alert-row">
                      {servicesError}
                      <CcureButton
                        variant="secondary"
                        size="sm"
                        onClick={loadServices}
                      >
                        Retry
                      </CcureButton>
                    </span>
                  </CcureAlert>
                )}

                <CcureCard as={"div"} bodyFlush className="ar-card">
                  <CcureTable
                    caption={`Services and ports — ${servicesTotal} services`}
                    columns={SERVICE_COLUMNS}
                    sort={tableSort(servicesSortBy, servicesSortDir)}
                    onSortChange={({ key }) => handleServicesSort(key)}
                    density="compact"
                    loading={servicesLoading}
                    loadingRows={8}
                  >
                    {!servicesLoading && services.length === 0 && (
                      <tr>
                        <td
                          colSpan={SERVICE_COLUMNS.length}
                          className="ar-ta-center ar-p-2xl-lg"
                        >
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
                            <td className="ar-mono ar-fw-bold">{s.port}</td>
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
                                className={`ar-chip ar-exposure ar-exposure--${rc.band}`}
                                title={s.risk_reason || ""}
                              >
                                {rc.text}
                              </span>
                            </td>
                            <td className="ar-t-xs ar-c-secondary">
                              {ago(s.last_seen)}
                            </td>
                            <td>
                              <CcureButton
                                variant="secondary"
                                size="sm"
                                onClick={() => {
                                  setActiveService(s);
                                  setModalAssetsSkip(0);
                                  setModalSearchInput("");
                                  setModalSearch("");
                                }}
                              >
                                View Assets
                              </CcureButton>
                            </td>
                          </tr>
                        );
                      })}
                  </CcureTable>

                  {/* Pagination */}
                  <div className="ar-p-sm-md ar-flex ar-ai-center ar-jc-between ar-border-t">
                    <span className="ar-t-xs ar-c-secondary">
                      Showing {servicesSkip + 1}–
                      {Math.min(servicesSkip + LIMIT, servicesTotal)} of{" "}
                      {servicesTotal.toLocaleString()}
                    </span>
                    <div className="ar-flex ar-gap-2xs">
                      <CcureButton
                        variant="secondary"
                        size="sm"
                        disabled={servicesSkip === 0}
                        onClick={() =>
                          setServicesSkip((s) => Math.max(0, s - LIMIT))
                        }
                      >
                        ← Prev
                      </CcureButton>
                      <CcureButton
                        variant="secondary"
                        size="sm"
                        disabled={servicesSkip + LIMIT >= servicesTotal}
                        onClick={() => setServicesSkip((s) => s + LIMIT)}
                      >
                        Next →
                      </CcureButton>
                    </div>
                  </div>
                </CcureCard>
              </div>
            </>
          )}

          {searchParams.get("tab") === "tls" && (
            <>
              {/* Filters */}
              <div className="ar-filterbar ar-flex ar-gap-sm ar-wrap ar-ai-center">
                <CcureInput
                  aria-label="Search certificates"
                  type="text"
                  placeholder="Search common name, issuer, IP…"
                  value={certsSearchInput}
                  onChange={(e) => handleCertsSearchChange(e.target.value)}
                  fieldClassName="ar-input--w240"
                />
                <div className="ar-push ar-t-xs ar-c-secondary">
                  {certsTotal.toLocaleString()} certificates · Page{" "}
                  {Math.floor(certsSkip / LIMIT) + 1} of{" "}
                  {Math.ceil(certsTotal / LIMIT) || 1}
                </div>
              </div>

              {/* Table */}
              <div className="ar-results">
                {certsError && (
                  <CcureAlert variant="danger" className="ar-mb-sm">
                    <span className="ar-alert-row">
                      {certsError}
                      <CcureButton
                        variant="secondary"
                        size="sm"
                        onClick={loadCertificates}
                      >
                        Retry
                      </CcureButton>
                    </span>
                  </CcureAlert>
                )}

                <CcureCard as={"div"} bodyFlush className="ar-card">
                  <CcureTable
                    caption={`TLS certificates — ${certsTotal} certificates`}
                    columns={CERT_COLUMNS}
                    sort={tableSort(certsSortBy, certsSortDir)}
                    onSortChange={({ key }) => handleCertsSort(key)}
                    density="compact"
                    loading={certsLoading}
                    loadingRows={8}
                  >
                    {!certsLoading && certs.length === 0 && (
                      <tr>
                        <td
                          colSpan={CERT_COLUMNS.length}
                          className="ar-ta-center ar-p-2xl-lg"
                        >
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

                        /* The grade letter is printed inside the chip, so the
                         colour reinforces a value that is always legible on
                         its own. */
                        const gradeBand =
                          { A: "a", B: "b", C: "c", D: "d", F: "f" }[c.grade] ||
                          "unknown";

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
                            <td className="ar-mono ar-t-xs">
                              {c.port}/{c.protocol?.toUpperCase()}
                            </td>
                            <td>
                              <span
                                className={`ar-chip ar-grade ar-grade--${gradeBand}`}
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
                                    className={`ar-mono ar-t-sm ar-expiry${
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
                              {/* Was a `<div onClick>`: a link in every way
                                except the ones a keyboard or a new tab
                                needs. */}
                              {c.asset_id ? (
                                <Link
                                  to={`/assets/${c.asset_id}`}
                                  className="ar-rowlink ar-fw-semibold"
                                >
                                  {c.asset_hostname || (
                                    <>
                                      <span aria-hidden="true">—</span>
                                      <span className="cc-sr-only">
                                        {`Asset ${c.asset_ip || ""}`.trim()}
                                      </span>
                                    </>
                                  )}
                                </Link>
                              ) : (
                                <div className="ar-fw-semibold">
                                  {c.asset_hostname || "—"}
                                </div>
                              )}
                              {c.asset_ip && (
                                <div className="ar-mono ar-t-xs ar-muted">
                                  {c.asset_ip}
                                </div>
                              )}
                            </td>
                            <td>
                              <div className="ar-issues">
                                {c.cert_is_self_signed && (
                                  <span className="ar-chip ar-issue ar-issue--bad">
                                    Self-Signed
                                  </span>
                                )}
                                {c.is_weak_cipher && (
                                  <span className="ar-chip ar-issue ar-issue--warn">
                                    Weak Cipher
                                  </span>
                                )}
                                {(c.issues || []).map((issue) => (
                                  <span className="ar-chip ar-t-xs" key={issue}>
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
                  </CcureTable>

                  {/* Pagination */}
                  <div className="ar-p-sm-md ar-flex ar-ai-center ar-jc-between ar-border-t">
                    <span className="ar-t-xs ar-c-secondary">
                      Showing {certsSkip + 1}–
                      {Math.min(certsSkip + LIMIT, certsTotal)} of{" "}
                      {certsTotal.toLocaleString()}
                    </span>
                    <div className="ar-flex ar-gap-2xs">
                      <CcureButton
                        variant="secondary"
                        size="sm"
                        disabled={certsSkip === 0}
                        onClick={() =>
                          setCertsSkip((s) => Math.max(0, s - LIMIT))
                        }
                      >
                        ← Prev
                      </CcureButton>
                      <CcureButton
                        variant="secondary"
                        size="sm"
                        disabled={certsSkip + LIMIT >= certsTotal}
                        onClick={() => setCertsSkip((s) => s + LIMIT)}
                      >
                        Next →
                      </CcureButton>
                    </div>
                  </div>
                </CcureCard>
              </div>
            </>
          )}
        </CcureTabPanel>
        {activeService && (
          <CcureModal
            open
            onClose={() => setActiveService(null)}
            title={
              <>
                Associated Assets for{" "}
                {activeService.service_name === "unknown" ? (
                  <span className="ar-muted ar-italic">(Unknown Service)</span>
                ) : (
                  <strong className="ar-c-link">
                    {activeService.service_name}
                  </strong>
                )}{" "}
                <span className="ar-t-sm ar-c-secondary ar-ml-xs ar-fw-regular">
                  on Port {activeService.port}/
                  {activeService.protocol?.toUpperCase()}
                </span>
              </>
            }
            size="xl"
            closeLabel="Close the associated-assets dialog"
            className="ar-modal-wide"
          >
            <div className="ar-flex ar-col ar-gap-md">
              <CcureInput
                aria-label="Search assets in this service"
                type="text"
                placeholder="Search assets by hostname or IP address…"
                value={modalSearchInput}
                onChange={(e) => handleModalSearchChange(e.target.value)}
              />

              {modalAssetsError && (
                <CcureAlert variant="danger">{modalAssetsError}</CcureAlert>
              )}

              <div className="ar-bordered ar-r-md ar-ovh">
                <CcureTable
                  caption={`Assets exposing ${
                    activeService.service_name === "unknown"
                      ? "an unknown service"
                      : activeService.service_name
                  } on port ${activeService.port}/${
                    activeService.protocol?.toUpperCase() || ""
                  }`}
                  columns={SERVICE_ASSET_COLUMNS}
                  density="compact"
                  loading={modalAssetsLoading}
                  loadingRows={5}
                >
                  {!modalAssetsLoading && modalAssets.length === 0 && (
                    <tr>
                      <td
                        colSpan={SERVICE_ASSET_COLUMNS.length}
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
                            {/* Was a `<span onClick>`. The link closes the
                                  dialog and goes where the span went. */}
                            <Link
                              to={`/assets/${asset.asset_id}`}
                              className="ar-linkish"
                              onClick={() => setActiveService(null)}
                            >
                              {asset.asset_hostname || (
                                <span className="cc-sr-only">
                                  {`Asset ${asset.asset_ip || ""}`.trim()}
                                </span>
                              )}
                            </Link>
                          </td>
                          <td className="ar-mono ar-t-sm">{asset.asset_ip}</td>
                          <td className="ar-t-sm">{asset.asset_type}</td>
                          <td>
                            <span
                              className={`ar-chip ar-portstate ar-portstate--${
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
                </CcureTable>
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
                  <CcureButton
                    variant="secondary"
                    size="sm"
                    aria-label="Previous page of associated assets"
                    disabled={modalAssetsSkip === 0}
                    onClick={() =>
                      setModalAssetsSkip((s) => Math.max(0, s - 10))
                    }
                  >
                    ← Prev
                  </CcureButton>
                  <CcureButton
                    variant="secondary"
                    size="sm"
                    aria-label="Next page of associated assets"
                    disabled={modalAssetsSkip + 10 >= modalAssetsTotal}
                    onClick={() => setModalAssetsSkip((s) => s + 10)}
                  >
                    Next →
                  </CcureButton>
                </div>
              </div>
            </div>
          </CcureModal>
        )}
      </CcurePage>
    </AppLayout>
  );
}
