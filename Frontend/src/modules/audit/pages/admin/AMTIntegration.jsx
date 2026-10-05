/**
 * src/modules/audit/pages/admin/AMTIntegration.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * AMT Inventory Integration & Coverage Reconciliation Dashboard.
 * - Multi-tenant assets.json upload
 * - Real-time Coverage Gap, Fully Audited, and Shadow IT reporting
 * - Progress rings and detailed card grids
 *
 * Checkpoint 3C batch 20 — design-system migration. Presentation and
 * accessibility only. The statistics load, the drilldown with its filters and
 * paging, the CSV export, and the inventory import — its file checks and their
 * messages, the multipart `file` field, and what follows success and failure —
 * are the code that was here, and `__tests__/pages/admin/AMTIntegration.test.jsx`
 * pins them. The import replaces the organisation's AMT inventory; nothing in
 * this file changes whether, when or what it sends.
 */
import { useId, useState, useEffect, useCallback } from "react";
import AppLayout from "@audit/components/layout/AppLayout";
import {
  importAmtInventory,
  getCoverageStats,
  getReconciliationDrilldown,
  exportReconciliationCsv,
} from "@audit/api/assets";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureCard,
  CcureEmptyState,
  CcureInput,
  CcureLoader,
  CcureTable,
} from "../../../../design-system";
import "../../styles/amt-integration.css";

/* Each category's drilldown title and description, as the page has always
   shown them. */
const CATEGORY_TEXT = {
  scanned: {
    title: "Total Scanned Devices",
    description: "Devices discovered during active network scanning.",
  },
  inventory: {
    title: "AMT Inventory Records",
    description: "All records imported from the corporate inventory file.",
  },
  matched: {
    title: "Fully Audited Assets",
    description:
      "Assets verified in both active scans and corporate inventory reference.",
  },
  shadow_it: {
    title: "Shadow IT Devices",
    description:
      "Unmanaged rogue devices found in scans but missing from AMT inventory.",
  },
  coverage_gap: {
    title: "Coverage Gap Assets",
    description:
      "Official inventory devices that have not been detected in any active scans.",
  },
};

const columnsFor = (headers) =>
  headers.map((header) => ({ key: header, header }));

const ASSET_COLUMNS = columnsFor([
  "Hostname",
  "IP Address",
  "MAC Address",
  "First Seen",
  "Risk Score",
  "Owner",
]);

const INVENTORY_COLUMNS = columnsFor([
  "Asset Tag",
  "Asset Name",
  "Serial",
  "Vendor",
  "Asset Type",
  "Owner/User",
  "Status",
  "Location",
  "Department",
]);

/* The bands the coverage ring was always coloured by — 90, 75 and 50 — named
   so the colour comes from a token rather than a literal. The percentage is
   printed beside it, so the colour is never the only carrier. */
const coverageBand = (pct) =>
  pct >= 90 ? "strong" : pct >= 75 ? "good" : pct >= 50 ? "fair" : "low";

/* Risk as the badge variant its literal colours stood for: red from 70, amber
   from 40, green below. The score and level are printed in the badge. */
const riskVariant = (score) =>
  score >= 70 ? "danger" : score >= 40 ? "warning" : "success";

export default function AMTIntegration() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Upload state
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadSuccess, setUploadSuccess] = useState(false);
  const [uploadError, setUploadError] = useState(null);

  // Drill-down states
  const [activeCategory, setActiveCategory] = useState(null);
  const [drilldownData, setDrilldownData] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [drilldownLoading, setDrilldownLoading] = useState(false);
  const [drilldownError, setDrilldownError] = useState(null);
  const [page, setPage] = useState(1);
  const [limit] = useState(10);
  const [search, setSearch] = useState("");
  const [ownerFilter, setOwnerFilter] = useState("");
  const [deptFilter, setDeptFilter] = useState("");
  const [locFilter, setLocFilter] = useState("");
  const [exporting, setExporting] = useState(false);
  const idBase = useId();

  const loadStats = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getCoverageStats();
      setStats(res.data);
    } catch {
      setError("Failed to load inventory coverage statistics.");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadDrilldown = useCallback(async () => {
    if (!activeCategory) return;
    setDrilldownLoading(true);
    setDrilldownError(null);
    try {
      const skip = (page - 1) * limit;
      const res = await getReconciliationDrilldown({
        category: activeCategory,
        search,
        owner: ownerFilter,
        department: deptFilter,
        location: locFilter,
        skip,
        limit,
      });
      setDrilldownData(res.data?.data || []);
      setTotalCount(res.data?.total || 0);
    } catch {
      setDrilldownError("Failed to load drilldown details.");
    } finally {
      setDrilldownLoading(false);
    }
  }, [activeCategory, page, limit, search, ownerFilter, deptFilter, locFilter]);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  useEffect(() => {
    if (activeCategory) {
      loadDrilldown();
    }
  }, [loadDrilldown, activeCategory]);

  const handleCategoryClick = (cat) => {
    if (activeCategory === cat) {
      setActiveCategory(null);
      setDrilldownData([]);
      setTotalCount(0);
    } else {
      setActiveCategory(cat);
      setPage(1);
      setSearch("");
      setOwnerFilter("");
      setDeptFilter("");
      setLocFilter("");
    }
  };

  const handleCsvExport = async () => {
    if (!activeCategory) return;
    setExporting(true);
    try {
      const response = await exportReconciliationCsv({
        category: activeCategory,
        search,
        owner: ownerFilter,
        department: deptFilter,
        location: locFilter,
      });
      const blob = new Blob([response.data], { type: "text/csv" });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `amt_${activeCategory}_export.csv`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      console.error("Export failed:", err);
    } finally {
      setExporting(false);
    }
  };

  const categoryTypeIsAsset = (cat) => {
    return cat === "scanned" || cat === "matched" || cat === "shadow_it";
  };

  /* Mirrors the server's own limits so the operator hears about a wrong file
     before uploading it, not after. The backend enforces both independently —
     `accept=".json"` does not apply to drag-and-drop, and nothing in the
     browser is a boundary the API may rely on. */
  const MAX_AMT_FILE_BYTES = 16 * 1024 * 1024;

  const acceptFile = (candidate) => {
    if (!candidate) return;
    setUploadSuccess(false);

    if (!(candidate.name || "").toLowerCase().endsWith(".json")) {
      setFile(null);
      setUploadError(
        `Unsupported file format: ${candidate.name}. The AMT inventory must be a .json export.`,
      );
      return;
    }
    if (candidate.size === 0) {
      setFile(null);
      setUploadError(`${candidate.name} is empty.`);
      return;
    }
    if (candidate.size > MAX_AMT_FILE_BYTES) {
      setFile(null);
      setUploadError(
        `${candidate.name} is ${(candidate.size / (1024 * 1024)).toFixed(1)} MB, above the ` +
          `${MAX_AMT_FILE_BYTES / (1024 * 1024)} MB limit.`,
      );
      return;
    }

    setFile(candidate);
    setUploadError(null);
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      acceptFile(e.target.files[0]);
    }
  };

  const handleUploadSubmit = async (e) => {
    e.preventDefault();
    if (!file) return;

    setUploading(true);
    setUploadError(null);
    setUploadSuccess(false);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await importAmtInventory(formData);
      if (res.data?.success) {
        setUploadSuccess(true);
        setFile(null);
        // Reload statistics after background task triggers
        setTimeout(() => {
          loadStats();
        }, 1500);
      } else {
        setUploadError(res.data?.detail || "Import failed.");
      }
    } catch (err) {
      setUploadError(
        err.response?.data?.detail || "An error occurred during file upload.",
      );
    } finally {
      setUploading(false);
    }
  };

  const categories = stats?.configured
    ? [
        {
          key: "scanned",
          label: "Total Scanned Devices",
          value: stats.total_scanned,
        },
        {
          key: "inventory",
          label: "AMT Inventory Records",
          value: stats.total_inventory,
        },
        {
          key: "matched",
          label: "Fully Audited (Scanned & Configured)",
          value: stats.fully_audited,
          tone: "success",
        },
        {
          key: "shadow_it",
          label: "Shadow IT (Unmanaged Rogue)",
          value: stats.shadow_it,
          tone: "warning",
          help: "Discovered during active scans, but not present in your official AMT inventory file.",
        },
        {
          key: "coverage_gap",
          label: "Coverage Gap (Offline / Firewall)",
          value: stats.coverage_gap,
          tone: "danger",
          help: "Listed in your AMT inventory records, but never successfully detected during active network scans.",
        },
      ]
    : [];

  const fileInputId = `${idBase}-file`;
  const fileStatusId = `${idBase}-file-status`;
  const isAssetCategory = categoryTypeIsAsset(activeCategory);
  const categoryText = CATEGORY_TEXT[activeCategory];

  return (
    <AppLayout pageTitle="AMT Integration">
      <div className="amt-page">
        <header className="amt-header">
          <div>
            <h1 className="amt-title">AMT Integration &amp; Reconciliation</h1>
            <p className="amt-subtitle">
              Configure and analyze CMDB coverage maps, Rogue Devices (Shadow
              IT), and scan gaps.
            </p>
          </div>
          <CcureButton
            variant="ghost"
            size="sm"
            onClick={loadStats}
            disabled={loading}
          >
            <span aria-hidden="true">↻</span> Refresh Stats
          </CcureButton>
        </header>

        {error && (
          <CcureAlert variant="danger" className="amt-alert">
            {error}
          </CcureAlert>
        )}

        <div className="amt-layout">
          <CcureCard
            className="amt-card"
            title="Import Corporate Inventory"
            subtitle="Upload the corporate `assets.json` or inventory export to reconcile device ownership. The matching runs asynchronously via background worker tasks."
          >
            <form className="amt-upload" onSubmit={handleUploadSubmit}>
              <div
                className="amt-drop"
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                    // `accept` does not apply to a drop, so this path needs the
                    // same checks the picker path gets.
                    acceptFile(e.dataTransfer.files[0]);
                  }
                }}
              >
                {/* Visually hidden, not display:none, so the input stays in the
                    tab order. The zone is its label: a click anywhere on it
                    opens the file chooser, as the zone always did. */}
                <input
                  id={fileInputId}
                  type="file"
                  accept=".json"
                  className="amt-drop__input"
                  onChange={handleFileChange}
                  aria-label="AMT inventory file (.json)"
                  aria-describedby={fileStatusId}
                />
                <label htmlFor={fileInputId} className="amt-drop__zone">
                  <span className="amt-drop__icon" aria-hidden="true">
                    📁
                  </span>
                  <span id={fileStatusId} className="amt-drop__status">
                    <span className="amt-drop__name">
                      {file ? file.name : "Drag & Drop assets.json here"}
                    </span>{" "}
                    <span className="amt-drop__hint">
                      {file
                        ? `${(file.size / 1024).toFixed(1)} KB`
                        : "or click to browse local files"}
                    </span>
                  </span>
                </label>
              </div>

              {uploadError && (
                <CcureAlert variant="danger" className="amt-alert">
                  {uploadError}
                </CcureAlert>
              )}

              {uploadSuccess && (
                <CcureAlert variant="success" className="amt-alert">
                  Inventory file successfully uploaded! Reconciliation is
                  running in the background.
                </CcureAlert>
              )}

              <CcureButton
                type="submit"
                variant="primary"
                block
                loading={uploading}
                disabled={!file || uploading}
              >
                {uploading
                  ? "Uploading & Syncing..."
                  : "Upload & Sync Inventory"}
              </CcureButton>
            </form>
          </CcureCard>

          <div className="amt-side">
            <CcureCard
              className="amt-card"
              title="Reconciliation Status"
              subtitle={
                stats?.configured
                  ? "Inventory linked successfully"
                  : "No active inventory file linked"
              }
              actions={
                stats?.configured ? (
                  <CcureBadge variant="success">Linked &amp; Active</CcureBadge>
                ) : null
              }
            >
              {!stats?.configured ? (
                <CcureEmptyState
                  icon="🔌"
                  title="CMDB Integration Inactive"
                  description="Please upload an assets.json file to map owner records, audit location parameters, and locate unmanaged devices on your networks."
                />
              ) : (
                <div className="amt-metrics">
                  <CcureButton
                    variant="ghost"
                    size="sm"
                    type="button"
                    className={`amt-ring amt-ring--${coverageBand(stats.coverage_percentage)}`}
                    aria-pressed={activeCategory === "matched"}
                    onClick={() => handleCategoryClick("matched")}
                  >
                    <span className="amt-ring__gauge">
                      <svg
                        className="amt-ring__svg"
                        width="140"
                        height="140"
                        aria-hidden="true"
                        focusable="false"
                      >
                        <circle
                          className="amt-ring__track"
                          cx="70"
                          cy="70"
                          r="56"
                        />
                        <circle
                          className="amt-ring__arc"
                          cx="70"
                          cy="70"
                          r="56"
                          strokeDasharray={`${2 * Math.PI * 56}`}
                          strokeDashoffset={`${2 * Math.PI * 56 * (1 - stats.coverage_percentage / 100)}`}
                          transform="rotate(-90 70 70)"
                        />
                      </svg>
                      <span className="amt-ring__center">
                        <span className="amt-ring__value">
                          {stats.coverage_percentage}%
                        </span>{" "}
                        <span className="amt-ring__label">Coverage</span>
                      </span>
                    </span>{" "}
                    <span className="amt-ring__caption">
                      <strong>{stats.fully_audited}</strong> of{" "}
                      <strong>{stats.total_inventory}</strong> inventory assets
                      matched.
                    </span>
                  </CcureButton>

                  <ul className="amt-categories">
                    {categories.map((c) => {
                      const helpId = `${idBase}-${c.key}-help`;
                      return (
                        <li key={c.key} className="amt-categories__item">
                          <CcureButton
                            variant="ghost"
                            size="sm"
                            type="button"
                            className="amt-category"
                            aria-pressed={activeCategory === c.key}
                            aria-describedby={c.help ? helpId : undefined}
                            onClick={() => handleCategoryClick(c.key)}
                          >
                            <span className="amt-category__label">
                              {c.label}:
                              {c.help && (
                                <span
                                  className="amt-category__help"
                                  title={c.help}
                                  aria-hidden="true"
                                >
                                  ℹ
                                </span>
                              )}
                            </span>{" "}
                            {/* A toned count is a badge. The same amber as text
                                on the card surface measured 3.85:1 in the light
                                theme; on its own tinted ground it passes. */}
                            {c.tone ? (
                              <CcureBadge
                                variant={c.tone}
                                className="amt-category__badge"
                              >
                                {c.value}
                              </CcureBadge>
                            ) : (
                              <span className="amt-category__value">
                                {c.value}
                              </span>
                            )}
                          </CcureButton>
                          {c.help && (
                            <span id={helpId} className="cc-sr-only">
                              {c.help}
                            </span>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                </div>
              )}
            </CcureCard>

            <CcureCard
              className="amt-card"
              title={
                <>
                  <span aria-hidden="true">🛡</span> CMDB Best Practices
                </>
              }
            >
              <ul className="amt-guidance">
                <li>
                  Ensure all asset MAC addresses in the uploaded file follow
                  standard formats.
                </li>
                <li>
                  Imported details automatically enrich the Active Asset
                  Registry upon subsequent discovery.
                </li>
                <li>
                  Live scanned assets take precedence to prevent
                  false-positives, while manually set owners are protected under
                  the provenance override protocol.
                </li>
              </ul>
            </CcureCard>
          </div>
        </div>

        {activeCategory && (
          <CcureCard
            className="amt-card"
            title={`${categoryText?.title} (${totalCount})`}
            subtitle={categoryText?.description}
            actions={
              <CcureButton
                variant="ghost"
                size="sm"
                onClick={handleCsvExport}
                disabled={exporting || drilldownLoading || totalCount === 0}
              >
                <span aria-hidden="true">📥</span>{" "}
                {exporting ? "Exporting CSV..." : "Export CSV"}
              </CcureButton>
            }
          >
            <div className="amt-filters">
              <CcureInput
                label="Search hostname, IP, MAC or serial"
                placeholder="Search Hostname, IP, MAC, Serial..."
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(1);
                }}
                fieldClassName="amt-filters__field amt-filters__field--search"
              />
              <CcureInput
                label="Owner"
                placeholder="Filter by Owner..."
                value={ownerFilter}
                onChange={(e) => {
                  setOwnerFilter(e.target.value);
                  setPage(1);
                }}
                fieldClassName="amt-filters__field"
              />
              <CcureInput
                label="Department"
                placeholder="Filter by Department..."
                value={deptFilter}
                onChange={(e) => {
                  setDeptFilter(e.target.value);
                  setPage(1);
                }}
                fieldClassName="amt-filters__field"
              />
              <CcureInput
                label="Location"
                placeholder="Filter by Location..."
                value={locFilter}
                onChange={(e) => {
                  setLocFilter(e.target.value);
                  setPage(1);
                }}
                fieldClassName="amt-filters__field"
              />
            </div>

            {drilldownLoading ? (
              <CcureLoader
                label="Loading asset details..."
                className="amt-state"
              />
            ) : drilldownError ? (
              <CcureAlert variant="danger" className="amt-alert">
                {drilldownError}
              </CcureAlert>
            ) : drilldownData.length === 0 ? (
              <CcureEmptyState
                title="No assets match the current filters."
                className="amt-state"
              />
            ) : (
              <>
                {/* Positioned: CcureTable does not contain its visually hidden
                    caption (batch 16). */}
                <div className="amt-table">
                  {/* The caption carries the count, like the card heading, so
                      it never reads as the category control's own label. */}
                  <CcureTable
                    caption={`${categoryText?.title} (${totalCount})`}
                    columns={
                      isAssetCategory ? ASSET_COLUMNS : INVENTORY_COLUMNS
                    }
                    density="compact"
                  >
                    {drilldownData.map((item, idx) =>
                      isAssetCategory ? (
                        <tr key={item.id || idx}>
                          <td>
                            <a
                              href={`/assets/${item.id}`}
                              className="amt-link amt-link--strong"
                            >
                              {item.hostname || "—"}
                            </a>
                          </td>
                          <td>
                            <a href={`/assets/${item.id}`} className="amt-link">
                              {item.ip_address || "—"}
                            </a>
                          </td>
                          <td>
                            <code className="amt-mono">
                              {item.mac_address || "—"}
                            </code>
                          </td>
                          <td>
                            {item.first_seen_at
                              ? new Date(
                                  item.first_seen_at,
                                ).toLocaleDateString()
                              : "—"}
                          </td>
                          <td>
                            <CcureBadge variant={riskVariant(item.risk_score)}>
                              {item.risk_score} ({item.risk_level})
                            </CcureBadge>
                          </td>
                          <td>{item.owner || "—"}</td>
                        </tr>
                      ) : (
                        <tr key={item.id || idx}>
                          <td className="amt-strong">
                            {item.asset_tag || "—"}
                          </td>
                          <td>{item.asset_name || "—"}</td>
                          <td>
                            <code className="amt-mono">
                              {item.serial || "—"}
                            </code>
                          </td>
                          <td>{item.vendor || "—"}</td>
                          <td>{item.asset_type || "—"}</td>
                          <td>{item.asset_user || "—"}</td>
                          <td>
                            <CcureBadge
                              variant={
                                item.status?.toLowerCase().includes("active") ||
                                item.status?.toLowerCase().includes("use")
                                  ? "success"
                                  : "neutral"
                              }
                            >
                              {item.status || "—"}
                            </CcureBadge>
                          </td>
                          <td>{item.location || "—"}</td>
                          <td>{item.company_name || "—"}</td>
                        </tr>
                      ),
                    )}
                  </CcureTable>
                </div>

                {totalCount > limit && (
                  <nav className="amt-pagination" aria-label="Drilldown pages">
                    <span className="amt-pagination__summary">
                      Showing <strong>{(page - 1) * limit + 1}</strong> to{" "}
                      <strong>{Math.min(page * limit, totalCount)}</strong> of{" "}
                      <strong>{totalCount}</strong> entries
                    </span>
                    <div className="amt-pagination__controls">
                      <CcureButton
                        variant="ghost"
                        size="sm"
                        onClick={() => setPage((p) => Math.max(1, p - 1))}
                        disabled={page === 1}
                      >
                        <span aria-hidden="true">◀</span> Previous
                      </CcureButton>
                      <CcureButton
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          setPage((p) =>
                            Math.min(Math.ceil(totalCount / limit), p + 1),
                          )
                        }
                        disabled={page >= Math.ceil(totalCount / limit)}
                      >
                        Next <span aria-hidden="true">▶</span>
                      </CcureButton>
                    </div>
                  </nav>
                )}
              </>
            )}
          </CcureCard>
        )}
      </div>
    </AppLayout>
  );
}
