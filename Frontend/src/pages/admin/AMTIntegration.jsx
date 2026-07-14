/**
 * src/pages/admin/AMTIntegration.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * AMT Inventory Integration & Coverage Reconciliation Dashboard.
 * - Multi-tenant assets.json upload
 * - Real-time Coverage Gap, Fully Audited, and Shadow IT reporting
 * - Progress rings and detailed card grids
 */
import { useState, useEffect, useCallback } from "react";
import AppLayout from "../../components/layout/AppLayout";
import {
  importAmtInventory,
  getCoverageStats,
  getReconciliationDrilldown,
  exportReconciliationCsv,
} from "../../api/assets";

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

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setUploadSuccess(false);
      setUploadError(null);
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

  const coverageColor = (pct) =>
    pct >= 90
      ? "#10b981"
      : pct >= 75
        ? "#14b8a6"
        : pct >= 50
          ? "#f59e0b"
          : "#ef4444";

  return (
    <AppLayout pageTitle="AMT Integration">
      <div className="db-page" style={{ padding: "28px" }}>
        {/* Header */}
        <div
          className="db-page-header"
          style={{ marginBottom: 24, borderBottom: "none" }}
        >
          <div>
            <div className="db-page-title">
              AMT Integration & Reconciliation
            </div>
            <div className="db-page-subtitle">
              Configure and analyze CMDB coverage maps, Rogue Devices (Shadow
              IT), and scan gaps.
            </div>
          </div>
          <div className="db-header-actions">
            <button
              className="db-btn db-btn--ghost"
              onClick={loadStats}
              disabled={loading}
            >
              ↻ Refresh Stats
            </button>
          </div>
        </div>

        {error && (
          <div
            className="db-alert db-alert--critical"
            style={{ marginBottom: 20 }}
          >
            <span className="db-alert-icon">⚠</span>
            <div>{error}</div>
          </div>
        )}

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1.2fr 1.8fr",
            gap: 24,
            alignItems: "start",
          }}
        >
          {/* Left Column: Import / Upload Form */}
          <div className="db-card" style={{ padding: 24 }}>
            <h3
              style={{
                margin: "0 0 8px 0",
                fontSize: "1.1rem",
                fontWeight: 700,
                color: "var(--text)",
              }}
            >
              Import Corporate Inventory
            </h3>
            <p
              style={{
                margin: "0 0 20px 0",
                fontSize: "0.78rem",
                color: "var(--text-muted)",
                lineHeight: 1.5,
              }}
            >
              Upload the corporate `assets.json` or inventory export to
              reconcile device ownership. The matching runs asynchronously via
              background worker tasks.
            </p>

            <form onSubmit={handleUploadSubmit}>
              <div
                style={{
                  border: "2px dashed var(--border)",
                  borderRadius: 8,
                  padding: "32px 16px",
                  textAlign: "center",
                  background: "rgba(255,255,255,0.01)",
                  cursor: "pointer",
                  transition: "border-color 0.2s, background-color 0.2s",
                  marginBottom: 20,
                }}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                    setFile(e.dataTransfer.files[0]);
                  }
                }}
                onClick={() => document.getElementById("file-input").click()}
              >
                <input
                  id="file-input"
                  type="file"
                  accept=".json"
                  onChange={handleFileChange}
                  style={{ display: "none" }}
                />
                <div style={{ fontSize: "2rem", marginBottom: 12 }}>📁</div>
                <div
                  style={{
                    fontSize: "0.82rem",
                    fontWeight: 600,
                    color: "var(--text)",
                    marginBottom: 4,
                  }}
                >
                  {file ? file.name : "Drag & Drop assets.json here"}
                </div>
                <div
                  style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}
                >
                  {file
                    ? `${(file.size / 1024).toFixed(1)} KB`
                    : "or click to browse local files"}
                </div>
              </div>

              {uploadError && (
                <div
                  className="db-alert db-alert--critical"
                  style={{ marginBottom: 16, fontSize: "0.75rem" }}
                >
                  <span className="db-alert-icon">⚠</span>
                  <div>{uploadError}</div>
                </div>
              )}

              {uploadSuccess && (
                <div
                  className="db-alert db-alert--success"
                  style={{ marginBottom: 16, fontSize: "0.75rem" }}
                >
                  <span className="db-alert-icon">✔</span>
                  <div>
                    Inventory file successfully uploaded! Reconciliation is
                    running in the background.
                  </div>
                </div>
              )}

              <button
                type="submit"
                className="db-btn db-btn--primary"
                style={{ width: "100%", padding: "10px", fontSize: "0.82rem" }}
                disabled={!file || uploading}
              >
                {uploading
                  ? "Uploading & Syncing..."
                  : "Upload & Sync Inventory"}
              </button>
            </form>
          </div>

          {/* Right Column: Integration Metrics & Coverage Ring */}
          <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
            {/* Top Row: Metrics Overview */}
            <div className="db-card" style={{ padding: 24 }}>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: 20,
                }}
              >
                <div>
                  <h3
                    style={{
                      margin: 0,
                      fontSize: "1.1rem",
                      fontWeight: 700,
                      color: "var(--text)",
                    }}
                  >
                    Reconciliation Status
                  </h3>
                  <div
                    style={{
                      fontSize: "0.72rem",
                      color: "var(--text-muted)",
                      marginTop: 4,
                    }}
                  >
                    {stats?.configured
                      ? "Inventory linked successfully"
                      : "No active inventory file linked"}
                  </div>
                </div>
                {stats?.configured && (
                  <span
                    className="db-status db-status--complete"
                    style={{
                      background: "rgba(16,185,129,0.12)",
                      color: "#10b981",
                      fontWeight: 700,
                    }}
                  >
                    Linked & Active
                  </span>
                )}
              </div>

              {!stats?.configured ? (
                <div
                  style={{
                    padding: "40px 0",
                    textAlign: "center",
                    color: "var(--text-muted)",
                  }}
                >
                  <div style={{ fontSize: "2.5rem", marginBottom: 16 }}>🔌</div>
                  <h4
                    style={{
                      color: "var(--text)",
                      marginBottom: 8,
                      fontSize: "0.9rem",
                    }}
                  >
                    CMDB Integration Inactive
                  </h4>
                  <p
                    style={{
                      maxWidth: 380,
                      margin: "0 auto",
                      fontSize: "0.75rem",
                      lineHeight: 1.5,
                    }}
                  >
                    Please upload an assets.json file to map owner records,
                    audit location parameters, and locate unmanaged devices on
                    your networks.
                  </p>
                </div>
              ) : (
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr",
                    gap: 24,
                    alignItems: "center",
                  }}
                >
                  {/* Coverage Gauge Ring */}
                  <div
                    onClick={() => handleCategoryClick("matched")}
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      alignItems: "center",
                      borderRight: "1px solid var(--border)",
                      paddingRight: 24,
                      cursor: "pointer",
                    }}
                  >
                    <div
                      style={{ position: "relative", width: 140, height: 140 }}
                    >
                      <svg width="140" height="140">
                        <circle
                          cx="70"
                          cy="70"
                          r="56"
                          fill="transparent"
                          stroke="var(--border)"
                          strokeWidth="10"
                        />
                        <circle
                          cx="70"
                          cy="70"
                          r="56"
                          fill="transparent"
                          stroke={coverageColor(stats.coverage_percentage)}
                          strokeWidth="10"
                          strokeDasharray={`${2 * Math.PI * 56}`}
                          strokeDashoffset={`${2 * Math.PI * 56 * (1 - stats.coverage_percentage / 100)}`}
                          strokeLinecap="round"
                          transform="rotate(-90 70 70)"
                        />
                      </svg>
                      <div
                        style={{
                          position: "absolute",
                          top: "50%",
                          left: "50%",
                          transform: "translate(-50%, -50%)",
                          textAlign: "center",
                        }}
                      >
                        <div
                          style={{
                            fontSize: "1.6rem",
                            fontWeight: 800,
                            color: coverageColor(stats.coverage_percentage),
                          }}
                        >
                          {stats.coverage_percentage}%
                        </div>
                        <div
                          style={{
                            fontSize: "0.58rem",
                            color: "var(--text-muted)",
                            textTransform: "uppercase",
                            fontWeight: 700,
                            marginTop: 2,
                          }}
                        >
                          Coverage
                        </div>
                      </div>
                    </div>
                    <div
                      style={{
                        fontSize: "0.72rem",
                        color: "var(--text-muted)",
                        marginTop: 12,
                        textAlign: "center",
                      }}
                    >
                      <strong>{stats.fully_audited}</strong> of{" "}
                      <strong>{stats.total_inventory}</strong> inventory assets
                      matched.
                    </div>
                  </div>

                  {/* Metrics List */}
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 14,
                    }}
                  >
                    <div
                      onClick={() => handleCategoryClick("scanned")}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        borderBottom: "1px solid var(--border)",
                        padding: "6px 8px",
                        cursor: "pointer",
                        borderRadius: 4,
                        background:
                          activeCategory === "scanned"
                            ? "rgba(59, 130, 246, 0.12)"
                            : "transparent",
                        transition: "all 0.2s",
                      }}
                      onMouseEnter={(e) => {
                        if (activeCategory !== "scanned")
                          e.currentTarget.style.background =
                            "rgba(255,255,255,0.03)";
                      }}
                      onMouseLeave={(e) => {
                        if (activeCategory !== "scanned")
                          e.currentTarget.style.background = "transparent";
                      }}
                    >
                      <span
                        style={{
                          fontSize: "0.78rem",
                          color:
                            activeCategory === "scanned"
                              ? "var(--text-primary)"
                              : "var(--text-muted)",
                          fontWeight: activeCategory === "scanned" ? 600 : 400,
                        }}
                      >
                        Total Scanned Devices:
                      </span>
                      <span
                        style={{
                          fontSize: "0.85rem",
                          fontWeight: 700,
                          color:
                            activeCategory === "scanned"
                              ? "var(--text-primary)"
                              : "var(--text)",
                        }}
                      >
                        {stats.total_scanned}
                      </span>
                    </div>
                    <div
                      onClick={() => handleCategoryClick("inventory")}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        borderBottom: "1px solid var(--border)",
                        padding: "6px 8px",
                        cursor: "pointer",
                        borderRadius: 4,
                        background:
                          activeCategory === "inventory"
                            ? "rgba(59, 130, 246, 0.12)"
                            : "transparent",
                        transition: "all 0.2s",
                      }}
                      onMouseEnter={(e) => {
                        if (activeCategory !== "inventory")
                          e.currentTarget.style.background =
                            "rgba(255,255,255,0.03)";
                      }}
                      onMouseLeave={(e) => {
                        if (activeCategory !== "inventory")
                          e.currentTarget.style.background = "transparent";
                      }}
                    >
                      <span
                        style={{
                          fontSize: "0.78rem",
                          color:
                            activeCategory === "inventory"
                              ? "var(--text-primary)"
                              : "var(--text-muted)",
                          fontWeight:
                            activeCategory === "inventory" ? 600 : 400,
                        }}
                      >
                        AMT Inventory Records:
                      </span>
                      <span
                        style={{
                          fontSize: "0.85rem",
                          fontWeight: 700,
                          color:
                            activeCategory === "inventory"
                              ? "var(--text-primary)"
                              : "var(--text)",
                        }}
                      >
                        {stats.total_inventory}
                      </span>
                    </div>
                    <div
                      onClick={() => handleCategoryClick("matched")}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        borderBottom: "1px solid var(--border)",
                        padding: "6px 8px",
                        cursor: "pointer",
                        borderRadius: 4,
                        background:
                          activeCategory === "matched"
                            ? "rgba(59, 130, 246, 0.12)"
                            : "transparent",
                        transition: "all 0.2s",
                      }}
                      onMouseEnter={(e) => {
                        if (activeCategory !== "matched")
                          e.currentTarget.style.background =
                            "rgba(255,255,255,0.03)";
                      }}
                      onMouseLeave={(e) => {
                        if (activeCategory !== "matched")
                          e.currentTarget.style.background = "transparent";
                      }}
                    >
                      <span
                        style={{
                          fontSize: "0.78rem",
                          color:
                            activeCategory === "matched"
                              ? "var(--text-primary)"
                              : "var(--text-muted)",
                          fontWeight: activeCategory === "matched" ? 600 : 400,
                        }}
                      >
                        Fully Audited (Scanned & Configured):
                      </span>
                      <span
                        style={{
                          fontSize: "0.85rem",
                          fontWeight: 700,
                          color: "#10b981",
                        }}
                      >
                        {stats.fully_audited}
                      </span>
                    </div>
                    <div
                      onClick={() => handleCategoryClick("shadow_it")}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        borderBottom: "1px solid var(--border)",
                        padding: "6px 8px",
                        cursor: "pointer",
                        borderRadius: 4,
                        background:
                          activeCategory === "shadow_it"
                            ? "rgba(59, 130, 246, 0.12)"
                            : "transparent",
                        transition: "all 0.2s",
                      }}
                      onMouseEnter={(e) => {
                        if (activeCategory !== "shadow_it")
                          e.currentTarget.style.background =
                            "rgba(255,255,255,0.03)";
                      }}
                      onMouseLeave={(e) => {
                        if (activeCategory !== "shadow_it")
                          e.currentTarget.style.background = "transparent";
                      }}
                    >
                      <span
                        style={{
                          fontSize: "0.78rem",
                          color:
                            activeCategory === "shadow_it"
                              ? "var(--text-primary)"
                              : "var(--text-muted)",
                          fontWeight:
                            activeCategory === "shadow_it" ? 600 : 400,
                          display: "flex",
                          alignItems: "center",
                          gap: 4,
                        }}
                      >
                        Shadow IT (Unmanaged Rogue):
                        <span
                          style={{ cursor: "help" }}
                          title="Discovered during active scans, but not present in your official AMT inventory file."
                        >
                          ℹ
                        </span>
                      </span>
                      <span
                        style={{
                          fontSize: "0.85rem",
                          fontWeight: 700,
                          color: "#f59e0b",
                        }}
                      >
                        {stats.shadow_it}
                      </span>
                    </div>
                    <div
                      onClick={() => handleCategoryClick("coverage_gap")}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        padding: "6px 8px",
                        cursor: "pointer",
                        borderRadius: 4,
                        background:
                          activeCategory === "coverage_gap"
                            ? "rgba(59, 130, 246, 0.12)"
                            : "transparent",
                        transition: "all 0.2s",
                      }}
                      onMouseEnter={(e) => {
                        if (activeCategory !== "coverage_gap")
                          e.currentTarget.style.background =
                            "rgba(255,255,255,0.03)";
                      }}
                      onMouseLeave={(e) => {
                        if (activeCategory !== "coverage_gap")
                          e.currentTarget.style.background = "transparent";
                      }}
                    >
                      <span
                        style={{
                          fontSize: "0.78rem",
                          color:
                            activeCategory === "coverage_gap"
                              ? "var(--text-primary)"
                              : "var(--text-muted)",
                          fontWeight:
                            activeCategory === "coverage_gap" ? 600 : 400,
                          display: "flex",
                          alignItems: "center",
                          gap: 4,
                        }}
                      >
                        Coverage Gap (Offline / Firewall):
                        <span
                          style={{ cursor: "help" }}
                          title="Listed in your AMT inventory records, but never successfully detected during active network scans."
                        >
                          ℹ
                        </span>
                      </span>
                      <span
                        style={{
                          fontSize: "0.85rem",
                          fontWeight: 700,
                          color: "#ef4444",
                        }}
                      >
                        {stats.coverage_gap}
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Reconciliation Guidelines Box */}
            <div
              className="db-card"
              style={{
                padding: 20,
                background: "rgba(59,130,246,0.02)",
                border: "1px solid rgba(59,130,246,0.1)",
              }}
            >
              <h4
                style={{
                  margin: "0 0 8px 0",
                  fontSize: "0.82rem",
                  fontWeight: 700,
                  color: "#60a5fa",
                }}
              >
                🛡 CMDB Best Practices
              </h4>
              <ul
                style={{
                  margin: 0,
                  paddingLeft: 16,
                  fontSize: "0.7rem",
                  color: "var(--text-muted)",
                  lineHeight: 1.6,
                }}
              >
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
            </div>
          </div>
        </div>

        {activeCategory && (
          <div className="db-card" style={{ marginTop: 24, padding: 24 }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: 20,
              }}
            >
              <div>
                <h3
                  style={{
                    margin: 0,
                    fontSize: "1.2rem",
                    fontWeight: 700,
                    color: "var(--text)",
                  }}
                >
                  {activeCategory === "scanned" &&
                    `Total Scanned Devices (${totalCount})`}
                  {activeCategory === "inventory" &&
                    `AMT Inventory Records (${totalCount})`}
                  {activeCategory === "matched" &&
                    `Fully Audited Assets (${totalCount})`}
                  {activeCategory === "shadow_it" &&
                    `Shadow IT Devices (${totalCount})`}
                  {activeCategory === "coverage_gap" &&
                    `Coverage Gap Assets (${totalCount})`}
                </h3>
                <div
                  style={{
                    fontSize: "0.75rem",
                    color: "var(--text-muted)",
                    marginTop: 4,
                  }}
                >
                  {activeCategory === "scanned" &&
                    "Devices discovered during active network scanning."}
                  {activeCategory === "inventory" &&
                    "All records imported from the corporate inventory file."}
                  {activeCategory === "matched" &&
                    "Assets verified in both active scans and corporate inventory reference."}
                  {activeCategory === "shadow_it" &&
                    "Unmanaged rogue devices found in scans but missing from AMT inventory."}
                  {activeCategory === "coverage_gap" &&
                    "Official inventory devices that have not been detected in any active scans."}
                </div>
              </div>
              <button
                onClick={handleCsvExport}
                className="db-btn db-btn--ghost"
                disabled={exporting || drilldownLoading || totalCount === 0}
              >
                📥 {exporting ? "Exporting CSV..." : "Export CSV"}
              </button>
            </div>

            <div
              style={{
                display: "flex",
                gap: 12,
                marginBottom: 20,
                flexWrap: "wrap",
              }}
            >
              <input
                type="text"
                placeholder="Search Hostname, IP, MAC, Serial..."
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(1);
                }}
                style={{
                  flex: 1.5,
                  minWidth: 200,
                  padding: "8px 12px",
                  borderRadius: 6,
                  border: "1px solid var(--border)",
                  background: "var(--bg-white)",
                  color: "var(--text)",
                  fontSize: "0.8rem",
                }}
              />
              <input
                type="text"
                placeholder="Filter by Owner..."
                value={ownerFilter}
                onChange={(e) => {
                  setOwnerFilter(e.target.value);
                  setPage(1);
                }}
                style={{
                  flex: 1,
                  minWidth: 140,
                  padding: "8px 12px",
                  borderRadius: 6,
                  border: "1px solid var(--border)",
                  background: "var(--bg-white)",
                  color: "var(--text)",
                  fontSize: "0.8rem",
                }}
              />
              <input
                type="text"
                placeholder="Filter by Department..."
                value={deptFilter}
                onChange={(e) => {
                  setDeptFilter(e.target.value);
                  setPage(1);
                }}
                style={{
                  flex: 1,
                  minWidth: 140,
                  padding: "8px 12px",
                  borderRadius: 6,
                  border: "1px solid var(--border)",
                  background: "var(--bg-white)",
                  color: "var(--text)",
                  fontSize: "0.8rem",
                }}
              />
              <input
                type="text"
                placeholder="Filter by Location..."
                value={locFilter}
                onChange={(e) => {
                  setLocFilter(e.target.value);
                  setPage(1);
                }}
                style={{
                  flex: 1,
                  minWidth: 140,
                  padding: "8px 12px",
                  borderRadius: 6,
                  border: "1px solid var(--border)",
                  background: "var(--bg-white)",
                  color: "var(--text)",
                  fontSize: "0.8rem",
                }}
              />
            </div>

            {drilldownLoading ? (
              <div
                style={{
                  textAlign: "center",
                  padding: "40px 0",
                  color: "var(--text-muted)",
                }}
              >
                <div className="mono" style={{ fontSize: "0.8rem" }}>
                  Loading asset details...
                </div>
              </div>
            ) : drilldownError ? (
              <div
                className="db-alert db-alert--critical"
                style={{ fontSize: "0.8rem" }}
              >
                <span className="db-alert-icon">⚠</span>
                <div>{drilldownError}</div>
              </div>
            ) : drilldownData.length === 0 ? (
              <div
                style={{
                  textAlign: "center",
                  padding: "40px 0",
                  color: "var(--text-muted)",
                  fontSize: "0.8rem",
                }}
              >
                No assets match the current filters.
              </div>
            ) : (
              <>
                <div style={{ overflowX: "auto" }}>
                  <table
                    className="data-table"
                    style={{
                      width: "100%",
                      borderCollapse: "collapse",
                      fontSize: "0.8rem",
                    }}
                  >
                    <thead>
                      {categoryTypeIsAsset(activeCategory) ? (
                        <tr>
                          <th
                            style={{ textAlign: "left", padding: "10px 12px" }}
                          >
                            Hostname
                          </th>
                          <th
                            style={{ textAlign: "left", padding: "10px 12px" }}
                          >
                            IP Address
                          </th>
                          <th
                            style={{ textAlign: "left", padding: "10px 12px" }}
                          >
                            MAC Address
                          </th>
                          <th
                            style={{ textAlign: "left", padding: "10px 12px" }}
                          >
                            First Seen
                          </th>
                          <th
                            style={{ textAlign: "left", padding: "10px 12px" }}
                          >
                            Risk Score
                          </th>
                          <th
                            style={{ textAlign: "left", padding: "10px 12px" }}
                          >
                            Owner
                          </th>
                        </tr>
                      ) : (
                        <tr>
                          <th
                            style={{ textAlign: "left", padding: "10px 12px" }}
                          >
                            Asset Tag
                          </th>
                          <th
                            style={{ textAlign: "left", padding: "10px 12px" }}
                          >
                            Asset Name
                          </th>
                          <th
                            style={{ textAlign: "left", padding: "10px 12px" }}
                          >
                            Serial
                          </th>
                          <th
                            style={{ textAlign: "left", padding: "10px 12px" }}
                          >
                            Vendor
                          </th>
                          <th
                            style={{ textAlign: "left", padding: "10px 12px" }}
                          >
                            Asset Type
                          </th>
                          <th
                            style={{ textAlign: "left", padding: "10px 12px" }}
                          >
                            Owner/User
                          </th>
                          <th
                            style={{ textAlign: "left", padding: "10px 12px" }}
                          >
                            Status
                          </th>
                          <th
                            style={{ textAlign: "left", padding: "10px 12px" }}
                          >
                            Location
                          </th>
                          <th
                            style={{ textAlign: "left", padding: "10px 12px" }}
                          >
                            Department
                          </th>
                        </tr>
                      )}
                    </thead>
                    <tbody>
                      {drilldownData.map((item, idx) =>
                        categoryTypeIsAsset(activeCategory) ? (
                          <tr key={item.id || idx}>
                            <td style={{ padding: "10px 12px" }}>
                              <a
                                href={`/assets/${item.id}`}
                                style={{
                                  color: "var(--primary, #3b82f6)",
                                  textDecoration: "none",
                                  fontWeight: 600,
                                }}
                              >
                                {item.hostname || "—"}
                              </a>
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              <a
                                href={`/assets/${item.id}`}
                                style={{
                                  color: "var(--primary, #3b82f6)",
                                  textDecoration: "none",
                                }}
                              >
                                {item.ip_address || "—"}
                              </a>
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              <code>{item.mac_address || "—"}</code>
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              {item.first_seen_at
                                ? new Date(
                                    item.first_seen_at,
                                  ).toLocaleDateString()
                                : "—"}
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              <span
                                style={{
                                  padding: "2px 6px",
                                  borderRadius: 4,
                                  fontSize: "0.72rem",
                                  fontWeight: 600,
                                  background:
                                    item.risk_score >= 70
                                      ? "rgba(239, 68, 68, 0.12)"
                                      : item.risk_score >= 40
                                        ? "rgba(245, 158, 11, 0.12)"
                                        : "rgba(16, 185, 129, 0.12)",
                                  color:
                                    item.risk_score >= 70
                                      ? "#ef4444"
                                      : item.risk_score >= 40
                                        ? "#f59e0b"
                                        : "#10b981",
                                }}
                              >
                                {item.risk_score} ({item.risk_level})
                              </span>
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              {item.owner || "—"}
                            </td>
                          </tr>
                        ) : (
                          <tr key={item.id || idx}>
                            <td
                              style={{ padding: "10px 12px", fontWeight: 600 }}
                            >
                              {item.asset_tag || "—"}
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              {item.asset_name || "—"}
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              <code>{item.serial || "—"}</code>
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              {item.vendor || "—"}
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              {item.asset_type || "—"}
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              {item.asset_user || "—"}
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              <span
                                style={{
                                  padding: "2px 6px",
                                  borderRadius: 4,
                                  fontSize: "0.72rem",
                                  fontWeight: 600,
                                  background:
                                    item.status
                                      ?.toLowerCase()
                                      .includes("active") ||
                                    item.status?.toLowerCase().includes("use")
                                      ? "rgba(16, 185, 129, 0.12)"
                                      : "rgba(255,255,255,0.05)",
                                  color:
                                    item.status
                                      ?.toLowerCase()
                                      .includes("active") ||
                                    item.status?.toLowerCase().includes("use")
                                      ? "#10b981"
                                      : "var(--text-muted)",
                                }}
                              >
                                {item.status || "—"}
                              </span>
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              {item.location || "—"}
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              {item.company_name || "—"}
                            </td>
                          </tr>
                        ),
                      )}
                    </tbody>
                  </table>
                </div>

                {totalCount > limit && (
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginTop: 20,
                    }}
                  >
                    <span
                      style={{
                        fontSize: "0.72rem",
                        color: "var(--text-muted)",
                      }}
                    >
                      Showing <strong>{(page - 1) * limit + 1}</strong> to{" "}
                      <strong>{Math.min(page * limit, totalCount)}</strong> of{" "}
                      <strong>{totalCount}</strong> entries
                    </span>
                    <div style={{ display: "flex", gap: 6 }}>
                      <button
                        onClick={() => setPage((p) => Math.max(1, p - 1))}
                        disabled={page === 1}
                        className="db-btn db-btn--ghost"
                        style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                      >
                        ◀ Previous
                      </button>
                      <button
                        onClick={() =>
                          setPage((p) =>
                            Math.min(Math.ceil(totalCount / limit), p + 1),
                          )
                        }
                        disabled={page >= Math.ceil(totalCount / limit)}
                        className="db-btn db-btn--ghost"
                        style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                      >
                        Next ▶
                      </button>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </AppLayout>
  );
}
