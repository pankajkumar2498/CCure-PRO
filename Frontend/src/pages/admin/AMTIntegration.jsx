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
import { importAmtInventory, getCoverageStats } from "../../api/assets";

export default function AMTIntegration() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Upload state
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadSuccess, setUploadSuccess] = useState(false);
  const [uploadError, setUploadError] = useState(null);

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

  useEffect(() => {
    loadStats();
  }, [loadStats]);

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
      setUploadError(err.response?.data?.detail || "An error occurred during file upload.");
    } finally {
      setUploading(false);
    }
  };

  const coverageColor = (pct) =>
    pct >= 90 ? "#10b981" : pct >= 75 ? "#14b8a6" : pct >= 50 ? "#f59e0b" : "#ef4444";

  return (
    <AppLayout pageTitle="AMT Integration">
      <div className="db-page" style={{ padding: "28px" }}>
        
        {/* Header */}
        <div className="db-page-header" style={{ marginBottom: 24, borderBottom: "none" }}>
          <div>
            <div className="db-page-title">AMT Integration & Reconciliation</div>
            <div className="db-page-subtitle">
              Configure and analyze CMDB coverage maps, Rogue Devices (Shadow IT), and scan gaps.
            </div>
          </div>
          <div className="db-header-actions">
            <button className="db-btn db-btn--ghost" onClick={loadStats} disabled={loading}>
              ↻ Refresh Stats
            </button>
          </div>
        </div>

        {error && (
          <div className="db-alert db-alert--critical" style={{ marginBottom: 20 }}>
            <span className="db-alert-icon">⚠</span>
            <div>{error}</div>
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1.8fr", gap: 24, alignItems: "start" }}>
          
          {/* Left Column: Import / Upload Form */}
          <div className="db-card" style={{ padding: 24 }}>
            <h3 style={{ margin: "0 0 8px 0", fontSize: "1.1rem", fontWeight: 700, color: "var(--text)" }}>
              Import Corporate Inventory
            </h3>
            <p style={{ margin: "0 0 20px 0", fontSize: "0.78rem", color: "var(--text-muted)", lineHeight: 1.5 }}>
              Upload the corporate `assets.json` or inventory export to reconcile device ownership. 
              The matching runs asynchronously via background worker tasks.
            </p>

            <form onSubmit={handleUploadSubmit}>
              <div style={{
                border: "2px dashed var(--border)",
                borderRadius: 8,
                padding: "32px 16px",
                textAlign: "center",
                background: "rgba(255,255,255,0.01)",
                cursor: "pointer",
                transition: "border-color 0.2s, background-color 0.2s",
                marginBottom: 20
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
                <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "var(--text)", marginBottom: 4 }}>
                  {file ? file.name : "Drag & Drop assets.json here"}
                </div>
                <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                  {file ? `${(file.size / 1024).toFixed(1)} KB` : "or click to browse local files"}
                </div>
              </div>

              {uploadError && (
                <div className="db-alert db-alert--critical" style={{ marginBottom: 16, fontSize: "0.75rem" }}>
                  <span className="db-alert-icon">⚠</span>
                  <div>{uploadError}</div>
                </div>
              )}

              {uploadSuccess && (
                <div className="db-alert db-alert--success" style={{ marginBottom: 16, fontSize: "0.75rem" }}>
                  <span className="db-alert-icon">✔</span>
                  <div>Inventory file successfully uploaded! Reconciliation is running in the background.</div>
                </div>
              )}

              <button 
                type="submit" 
                className="db-btn db-btn--primary" 
                style={{ width: "100%", padding: "10px", fontSize: "0.82rem" }}
                disabled={!file || uploading}
              >
                {uploading ? "Uploading & Syncing..." : "Upload & Sync Inventory"}
              </button>
            </form>
          </div>

          {/* Right Column: Integration Metrics & Coverage Ring */}
          <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
            
            {/* Top Row: Metrics Overview */}
            <div className="db-card" style={{ padding: 24 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: "1.1rem", fontWeight: 700, color: "var(--text)" }}>Reconciliation Status</h3>
                  <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: 4 }}>
                    {stats?.configured ? "Inventory linked successfully" : "No active inventory file linked"}
                  </div>
                </div>
                {stats?.configured && (
                  <span className="db-status db-status--complete" style={{ background: "rgba(16,185,129,0.12)", color: "#10b981", fontWeight: 700 }}>
                    Linked & Active
                  </span>
                )}
              </div>

              {!stats?.configured ? (
                <div style={{ padding: "40px 0", textAlign: "center", color: "var(--text-muted)" }}>
                  <div style={{ fontSize: "2.5rem", marginBottom: 16 }}>🔌</div>
                  <h4 style={{ color: "var(--text)", marginBottom: 8, fontSize: "0.9rem" }}>CMDB Integration Inactive</h4>
                  <p style={{ maxWidth: 380, margin: "0 auto", fontSize: "0.75rem", lineHeight: 1.5 }}>
                    Please upload an assets.json file to map owner records, audit location parameters, 
                    and locate unmanaged devices on your networks.
                  </p>
                </div>
              ) : (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24, alignItems: "center" }}>
                  
                  {/* Coverage Gauge Ring */}
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", borderRight: "1px solid var(--border)", paddingRight: 24 }}>
                    <div style={{ position: "relative", width: 140, height: 140 }}>
                      <svg width="140" height="140">
                        <circle cx="70" cy="70" r="56" fill="transparent" stroke="var(--border)" strokeWidth="10" />
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
                      <div style={{
                        position: "absolute",
                        top: "50%",
                        left: "50%",
                        transform: "translate(-50%, -50%)",
                        textAlign: "center"
                      }}>
                        <div style={{ fontSize: "1.6rem", fontWeight: 800, color: coverageColor(stats.coverage_percentage) }}>
                          {stats.coverage_percentage}%
                        </div>
                        <div style={{ fontSize: "0.58rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 700, marginTop: 2 }}>
                          Coverage
                        </div>
                      </div>
                    </div>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: 12, textAlign: "center" }}>
                      <strong>{stats.fully_audited}</strong> of <strong>{stats.total_inventory}</strong> inventory assets matched.
                    </div>
                  </div>

                  {/* Metrics List */}
                  <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border)", paddingBottom: 8 }}>
                      <span style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>Total Scanned Devices:</span>
                      <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--text)" }}>{stats.total_scanned}</span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border)", paddingBottom: 8 }}>
                      <span style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>AMT Inventory Records:</span>
                      <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--text)" }}>{stats.total_inventory}</span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border)", paddingBottom: 8 }}>
                      <span style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>Fully Audited (Scanned & Configured):</span>
                      <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "#10b981" }}>{stats.fully_audited}</span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border)", paddingBottom: 8 }}>
                      <span style={{ fontSize: "0.78rem", color: "var(--text-muted)", display: "flex", alignItems: "center", gap: 4 }}>
                        Shadow IT (Unmanaged Rogue): 
                        <span style={{ cursor: "help" }} title="Discovered during active scans, but not present in your official AMT inventory file.">ℹ</span>
                      </span>
                      <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "#f59e0b" }}>{stats.shadow_it}</span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ fontSize: "0.78rem", color: "var(--text-muted)", display: "flex", alignItems: "center", gap: 4 }}>
                        Coverage Gap (Offline / Firewall):
                        <span style={{ cursor: "help" }} title="Listed in your AMT inventory records, but never successfully detected during active network scans.">ℹ</span>
                      </span>
                      <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "#ef4444" }}>{stats.coverage_gap}</span>
                    </div>
                  </div>

                </div>
              )}
            </div>

            {/* Reconciliation Guidelines Box */}
            <div className="db-card" style={{ padding: 20, background: "rgba(59,130,246,0.02)", border: "1px solid rgba(59,130,246,0.1)" }}>
              <h4 style={{ margin: "0 0 8px 0", fontSize: "0.82rem", fontWeight: 700, color: "#60a5fa" }}>
                🛡 CMDB Best Practices
              </h4>
              <ul style={{ margin: 0, paddingLeft: 16, fontSize: "0.7rem", color: "var(--text-muted)", lineHeight: 1.6 }}>
                <li>Ensure all asset MAC addresses in the uploaded file follow standard formats.</li>
                <li>Imported details automatically enrich the Active Asset Registry upon subsequent discovery.</li>
                <li>Live scanned assets take precedence to prevent false-positives, while manually set owners are protected under the provenance override protocol.</li>
              </ul>
            </div>

          </div>

        </div>

      </div>
    </AppLayout>
  );
}
