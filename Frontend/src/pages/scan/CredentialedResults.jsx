/**
 * src/pages/scan/CredentialedResults.jsx
 * Displays credentialed scan report.
 * Can hydrate from router state (fresh scan) or GET /scans/{id} (history).
 */
import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import AppLayout  from "../../components/layout/AppLayout";
import RiskBadge  from "../../components/scan/RiskBadge";
import { getScan } from "../../api/scans";

const SEV_COLOR = {
  Critical: "#ff4d4d", High: "#f97316", Medium: "#f59e0b", Low: "#22c55e", Info: "#60a5fa",
};

/* ── helpers ── */
function KV({ k, v, danger, warn, mono }) {
  return (
    <div className="kv-row">
      <span className="kv-key">{k}</span>
      <span className="kv-val" style={{
        color:      danger ? "#ff4d4d" : warn ? "#f59e0b" : undefined,
        fontFamily: mono ? "var(--mono)" : undefined,
        fontSize:   mono ? 12 : undefined,
      }}>
        {v}
      </span>
    </div>
  );
}

function Section({ title, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ marginBottom: 10 }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "10px 14px", background: "var(--bg-app)", border: "1px solid var(--border)",
          borderRadius: open ? "8px 8px 0 0" : 8, cursor: "pointer", fontFamily: "var(--font)",
          fontWeight: 600, fontSize: "0.84rem", color: "var(--text-mid)", transition: "background 0.12s",
        }}
        onMouseEnter={e => e.currentTarget.style.background = "#f1f5f9"}
        onMouseLeave={e => e.currentTarget.style.background = "var(--bg-app)"}
      >
        <span>{title}</span>
        <span style={{ color: "var(--text-faint)", fontSize: "0.75rem" }}>{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div style={{
          border: "1px solid var(--border)", borderTop: "none",
          borderRadius: "0 0 8px 8px", padding: "16px",
          background: "var(--bg-white)",
        }}>
          {children}
        </div>
      )}
    </div>
  );
}

function CredTable({ head, rows }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem" }}>
        <thead>
          <tr>
            {head.map(h => (
              <th key={h} style={{ padding: "7px 10px", background: "var(--bg-app)", fontWeight: 600, fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: "1px solid var(--border)", textAlign: "left" }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} style={row._style || {}}>
              {row.cells.map((cell, j) => (
                <td key={j} style={{ padding: "7px 10px", borderBottom: "1px solid #f1f5f9", ...(cell.style || {}) }}>
                  {cell.content}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const maskSecretLine = value => {
  const text = String(value ?? "");
  const eq = text.indexOf("=");
  if (eq === -1) return text.replace(/(:\s*)(.+)$/i, "$1********");
  return `${text.slice(0, eq + 1)}********`;
};

function hydrateFromHistory(detail) {
  const report = detail?.results?.credentialed?.report;
  return report ? { scan_id: detail.id, scan_no: detail.scan_no ?? detail.display_id, ...report } : null;
}

export default function CredentialedResults() {
  const navigate     = useNavigate();
  const location     = useLocation();
  const stateResult  = location.state?.result ?? null;
  const scanIdParam  = new URLSearchParams(location.search).get("scan_id");

  const [result,    setResult]    = useState(stateResult);
  const [loading,   setLoading]   = useState(!stateResult && !!scanIdParam);
  const [error,     setError]     = useState("");
  const [cveFilter, setCveFilter] = useState("All");

  useEffect(() => {
    if (stateResult) { setResult(stateResult); setLoading(false); return; }
    if (!scanIdParam) { setLoading(false); return; }

    let cancelled = false;
    setLoading(true);
    getScan(scanIdParam)
      .then(({ data }) => {
        if (cancelled) return;
        const r = hydrateFromHistory(data);
        if (!r) throw new Error("Stored credentialed report not found for this scan.");
        setResult(r);
      })
      .catch(err => {
        if (cancelled) return;
        setError(err.response?.data?.detail || err.message || "Failed to load results.");
      })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, [scanIdParam, stateResult]);

  useEffect(() => {
    if (!loading && !result && !scanIdParam && !error) {
      navigate("/scan/credentialed", { replace: true });
    }
  }, [loading, result, scanIdParam, error, navigate]);

  /* ── loading ── */
  if (loading) {
    return (
      <AppLayout pageTitle="Credentialed Results">
        <div className="page-inner" style={{ display: "flex", justifyContent: "center", paddingTop: 60 }}>
          <div className="spinner" />
        </div>
      </AppLayout>
    );
  }

  /* ── error ── */
  if (error) {
    return (
      <AppLayout pageTitle="Credentialed Results">
        <div className="page-inner">
          <div className="page-title-row">
            <h2 className="page-title">Credentialed Scan Results</h2>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn btn--ghost" onClick={() => navigate("/history")}>History</button>
              <button className="btn btn--primary" onClick={() => navigate("/scan/credentialed")}>New Scan</button>
            </div>
          </div>
          <div className="alert alert--error">{error}</div>
        </div>
      </AppLayout>
    );
  }

  if (!result) return null;

  const {
    target, username, scan_id, scan_no, display_id, scan_duration,
    detected_os = "linux",
    os_type_was_auto = false,
    system_info = {},
    packages = [], package_count = 0,
    running_services = [],
    open_ports_credentialed = [],
    users = [],
    suid_binaries = [], world_writable_dirs = [],
    sudo_nopasswd = false, sudo_rules_raw = "",
    security_issues = [],
    failed_login_count = 0, brute_force_warning = false,
    failed_logins_recent = [],
    network_interfaces_raw = "",
    env_vars_flagged = [],
    cves = [], cve_count = 0, severity_summary = {},
  } = result;

  const osLabel    = detected_os === "windows" ? "Windows" : "Linux";
  const osIcon     = detected_os === "windows" ? "🪟" : "🐧";
  const osBadgeClr = detected_os === "windows" ? "#0078d4" : "#f97316";

  const overallRisk = (() => {
    if (severity_summary.Critical > 0) return "Critical";
    if (severity_summary.High     > 0) return "High";
    if (severity_summary.Medium   > 0) return "Medium";
    if (severity_summary.Low      > 0) return "Low";
    return "Info";
  })();

  const SEV_ORDER   = ["All", "Critical", "High", "Medium", "Low", "Info"];
  const filteredCves = cveFilter === "All" ? cves : cves.filter(c => c.severity === cveFilter);
  const vulnerablePackageNames = new Set(
    cves.map(c => String(c.package || "").toLowerCase()).filter(Boolean)
  );
  const packagesWithCves = packages.filter(pkg => vulnerablePackageNames.has(String(pkg.name || "").toLowerCase()));
  const hasAdvancedEvidence = Boolean(
    sudo_rules_raw ||
    network_interfaces_raw ||
    failed_logins_recent.length > 0 ||
    env_vars_flagged.length > 0 ||
    packages.length > 0
  );

  return (
    <AppLayout pageTitle="Credentialed Results">
      <div className="page-inner">

        {/* Page header */}
        <div className="page-title-row">
          <div>
            <h2 className="page-title">🔐 Credentialed Scan Results</h2>
            <p className="page-subtitle">
              <code className="ip-code">{target}</code>
              {username && <span className="muted"> · user: {username}</span>}
              {scan_duration && <span className="muted"> · {scan_duration}s</span>}
              {scan_id && <span className="muted"> · Scan No. {scan_no ?? display_id ?? "-"}</span>}
              {os_type_was_auto && (
                <span style={{
                  marginLeft: 8, padding: "2px 8px", borderRadius: 4, fontSize: 11,
                  background: osBadgeClr + "22", color: osBadgeClr,
                  border: `1px solid ${osBadgeClr}44`, fontWeight: 600,
                }}>
                  {osIcon} {osLabel} (auto-detected)
                </span>
              )}
            </p>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn btn--ghost" onClick={() => navigate("/scan/credentialed")}>← New Scan</button>
            <button className="btn btn--ghost" onClick={() => navigate("/history")}>History</button>
          </div>
        </div>

        {/* Summary bar */}
        <div className="summary-bar" style={{ flexWrap: "wrap" }}>
          <span className="summary-item"><RiskBadge level={overallRisk} /></span>
          <span className="summary-item"><b>{system_info.os_name || osLabel}</b></span>
          <span className="summary-item muted">
            {detected_os === "windows"
              ? <>Build <b>{system_info.os_build || system_info.os_version_id || "—"}</b></>
              : <>Kernel <b>{system_info.kernel_version || "—"}</b></>}
          </span>
          <span className="summary-item"><b>{package_count}</b> packages</span>
          <span className="summary-item" style={{ color: cve_count > 0 ? "#f97316" : "var(--ok)" }}>
            <b>{cve_count}</b> CVE{cve_count !== 1 ? "s" : ""}
          </span>
          {brute_force_warning && (
            <span className="summary-item" style={{ color: "#ff4d4d" }}>⚠ Brute-force activity detected</span>
          )}
        </div>

        {/* System Info */}
        <Section title="🖥 System Information" defaultOpen>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 24px" }}>
            <KV k="OS"          v={system_info.os_name       || "—"} />
            <KV k="Version"     v={system_info.os_version_id  || "—"} />
            <KV k="Kernel"      v={system_info.kernel_version || "—"} mono />
            <KV k="Hostname"    v={system_info.hostname       || "—"} mono />
            <KV k="CPU"         v={system_info.cpu_model      || "—"} />
            <KV k="CPU Count"   v={system_info.cpu_count      || "—"} />
            <KV k="Architecture" v={system_info.cpu_arch     || "—"} />
            <KV k="Uptime"      v={system_info.uptime         || "—"} />
            {system_info.memory_summary?.total && (
              <>
                <KV k="RAM Total" v={system_info.memory_summary.total} />
                <KV k="RAM Used"  v={system_info.memory_summary.used} />
              </>
            )}
          </div>
          {system_info.disk_usage?.length > 0 && (
            <div style={{ marginTop: 14 }}>
              <h4 className="section-title">Disk Usage</h4>
              <CredTable
                head={["Filesystem", "Size", "Used", "Available", "Use%", "Mount"]}
                rows={system_info.disk_usage.map(d => ({
                  cells: [
                    { content: <code style={{ fontSize: 11 }}>{d.filesystem}</code> },
                    { content: d.size },
                    { content: d.used },
                    { content: d.available },
                    { content: d.use_pct, style: { color: parseInt(d.use_pct) > 80 ? "#f97316" : undefined } },
                    { content: <code style={{ fontSize: 11 }}>{d.mounted_on}</code> },
                  ],
                }))}
              />
            </div>
          )}
        </Section>

        {/* CVEs */}
        {cve_count > 0 && (
          <Section title={`⚠ CVE Findings (${cve_count})`} defaultOpen>
            {/* Severity summary chips */}
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 12 }}>
              {Object.entries(severity_summary).filter(([, n]) => n > 0).map(([sev, n]) => (
                <span key={sev} style={{ fontFamily: "var(--mono)", fontSize: 12, color: SEV_COLOR[sev] || "var(--text-muted)" }}>
                  {n} {sev}
                </span>
              ))}
            </div>

            {/* Filter tabs */}
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
              {SEV_ORDER.map(sev => (
                <button
                  key={sev}
                  onClick={() => setCveFilter(sev)}
                  style={{
                    padding: "4px 12px", borderRadius: 5, border: `1px solid ${SEV_COLOR[sev] || "var(--border)"}`,
                    background: cveFilter === sev ? (SEV_COLOR[sev] || "var(--accent)") : "transparent",
                    color: cveFilter === sev ? "#fff" : (SEV_COLOR[sev] || "var(--text-muted)"),
                    fontFamily: "var(--font)", fontSize: "0.78rem", cursor: "pointer", transition: "all 0.12s",
                  }}
                >
                  {sev}
                  {sev !== "All" && severity_summary[sev] > 0 && (
                    <span style={{ marginLeft: 4, opacity: 0.8 }}>({severity_summary[sev]})</span>
                  )}
                </button>
              ))}
            </div>

            <div className="cve-list">
              {filteredCves.map((cve, i) => (
                <div key={i} className="cve-row" style={{ flexDirection: "column", gap: 4, alignItems: "flex-start" }}>
                  <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                    <span className="cve-id" style={{ color: SEV_COLOR[cve.severity] || "#60a5fa" }}>{cve.cve_id}</span>
                    <span className="cve-sev" style={{ color: SEV_COLOR[cve.severity] }}>{cve.severity}</span>
                    {cve.cvss_score && (
                      <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-muted)" }}>CVSS {cve.cvss_score}</span>
                    )}
                    {cve.package && (
                      <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-faint)" }}>
                        {cve.package} {cve.installed_ver}
                      </span>
                    )}
                    {cve.fixed_ver && (
                      <span style={{ fontSize: 11, color: "var(--ok)" }}>→ fixed in {cve.fixed_ver}</span>
                    )}
                  </div>
                  <span className="cve-desc">{cve.description}</span>
                </div>
              ))}
            </div>
          </Section>
        )}

        {/* Security Audit */}
        <Section title="🔒 Security Audit" defaultOpen={security_issues.length > 0 || sudo_nopasswd}>
          {security_issues.length > 0 && (
            <ul className="issue-list" style={{ marginBottom: 12 }}>
              {security_issues.map((iss, i) => <li key={i} style={{ color: "#f97316" }}>{iss}</li>)}
            </ul>
          )}
          <div className="kv-grid">
            <KV k="NOPASSWD Sudo"      v={sudo_nopasswd ? "⚠ YES — any command without password" : "No"} danger={sudo_nopasswd} />
            <KV k="SUID Binaries"      v={`${suid_binaries.length} found`} warn={suid_binaries.length > 15} />
            <KV k="World-Writable Dirs" v={`${world_writable_dirs.length} found`} warn={world_writable_dirs.length > 0} />
            <KV k="Failed Logins"      v={`${failed_login_count}${brute_force_warning ? " ⚠ possible brute force" : ""}`} danger={brute_force_warning} />
          </div>
          {suid_binaries.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <h4 className="section-title">SUID Binaries</h4>
              <div style={{ maxHeight: 160, overflowY: "auto", fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.6 }}>
                {suid_binaries.map((b, i) => <div key={i}>{b}</div>)}
              </div>
            </div>
          )}
        </Section>

        {/* Running Services */}
        {running_services.length > 0 && (
          <Section title={`⚙️ Running Services (${running_services.length})`}>
            <CredTable
              head={["Service", "Status", "Description"]}
              rows={running_services.map(svc => ({
                cells: [
                  { content: <code style={{ fontSize: 11 }}>{svc.name}</code> },
                  { content: svc.sub_state || "running", style: { color: "var(--ok)", fontSize: 11 } },
                  { content: svc.description, style: { fontSize: 12, color: "var(--text-muted)" } },
                ],
              }))}
            />
          </Section>
        )}

        {/* Open Ports */}
        {open_ports_credentialed.length > 0 && (
          <Section title={`🔌 Open Ports — socket table (${open_ports_credentialed.length})`}>
            <CredTable
              head={["State", "Local Addr", "Port", "Process"]}
              rows={open_ports_credentialed.map(p => ({
                cells: [
                  { content: p.state, style: { color: "var(--ok)", fontSize: 11 } },
                  { content: <code style={{ fontSize: 11 }}>{p.local_addr}</code> },
                  { content: <code style={{ fontSize: 12 }}>{p.port}</code> },
                  { content: p.process, style: { fontSize: 11, color: "var(--text-muted)" } },
                ],
              }))}
            />
          </Section>
        )}

        {/* Packages */}
        {packagesWithCves.length > 0 && (
          <Section title={`Packages with CVE Matches (${packagesWithCves.length})`}>
            <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
              Showing only packages that match vulnerability findings.
            </p>
            <CredTable
              head={["Package", "Version", "Manager", "CVE?"]}
              rows={packagesWithCves.map(pkg => {
                return {
                  _style: { background: "rgba(249,115,22,0.07)" },
                  cells: [
                    { content: <span style={{ color: "#f97316" }}>{pkg.name}<span style={{ marginLeft: 6, fontSize: 10, color: "#f97316" }}>match</span></span> },
                    { content: <code style={{ fontSize: 11 }}>{pkg.version}</code> },
                    { content: pkg.manager, style: { fontSize: 11, color: "var(--text-muted)" } },
                    { content: "CVE match", style: { fontSize: 11, color: "#f97316" } },
                  ],
                };
              })}
            />
          </Section>
        )}

        {/* Users */}
        {users.length > 0 && (
          <Section title={`👤 Users (${users.length})`}>
            <CredTable
              head={["Username", "UID", "Shell", "Home", "Type"]}
              rows={users.filter(u => !u.is_system || u.is_root).map(u => ({
                _style: u.is_root ? { color: "#ff4d4d" } : {},
                cells: [
                  { content: <code style={{ fontSize: 12 }}>{u.username}</code> },
                  { content: u.uid, style: { fontSize: 11 } },
                  { content: u.shell, style: { fontSize: 11, color: "var(--text-muted)" } },
                  { content: u.home,  style: { fontSize: 11, color: "var(--text-muted)" } },
                  { content: u.is_root ? "⚠ root" : "user", style: { fontSize: 11 } },
                ],
              }))}
            />
          </Section>
        )}

        {/* Login History */}
        {failed_login_count > 0 && (
          <Section title="📋 Login History">
            <div className="kv-grid">
              <KV k="Failed Logins"    v={String(failed_login_count)}               danger={brute_force_warning} />
              <KV k="Brute Force Alert" v={brute_force_warning ? "⚠ YES" : "No"}    danger={brute_force_warning} />
            </div>
          </Section>
        )}

        {/* Advanced Evidence */}
        {hasAdvancedEvidence && (
          <Section title="Advanced Evidence">
            <p className="muted" style={{ fontSize: 12, marginBottom: 12 }}>
              Raw evidence is hidden by default to keep the report readable. Sensitive values are masked.
            </p>
            {sudo_rules_raw && (
              <div style={{ marginTop: 12 }}>
                <h4 className="section-title">Sudo Rules</h4>
                <pre style={{ background: "var(--bg-app)", border: "1px solid var(--border)", borderRadius: 6, padding: "10px 12px", fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-mid)", overflowX: "auto", maxHeight: 160, overflowY: "auto" }}>
                  {sudo_rules_raw}
                </pre>
              </div>
            )}
            {failed_logins_recent.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <h4 className="section-title">Recent Login Failures</h4>
                <pre style={{ background: "var(--bg-app)", border: "1px solid var(--border)", borderRadius: 6, padding: "10px 12px", fontFamily: "var(--mono)", fontSize: 12, maxHeight: 140, overflowY: "auto" }}>
                  {failed_logins_recent.join("\n")}
                </pre>
              </div>
            )}
            {network_interfaces_raw && (
              <>
                <h4 className="section-title">Network Interfaces</h4>
                <pre style={{ background: "var(--bg-app)", border: "1px solid var(--border)", borderRadius: 6, padding: "10px 12px", fontFamily: "var(--mono)", fontSize: 12, maxHeight: 180, overflowY: "auto" }}>
                  {network_interfaces_raw}
                </pre>
              </>
            )}
            {env_vars_flagged.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <h4 className="section-title" style={{ color: "#f97316" }}>
                  ⚠ Sensitive Environment Variables ({env_vars_flagged.length})
                </h4>
                {env_vars_flagged.map((v, i) => (
                  <div key={i} style={{ fontFamily: "var(--mono)", fontSize: 11, color: "#f97316", marginBottom: 2 }}>{maskSecretLine(v)}</div>
                ))}
              </div>
            )}
            {packages.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <h4 className="section-title">Full Package Inventory ({package_count})</h4>
                <CredTable
                  head={["Package", "Version", "Manager"]}
                  rows={packages.map(pkg => ({
                    cells: [
                      { content: pkg.name },
                      { content: <code style={{ fontSize: 11 }}>{pkg.version}</code> },
                      { content: pkg.manager, style: { fontSize: 11, color: "var(--text-muted)" } },
                    ],
                  }))}
                />
              </div>
            )}
          </Section>
        )}

        {/* Footer */}
        <div className="phase-footer" style={{ marginTop: 16 }}>
          <span className="muted" style={{ fontSize: 13 }}>
            Credentialed scan complete — results saved to history.
          </span>
          <div style={{ display: "flex", gap: 10 }}>
            <button className="btn btn--ghost" onClick={() => navigate("/history")}>View History</button>
            <button className="btn btn--primary" onClick={() => navigate("/scan/credentialed")}>↺ New Scan</button>
          </div>
        </div>

      </div>
    </AppLayout>
  );
}
