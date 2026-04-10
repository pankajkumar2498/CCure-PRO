/**
 * src/pages/scan/CredentialedResults.jsx
 *
 * Route: /scan/credentialed/results
 * Displays the credentialed scan report and can restore it from
 * persisted scan history using scan_id in the URL.
 */

import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import AppShell    from "../../components/layout/AppShell";
import RiskBadge   from "../../components/scan/RiskBadge";
import { getScan } from "../../api/scans";

const SEV_COLOR = {
  Critical: "#ff4d4d",
  High:     "#f97316",
  Medium:   "#f59e0b",
  Low:      "#22c55e",
  Info:     "#60a5fa",
};

function KV({ k, v, danger, warn, mono }) {
  return (
    <div className="kv-row">
      <span className="kv-key">{k}</span>
      <span
        className="kv-val"
        style={{
          color:      danger ? "#ff4d4d" : warn ? "#f59e0b" : undefined,
          fontFamily: mono ? "var(--mono)" : undefined,
          fontSize:   mono ? 12 : undefined,
        }}
      >
        {v}
      </span>
    </div>
  );
}

function Section({ title, icon, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="audit-section" style={{ marginBottom: 12 }}>
      <button
        className="cred-section-toggle"
        onClick={() => setOpen(o => !o)}
      >
        <span>{icon} {title}</span>
        <span>{open ? "▲" : "▼"}</span>
      </button>
      {open && <div className="cred-section-body">{children}</div>}
    </div>
  );
}

function SeverityBar({ counts }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (!total) return <span className="muted" style={{ fontSize: 13 }}>No CVEs found</span>;
  return (
    <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
      {Object.entries(counts).filter(([, n]) => n > 0).map(([sev, n]) => (
        <span
          key={sev}
          style={{
            fontFamily: "var(--mono)",
            fontSize:   12,
            color:      SEV_COLOR[sev] || "var(--text-muted)",
          }}
        >
          {n} {sev}
        </span>
      ))}
    </div>
  );
}

function hydrateStoredCredentialedResult(detail) {
  const report = detail?.results?.credentialed?.report;
  if (!report) {
    return null;
  }

  return {
    scan_id: detail.id,
    ...report,
  };
}

export default function CredentialedResults() {
  const navigate = useNavigate();
  const location = useLocation();
  const stateResult = location.state?.result ?? null;
  const scanIdFromUrl = new URLSearchParams(location.search).get("scan_id");

  const [result, setResult]       = useState(stateResult);
  const [loading, setLoading]     = useState(!stateResult && !!scanIdFromUrl);
  const [error, setError]         = useState("");
  const [cveFilter, setCveFilter] = useState("All");

  useEffect(() => {
    if (stateResult) {
      setResult(stateResult);
      setLoading(false);
      setError("");
      return;
    }

    if (!scanIdFromUrl) {
      setResult(null);
      setLoading(false);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError("");

    getScan(scanIdFromUrl)
      .then(({ data }) => {
        if (cancelled) return;

        const storedResult = hydrateStoredCredentialedResult(data);
        if (!storedResult) {
          throw new Error("Stored credentialed report was not found for this scan.");
        }

        setResult(storedResult);
      })
      .catch((err) => {
        if (cancelled) return;
        setResult(null);
        setError(err.response?.data?.detail || err.message || "Failed to load saved credentialed results.");
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [scanIdFromUrl, stateResult]);

  useEffect(() => {
    if (!loading && !result && !scanIdFromUrl && !error) {
      navigate("/scan/credentialed", { replace: true });
    }
  }, [error, loading, navigate, result, scanIdFromUrl]);

  if (loading) {
    return (
      <AppShell>
        <div className="page-content">
          <div style={{ display: "flex", justifyContent: "center", padding: 60 }}>
            <div className="spinner" />
          </div>
        </div>
      </AppShell>
    );
  }

  if (error) {
    return (
      <AppShell>
        <div className="page-content">
          <div className="page-header">
            <div>
              <h2 className="page-title">Credentialed Scan Results</h2>
              <p className="page-sub">Saved results could not be loaded.</p>
            </div>
            <div className="page-header-actions">
              <button className="phase-btn phase-btn--ghost" onClick={() => navigate("/history")}>
                History
              </button>
              <button className="phase-btn" onClick={() => navigate("/scan/credentialed")}>
                New Credentialed Scan
              </button>
            </div>
          </div>
          <div className="scan-error">{error}</div>
        </div>
      </AppShell>
    );
  }

  if (!result) {
    return null;
  }

  const {
    target, username, scan_id, scan_duration,
    system_info = {},
    packages = [], package_count = 0,
    running_services = [],
    open_ports_credentialed = [],
    users = [],
    suid_binaries = [], world_writable_dirs = [],
    sudo_nopasswd = false, sudo_rules_raw = "", cron_info_raw = "",
    security_issues = [],
    failed_login_count = 0, brute_force_warning = false,
    failed_logins_recent = [],
    network_interfaces_raw = "",
    env_vars_flagged = [],
    cves = [], cve_count = 0, severity_summary = {},
  } = result;

  const overallRisk = (() => {
    if (severity_summary.Critical > 0) return "Critical";
    if (severity_summary.High     > 0) return "High";
    if (severity_summary.Medium   > 0) return "Medium";
    if (severity_summary.Low      > 0) return "Low";
    return "Info";
  })();

  const SEV_ORDER = ["All", "Critical", "High", "Medium", "Low", "Info"];
  const filteredCves = cveFilter === "All"
    ? cves
    : cves.filter(c => c.severity === cveFilter);
  const usernameLabel = username ? `user: ${username}` : "user not stored";

  return (
    <AppShell>
      <div className="page-content">

        {/* ── Page header ── */}
        <div className="page-header">
          <div>
            <h2 className="page-title">
              🔐 Credentialed Scan Results
            </h2>
            <p className="page-sub">
              <code className="ip">{target}</code>
              {" "}·{" "}
              <span className="muted">{usernameLabel}</span>
              {" "}·{" "}
              <span className="muted">{scan_duration}s</span>
              {scan_id && (
                <span className="muted"> · Scan #{scan_id}</span>
              )}
            </p>
          </div>
          <div className="page-header-actions">
            <button
              className="phase-btn phase-btn--ghost"
              onClick={() => navigate("/scan/credentialed")}
            >
              ← New Scan
            </button>
            <button
              className="phase-btn phase-btn--ghost"
              onClick={() => navigate("/history")}
            >
              History
            </button>
          </div>
        </div>

        {/* ── Summary bar ── */}
        <div className="summary-bar" style={{ flexWrap: "wrap", gap: 12 }}>
          <span className="sb-item">
            <RiskBadge level={overallRisk} score={0} />
          </span>
          <span className="sb-item">
            <b>{system_info.os_name || "Linux"}</b>
          </span>
          <span className="sb-item muted">
            Kernel <b>{system_info.kernel_version || "—"}</b>
          </span>
          <span className="sb-item">
            <b>{package_count}</b> packages
          </span>
          <span className="sb-item" style={{ color: cve_count > 0 ? "#f97316" : "var(--ok)" }}>
            <b>{cve_count}</b> CVE{cve_count !== 1 ? "s" : ""}
          </span>
          {brute_force_warning && (
            <span className="sb-item" style={{ color: "#ff4d4d" }}>
              ⚠ Brute-force activity detected
            </span>
          )}
        </div>

        {/* ── System Info ── */}
        <Section title="System Information" icon="🖥" defaultOpen>
          <div className="kv-grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
            <KV k="OS"               v={system_info.os_name        || "—"} />
            <KV k="Version"          v={system_info.os_version_id   || "—"} />
            <KV k="Kernel"           v={system_info.kernel_version  || "—"} mono />
            <KV k="Hostname"         v={system_info.hostname        || "—"} mono />
            <KV k="CPU"              v={system_info.cpu_model       || "—"} />
            <KV k="CPU Count"        v={system_info.cpu_count       || "—"} />
            <KV k="Architecture"     v={system_info.cpu_arch        || "—"} />
            <KV k="Uptime"           v={system_info.uptime          || "—"} />
            {system_info.memory_summary?.total && (
              <>
                <KV k="RAM Total"    v={system_info.memory_summary.total} />
                <KV k="RAM Used"     v={system_info.memory_summary.used} />
                <KV k="RAM Free"     v={system_info.memory_summary.available || system_info.memory_summary.free} />
              </>
            )}
          </div>
          {system_info.disk_usage?.length > 0 && (
            <>
              <h4 className="section-title" style={{ marginTop: 16 }}>Disk Usage</h4>
              <div style={{ overflowX: "auto" }}>
                <table className="cred-table">
                  <thead>
                    <tr>
                      <th>Filesystem</th><th>Size</th><th>Used</th><th>Available</th><th>Use%</th><th>Mount</th>
                    </tr>
                  </thead>
                  <tbody>
                    {system_info.disk_usage.map((d, i) => (
                      <tr key={i}>
                        <td><code style={{ fontSize: 11 }}>{d.filesystem}</code></td>
                        <td>{d.size}</td>
                        <td>{d.used}</td>
                        <td>{d.available}</td>
                        <td style={{ color: parseInt(d.use_pct) > 80 ? "#f97316" : undefined }}>
                          {d.use_pct}
                        </td>
                        <td><code style={{ fontSize: 11 }}>{d.mounted_on}</code></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </Section>

        {/* ── CVEs ── */}
        {cve_count > 0 && (
          <Section title={`CVE Findings (${cve_count})`} icon="⚠" defaultOpen>
            <div style={{ marginBottom: 12 }}>
              <SeverityBar counts={severity_summary} />
            </div>
            {/* Filter tabs */}
            <div style={{ display: "flex", gap: 6, marginBottom: 12, flexWrap: "wrap" }}>
              {SEV_ORDER.map(sev => (
                <button
                  key={sev}
                  className={`phase-btn phase-btn--ghost ${cveFilter === sev ? "shell-nav-link--active" : ""}`}
                  style={{
                    fontSize: 11,
                    padding: "3px 10px",
                    borderColor: SEV_COLOR[sev] || "var(--border)",
                    color: cveFilter === sev ? (SEV_COLOR[sev] || "var(--accent)") : undefined,
                  }}
                  onClick={() => setCveFilter(sev)}
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
                    <span className="cve-id" style={{ color: SEV_COLOR[cve.severity] || "#60a5fa" }}>
                      {cve.cve_id}
                    </span>
                    <span className="cve-sev" style={{ color: SEV_COLOR[cve.severity] }}>
                      {cve.severity}
                    </span>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-muted)" }}>
                      CVSS {cve.cvss_score}
                    </span>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-faint)" }}>
                      {cve.package} {cve.installed_ver}
                    </span>
                    {cve.fixed_ver && (
                      <span style={{ fontSize: 11, color: "var(--ok)" }}>
                        → fixed in {cve.fixed_ver}
                      </span>
                    )}
                  </div>
                  <span className="cve-desc">{cve.description}</span>
                </div>
              ))}
            </div>
          </Section>
        )}

        {/* ── Security Audit ── */}
        <Section title="Security Audit" icon="🔒" defaultOpen={security_issues.length > 0}>
          {security_issues.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <ul className="issue-list">
                {security_issues.map((iss, i) => (
                  <li key={i} style={{ color: "#f97316" }}>{iss}</li>
                ))}
              </ul>
            </div>
          )}
          <div className="kv-grid">
            <KV
              k="NOPASSWD Sudo"
              v={sudo_nopasswd ? "⚠ YES — any command runs without password" : "No"}
              danger={sudo_nopasswd}
            />
            <KV
              k="SUID Binaries"
              v={`${suid_binaries.length} found`}
              warn={suid_binaries.length > 15}
            />
            <KV
              k="World-Writable Dirs"
              v={`${world_writable_dirs.length} found`}
              warn={world_writable_dirs.length > 0}
            />
            <KV
              k="Failed Logins"
              v={`${failed_login_count}${brute_force_warning ? " ⚠ possible brute force" : ""}`}
              danger={brute_force_warning}
            />
          </div>
          {suid_binaries.length > 0 && (
            <>
              <h4 className="section-title" style={{ marginTop: 12 }}>SUID Binaries</h4>
              <div style={{ maxHeight: 160, overflowY: "auto" }}>
                {suid_binaries.map((b, i) => (
                  <div key={i} style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-muted)", marginBottom: 2 }}>
                    {b}
                  </div>
                ))}
              </div>
            </>
          )}
          {sudo_rules_raw && (
            <>
              <h4 className="section-title" style={{ marginTop: 12 }}>Sudo Rules</h4>
              <pre className="cred-pre">{sudo_rules_raw}</pre>
            </>
          )}
        </Section>

        {/* ── Running Services ── */}
        {running_services.length > 0 && (
          <Section title={`Running Services (${running_services.length})`} icon="⚙️">
            <div style={{ maxHeight: 260, overflowY: "auto" }}>
              <table className="cred-table">
                <thead>
                  <tr><th>Service</th><th>Status</th><th>Description</th></tr>
                </thead>
                <tbody>
                  {running_services.map((svc, i) => (
                    <tr key={i}>
                      <td><code style={{ fontSize: 11 }}>{svc.name}</code></td>
                      <td><span style={{ color: "var(--ok)", fontSize: 11 }}>{svc.sub_state || "running"}</span></td>
                      <td style={{ fontSize: 12, color: "var(--text-muted)" }}>{svc.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
        )}

        {/* ── Open Ports (from socket table) ── */}
        {open_ports_credentialed.length > 0 && (
          <Section title={`Open Ports — socket table (${open_ports_credentialed.length})`} icon="🔌">
            <div style={{ maxHeight: 220, overflowY: "auto" }}>
              <table className="cred-table">
                <thead>
                  <tr><th>State</th><th>Local Address</th><th>Port</th><th>Process</th></tr>
                </thead>
                <tbody>
                  {open_ports_credentialed.map((p, i) => (
                    <tr key={i}>
                      <td style={{ color: "var(--ok)", fontSize: 11 }}>{p.state}</td>
                      <td><code style={{ fontSize: 11 }}>{p.local_addr}</code></td>
                      <td><code style={{ fontSize: 12 }}>{p.port}</code></td>
                      <td style={{ fontSize: 11, color: "var(--text-muted)" }}>{p.process}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
        )}

        {/* ── Installed Packages ── */}
        {packages.length > 0 && (
          <Section title={`Installed Packages (${package_count})`} icon="📦">
            <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
              Showing packages with CVE matches highlighted. Full list: {package_count} packages.
            </p>
            <div style={{ maxHeight: 300, overflowY: "auto" }}>
              <table className="cred-table">
                <thead>
                  <tr><th>Package</th><th>Version</th><th>Manager</th><th>CVE?</th></tr>
                </thead>
                <tbody>
                  {packages.map((pkg, i) => {
                    const hasCve = cves.some(c => c.package?.toLowerCase() === pkg.name?.toLowerCase());
                    return (
                      <tr key={i} style={hasCve ? { background: "rgba(249,115,22,0.08)" } : {}}>
                        <td style={{ color: hasCve ? "#f97316" : undefined }}>
                          {pkg.name}
                          {hasCve && <span style={{ marginLeft: 6, fontSize: 10, color: "#f97316" }}>⚠ CVE</span>}
                        </td>
                        <td><code style={{ fontSize: 11 }}>{pkg.version}</code></td>
                        <td style={{ fontSize: 11, color: "var(--text-muted)" }}>{pkg.manager}</td>
                        <td style={{ fontSize: 11 }}>{hasCve ? "⚠" : "—"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Section>
        )}

        {/* ── Users ── */}
        {users.length > 0 && (
          <Section title={`Users (${users.length})`} icon="👤">
            <div style={{ maxHeight: 220, overflowY: "auto" }}>
              <table className="cred-table">
                <thead>
                  <tr><th>Username</th><th>UID</th><th>Shell</th><th>Home</th><th>Type</th></tr>
                </thead>
                <tbody>
                  {users.filter(u => !u.is_system || u.is_root).map((u, i) => (
                    <tr key={i} style={u.is_root ? { color: "#ff4d4d" } : {}}>
                      <td><code style={{ fontSize: 12 }}>{u.username}</code></td>
                      <td style={{ fontSize: 11 }}>{u.uid}</td>
                      <td style={{ fontSize: 11, color: "var(--text-muted)" }}>{u.shell}</td>
                      <td style={{ fontSize: 11, color: "var(--text-muted)" }}>{u.home}</td>
                      <td style={{ fontSize: 11 }}>{u.is_root ? "⚠ root" : "user"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
        )}

        {/* ── Login History ── */}
        {(failed_login_count > 0 || failed_logins_recent.length > 0) && (
          <Section title="Login History" icon="📋">
            <div className="kv-grid">
              <KV k="Failed Logins"      v={String(failed_login_count)} danger={brute_force_warning} />
              <KV k="Brute Force Alert"  v={brute_force_warning ? "⚠ YES" : "No"} danger={brute_force_warning} />
            </div>
            {failed_logins_recent.length > 0 && (
              <>
                <h4 className="section-title" style={{ marginTop: 12 }}>Recent Failures</h4>
                <pre className="cred-pre" style={{ maxHeight: 140 }}>
                  {failed_logins_recent.join("\n")}
                </pre>
              </>
            )}
          </Section>
        )}

        {/* ── Network ── */}
        {(network_interfaces_raw || env_vars_flagged.length > 0) && (
          <Section title="Network &amp; Environment" icon="🌐">
            {network_interfaces_raw && (
              <>
                <h4 className="section-title">Network Interfaces</h4>
                <pre className="cred-pre" style={{ maxHeight: 180 }}>{network_interfaces_raw}</pre>
              </>
            )}
            {env_vars_flagged.length > 0 && (
              <>
                <h4 className="section-title" style={{ marginTop: 12, color: "#f97316" }}>
                  ⚠ Sensitive Environment Variables ({env_vars_flagged.length})
                </h4>
                {env_vars_flagged.map((v, i) => (
                  <div key={i} style={{ fontFamily: "var(--mono)", fontSize: 11, color: "#f97316", marginBottom: 2 }}>
                    {v}
                  </div>
                ))}
              </>
            )}
          </Section>
        )}

        {/* ── Footer ── */}
        <div className="phase-footer" style={{ marginTop: 16 }}>
          <span className="muted" style={{ fontSize: 13 }}>
            Credentialed scan complete — results saved to history.
          </span>
          <div style={{ display: "flex", gap: 10 }}>
            <button
              className="phase-btn phase-btn--ghost"
              onClick={() => navigate("/history")}
            >
              View History
            </button>
            <button
              className="phase-btn"
              onClick={() => navigate("/scan/credentialed")}
            >
              ↺ New Credentialed Scan
            </button>
          </div>
        </div>

      </div>
    </AppShell>
  );
}
